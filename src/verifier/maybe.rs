//! Missing types: BpfVerifierEnv, BpfVerifierState, BpfSccCallchain, BpfSccVisit, BpfInsn, BpfRegState, BpfVerifierStateList

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, st))]
pub fn maybe_enter_scc(env: &mut BpfVerifierEnv, st: &mut BpfVerifierState) -> Result<i32> {
    let callchain: &mut BpfSccCallchain = &mut env.callchain_buf;

    if !compute_scc_callchain(env, st, callchain) {
        return Ok(0);
    }

    let mut visit = scc_visit_lookup(env, callchain);
    if visit.is_none() {
        visit = scc_visit_alloc(env, callchain);
    }
    let visit = visit.ok_or_else(|| anyhow!("maybe_enter_scc failed"))?;

    if visit.entry_state.is_none() {
        visit.entry_state = Some(st);
        if (env.log.level & BPF_LOG_LEVEL2) != 0 {
            verbose(env, format!("SCC enter {}\n", format_callchain(env, callchain)?));
        }
    }
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, st))]
pub fn maybe_exit_scc(env: &mut BpfVerifierEnv, st: &mut BpfVerifierState) -> Result<i32> {
    let callchain: &mut BpfSccCallchain = &mut env.callchain_buf;

    if !compute_scc_callchain(env, st, callchain) {
        return Ok(0);
    }

    let visit = scc_visit_lookup(env, callchain);
    if visit.is_none() {
        if !st.speculative {
            verifier_bug(env, format!("scc exit: no visit info for call chain {}", format_callchain(env, callchain)?));
            return Err(anyhow!("maybe_exit_scc failed"));
        }
        return Ok(0);
    }

    let visit = visit.unwrap();
    if visit.entry_state != Some(st) {
        return Ok(0);
    }

    if (env.log.level & BPF_LOG_LEVEL2) != 0 {
        verbose(env, format!("SCC exit {}\n", format_callchain(env, callchain)?));
    }

    visit.entry_state = None;
    env.num_backedges -= visit.num_backedges;
    visit.num_backedges = 0;
    update_peak_states(env);
    propagate_backedges(env, visit)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn, dst_reg))]
pub fn maybe_fork_scalars(env: &mut BpfVerifierEnv, insn: &BpfInsn, dst_reg: &mut BpfRegState) -> Result<i32> {
    let alu32 = if dst_reg.smin_value == -1 && dst_reg.smax_value == 0 {
        false
    } else if dst_reg.s32_min_value == -1 && dst_reg.s32_max_value == 0 {
        true
    } else {
        return Ok(0);
    };

    let branch = push_stack(env, env.insn_idx, env.insn_idx, false)?;
    let regs = &mut branch.frame[branch.curframe as usize].regs;

    if alu32 {
        inner_mark_reg32_known(&mut regs[insn.dst_reg as usize], 0);
        inner_mark_reg32_known(dst_reg, !0u64);
    } else {
        inner_mark_reg_known(&mut regs[insn.dst_reg as usize], 0);
        inner_mark_reg_known(dst_reg, !0u64);
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, sl))]
pub fn maybe_free_verifier_state(env: &mut BpfVerifierEnv, sl: &mut BpfVerifierStateList) -> Result<()> {
    if !sl.in_free_list || sl.state.branches != 0 || incomplete_read_marks(env, &mut sl.state)? {
        return Ok(());
    }
    list_del(&mut sl.node);
    free_verifier_state(&mut sl.state, false)?;
    kfree(sl);
    env.free_list_size -= 1;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, rold, rcur))]
pub fn maybe_widen_reg(env: &mut BpfVerifierEnv, rold: &mut BpfRegState, rcur: &mut BpfRegState) -> Result<()> {
    if rold.r#type != SCALAR_VALUE || rcur.r#type != SCALAR_VALUE {
        return Ok(());
    }
    if rold.precise || rcur.precise || scalars_exact_for_widen(rold, rcur) {
        return Ok(());
    }
    inner_mark_reg_unknown(env, rcur);
    Ok(())
}
