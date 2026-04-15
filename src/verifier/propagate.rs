//! Missing types: BpfVerifierEnv, BpfSccVisit, BpfSccBackedge, BpfVerifierState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, visit))]
pub fn propagate_backedges(env: &mut BpfVerifierEnv, visit: &mut BpfSccVisit) -> Result<i32> {
    let mut i = 0;

    loop {
        i += 1;
        if i > MAX_BACKEDGE_ITERS {
            if (env.log.level & BPF_LOG_LEVEL2) != 0 {
                verbose(env, format!("{}: too many iterations\n", "propagate_backedges"));
            }
            let mut b = visit.backedges.as_mut();
            while let Some(be) = b {
                mark_all_scalars_precise(env, &mut be.state)?;
                b = be.next.as_mut();
            }
            break;
        }

        let mut changed = false;
        let mut b = visit.backedges.as_mut();
        while let Some(be) = b {
            let st: &mut BpfVerifierState = &mut be.state;
            propagate_precision(env, be.state.equal_state, st, &mut changed)?;
            b = be.next.as_mut();
        }

        if !changed {
            break;
        }
    }

    free_backedges(visit)?;
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, old, cur, changed))]
pub fn propagate_precision(
    env: &mut BpfVerifierEnv,
    old: &BpfVerifierState,
    cur: &mut BpfVerifierState,
    changed: &mut bool,
) -> Result<i32> {
    for fr in (0..=old.curframe as usize).rev() {
        let state = &old.frame[fr];
        let mut first = true;

        for i in 0..BPF_REG_FP as usize {
            let state_reg = &state.regs[i];
            if state_reg.r#type != SCALAR_VALUE || !state_reg.precise {
                continue;
            }
            bt_set_frame_reg(&mut env.bt, fr as i32, i as i32);
            first = false;
        }

        for i in 0..(state.allocated_stack / BPF_REG_SIZE as i32) as usize {
            if !is_spilled_reg(&state.stack[i]) {
                continue;
            }
            let state_reg = &state.stack[i].spilled_ptr;
            if state_reg.r#type != SCALAR_VALUE || !state_reg.precise {
                continue;
            }
            bt_set_frame_slot(&mut env.bt, fr as i32, i as u32);
            first = false;
        }

        if !first && (env.log.level & BPF_LOG_LEVEL2) != 0 {
            verbose(env, "\n");
        }
    }

    inner_mark_chain_precision(env, cur, -1, Some(changed))?;
    Ok(0)
}
