//! Missing types: BpfVerifierEnv, BpfFuncState, BpfVerifierState, BpfVerifierStateList

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, st))]
pub fn clean_func_state(env: &mut BpfVerifierEnv, st: &mut BpfFuncState, ip: u32) -> Result<()> {
    let live_regs = env.insn_aux_data[ip as usize].live_regs_before;

    for i in 0..BPF_REG_FP as usize {
        /* liveness must not touch this register anymore */
        if (live_regs & BIT(i as u32)) == 0 {
            /* since the register is unused, clear its state
             * to make further comparison simpler
             */
            inner_mark_reg_not_init(env, &mut st.regs[i]);
        }
    }

    for i in 0..(st.allocated_stack / BPF_REG_SIZE) as usize {
        if !bpf_stack_slot_alive(env, st.frameno, i as u32) {
            inner_mark_reg_not_init(env, &mut st.stack[i].spilled_ptr);
            for j in 0..BPF_REG_SIZE as usize {
                st.stack[i].slot_type[j] = STACK_INVALID;
            }
        }
    }

    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, cur))]
pub fn clean_live_states(env: &mut BpfVerifierEnv, insn: i32, cur: &BpfVerifierState) -> Result<()> {
    let head = explored_state(env, insn);
    for sl in head.iter_mut() {
        let state = &mut sl.state;
        if state.branches != 0 {
            continue;
        }
        if state.insn_idx != insn || !same_callsites(state, cur) {
            continue;
        }
        if state.cleaned {
            /* all regs in this state in all frames were already marked */
            continue;
        }
        if incomplete_read_marks(env, state) {
            continue;
        }
        clean_verifier_state(env, state)?;
    }
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, st))]
pub fn clean_verifier_state(env: &mut BpfVerifierEnv, st: &mut BpfVerifierState) -> Result<()> {
    bpf_live_stack_query_init(env, st);
    st.cleaned = true;
    for i in 0..=st.curframe as usize {
        let ip = frame_insn_idx(st, i as i32);
        clean_func_state(env, st.frame[i], ip as u32)?;
    }
    Ok(())
}
