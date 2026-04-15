//! Missing types: BpfVerifierEnv, BpfFuncState, BpfRegState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, state))]
pub fn init_func_state(
    env: &mut BpfVerifierEnv,
    state: &mut BpfFuncState,
    callsite: i32,
    frameno: i32,
    subprogno: i32,
) -> Result<()> {
    state.callsite = callsite;
    state.frameno = frameno;
    state.subprogno = subprogno;
    state.callback_ret_range = retval_range(0, 0);
    init_reg_state(env, state)?;
    mark_verifier_state_scratched(env);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, state))]
pub fn init_reg_state(env: &mut BpfVerifierEnv, state: &mut BpfFuncState) -> Result<()> {
    let regs: &mut [BpfRegState] = &mut state.regs;

    for i in 0..MAX_BPF_REG as usize {
        mark_reg_not_init(env, regs, i as i32);
        regs[i].subreg_def = DEF_NOT_SUBREG;
    }

    /* frame pointer */
    regs[BPF_REG_FP as usize].r#type = PTR_TO_STACK;
    mark_reg_known_zero(env, regs, BPF_REG_FP as i32);
    regs[BPF_REG_FP as usize].frameno = state.frameno;

    Ok(())
}
