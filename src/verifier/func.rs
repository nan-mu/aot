//! Missing types: BpfVerifierEnv, BpfRegState, BpfVerifierState, BpfFuncState, ExactLevel

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn func(env: &mut BpfVerifierEnv, reg: &BpfRegState) -> Result<&mut BpfFuncState> {
    let cur: &mut BpfVerifierState = env.cur_state;
    Ok(cur.frame[reg.frameno as usize])
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, old, cur))]
pub fn func_states_equal(
    env: &mut BpfVerifierEnv,
    old: &mut BpfFuncState,
    cur: &mut BpfFuncState,
    insn_idx: u32,
    exact: ExactLevel,
) -> Result<bool> {
    let live_regs = env.insn_aux_data[insn_idx as usize].live_regs_before;

    if old.callback_depth > cur.callback_depth {
        return Ok(false);
    }

    for i in 0..MAX_BPF_REG as usize {
        if ((1u16 << i) & live_regs) != 0
            && !regsafe(env, &old.regs[i], &cur.regs[i], &mut env.idmap_scratch, exact)
        {
            return Ok(false);
        }
    }

    if !stacksafe(env, old, cur, &mut env.idmap_scratch, exact) {
        return Ok(false);
    }

    Ok(true)
}
