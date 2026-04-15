//! Missing types: BpfVerifierEnv, BpfVerifierState, BpfInsn, BpfFuncState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn in_rbtree_lock_required_cb(env: &mut BpfVerifierEnv) -> Result<bool> {
    let state: &mut BpfVerifierState = env.cur_state;
    let insn: &mut [BpfInsn] = env.prog.insnsi;

    if state.curframe == 0 {
        return Ok(false);
    }

    let callee: &mut BpfFuncState = state.frame[state.curframe as usize];
    if !callee.in_callback_fn {
        return Ok(false);
    }

    let kfunc_btf_id = insn[callee.callsite as usize].imm;
    Ok(is_rbtree_lock_required_kfunc(kfunc_btf_id))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn in_rcu_cs(env: &mut BpfVerifierEnv) -> Result<bool> {
    Ok(env.cur_state.active_rcu_locks != 0
        || env.cur_state.active_locks != 0
        || !in_sleepable(env)?)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn in_sleepable(env: &mut BpfVerifierEnv) -> Result<bool> {
    Ok(env.cur_state.in_sleepable)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn in_sleepable_context(env: &mut BpfVerifierEnv) -> Result<bool> {
    Ok(env.cur_state.active_rcu_locks == 0
        && env.cur_state.active_preempt_locks == 0
        && env.cur_state.active_locks == 0
        && env.cur_state.active_irq_id == 0
        && in_sleepable(env)?)
}
