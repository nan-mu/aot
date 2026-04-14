//! Missing types: BpfVerifierEnv, BpfVerifierState, BpfReferenceState, RefStateType

use anyhow::{anyhow, Result};
use tracing::instrument;

/// Manual inspection passed
#[instrument(skip(env))]
pub fn acquire_irq_state(env: &mut BpfVerifierEnv, insn_idx: i32) -> Result<i32> {
    let s = acquire_reference_state(env, insn_idx)
        .ok_or_else(|| anyhow!("-ENOMEM: failed to acquire reference state for irq"))?;
    s.r#type = RefStateType::RefTypeIrq;
    env.id_gen += 1;
    s.id = env.id_gen;

    let state: &mut BpfVerifierState = env.cur_state;
    state.active_irq_id = s.id;
    Ok(s.id)
}

/// Manual inspection passed
#[instrument(skip(env, ptr))]
pub fn acquire_lock_state(
    env: &mut BpfVerifierEnv,
    insn_idx: i32,
    r#type: RefStateType,
    id: i32,
    ptr: *mut core::ffi::c_void,
) -> Result<()> {
    let s = acquire_reference_state(env, insn_idx)
        .ok_or_else(|| anyhow!("-ENOMEM: failed to acquire reference state for lock"))?;
    s.r#type = r#type;
    s.id = id;
    s.ptr = ptr;

    let state: &mut BpfVerifierState = env.cur_state;
    state.active_locks += 1;
    state.active_lock_id = id;
    state.active_lock_ptr = ptr;
    Ok(())
}

/// Manual inspection passed
#[instrument(skip(env))]
pub fn acquire_reference(env: &mut BpfVerifierEnv, insn_idx: i32) -> Result<i32> {
    let s = acquire_reference_state(env, insn_idx)
        .ok_or_else(|| anyhow!("-ENOMEM: failed to acquire reference state"))?;
    s.r#type = RefStateType::RefTypePtr;
    env.id_gen += 1;
    s.id = env.id_gen;
    Ok(s.id)
}

// 最好不要用Option，resize_reference_state可能会返回有意义的Err，直接向上传递就好
#[instrument(skip(env))]
pub fn acquire_reference_state(
    env: &mut BpfVerifierEnv,
    insn_idx: i32,
) -> Option<&mut BpfReferenceState> {
    let state: &mut BpfVerifierState = env.cur_state;
    let new_ofs = state.acquired_refs;

    if resize_reference_state(state, state.acquired_refs + 1).is_err() {
        return None;
    }

    state.refs[new_ofs].insn_idx = insn_idx;
    Some(&mut state.refs[new_ofs])
}
