//! Missing types: BpfVerifierEnv, BpfVerifierState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn release_btfs(env: &mut BpfVerifierEnv) -> Result<()> {
    __bpf_free_used_btfs(env.used_btfs, env.used_btf_cnt);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn release_insn_arrays(env: &mut BpfVerifierEnv) -> Result<()> {
    for i in 0..env.insn_array_map_cnt as usize {
        bpf_insn_array_release(env.insn_array_maps[i]);
    }
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(state))]
pub fn release_irq_state(state: &mut BpfVerifierState, id: i32) -> Result<i32> {
    let mut prev_id: u32 = 0;

    if id as u32 != state.active_irq_id {
        return Err(anyhow!("release_irq_state failed"));
    }

    for i in 0..state.acquired_refs as usize {
        if state.refs[i].r#type != REF_TYPE_IRQ {
            continue;
        }
        if state.refs[i].id == id as u32 {
            release_reference_state(state, i)?;
            state.active_irq_id = prev_id;
            return Ok(0);
        }
        prev_id = state.refs[i].id;
    }

    Err(anyhow!("release_irq_state failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(state))]
pub fn release_lock_state(
    state: &mut BpfVerifierState,
    r#type: i32,
    id: i32,
    ptr: *mut core::ffi::c_void,
) -> Result<i32> {
    let mut prev_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut prev_id: u32 = 0;

    for i in 0..state.acquired_refs as usize {
        if state.refs[i].r#type as i32 == r#type && state.refs[i].id == id as u32 && state.refs[i].ptr == ptr {
            release_reference_state(state, i)?;
            state.active_locks -= 1;
            state.active_lock_id = prev_id;
            state.active_lock_ptr = prev_ptr;
            return Ok(0);
        }
        if (state.refs[i].r#type & REF_TYPE_LOCK_MASK) != 0 {
            prev_id = state.refs[i].id;
            prev_ptr = state.refs[i].ptr;
        }
    }

    Err(anyhow!("release_lock_state failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn release_maps(env: &mut BpfVerifierEnv) -> Result<()> {
    __bpf_free_used_maps(env.prog.aux, env.used_maps, env.used_map_cnt);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn release_reference(env: &mut BpfVerifierEnv, ref_obj_id: i32) -> Result<i32> {
    let vstate = &mut env.cur_state;
    release_reference_nomark(vstate, ref_obj_id)?;

    bpf_for_each_reg_in_vstate(vstate, |reg| {
        if reg.ref_obj_id == ref_obj_id as u32 {
            mark_reg_invalid(env, reg);
        }
    });

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(state))]
pub fn release_reference_nomark(state: &mut BpfVerifierState, ref_obj_id: i32) -> Result<i32> {
    for i in 0..state.acquired_refs as usize {
        if state.refs[i].r#type != REF_TYPE_PTR {
            continue;
        }
        if state.refs[i].id == ref_obj_id as u32 {
            release_reference_state(state, i)?;
            return Ok(0);
        }
    }
    Err(anyhow!("release_reference_nomark failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(state))]
pub fn release_reference_state(state: &mut BpfVerifierState, idx: usize) -> Result<()> {
    let last_idx = state.acquired_refs as usize - 1;
    if last_idx != 0 && idx != last_idx {
        for i in idx..last_idx {
            state.refs[i] = state.refs[i + 1];
        }
    }
    state.refs[last_idx] = BpfReferenceState::default();
    state.acquired_refs -= 1;
    Ok(())
}
