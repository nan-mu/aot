//! Missing types: BpfVerifierState, BpfRegState, BpfFuncState, BpfVerifierEnv

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(old, cur))]
pub fn iter_active_depths_differ(old: &BpfVerifierState, cur: &BpfVerifierState) -> Result<bool> {
    for fr in (0..=old.curframe as usize).rev() {
        let state: &BpfFuncState = old.frame[fr];
        for i in 0..(state.allocated_stack / BPF_REG_SIZE as i32) as usize {
            if state.stack[i].slot_type[0] != STACK_ITER {
                continue;
            }

            let slot: &BpfRegState = &state.stack[i].spilled_ptr;
            if slot.iter.state != BPF_ITER_STATE_ACTIVE {
                continue;
            }

            let cur_slot: &BpfRegState = &cur.frame[fr].stack[i].spilled_ptr;
            if cur_slot.iter.depth != slot.iter.depth {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn iter_get_spi(env: &mut BpfVerifierEnv, reg: &BpfRegState, nr_slots: i32) -> Result<i32> {
    stack_slot_obj_get_spi(env, reg, "iter", nr_slots)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn iter_ref_obj_id(env: &mut BpfVerifierEnv, reg: &BpfRegState, spi: i32) -> Result<u32> {
    let state = func(env, reg)?;
    Ok(state.stack[spi as usize].spilled_ptr.ref_obj_id)
}
