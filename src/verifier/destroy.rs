//! Missing types: BpfVerifierEnv, BpfFuncState, BpfRegState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, state))]
pub fn destroy_if_dynptr_stack_slot(
    env: &mut BpfVerifierEnv,
    state: &mut BpfFuncState,
    mut spi: i32,
) -> Result<i32> {
    /* We always ensure that STACK_DYNPTR is never set partially,
     * hence just checking for slot_type[0] is enough. This is
     * different for STACK_SPILL, where it may be only set for
     * 1 byte, so code has to use is_spilled_reg.
     */
    if state.stack[spi as usize].slot_type[0] != STACK_DYNPTR {
        return Ok(0);
    }

    /* Reposition spi to first slot */
    if !state.stack[spi as usize].spilled_ptr.dynptr.first_slot {
        spi += 1;
    }

    if dynptr_type_refcounted(state.stack[spi as usize].spilled_ptr.dynptr.r#type) {
        verbose(env, "cannot overwrite referenced dynptr\n");
        return Err(anyhow!("destroy_if_dynptr_stack_slot failed"));
    }

    mark_stack_slot_scratched(env, spi);
    mark_stack_slot_scratched(env, spi - 1);

    /* Writing partially to one dynptr stack slot destroys both. */
    for i in 0..BPF_REG_SIZE as usize {
        state.stack[spi as usize].slot_type[i] = STACK_INVALID;
        state.stack[(spi - 1) as usize].slot_type[i] = STACK_INVALID;
    }

    let dynptr_id = state.stack[spi as usize].spilled_ptr.id;
    /* Invalidate any slices associated with this dynptr */
    bpf_for_each_reg_in_vstate(env.cur_state, |dreg: &mut BpfRegState| {
        /* Dynptr slices are only PTR_TO_MEM_OR_NULL and PTR_TO_MEM */
        if dreg.r#type != (PTR_TO_MEM | PTR_MAYBE_NULL) && dreg.r#type != PTR_TO_MEM {
            return;
        }
        if dreg.dynptr_id == dynptr_id {
            mark_reg_invalid(env, dreg);
        }
    });

    /* Do not release reference state, we are destroying dynptr on stack,
     * not using some helper to release it. Just reset register.
     */
    inner_mark_reg_not_init(env, &mut state.stack[spi as usize].spilled_ptr);
    inner_mark_reg_not_init(env, &mut state.stack[(spi - 1) as usize].spilled_ptr);

    bpf_mark_stack_write(env, state.frameno, BIT((spi - 1) as u32) | BIT(spi as u32));

    Ok(0)
}
