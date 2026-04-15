//! Missing types: BpfVerifierEnv, BpfFuncState, BpfRegState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, state))]
pub fn invalidate_dynptr(env: &mut BpfVerifierEnv, state: &mut BpfFuncState, spi: i32) -> Result<()> {
    for i in 0..BPF_REG_SIZE as usize {
        state.stack[spi as usize].slot_type[i] = STACK_INVALID;
        state.stack[(spi - 1) as usize].slot_type[i] = STACK_INVALID;
    }

    inner_mark_reg_not_init(env, &mut state.stack[spi as usize].spilled_ptr);
    inner_mark_reg_not_init(env, &mut state.stack[(spi - 1) as usize].spilled_ptr);

    bpf_mark_stack_write(env, state.frameno, BIT((spi - 1) as u32) | BIT(spi as u32));
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn invalidate_non_owning_refs(env: &mut BpfVerifierEnv) -> Result<()> {
    bpf_for_each_reg_in_vstate(env.cur_state, |reg: &mut BpfRegState| {
        if type_is_non_owning_ref(reg.r#type) {
            mark_reg_invalid(env, reg);
        }
    });
    Ok(())
}
