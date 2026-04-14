//! Missing types: BpfVerifierEnv, BpfRegState, BpfDynptrType, BpfFuncState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn dynptr_get_spi(env: &mut BpfVerifierEnv, reg: &BpfRegState) -> Result<i32> {
    stack_slot_obj_get_spi(env, reg, "dynptr", BPF_DYNPTR_NR_SLOTS)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn dynptr_get_type(env: &mut BpfVerifierEnv, reg: &BpfRegState) -> Result<BpfDynptrType> {
    let state: &mut BpfFuncState = func(env, reg);

    if reg.r#type == CONST_PTR_TO_DYNPTR {
        return Ok(reg.dynptr.r#type);
    }

    let spi = inner_get_spi(reg.off);
    if spi < 0 {
        verbose(env, "verifier internal error: invalid spi when querying dynptr type\n");
        return Err(anyhow!("dynptr_get_type failed"));
    }

    Ok(state.stack[spi as usize].spilled_ptr.dynptr.r#type)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn dynptr_id(env: &mut BpfVerifierEnv, reg: &BpfRegState) -> Result<i32> {
    let state: &mut BpfFuncState = func(env, reg);

    if reg.r#type == CONST_PTR_TO_DYNPTR {
        return Ok(reg.id);
    }
    let spi = dynptr_get_spi(env, reg)?;
    Ok(state.stack[spi as usize].spilled_ptr.id)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn dynptr_ref_obj_id(env: &mut BpfVerifierEnv, reg: &BpfRegState) -> Result<i32> {
    let state: &mut BpfFuncState = func(env, reg);

    if reg.r#type == CONST_PTR_TO_DYNPTR {
        return Ok(reg.ref_obj_id);
    }
    let spi = dynptr_get_spi(env, reg)?;
    Ok(state.stack[spi as usize].spilled_ptr.ref_obj_id)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn dynptr_type_refcounted(r#type: BpfDynptrType) -> Result<bool> {
    Ok(r#type == BPF_DYNPTR_TYPE_RINGBUF || r#type == BPF_DYNPTR_TYPE_FILE)
}
