//! Missing types: BpfArgType, BpfDynptrType

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn arg_to_dynptr_type(arg_type: BpfArgType) -> Result<BpfDynptrType> {
    match arg_type & DYNPTR_TYPE_FLAG_MASK {
        DYNPTR_TYPE_LOCAL => Ok(BPF_DYNPTR_TYPE_LOCAL),
        DYNPTR_TYPE_RINGBUF => Ok(BPF_DYNPTR_TYPE_RINGBUF),
        DYNPTR_TYPE_SKB => Ok(BPF_DYNPTR_TYPE_SKB),
        DYNPTR_TYPE_XDP => Ok(BPF_DYNPTR_TYPE_XDP),
        DYNPTR_TYPE_SKB_META => Ok(BPF_DYNPTR_TYPE_SKB_META),
        DYNPTR_TYPE_FILE => Ok(BPF_DYNPTR_TYPE_FILE),
        _ => Err(anyhow!("arg_to_dynptr_type failed")),
    }
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn arg_type_is_dynptr(r#type: BpfArgType) -> Result<bool> {
    Ok(base_type(r#type) == ARG_PTR_TO_DYNPTR)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn arg_type_is_mem_size(r#type: BpfArgType) -> Result<bool> {
    Ok(r#type == ARG_CONST_SIZE || r#type == ARG_CONST_SIZE_OR_ZERO)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn arg_type_is_raw_mem(r#type: BpfArgType) -> Result<bool> {
    Ok(base_type(r#type) == ARG_PTR_TO_MEM && (r#type & MEM_UNINIT) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn arg_type_is_release(r#type: BpfArgType) -> Result<bool> {
    Ok((r#type & OBJ_RELEASE) != 0)
}
