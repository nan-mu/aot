//! Missing types: BpfMap

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(map))]
pub fn helper_multiple_ref_obj_use(func_id: BpfFuncId, map: &BpfMap) -> Result<bool> {
    let mut ref_obj_uses = 0;

    if is_ptr_cast_function(func_id) {
        ref_obj_uses += 1;
    }
    if is_acquire_function(func_id, map) {
        ref_obj_uses += 1;
    }
    if is_dynptr_ref_function(func_id) {
        ref_obj_uses += 1;
    }

    Ok(ref_obj_uses > 1)
}
