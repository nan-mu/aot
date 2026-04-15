//! Missing types: BpfRegState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(ptr_reg, alu_limit))]
pub fn retrieve_ptr_limit(ptr_reg: &BpfRegState, alu_limit: &mut u32, mask_to_left: bool) -> Result<i32> {
    let (max, ptr_limit): (u32, i64) = match ptr_reg.r#type {
        PTR_TO_STACK => {
            let max = MAX_BPF_STACK as u32 + if mask_to_left { 1 } else { 0 };
            let ptr_limit = -((ptr_reg.var_off.value as i64) + (ptr_reg.off as i64));
            (max, ptr_limit)
        }
        PTR_TO_MAP_VALUE => {
            let max = ptr_reg.map_ptr.value_size;
            let lim = if mask_to_left {
                ptr_reg.smin_value
            } else {
                ptr_reg.umax_value as i64
            } + ptr_reg.off as i64;
            (max, lim)
        }
        _ => return Ok(REASON_TYPE),
    };

    if ptr_limit < 0 || (ptr_limit as u32) >= max {
        return Ok(REASON_LIMIT);
    }

    *alu_limit = ptr_limit as u32;
    Ok(0)
}
