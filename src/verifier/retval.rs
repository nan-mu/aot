//! Missing types: BpfRetvalRange, BpfRegState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn retval_range(minval: i32, maxval: i32) -> Result<BpfRetvalRange> {
    Ok(BpfRetvalRange { minval, maxval })
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn retval_range_within(range: BpfRetvalRange, reg: &BpfRegState, return_32bit: bool) -> Result<bool> {
    Ok(if return_32bit {
        range.minval <= reg.s32_min_value && reg.s32_max_value <= range.maxval
    } else {
        range.minval as i64 <= reg.smin_value && reg.smax_value <= range.maxval as i64
    })
}
