//! Missing types: BpfRegState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(old, cur))]
pub fn range_within(old: &BpfRegState, cur: &BpfRegState) -> Result<bool> {
    Ok(old.umin_value <= cur.umin_value
        && old.umax_value >= cur.umax_value
        && old.smin_value <= cur.smin_value
        && old.smax_value >= cur.smax_value
        && old.u32_min_value <= cur.u32_min_value
        && old.u32_max_value >= cur.u32_max_value
        && old.s32_min_value <= cur.s32_min_value
        && old.s32_max_value >= cur.s32_max_value)
}
