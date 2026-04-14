//! Missing types: BpfSubprogInfo

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn cmp_ptr_to_u32(a: &u32, b: &u32) -> Result<i32> {
    Ok(*a as i32 - *b as i32)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(a, b))]
pub fn cmp_subprogs(a: &BpfSubprogInfo, b: &BpfSubprogInfo) -> Result<i32> {
    Ok(a.start - b.start)
}
