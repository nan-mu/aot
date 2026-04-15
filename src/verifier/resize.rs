//! Missing types: BpfVerifierState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(state))]
pub fn resize_reference_state(state: &mut BpfVerifierState, n: usize) -> Result<i32> {
    let refs = realloc_array(Some(state.refs.clone()), state.acquired_refs as usize, n)?;
    state.refs = refs.ok_or_else(|| anyhow!("resize_reference_state failed"))?;
    state.acquired_refs = n as u32;
    Ok(0)
}
