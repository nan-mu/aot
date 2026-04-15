//! Missing types: BpfVerifierState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(a, b))]
pub fn same_callsites(a: &BpfVerifierState, b: &BpfVerifierState) -> Result<bool> {
    if a.curframe != b.curframe {
        return Ok(false);
    }

    for fr in (0..=a.curframe as usize).rev() {
        if a.frame[fr].callsite != b.frame[fr].callsite {
            return Ok(false);
        }
    }

    Ok(true)
}
