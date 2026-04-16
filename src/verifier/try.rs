//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn try_match_pkt_pointers() -> Result<bool> {
    let _ = Some(()).context("try_match_pkt_pointers")?;
    Err(anyhow!("try_match_pkt_pointers failed"))
}
