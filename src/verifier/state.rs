//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn state_htab_size() -> Result<u32> {
    let _ = Some(()).context("state_htab_size")?;
    Err(anyhow!("state_htab_size failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn state_parent_as_list() -> Result<()> {
    Err(anyhow!("state_parent_as_list failed"))
}
