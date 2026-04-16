//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn states_equal() -> Result<bool> {
    let _ = Some(()).context("states_equal")?;
    Err(anyhow!("states_equal failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn states_maybe_looping() -> Result<bool> {
    Err(anyhow!("states_maybe_looping failed"))
}
