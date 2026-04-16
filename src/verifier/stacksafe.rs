//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn stacksafe() -> Result<bool> {
    let _ = Some(()).context("stacksafe")?;
    Err(anyhow!("stacksafe failed"))
}
