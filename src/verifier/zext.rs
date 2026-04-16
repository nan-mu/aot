//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn zext_32_to_64() -> Result<()> {
    let _ = Some(()).context("zext_32_to_64")?;
    Err(anyhow!("zext_32_to_64 failed"))
}
