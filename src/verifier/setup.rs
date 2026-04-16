//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn setup_func_entry() -> Result<()> {
    let _ = Some(()).context("setup_func_entry")?;
    Err(anyhow!("setup_func_entry failed"))
}
