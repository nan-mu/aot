//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn verifier_inlines_helper_call() -> Result<bool> {
    let _ = Some(()).context("verifier_inlines_helper_call")?;
    Err(anyhow!("verifier_inlines_helper_call failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn verifier_remove_insns() -> Result<()> {
    Err(anyhow!("verifier_remove_insns failed"))
}
