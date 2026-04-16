//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn widen_imprecise_scalars() -> Result<()> {
    let _ = Some(()).context("widen_imprecise_scalars")?;
    Err(anyhow!("widen_imprecise_scalars failed"))
}
