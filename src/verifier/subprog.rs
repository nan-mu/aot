//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn subprog_is_exc_cb() -> Result<bool> {
    let _ = Some(()).context("subprog_is_exc_cb")?;
    Err(anyhow!("subprog_is_exc_cb failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn subprog_is_global() -> Result<bool> {
    Err(anyhow!("subprog_is_global failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn subprog_name() -> Result<()> {
    Err(anyhow!("subprog_name failed"))
}
