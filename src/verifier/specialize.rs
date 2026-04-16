//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn specialize_kfunc() -> Result<()> {
    let _ = Some(()).context("specialize_kfunc")?;
    Err(anyhow!("specialize_kfunc failed"))
}
