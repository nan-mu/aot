//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn unbound_reg_init() -> Result<()> {
    let _ = Some(()).context("unbound_reg_init")?;
    Err(anyhow!("unbound_reg_init failed"))
}
