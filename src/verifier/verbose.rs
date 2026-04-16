//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn verbose() -> Result<()> {
    let _ = Some(()).context("verbose")?;
    Err(anyhow!("verbose failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn verbose_insn() -> Result<()> {
    Err(anyhow!("verbose_insn failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn verbose_invalid_scalar() -> Result<()> {
    Err(anyhow!("verbose_invalid_scalar failed"))
}
