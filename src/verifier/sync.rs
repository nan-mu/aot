//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn sync_linked_regs() -> Result<()> {
    let _ = Some(()).context("sync_linked_regs")?;
    Err(anyhow!("sync_linked_regs failed"))
}
