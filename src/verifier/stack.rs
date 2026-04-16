//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn stack_slot_obj_get_spi() -> Result<()> {
    let _ = Some(()).context("stack_slot_obj_get_spi")?;
    Err(anyhow!("stack_slot_obj_get_spi failed"))
}
