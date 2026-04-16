use anyhow::{Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(stype))]
pub fn scrub_spilled_slot(stype: &mut u8) -> Result<()> {
    let _ = Some(stype).context("scrub_spilled_slot stype is required")?;
    if *stype != STACK_INVALID {
        *stype = STACK_MISC;
    }
    Ok(())
}
