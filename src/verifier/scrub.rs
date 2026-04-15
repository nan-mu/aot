use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn scrub_spilled_slot(stype: &mut u8) -> Result<()> {
    if *stype != STACK_INVALID {
        *stype = STACK_MISC;
    }
    Ok(())
}
