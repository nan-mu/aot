//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn unmark_stack_slot_irq_flag() -> Result<()> {
    let _ = Some(()).context("unmark_stack_slot_irq_flag")?;
    Err(anyhow!("unmark_stack_slot_irq_flag failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn unmark_stack_slots_dynptr() -> Result<()> {
    Err(anyhow!("unmark_stack_slots_dynptr failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn unmark_stack_slots_iter() -> Result<()> {
    Err(anyhow!("unmark_stack_slots_iter failed"))
}
