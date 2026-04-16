//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn update_alu_sanitation_state() -> Result<()> {
    let _ = Some(()).context("update_alu_sanitation_state")?;
    Err(anyhow!("update_alu_sanitation_state failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn update_branch_counts() -> Result<()> {
    Err(anyhow!("update_branch_counts failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn update_loop_inline_state() -> Result<()> {
    Err(anyhow!("update_loop_inline_state failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn update_peak_states() -> Result<()> {
    Err(anyhow!("update_peak_states failed"))
}

#[instrument(skip_all)]
pub fn inner_update_reg32_bounds() -> Result<()> {
    Err(anyhow!("inner_update_reg32_bounds failed"))
}

#[instrument(skip_all)]
pub fn inner_update_reg64_bounds() -> Result<()> {
    Err(anyhow!("inner_update_reg64_bounds failed"))
}

#[instrument(skip_all)]
pub fn inner_update_reg_bounds() -> Result<()> {
    Err(anyhow!("inner_update_reg_bounds failed"))
}
