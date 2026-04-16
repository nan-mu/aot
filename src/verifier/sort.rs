//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn sort_insn_array_uniq() -> Result<()> {
    let _ = Some(()).context("sort_insn_array_uniq")?;
    Err(anyhow!("sort_insn_array_uniq failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn sort_kfunc_descs_by_imm_off() -> Result<()> {
    Err(anyhow!("sort_kfunc_descs_by_imm_off failed"))
}
