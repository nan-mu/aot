//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn visit_func_call_insn() -> Result<()> {
    let _ = Some(()).context("visit_func_call_insn")?;
    Err(anyhow!("visit_func_call_insn failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn visit_gotox_insn() -> Result<()> {
    Err(anyhow!("visit_gotox_insn failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn visit_insn() -> Result<()> {
    Err(anyhow!("visit_insn failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn visit_tailcall_insn() -> Result<()> {
    Err(anyhow!("visit_tailcall_insn failed"))
}
