use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn register_is_null(reg: &BpfRegState) -> Result<bool> {
    Ok(reg.r#type == SCALAR_VALUE && tnum_equals_const(reg.var_off, 0))
}
