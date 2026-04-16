//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn type_is_rcu() -> Result<bool> {
    let _ = Some(()).context("type_is_rcu")?;
    Err(anyhow!("type_is_rcu failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn type_is_rcu_or_null() -> Result<bool> {
    Err(anyhow!("type_is_rcu_or_null failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn type_is_rdonly_mem() -> Result<bool> {
    Err(anyhow!("type_is_rdonly_mem failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn type_is_trusted() -> Result<bool> {
    Err(anyhow!("type_is_trusted failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn type_is_trusted_or_null() -> Result<bool> {
    Err(anyhow!("type_is_trusted_or_null failed"))
}
