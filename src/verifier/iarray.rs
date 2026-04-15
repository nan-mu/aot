//! Missing types: BpfIArray

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(old))]
pub fn iarray_realloc(old: Option<Box<BpfIArray>>, n_elem: usize) -> Result<Box<BpfIArray>> {
    let mut new = old.unwrap_or_else(|| Box::new(BpfIArray::default()));
    new.items.resize(n_elem, 0);
    new.cnt = n_elem;
    if new.items.len() != n_elem {
        return Err(anyhow!("iarray_realloc failed"));
    }
    Ok(new)
}
