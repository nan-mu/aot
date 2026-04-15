use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn realloc_array<T: Default + Clone>(
    mut arr: Option<Vec<T>>,
    old_n: usize,
    new_n: usize,
) -> Result<Option<Vec<T>>> {
    if new_n == 0 || old_n == new_n {
        return Ok(arr);
    }

    let mut v = arr.take().unwrap_or_default();
    if new_n > old_n {
        v.resize(new_n, T::default());
    } else {
        v.truncate(new_n);
    }

    Ok(Some(v))
}
