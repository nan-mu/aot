use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn error_recoverable_with_nospec(err: i32) -> Result<bool> {
    /* Should only return true for non-fatal errors that are allowed to
     * occur during speculative verification. For these we can insert a
     * nospec and the program might still be accepted. Do not include
     * something like ENOMEM because it is likely to re-occur for the next
     * architectural path once it has been recovered-from in all speculative
     * paths.
     */
    Ok(err == -EPERM || err == -EACCES || err == -EINVAL)
}
