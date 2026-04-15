//! Missing types: BpfVerifierEnv

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn round_up_stack_depth(env: &BpfVerifierEnv, stack_depth: i32) -> Result<i32> {
    if env.prog.jit_requested {
        return Ok(round_up(stack_depth, 16));
    }

    /* round up to 32-bytes for interpreter stack granularity */
    Ok(round_up(core::cmp::max(stack_depth as u32, 1) as i32, 32))
}
