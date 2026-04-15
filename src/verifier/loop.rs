//! Missing types: BpfVerifierEnv, BpfRegState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn loop_flag_is_zero(env: &mut BpfVerifierEnv) -> Result<bool> {
    let reg: &mut BpfRegState = reg_state(env, BPF_REG_4);
    let reg_is_null = register_is_null(reg);

    if reg_is_null {
        mark_chain_precision(env, BPF_REG_4)?;
    }

    Ok(reg_is_null)
}
