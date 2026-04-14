//! Missing types: BpfVerifierEnv, BpfInsnAuxData

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn cur_aux(env: &BpfVerifierEnv) -> Result<&BpfInsnAuxData> {
    Ok(&env.insn_aux_data[env.insn_idx as usize])
}
