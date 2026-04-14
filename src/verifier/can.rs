//! Missing types: BpfMapType, BpfVerifierEnv, BpfInsn

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn can_elide_value_nullness(r#type: BpfMapType) -> Result<bool> {
    match r#type {
        BPF_MAP_TYPE_ARRAY | BPF_MAP_TYPE_PERCPU_ARRAY => Ok(true),
        _ => Ok(false),
    }
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn))]
pub fn can_skip_alu_sanitation(env: &BpfVerifierEnv, insn: &BpfInsn) -> Result<bool> {
    Ok(env.bypass_spec_v1 || BPF_SRC(insn.code) == BPF_K || cur_aux(env).nospec)
}
