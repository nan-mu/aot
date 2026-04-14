//! Missing types: BpfVerifierEnv, BpfInsn

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn))]
pub fn atomic_ptr_type_ok(env: &mut BpfVerifierEnv, regno: i32, insn: &BpfInsn) -> Result<bool> {
    if is_ctx_reg(env, regno) {
        return Ok(false);
    }
    if is_pkt_reg(env, regno) {
        return Ok(false);
    }
    if is_flow_key_reg(env, regno) {
        return Ok(false);
    }
    if is_sk_reg(env, regno) {
        return Ok(false);
    }
    if is_arena_reg(env, regno) {
        return Ok(bpf_jit_supports_insn(insn, true));
    }

    Ok(true)
}
