//! Missing types: BpfVerifierEnv, BpfRegState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, src_reg))]
pub fn assign_scalar_id_before_mov(
    env: &mut BpfVerifierEnv,
    src_reg: &mut BpfRegState,
) -> Result<()> {
    if src_reg.r#type != SCALAR_VALUE {
        return Ok(());
    }

    if (src_reg.id & BPF_ADD_CONST) != 0 {
        /*
         * The verifier is processing rX = rY insn and
         * rY->id has special linked register already.
         * Cleared it, since multiple rX += const are not supported.
         */
        src_reg.id = 0;
        src_reg.off = 0;
    }

    if src_reg.id == 0 && !tnum_is_const(src_reg.var_off) {
        /* Ensure that src_reg has a valid ID that will be copied to
         * dst_reg and then will be used by sync_linked_regs() to
         * propagate min/max range.
         */
        env.id_gen += 1;
        src_reg.id = env.id_gen;
    }

    Ok(())
}
