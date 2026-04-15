//! Missing types: BpfVerifierEnv, BpfRegState, BpfIdmap

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, rold, rcur, idmap))]
pub fn regsafe(
    env: &mut BpfVerifierEnv,
    rold: &BpfRegState,
    rcur: &BpfRegState,
    idmap: &mut BpfIdmap,
    exact: ExactLevel,
) -> Result<bool> {
    if exact == EXACT {
        return regs_exact(rold, rcur, idmap);
    }

    if rold.r#type == NOT_INIT {
        return Ok(true);
    }

    if rold.r#type != rcur.r#type {
        return Ok(false);
    }

    match base_type(rold.r#type) {
        SCALAR_VALUE => {
            if env.explore_alu_limits {
                return Ok(regs_equal_except_ids(rold, rcur)
                    && check_scalar_ids(rold.id, rcur.id, idmap));
            }
            if !rold.precise && exact == NOT_EXACT {
                return Ok(true);
            }
            if rold.id != 0 && (rold.id & BPF_ADD_CONST) != (rcur.id & BPF_ADD_CONST) {
                return Ok(false);
            }
            if (rold.id & BPF_ADD_CONST) != 0 && rold.off != rcur.off {
                return Ok(false);
            }
            Ok(
                check_scalar_ids(rold.id, rcur.id, idmap)
                    && range_within(rold, rcur)?
                    && tnum_in(rold.var_off, rcur.var_off),
            )
        }
        PTR_TO_STACK => Ok(regs_exact(rold, rcur, idmap)? && rold.frameno == rcur.frameno),
        PTR_TO_ARENA => Ok(true),
        _ => regs_exact(rold, rcur, idmap),
    }
}
