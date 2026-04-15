//! Missing types: BpfVerifierEnv, BpfRegState, BpfIdmap

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn reset_idmap_scratch(env: &mut BpfVerifierEnv) -> Result<()> {
    let idmap: &mut BpfIdmap = &mut env.idmap_scratch;
    idmap.tmp_id_gen = env.id_gen;
    idmap.cnt = 0;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reset_reg32_and_tnum(reg: &mut BpfRegState) -> Result<()> {
    inner_mark_reg32_unbounded(reg);
    reg.var_off = tnum_unknown;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reset_reg64_and_tnum(reg: &mut BpfRegState) -> Result<()> {
    inner_mark_reg64_unbounded(reg);
    reg.var_off = tnum_unknown;
    Ok(())
}
