//! Missing types: BpfVerifierEnv, BpfVerifierState, BpfSccCallchain, BpfSccVisit

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, st))]
pub fn incomplete_read_marks(env: &mut BpfVerifierEnv, st: &mut BpfVerifierState) -> Result<bool> {
    let callchain: &mut BpfSccCallchain = &mut env.callchain_buf;

    if !compute_scc_callchain(env, st, callchain) {
        return Ok(false);
    }

    let visit: Option<&mut BpfSccVisit> = scc_visit_lookup(env, callchain);
    if visit.is_none() {
        return Ok(false);
    }

    Ok(visit.unwrap().backedges.is_some())
}
