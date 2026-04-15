//! Missing types: BpfVerifierEnv, BpfSubprogInfo

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn merge_callee_effects(env: &mut BpfVerifierEnv, t: i32, w: i32) -> Result<()> {
    let caller: &mut BpfSubprogInfo = bpf_find_containing_subprog(env, t);
    let callee: &mut BpfSubprogInfo = bpf_find_containing_subprog(env, w);

    caller.changes_pkt_data |= callee.changes_pkt_data;
    caller.might_sleep |= callee.might_sleep;
    Ok(())
}
