//! Missing types: BpfVerifierEnv, BpfSubprogInfo, BpfIArray

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn create_jt(t: i32, env: &mut BpfVerifierEnv) -> Result<&mut BpfIArray> {
    let subprog: &BpfSubprogInfo = bpf_find_containing_subprog(env, t);
    let subprog_start = subprog.start;
    let subprog_end = (subprog + 1).start;
    let jt: &mut BpfIArray = jt_from_subprog(env, subprog_start, subprog_end)?;

    /* Check that the every element of the jump table fits within the given subprogram */
    for i in 0..jt.cnt as usize {
        if jt.items[i] < subprog_start || jt.items[i] >= subprog_end {
            verbose(
                env,
                format!(
                    "jump table for insn {} points outside of the subprog [{},{}]\n",
                    t, subprog_start, subprog_end
                ),
            );
            return Err(anyhow!("create_jt failed"));
        }
    }

    Ok(jt)
}
