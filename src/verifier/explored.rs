//! Missing types: BpfVerifierEnv, ListHead, BpfVerifierState, BpfFuncState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn explored_state(env: &mut BpfVerifierEnv, idx: i32) -> Result<&mut ListHead> {
    let cur: &mut BpfVerifierState = env.cur_state;
    let state: &mut BpfFuncState = cur.frame[cur.curframe as usize];
    let bucket = ((idx as u32 ^ state.callsite as u32) % state_htab_size(env) as u32) as usize;
    Ok(&mut env.explored_states[bucket])
}
