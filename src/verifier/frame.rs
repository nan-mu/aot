//! Missing types: BpfVerifierState, BpfFuncState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(st))]
pub fn frame_insn_idx(st: &BpfVerifierState, frame: u32) -> Result<u32> {
    Ok(if frame == st.curframe as u32 {
        st.insn_idx as u32
    } else {
        st.frame[(frame + 1) as usize].callsite as u32
    })
}
