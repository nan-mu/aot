//! Missing types: BpfVerifierEnv, BpfFuncState, BpfStackState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, state))]
pub fn grow_stack_state(env: &mut BpfVerifierEnv, state: &mut BpfFuncState, size: i32) -> Result<i32> {
    let old_n = (state.allocated_stack / BPF_REG_SIZE as i32) as usize;

    /* The stack size is always a multiple of BPF_REG_SIZE. */
    let size = round_up(size, BPF_REG_SIZE as i32);
    let n = (size / BPF_REG_SIZE as i32) as usize;

    if old_n >= n {
        return Ok(0);
    }

    let mut new_stack = realloc_array::<BpfStackState>(&mut state.stack, old_n, n)
        .ok_or_else(|| anyhow!("grow_stack_state failed"))?;
    state.stack.append(&mut new_stack);
    state.allocated_stack = size;

    /* update known max for given subprogram */
    if env.subprog_info[state.subprogno as usize].stack_depth < size {
        env.subprog_info[state.subprogno as usize].stack_depth = size;
    }

    Ok(0)
}
