//! Missing types: BpfFuncState, BpfMap, BpfInsnArrayValue, BpfVerifierState, BpfReferenceState, BpfRegState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(dst, src))]
pub fn copy_array<T: Clone>(dst: &mut Vec<T>, src: &[T], n: usize) -> Result<()> {
    if src.is_empty() {
        return Ok(());
    }
    dst.clear();
    dst.extend_from_slice(&src[..n]);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(dst, src))]
pub fn copy_func_state(dst: &mut BpfFuncState, src: &BpfFuncState) -> Result<i32> {
    *dst = src.clone();
    copy_stack_state(dst, src)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(map, items))]
pub fn copy_insn_array(map: &BpfMap, start: u32, end: u32, items: &mut [u32]) -> Result<i32> {
    for i in start..=end {
        let value: &BpfInsnArrayValue = map_lookup_elem(map, &i).ok_or_else(|| anyhow!("copy_insn_array failed"))?;
        items[(i - start) as usize] = value.xlated_off;
    }
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(map, off))]
pub fn copy_insn_array_uniq(map: &BpfMap, start: u32, end: u32, off: &mut [u32]) -> Result<i32> {
    copy_insn_array(map, start, end, off)?;
    sort_insn_array_uniq(off, (end - start + 1) as usize)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(dst, src))]
pub fn copy_reference_state(dst: &mut BpfVerifierState, src: &BpfVerifierState) -> Result<i32> {
    dst.refs = src.refs.clone();
    dst.acquired_refs = src.acquired_refs;
    dst.active_locks = src.active_locks;
    dst.active_preempt_locks = src.active_preempt_locks;
    dst.active_rcu_locks = src.active_rcu_locks;
    dst.active_irq_id = src.active_irq_id;
    dst.active_lock_id = src.active_lock_id;
    dst.active_lock_ptr = src.active_lock_ptr;
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(dst, src))]
pub fn copy_register_state(dst: &mut BpfRegState, src: &BpfRegState) -> Result<()> {
    *dst = src.clone();
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(dst, src))]
pub fn copy_stack_state(dst: &mut BpfFuncState, src: &BpfFuncState) -> Result<i32> {
    dst.stack = src.stack.clone();
    dst.allocated_stack = src.allocated_stack;
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(dst_state, src))]
pub fn copy_verifier_state(dst_state: &mut BpfVerifierState, src: &BpfVerifierState) -> Result<i32> {
    dst_state.jmp_history = src.jmp_history.clone();
    dst_state.jmp_history_cnt = src.jmp_history_cnt;

    copy_reference_state(dst_state, src)?;
    dst_state.speculative = src.speculative;
    dst_state.in_sleepable = src.in_sleepable;
    dst_state.cleaned = src.cleaned;
    dst_state.curframe = src.curframe;
    dst_state.branches = src.branches;
    dst_state.parent = src.parent;
    dst_state.first_insn_idx = src.first_insn_idx;
    dst_state.last_insn_idx = src.last_insn_idx;
    dst_state.dfs_depth = src.dfs_depth;
    dst_state.callback_unroll_depth = src.callback_unroll_depth;
    dst_state.may_goto_depth = src.may_goto_depth;
    dst_state.equal_state = src.equal_state;

    for i in 0..=src.curframe as usize {
        copy_func_state(dst_state.frame[i], src.frame[i])?;
    }

    Ok(0)
}
