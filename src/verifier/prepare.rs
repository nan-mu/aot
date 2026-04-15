//! Missing types: BpfVerifierEnv, BpfVerifierState, BpfFuncState, BpfRegState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn_idx))]
pub fn prepare_func_exit(env: &mut BpfVerifierEnv, insn_idx: &mut i32) -> Result<i32> {
    let state: &mut BpfVerifierState = env.cur_state;

    bpf_update_live_stack(env)?;

    let callee_idx = state.curframe as usize;
    let callee: &mut BpfFuncState = &mut state.frame[callee_idx];
    let r0: &mut BpfRegState = &mut callee.regs[BPF_REG_0 as usize];

    if r0.r#type == PTR_TO_STACK {
        verbose(env, "cannot return stack pointer to the caller\n");
        return Err(anyhow!("prepare_func_exit failed"));
    }

    let caller: &mut BpfFuncState = &mut state.frame[callee_idx - 1];

    if callee.in_callback_fn {
        if r0.r#type != SCALAR_VALUE {
            verbose(env, "R0 not a scalar value\n");
            return Err(anyhow!("prepare_func_exit failed"));
        }

        mark_chain_precision(env, BPF_REG_0)?;

        if !retval_range_within(callee.callback_ret_range, r0, false) {
            verbose_invalid_scalar(env, r0, callee.callback_ret_range, "At callback return", "R0");
            return Err(anyhow!("prepare_func_exit failed"));
        }
        if !bpf_calls_callback(env, callee.callsite)? {
            return Err(anyhow!("prepare_func_exit failed"));
        }
    } else {
        caller.regs[BPF_REG_0 as usize] = *r0;
    }

    let in_callback_fn = callee.in_callback_fn;
    *insn_idx = if in_callback_fn {
        callee.callsite
    } else {
        callee.callsite + 1
    };

    free_func_state(callee)?;
    state.frame[callee_idx] = BpfFuncState::default();
    state.curframe -= 1;

    if in_callback_fn {
        if let Some(prev_st) = find_prev_entry(env, state, *insn_idx) {
            widen_imprecise_scalars(env, prev_st, state)?;
        }
    }

    Ok(0)
}
