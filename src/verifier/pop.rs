//! Missing types: BpfVerifierEnv, BpfVerifierState, BpfVerifierStackElem

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, prev_insn_idx, insn_idx))]
pub fn pop_stack(
    env: &mut BpfVerifierEnv,
    prev_insn_idx: Option<&mut i32>,
    insn_idx: Option<&mut i32>,
    pop_log: bool,
) -> Result<i32> {
    if env.head.is_none() {
        return Err(anyhow!("pop_stack failed"));
    }

    let mut head = env.head.take().unwrap();

    if let Some(cur) = env.cur_state.as_mut() {
        copy_verifier_state(cur, &head.st)?;
    }
    if pop_log {
        bpf_vlog_reset(&mut env.log, head.log_pos);
    }
    if let Some(v) = insn_idx {
        *v = head.insn_idx;
    }
    if let Some(v) = prev_insn_idx {
        *v = head.prev_insn_idx;
    }

    let next = head.next.take();
    free_verifier_state(&mut head.st, false)?;
    kfree(head);
    env.head = next;
    env.stack_size -= 1;
    Ok(0)
}
