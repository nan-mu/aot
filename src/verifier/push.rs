//! Missing types: BpfVerifierEnv, BpfVerifierState, BpfInsn

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn push_insn(t: i32, w: i32, e: i32, env: &mut BpfVerifierEnv) -> Result<i32> {
    if e == FALLTHROUGH && env.cfg.insn_state[t as usize] >= (DISCOVERED | FALLTHROUGH) {
        return Ok(DONE_EXPLORING);
    }
    if e == BRANCH && env.cfg.insn_state[t as usize] >= (DISCOVERED | BRANCH) {
        return Ok(DONE_EXPLORING);
    }

    if w < 0 || w >= env.prog.len as i32 {
        verbose(env, format!("jump out of range from insn {} to {}\n", t, w));
        return Err(anyhow!("push_insn failed"));
    }

    if e == BRANCH {
        mark_prune_point(env, w)?;
        mark_jmp_point(env, w)?;
    }

    if env.cfg.insn_state[w as usize] == 0 {
        env.cfg.insn_state[t as usize] = DISCOVERED | e;
        env.cfg.insn_state[w as usize] = DISCOVERED;
        if env.cfg.cur_stack >= env.prog.len as usize {
            return Err(anyhow!("push_insn failed"));
        }
        env.cfg.insn_stack[env.cfg.cur_stack] = w;
        env.cfg.cur_stack += 1;
        return Ok(KEEP_EXPLORING);
    } else if (env.cfg.insn_state[w as usize] & 0xF0) == DISCOVERED {
        if env.bpf_capable {
            return Ok(DONE_EXPLORING);
        }
        verbose(env, format!("back-edge from insn {} to {}\n", t, w));
        return Err(anyhow!("push_insn failed"));
    } else if env.cfg.insn_state[w as usize] == EXPLORED {
        env.cfg.insn_state[t as usize] = DISCOVERED | e;
    } else {
        return Err(anyhow!("push_insn failed"));
    }

    Ok(DONE_EXPLORING)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn push_stack(
    env: &mut BpfVerifierEnv,
    insn_idx: i32,
    prev_insn_idx: i32,
    speculative: bool,
) -> Result<&mut BpfVerifierState> {
    let mut elem = BpfVerifierStackElem::default();
    elem.insn_idx = insn_idx;
    elem.prev_insn_idx = prev_insn_idx;
    elem.next = env.head.take();
    elem.log_pos = env.log.end_pos;

    copy_verifier_state(&mut elem.st, env.cur_state)?;
    elem.st.speculative |= speculative;

    env.stack_size += 1;
    if env.stack_size > BPF_COMPLEXITY_LIMIT_JMP_SEQ {
        verbose(env, format!("The sequence of {} jumps is too complex.\n", env.stack_size));
        return Err(anyhow!("push_stack failed"));
    }

    if let Some(parent) = elem.st.parent.as_mut() {
        parent.branches += 1;
    }

    env.head = Some(Box::new(elem));
    Ok(&mut env.head.as_mut().unwrap().st)
}
