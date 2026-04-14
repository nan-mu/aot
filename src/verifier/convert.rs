//! Missing types: BpfVerifierEnv, BpfInsn, BpfProg

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn convert_ctx_accesses(env: &mut BpfVerifierEnv) -> Result<i32> {
    let ops = env.ops;
    let insn_cnt = env.prog.len as usize;

    if ops.gen_epilogue.is_some() {
        let epilogue_cnt = ops
            .gen_epilogue
            .unwrap()(&mut env.epilogue_buf, env.prog, -(env.subprog_info[0].stack_depth + 8));
        if epilogue_cnt >= INSN_BUF_SIZE {
            verifier_bug(env, "epilogue is too long");
            return Err(anyhow!("convert_ctx_accesses failed"));
        }
    }

    if ops.gen_prologue.is_some() || env.seen_direct_write {
        let cnt = ops
            .gen_prologue
            .ok_or_else(|| anyhow!("convert_ctx_accesses failed"))?(
            &mut env.insn_buf,
            env.seen_direct_write,
            env.prog,
        );
        if cnt >= INSN_BUF_SIZE {
            verifier_bug(env, "prologue is too long");
            return Err(anyhow!("convert_ctx_accesses failed"));
        }
    }

    for i in 0..insn_cnt {
        let insn: &mut BpfInsn = &mut env.prog.insnsi[i];
        if env.insn_aux_data[i].nospec {
            let patch = [BPF_ST_NOSPEC(), *insn];
            env.prog = bpf_patch_insn_data(env, i as i32, &patch, patch.len() as i32)
                .context("convert_ctx_accesses failed")?;
        }
    }

    Ok(0)
}
