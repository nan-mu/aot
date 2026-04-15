//! Missing types: BpfVerifierEnv, BpfSubprogInfo, BpfInsnAuxData, BpfInsn

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn remove_fastcall_spills_fills(env: &mut BpfVerifierEnv) -> Result<i32> {
    let mut subprog_idx = 0usize;
    let mut modified = false;
    let insn_cnt = env.prog.len as usize;

    for i in 0..insn_cnt {
        let spills_num = env.insn_aux_data[i].fastcall_spills_num;
        if spills_num > 0 {
            for j in 1..=spills_num as usize {
                env.prog.insnsi[i - j] = NOP;
                env.prog.insnsi[i + j] = NOP;
            }
            modified = true;
        }

        if env.subprog_info[subprog_idx + 1].start as usize == i + 1 {
            if modified && !env.subprog_info[subprog_idx].keep_fastcall_stack {
                env.subprog_info[subprog_idx].stack_depth = -env.subprog_info[subprog_idx].fastcall_stack_off;
            }
            subprog_idx += 1;
            modified = false;
        }
    }

    Ok(0)
}
