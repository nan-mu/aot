//! Missing types: BpfVerifierEnv, BpfInsnAuxData, BpfInsn

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn opt_hard_wire_dead_code_branches(env: &mut BpfVerifierEnv) -> Result<()> {
    let aux_data: &mut [BpfInsnAuxData] = &mut env.insn_aux_data;
    let mut ja: BpfInsn = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    let insn_cnt = env.prog.len as usize;

    for i in 0..insn_cnt {
        let insn = env.prog.insnsi[i];
        if !insn_is_cond_jump(insn.code)? {
            continue;
        }

        if !aux_data[i + 1].seen {
            ja.off = insn.off;
        } else if !aux_data[(i + 1) + insn.off as usize].seen {
            ja.off = 0;
        } else {
            continue;
        }

        if bpf_prog_is_offloaded(env.prog.aux) {
            bpf_prog_offload_replace_insn(env, i as i32, &ja);
        }

        env.prog.insnsi[i] = ja;
    }

    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn opt_remove_dead_code(env: &mut BpfVerifierEnv) -> Result<i32> {
    let mut insn_cnt = env.prog.len as i32;
    let mut i = 0;

    while i < insn_cnt {
        let mut j = 0;
        while i + j < insn_cnt && !env.insn_aux_data[(i + j) as usize].seen {
            j += 1;
        }
        if j == 0 {
            i += 1;
            continue;
        }

        verifier_remove_insns(env, i, j)?;
        insn_cnt = env.prog.len as i32;
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn opt_remove_nops(env: &mut BpfVerifierEnv) -> Result<i32> {
    let mut insn_cnt = env.prog.len as i32;
    let mut i = 0;

    while i < insn_cnt {
        let is_may_goto_0 = env.prog.insnsi[i as usize] == MAY_GOTO_0;
        let is_ja = env.prog.insnsi[i as usize] == NOP;

        if !is_may_goto_0 && !is_ja {
            i += 1;
            continue;
        }

        verifier_remove_insns(env, i, 1)?;
        insn_cnt -= 1;
        i -= if is_may_goto_0 && i > 0 { 2 } else { 1 };
        if i < 0 {
            i = 0;
        }
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, attr))]
pub fn opt_subreg_zext_lo32_rnd_hi32(env: &mut BpfVerifierEnv, attr: &BpfAttr) -> Result<i32> {
    let mut delta = 0;
    let mut len = env.prog.len as i32;
    let mut rnd_hi32 = (attr.prog_flags & BPF_F_TEST_RND_HI32) != 0;

    env.insn_buf[1] = BPF_ZEXT_REG(0);
    env.insn_buf[3] = BPF_ALU64_IMM(BPF_MOV, BPF_REG_AX, 0);
    env.insn_buf[4] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_AX, 32);
    env.insn_buf[5] = BPF_ALU64_REG(BPF_OR, 0, BPF_REG_AX);

    let mut i = 0;
    while i < len {
        let adj_idx = i + delta;
        let insn = env.prog.insnsi[adj_idx as usize];
        let load_reg = insn_def_regno(&insn)?;

        if !env.insn_aux_data[adj_idx as usize].zext_dst {
            if !rnd_hi32 || load_reg == -1 {
                i += 1;
                continue;
            }
            if is_reg64(&insn, load_reg, None, DST_OP) {
                if BPF_CLASS(insn.code) == BPF_LD && BPF_MODE(insn.code) == BPF_IMM {
                    i += 1;
                }
                i += 1;
                continue;
            }

            if BPF_CLASS(insn.code) == BPF_LDX && env.insn_aux_data[adj_idx as usize].ptr_type == PTR_TO_CTX {
                i += 1;
                continue;
            }

            let imm_rnd = get_random_u32();
            env.insn_buf[2] = insn;
            env.insn_buf[3].imm = imm_rnd as i32;
            env.insn_buf[5].dst_reg = load_reg as u8;
            let patch = [env.insn_buf[2], env.insn_buf[3], env.insn_buf[4], env.insn_buf[5]];

            let new_prog = bpf_patch_insn_data(env, adj_idx, &patch, 4)
                .ok_or_else(|| anyhow!("opt_subreg_zext_lo32_rnd_hi32 failed"))?;
            env.prog = new_prog;
            delta += 3;
            len = env.prog.len as i32;
            i += 1;
            continue;
        }

        if !bpf_jit_needs_zext() && !is_cmpxchg_insn(&insn)? {
            i += 1;
            continue;
        }
        if bpf_pseudo_kfunc_call(&insn) {
            i += 1;
            continue;
        }
        if load_reg == -1 {
            return Err(anyhow!("opt_subreg_zext_lo32_rnd_hi32 failed"));
        }

        env.insn_buf[0] = insn;
        env.insn_buf[1].dst_reg = load_reg as u8;
        env.insn_buf[1].src_reg = load_reg as u8;
        let patch = [env.insn_buf[0], env.insn_buf[1]];

        let new_prog = bpf_patch_insn_data(env, adj_idx, &patch, 2)
            .ok_or_else(|| anyhow!("opt_subreg_zext_lo32_rnd_hi32 failed"))?;
        env.prog = new_prog;
        delta += 1;
        len = env.prog.len as i32;
        i += 1;
    }

    Ok(0)
}
