//! Missing types: BpfVerifierEnv, BpfProg, BpfInsn

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, total_cnt))]
pub fn inline_bpf_loop(
    env: &mut BpfVerifierEnv,
    position: i32,
    stack_base: i32,
    callback_subprogno: u32,
    total_cnt: &mut u32,
) -> Result<&mut BpfProg> {
    let r6_offset = stack_base + 0 * BPF_REG_SIZE as i32;
    let r7_offset = stack_base + 1 * BPF_REG_SIZE as i32;
    let r8_offset = stack_base + 2 * BPF_REG_SIZE as i32;
    let reg_loop_max = BPF_REG_6;
    let reg_loop_cnt = BPF_REG_7;
    let reg_loop_ctx = BPF_REG_8;

    let insn_buf: &mut [BpfInsn] = &mut env.insn_buf;
    let mut cnt: u32 = 0;

    /* This represents an inlined version of bpf_iter.c:bpf_loop,
     * be careful to modify this code in sync.
     */
    insn_buf[cnt as usize] = BPF_JMP_IMM(BPF_JLE, BPF_REG_1, BPF_MAX_LOOPS, 2);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_MOV32_IMM(BPF_REG_0, -E2BIG);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_JMP_IMM(BPF_JA, 0, 0, 16);
    cnt += 1;

    insn_buf[cnt as usize] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, r6_offset);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, r7_offset);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_8, r8_offset);
    cnt += 1;

    insn_buf[cnt as usize] = BPF_MOV64_REG(reg_loop_max, BPF_REG_1);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_MOV32_IMM(reg_loop_cnt, 0);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_MOV64_REG(reg_loop_ctx, BPF_REG_3);
    cnt += 1;

    insn_buf[cnt as usize] = BPF_JMP_REG(BPF_JGE, reg_loop_cnt, reg_loop_max, 5);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_MOV64_REG(BPF_REG_1, reg_loop_cnt);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_MOV64_REG(BPF_REG_2, reg_loop_ctx);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_CALL_REL(0);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_ALU64_IMM(BPF_ADD, reg_loop_cnt, 1);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, -6);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_MOV64_REG(BPF_REG_0, reg_loop_cnt);
    cnt += 1;

    insn_buf[cnt as usize] = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, r6_offset);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_10, r7_offset);
    cnt += 1;
    insn_buf[cnt as usize] = BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_10, r8_offset);
    cnt += 1;

    *total_cnt = cnt;
    let new_prog = bpf_patch_insn_data(env, position, &insn_buf[..cnt as usize], cnt as i32)
        .ok_or_else(|| anyhow!("inline_bpf_loop failed"))?;

    let callback_start = env.subprog_info[callback_subprogno as usize].start;
    let call_insn_offset = position + 12;
    let callback_offset = callback_start - call_insn_offset - 1;
    new_prog.insnsi[call_insn_offset as usize].imm = callback_offset;

    Ok(new_prog)
}
