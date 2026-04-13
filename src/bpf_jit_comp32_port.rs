// SPDX-License-Identifier: GPL-2.0
/*
 * BPF JIT compiler for RV32G
 *
 * Rust 机械迁移版（先原样照搬结构）
 *
 * 说明：
 * - 当前版本优先保持与 `bpf_jit_comp32.c` 的命名和层次一致。
 * - 暂不追求可编译，通过占位类型与外部符号保留原始结构。
 * - 后续再逐步把宏、常量、辅助函数和上下文类型补齐。
 */

#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub type s8 = i8;
pub type s16 = i16;
pub type s32 = i32;
pub type u8_ = u8;
pub type u32_ = u32;
pub type u64_ = u64;

pub struct rv_jit_context {
    pub stack_size: i32,
    pub ninsns: i32,
}

pub struct bpf_prog;
pub struct bpf_insn;

/*
 * Stack layout during BPF program execution:
 *
 *                     high
 *     RV32 fp =>  +----------+
 *                 | saved ra |
 *                 | saved fp | RV32 callee-saved registers
 *                 |   ...    |
 *                 +----------+ <= (fp - 4 * NR_SAVED_REGISTERS)
 *                 |  hi(R6)  |
 *                 |  lo(R6)  |
 *                 |  hi(R7)  | JIT scratch space for BPF registers
 *                 |  lo(R7)  |
 *                 |   ...    |
 *  BPF_REG_FP =>  +----------+ <= (fp - 4 * NR_SAVED_REGISTERS
 *                 |          |        - 4 * BPF_JIT_SCRATCH_REGS)
 *                 |          |
 *                 |   ...    | BPF program stack
 *                 |          |
 *     RV32 sp =>  +----------+
 *                 |          |
 *                 |   ...    | Function call stack
 *                 |          |
 *                 +----------+
 *                     low
 */

pub const BPF_R6_HI: usize = 0;
pub const BPF_R6_LO: usize = 1;
pub const BPF_R7_HI: usize = 2;
pub const BPF_R7_LO: usize = 3;
pub const BPF_R8_HI: usize = 4;
pub const BPF_R8_LO: usize = 5;
pub const BPF_R9_HI: usize = 6;
pub const BPF_R9_LO: usize = 7;
pub const BPF_AX_HI: usize = 8;
pub const BPF_AX_LO: usize = 9;
pub const BPF_JIT_SCRATCH_REGS: usize = 10;

pub const NR_SAVED_REGISTERS: i32 = 9;

pub const fn STACK_OFFSET(k: usize) -> s8 {
    (-4 - (4 * NR_SAVED_REGISTERS) - (4 * k as i32)) as s8
}

pub const MAX_BPF_JIT_REG: s8 = 16;
pub const TMP_REG_1: usize = (MAX_BPF_JIT_REG as usize) + 0;
pub const TMP_REG_2: usize = (MAX_BPF_JIT_REG as usize) + 1;

pub const RV_REG_ZERO: s8 = 0;
pub const RV_REG_RA: s8 = 1;
pub const RV_REG_SP: s8 = 2;
pub const RV_REG_FP: s8 = 8;
pub const RV_REG_A0: s8 = 10;
pub const RV_REG_A1: s8 = 11;
pub const RV_REG_A2: s8 = 12;
pub const RV_REG_A3: s8 = 13;
pub const RV_REG_A4: s8 = 14;
pub const RV_REG_A5: s8 = 15;
pub const RV_REG_A6: s8 = 16;
pub const RV_REG_A7: s8 = 17;
pub const RV_REG_S1: s8 = 9;
pub const RV_REG_S2: s8 = 18;
pub const RV_REG_S3: s8 = 19;
pub const RV_REG_S4: s8 = 20;
pub const RV_REG_S5: s8 = 21;
pub const RV_REG_S6: s8 = 22;
pub const RV_REG_S7: s8 = 23;
pub const RV_REG_T0: s8 = 5;
pub const RV_REG_T1: s8 = 6;
pub const RV_REG_T2: s8 = 7;
pub const RV_REG_T3: s8 = 28;
pub const RV_REG_T4: s8 = 29;
pub const RV_REG_T5: s8 = 30;
pub const RV_REG_T6: s8 = 31;

pub const RV_REG_TCC: s8 = RV_REG_T6;
pub const RV_REG_TCC_SAVED: s8 = RV_REG_S7;

pub const BPF_REG_0: usize = 0;
pub const BPF_REG_1: usize = 1;
pub const BPF_REG_2: usize = 2;
pub const BPF_REG_3: usize = 3;
pub const BPF_REG_4: usize = 4;
pub const BPF_REG_5: usize = 5;
pub const BPF_REG_6: usize = 6;
pub const BPF_REG_7: usize = 7;
pub const BPF_REG_8: usize = 8;
pub const BPF_REG_9: usize = 9;
pub const BPF_REG_FP: usize = 10;
pub const BPF_REG_AX: usize = 11;

pub static BPF2RV32: [[s8; 2]; 18] = [
    [RV_REG_S2, RV_REG_S1],
    [RV_REG_A1, RV_REG_A0],
    [RV_REG_A3, RV_REG_A2],
    [RV_REG_A5, RV_REG_A4],
    [RV_REG_A7, RV_REG_A6],
    [RV_REG_S4, RV_REG_S3],
    [STACK_OFFSET(BPF_R6_HI), STACK_OFFSET(BPF_R6_LO)],
    [STACK_OFFSET(BPF_R7_HI), STACK_OFFSET(BPF_R7_LO)],
    [STACK_OFFSET(BPF_R8_HI), STACK_OFFSET(BPF_R8_LO)],
    [STACK_OFFSET(BPF_R9_HI), STACK_OFFSET(BPF_R9_LO)],
    [RV_REG_S6, RV_REG_S5],
    [STACK_OFFSET(BPF_AX_HI), STACK_OFFSET(BPF_AX_LO)],
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [RV_REG_T3, RV_REG_T2],
    [RV_REG_T5, RV_REG_T4],
];

pub fn hi(r: &[s8; 2]) -> s8 {
    r[0]
}

pub fn lo(r: &[s8; 2]) -> s8 {
    r[1]
}

pub fn emit(_insn: u32, _ctx: &mut rv_jit_context) {}
pub fn rv_lui(_rd: s8, _imm: u32) -> u32 { 0 }
pub fn rv_addi(_rd: s8, _rs: s8, _imm: i32) -> u32 { 0 }
pub fn rv_lw(_rd: s8, _off: i32, _rs: s8) -> u32 { 0 }
pub fn rv_sw(_rs1: s8, _off: i32, _rs2: s8) -> u32 { 0 }
pub fn rv_jalr(_rd: s8, _rs: s8, _off: i32) -> u32 { 0 }
pub fn rv_auipc(_rd: s8, _imm: i32) -> u32 { 0 }
pub fn rv_jal(_rd: s8, _off: i32) -> u32 { 0 }
pub fn is_21b_int(_v: i32) -> bool { true }

pub fn emit_imm(rd: s8, imm: s32, ctx: &mut rv_jit_context) {
    let upper = ((imm + (1 << 11)) >> 12) as u32;
    let lower = (imm & 0xfff) as u32;

    if upper != 0 {
        emit(rv_lui(rd, upper), ctx);
        emit(rv_addi(rd, rd, lower as i32), ctx);
    } else {
        emit(rv_addi(rd, RV_REG_ZERO, lower as i32), ctx);
    }
}

pub fn emit_imm32(rd: &[s8; 2], imm: s32, ctx: &mut rv_jit_context) {
    emit_imm(lo(rd), imm, ctx);

    if imm >= 0 {
        emit(rv_addi(hi(rd), RV_REG_ZERO, 0), ctx);
    } else {
        emit(rv_addi(hi(rd), RV_REG_ZERO, -1), ctx);
    }
}

pub fn emit_imm64(rd: &[s8; 2], imm_hi: s32, imm_lo: s32, ctx: &mut rv_jit_context) {
    emit_imm(lo(rd), imm_lo, ctx);
    emit_imm(hi(rd), imm_hi, ctx);
}

pub fn __build_epilogue(is_tail_call: bool, ctx: &mut rv_jit_context) {
    let stack_adjust = ctx.stack_size;
    let r0 = &BPF2RV32[BPF_REG_0];

    if !is_tail_call {
        emit(rv_addi(RV_REG_A0, lo(r0), 0), ctx);
        emit(rv_addi(RV_REG_A1, hi(r0), 0), ctx);
    }

    emit(rv_lw(RV_REG_RA, stack_adjust - 4, RV_REG_SP), ctx);
    emit(rv_lw(RV_REG_FP, stack_adjust - 8, RV_REG_SP), ctx);
    emit(rv_lw(RV_REG_S1, stack_adjust - 12, RV_REG_SP), ctx);
    emit(rv_lw(RV_REG_S2, stack_adjust - 16, RV_REG_SP), ctx);
    emit(rv_lw(RV_REG_S3, stack_adjust - 20, RV_REG_SP), ctx);
    emit(rv_lw(RV_REG_S4, stack_adjust - 24, RV_REG_SP), ctx);
    emit(rv_lw(RV_REG_S5, stack_adjust - 28, RV_REG_SP), ctx);
    emit(rv_lw(RV_REG_S6, stack_adjust - 32, RV_REG_SP), ctx);
    emit(rv_lw(RV_REG_S7, stack_adjust - 36, RV_REG_SP), ctx);
    emit(rv_addi(RV_REG_SP, RV_REG_SP, stack_adjust), ctx);

    if is_tail_call {
        emit(rv_jalr(RV_REG_ZERO, RV_REG_T0, 4), ctx);
    } else {
        emit(rv_jalr(RV_REG_ZERO, RV_REG_RA, 0), ctx);
    }
}

pub fn is_stacked(reg: s8) -> bool {
    reg < 0
}

pub fn bpf_get_reg64<'a>(reg: &'a [s8; 2], tmp: &'a [s8; 2], ctx: &mut rv_jit_context) -> &'a [s8; 2] {
    if is_stacked(hi(reg)) {
        emit(rv_lw(hi(tmp), hi(reg) as i32, RV_REG_FP), ctx);
        emit(rv_lw(lo(tmp), lo(reg) as i32, RV_REG_FP), ctx);
        tmp
    } else {
        reg
    }
}

pub fn bpf_put_reg64(reg: &[s8; 2], src: &[s8; 2], ctx: &mut rv_jit_context) {
    if is_stacked(hi(reg)) {
        emit(rv_sw(RV_REG_FP, hi(reg) as i32, hi(src)), ctx);
        emit(rv_sw(RV_REG_FP, lo(reg) as i32, lo(src)), ctx);
    }
}

pub fn bpf_get_reg32<'a>(reg: &'a [s8; 2], tmp: &'a [s8; 2], ctx: &mut rv_jit_context) -> &'a [s8; 2] {
    if is_stacked(lo(reg)) {
        emit(rv_lw(lo(tmp), lo(reg) as i32, RV_REG_FP), ctx);
        tmp
    } else {
        reg
    }
}

pub fn bpf_put_reg32(reg: &[s8; 2], src: &[s8; 2], ctx: &mut rv_jit_context) {
    if is_stacked(lo(reg)) {
        emit(rv_sw(RV_REG_FP, lo(reg) as i32, lo(src)), ctx);
        emit(rv_sw(RV_REG_FP, hi(reg) as i32, RV_REG_ZERO), ctx);
    } else {
        emit(rv_addi(hi(reg), RV_REG_ZERO, 0), ctx);
    }
}

pub fn emit_jump_and_link(rd: u8, rvoff: s32, force_jalr: bool, ctx: &mut rv_jit_context) {
    let upper: s32;
    let lower: s32;

    if rvoff != 0 && is_21b_int(rvoff) && !force_jalr {
        emit(rv_jal(rd as s8, rvoff >> 1), ctx);
        return;
    }

    upper = (rvoff + (1 << 11)) >> 12;
    lower = rvoff & 0xfff;
    emit(rv_auipc(RV_REG_T1, upper), ctx);
    emit(rv_jalr(rd as s8, RV_REG_T1, lower), ctx);
}
