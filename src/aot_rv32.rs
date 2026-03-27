// SPDX-License-Identifier: (Apache-2.0 OR MIT)
// RV32 JIT compiler for eBPF
// Translates eBPF bytecode -> Vec<u32> of RISC-V 32-bit machine words.
// See comments throughout for design notes.

#![allow(dead_code)]

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// eBPF opcode constants
// ---------------------------------------------------------------------------

pub const INSN_SIZE: usize = 8;

// ALU32
pub const ADD32_IMM:  u8 = 0x04;  pub const ADD32_REG:  u8 = 0x0c;
pub const SUB32_IMM:  u8 = 0x14;  pub const SUB32_REG:  u8 = 0x1c;
pub const MUL32_IMM:  u8 = 0x24;  pub const MUL32_REG:  u8 = 0x2c;
pub const DIV32_IMM:  u8 = 0x34;  pub const DIV32_REG:  u8 = 0x3c;
pub const OR32_IMM:   u8 = 0x44;  pub const OR32_REG:   u8 = 0x4c;
pub const AND32_IMM:  u8 = 0x54;  pub const AND32_REG:  u8 = 0x5c;
pub const LSH32_IMM:  u8 = 0x64;  pub const LSH32_REG:  u8 = 0x6c;
pub const RSH32_IMM:  u8 = 0x74;  pub const RSH32_REG:  u8 = 0x7c;
pub const NEG32:      u8 = 0x84;
pub const MOD32_IMM:  u8 = 0x94;  pub const MOD32_REG:  u8 = 0x9c;
pub const XOR32_IMM:  u8 = 0xa4;  pub const XOR32_REG:  u8 = 0xac;
pub const MOV32_IMM:  u8 = 0xb4;  pub const MOV32_REG:  u8 = 0xbc;
pub const ARSH32_IMM: u8 = 0xc4;  pub const ARSH32_REG: u8 = 0xcc;
pub const LE:         u8 = 0xd4;  pub const BE:         u8 = 0xdc;

// ALU64
pub const ADD64_IMM:  u8 = 0x07;  pub const ADD64_REG:  u8 = 0x0f;
pub const SUB64_IMM:  u8 = 0x17;  pub const SUB64_REG:  u8 = 0x1f;
pub const MUL64_IMM:  u8 = 0x27;  pub const MUL64_REG:  u8 = 0x2f;
pub const DIV64_IMM:  u8 = 0x37;  pub const DIV64_REG:  u8 = 0x3f;
pub const OR64_IMM:   u8 = 0x47;  pub const OR64_REG:   u8 = 0x4f;
pub const AND64_IMM:  u8 = 0x57;  pub const AND64_REG:  u8 = 0x5f;
pub const LSH64_IMM:  u8 = 0x67;  pub const LSH64_REG:  u8 = 0x6f;
pub const RSH64_IMM:  u8 = 0x77;  pub const RSH64_REG:  u8 = 0x7f;
pub const NEG64:      u8 = 0x87;
pub const MOD64_IMM:  u8 = 0x97;  pub const MOD64_REG:  u8 = 0x9f;
pub const XOR64_IMM:  u8 = 0xa7;  pub const XOR64_REG:  u8 = 0xaf;
pub const MOV64_IMM:  u8 = 0xb7;  pub const MOV64_REG:  u8 = 0xbf;
pub const ARSH64_IMM: u8 = 0xc7;  pub const ARSH64_REG: u8 = 0xcf;

// Memory
pub const LD_ABS_B:  u8 = 0x30;  pub const LD_ABS_H:  u8 = 0x28;
pub const LD_ABS_W:  u8 = 0x20;  pub const LD_ABS_DW: u8 = 0x38;
pub const LD_IND_B:  u8 = 0x50;  pub const LD_IND_H:  u8 = 0x48;
pub const LD_IND_W:  u8 = 0x40;  pub const LD_IND_DW: u8 = 0x58;
pub const LD_DW_IMM: u8 = 0x18;  // 16-byte wide double-word load-immediate
pub const LD_B_REG:  u8 = 0x71;  pub const LD_H_REG:  u8 = 0x69;
pub const LD_W_REG:  u8 = 0x61;  pub const LD_DW_REG: u8 = 0x79;
pub const ST_B_IMM:  u8 = 0x72;  pub const ST_H_IMM:  u8 = 0x6a;
pub const ST_W_IMM:  u8 = 0x62;  pub const ST_DW_IMM: u8 = 0x7a;
pub const ST_B_REG:  u8 = 0x73;  pub const ST_H_REG:  u8 = 0x6b;
pub const ST_W_REG:  u8 = 0x63;  pub const ST_DW_REG: u8 = 0x7b;

// JMP
pub const JA:        u8 = 0x05;
pub const JEQ_IMM:   u8 = 0x15;  pub const JEQ_REG:   u8 = 0x1d;
pub const JGT_IMM:   u8 = 0x25;  pub const JGT_REG:   u8 = 0x2d;
pub const JGE_IMM:   u8 = 0x35;  pub const JGE_REG:   u8 = 0x3d;
pub const JSET_IMM:  u8 = 0x45;  pub const JSET_REG:  u8 = 0x4d;
pub const JNE_IMM:   u8 = 0x55;  pub const JNE_REG:   u8 = 0x5d;
pub const JSGT_IMM:  u8 = 0x65;  pub const JSGT_REG:  u8 = 0x6d;
pub const JSGE_IMM:  u8 = 0x75;  pub const JSGE_REG:  u8 = 0x7d;
pub const JLT_IMM:   u8 = 0xa5;  pub const JLT_REG:   u8 = 0xad;
pub const JLE_IMM:   u8 = 0xb5;  pub const JLE_REG:   u8 = 0xbd;
pub const JSLT_IMM:  u8 = 0xc5;  pub const JSLT_REG:  u8 = 0xcd;
pub const JSLE_IMM:  u8 = 0xd5;  pub const JSLE_REG:  u8 = 0xdd;
// JMP32
pub const JEQ_IMM32:  u8 = 0x16;  pub const JEQ_REG32:  u8 = 0x1e;
pub const JGT_IMM32:  u8 = 0x26;  pub const JGT_REG32:  u8 = 0x2e;
pub const JGE_IMM32:  u8 = 0x36;  pub const JGE_REG32:  u8 = 0x3e;
pub const JSET_IMM32: u8 = 0x46;  pub const JSET_REG32: u8 = 0x4e;
pub const JNE_IMM32:  u8 = 0x56;  pub const JNE_REG32:  u8 = 0x5e;
pub const JSGT_IMM32: u8 = 0x66;  pub const JSGT_REG32: u8 = 0x6e;
pub const JSGE_IMM32: u8 = 0x76;  pub const JSGE_REG32: u8 = 0x7e;
pub const JLT_IMM32:  u8 = 0xa6;  pub const JLT_REG32:  u8 = 0xae;
pub const JLE_IMM32:  u8 = 0xb6;  pub const JLE_REG32:  u8 = 0xbe;
pub const JSLT_IMM32: u8 = 0xc6;  pub const JSLT_REG32: u8 = 0xce;
pub const JSLE_IMM32: u8 = 0xd6;  pub const JSLE_REG32: u8 = 0xde;

pub const CALL:      u8 = 0x85;
pub const TAIL_CALL: u8 = 0x8d;
pub const EXIT:      u8 = 0x95;

pub const STACK_SIZE: usize = 512;

/// Decoded eBPF instruction.
#[derive(Debug, Clone)]
pub struct Insn {
    pub opc: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

pub fn get_insn(prog: &[u8], idx: usize) -> Insn {
    let b = idx * INSN_SIZE;
    Insn {
        opc: prog[b],
        dst: prog[b + 1] & 0x0f,
        src: (prog[b + 1] >> 4) & 0x0f,
        off: i16::from_le_bytes([prog[b + 2], prog[b + 3]]),
        imm: i32::from_le_bytes([prog[b + 4], prog[b + 5], prog[b + 6], prog[b + 7]]),
    }
}
// ---------------------------------------------------------------------------
// RV32 register aliases
// ---------------------------------------------------------------------------
//
// 64-bit register pairs: each eBPF register occupies two adjacent RV32
// registers (lo, hi = lo+1).  map_reg_lo() returns the low-word register;
// map_reg_hi() returns lo+1 (the high word).
// For read-only R10 (fp) the high half is always ZERO.

pub const ZERO: u32 =  0;  // hard-wired zero
pub const RA:   u32 =  1;  // return address
pub const SP:   u32 =  2;  // stack pointer
pub const T0:   u32 =  5;  // scratch 0
pub const T1:   u32 =  6;  // scratch 1
pub const T2:   u32 =  7;  // scratch 2
pub const S0:   u32 =  8;  // fp / eBPF R10 lo  (hi = S1 = x9, kept zero by convention)
pub const S1:   u32 =  9;  // helper-table base AND eBPF R10 hi placeholder
                        // NOTE: R10 is read-only in eBPF so its hi word is never written
pub const A0:   u32 = 10;  // eBPF R1  lo
pub const A1:   u32 = 11;  // eBPF R1  hi
pub const A2:   u32 = 12;  // eBPF R2  lo
pub const A3:   u32 = 13;  // eBPF R2  hi
pub const A4:   u32 = 14;  // eBPF R0  lo  (return value low word)
pub const A5:   u32 = 15;  // eBPF R0  hi  (return value high word)
pub const A6:   u32 = 16;  // eBPF R3  lo
pub const A7:   u32 = 17;  // eBPF R3  hi
pub const S2:   u32 = 18;  // eBPF R4  lo
pub const S3:   u32 = 19;  // eBPF R4  hi
pub const S4:   u32 = 20;  // eBPF R5  lo
pub const S5:   u32 = 21;  // eBPF R5  hi
pub const S6:   u32 = 22;  // eBPF R6  lo
pub const S7:   u32 = 23;  // eBPF R6  hi
pub const S8:   u32 = 24;  // eBPF R7  lo
pub const S9:   u32 = 25;  // eBPF R7  hi
pub const S10:  u32 = 26;  // eBPF R8  lo
pub const S11:  u32 = 27;  // eBPF R8  hi
pub const T3:   u32 = 28;  // eBPF R9  lo
pub const T4:   u32 = 29;  // eBPF R9  hi
pub const T5:   u32 = 30;  // extra scratch (64-bit ops)
pub const T6:   u32 = 31;  // extra scratch (64-bit ops)

// Register-pair lo-word map (index = eBPF register number 0-10)
pub const REG_LO_MAP: [u32; 11] = [
    A4,   // R0  lo
    A0,   // R1  lo
    A2,   // R2  lo
    A6,   // R3  lo
    S2,   // R4  lo
    S4,   // R5  lo
    S6,   // R6  lo
    S8,   // R7  lo
    S10,  // R8  lo
    T3,   // R9  lo
    S0,   // R10 lo (fp)
];

/// Low 32-bit word of eBPF register `r`.
pub fn map_reg_lo(r: u8) -> u32 {
    assert!((r as usize) < REG_LO_MAP.len(), "invalid eBPF register {r}");
    REG_LO_MAP[r as usize]
}

/// High 32-bit word of eBPF register `r` (= lo + 1, except R10 whose hi = ZERO).
pub fn map_reg_hi(r: u8) -> u32 {
    if r == 10 { return ZERO; }  // R10 is read-only fp; high half is always 0
    map_reg_lo(r) + 1
}

/// Backward-compat alias: returns the lo word (used for 32-bit ops).
#[inline]
pub fn map_reg(r: u8) -> u32 { map_reg_lo(r) }
// ---------------------------------------------------------------------------
// RV32 instruction encoders
// ---------------------------------------------------------------------------

/// R-type: funct7 | rs2 | rs1 | funct3 | rd | opcode
#[inline]
fn enc_r(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opc: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opc
}

/// I-type: imm[11:0] | rs1 | funct3 | rd | opcode
#[inline]
fn enc_i(imm: i32, rs1: u32, funct3: u32, rd: u32, opc: u32) -> u32 {
    let i = (imm as u32) & 0xFFF;
    (i << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opc
}

/// S-type: imm[11:5] | rs2 | rs1 | funct3 | imm[4:0] | opcode
#[inline]
fn enc_s(imm: i32, rs2: u32, rs1: u32, funct3: u32, opc: u32) -> u32 {
    let i = (imm as u32) & 0xFFF;
    ((i >> 5 & 0x7F) << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | ((i & 0x1F) << 7) | opc
}

/// B-type: imm[12|10:5] | rs2 | rs1 | funct3 | imm[4:1|11] | opcode
/// imm is a signed byte offset (must be even).
#[inline]
fn enc_b(imm: i32, rs2: u32, rs1: u32, funct3: u32, opc: u32) -> u32 {
    let i = imm as u32;
    let b12   = (i >> 12) & 1;
    let b11   = (i >> 11) & 1;
    let b10_5 = (i >>  5) & 0x3F;
    let b4_1  = (i >>  1) & 0xF;
    (b12 << 31) | (b10_5 << 25) | (rs2 << 20) | (rs1 << 15)
        | (funct3 << 12) | (b4_1 << 8) | (b11 << 7) | opc
}

/// U-type: imm[31:12] | rd | opcode
#[inline]
fn enc_u(imm: i32, rd: u32, opc: u32) -> u32 {
    ((imm as u32) & 0xFFFF_F000) | (rd << 7) | opc
}

/// J-type / JAL: imm[20|10:1|11|19:12] | rd | opcode
/// imm is a signed byte offset (must be even).
#[inline]
fn enc_j(imm: i32, rd: u32, opc: u32) -> u32 {
    let i = imm as u32;
    let b20    = (i >> 20) & 1;
    let b19_12 = (i >> 12) & 0xFF;
    let b11    = (i >> 11) & 1;
    let b10_1  = (i >>  1) & 0x3FF;
    (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | (rd << 7) | opc
}

// -- Integer Reg-Imm (opcode 0x13) --
fn rv_addi(rd: u32, rs1: u32, imm: i32)   -> u32 { enc_i(imm, rs1, 0b000, rd, 0x13) }
fn rv_slti(rd: u32, rs1: u32, imm: i32)   -> u32 { enc_i(imm, rs1, 0b010, rd, 0x13) }
fn rv_sltiu(rd: u32, rs1: u32, imm: i32)  -> u32 { enc_i(imm, rs1, 0b011, rd, 0x13) }
fn rv_xori(rd: u32, rs1: u32, imm: i32)   -> u32 { enc_i(imm, rs1, 0b100, rd, 0x13) }
fn rv_ori(rd: u32, rs1: u32, imm: i32)    -> u32 { enc_i(imm, rs1, 0b110, rd, 0x13) }
fn rv_andi(rd: u32, rs1: u32, imm: i32)   -> u32 { enc_i(imm, rs1, 0b111, rd, 0x13) }
fn rv_slli(rd: u32, rs1: u32, shamt: u32) -> u32 { enc_i(shamt as i32 & 0x1F, rs1, 0b001, rd, 0x13) }
fn rv_srli(rd: u32, rs1: u32, shamt: u32) -> u32 { enc_i(shamt as i32 & 0x1F, rs1, 0b101, rd, 0x13) }
fn rv_srai(rd: u32, rs1: u32, shamt: u32) -> u32 {
    // bit 10 of imm = 1 selects arithmetic right shift
    enc_i(0x400 | (shamt as i32 & 0x1F), rs1, 0b101, rd, 0x13)
}

// -- Integer Reg-Reg (opcode 0x33) --
fn rv_add(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b000_0000, rs2, rs1, 0b000, rd, 0x33) }
fn rv_sub(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b010_0000, rs2, rs1, 0b000, rd, 0x33) }
fn rv_sll(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b000_0000, rs2, rs1, 0b001, rd, 0x33) }
fn rv_slt(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b000_0000, rs2, rs1, 0b010, rd, 0x33) }
fn rv_sltu(rd: u32, rs1: u32, rs2: u32) -> u32 { enc_r(0b000_0000, rs2, rs1, 0b011, rd, 0x33) }
fn rv_xor(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b000_0000, rs2, rs1, 0b100, rd, 0x33) }
fn rv_srl(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b000_0000, rs2, rs1, 0b101, rd, 0x33) }
fn rv_sra(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b010_0000, rs2, rs1, 0b101, rd, 0x33) }
fn rv_or(rd: u32, rs1: u32, rs2: u32)   -> u32 { enc_r(0b000_0000, rs2, rs1, 0b110, rd, 0x33) }
fn rv_and(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b000_0000, rs2, rs1, 0b111, rd, 0x33) }

// -- RV32M: multiply / divide / remainder (funct7 = 0b000_0001) --
fn rv_mul(rd: u32, rs1: u32, rs2: u32)   -> u32 { enc_r(0b000_0001, rs2, rs1, 0b000, rd, 0x33) }
fn rv_mulh(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b000_0001, rs2, rs1, 0b001, rd, 0x33) }
fn rv_mulhu(rd: u32, rs1: u32, rs2: u32) -> u32 { enc_r(0b000_0001, rs2, rs1, 0b011, rd, 0x33) }
fn rv_div(rd: u32, rs1: u32, rs2: u32)   -> u32 { enc_r(0b000_0001, rs2, rs1, 0b100, rd, 0x33) }
fn rv_divu(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b000_0001, rs2, rs1, 0b101, rd, 0x33) }
fn rv_rem(rd: u32, rs1: u32, rs2: u32)   -> u32 { enc_r(0b000_0001, rs2, rs1, 0b110, rd, 0x33) }
fn rv_remu(rd: u32, rs1: u32, rs2: u32)  -> u32 { enc_r(0b000_0001, rs2, rs1, 0b111, rd, 0x33) }

// -- Loads (opcode 0x03) --
fn rv_lb(rd: u32, rs1: u32, imm: i32)  -> u32 { enc_i(imm, rs1, 0b000, rd, 0x03) }
fn rv_lh(rd: u32, rs1: u32, imm: i32)  -> u32 { enc_i(imm, rs1, 0b001, rd, 0x03) }
fn rv_lw(rd: u32, rs1: u32, imm: i32)  -> u32 { enc_i(imm, rs1, 0b010, rd, 0x03) }
fn rv_lbu(rd: u32, rs1: u32, imm: i32) -> u32 { enc_i(imm, rs1, 0b100, rd, 0x03) }
fn rv_lhu(rd: u32, rs1: u32, imm: i32) -> u32 { enc_i(imm, rs1, 0b101, rd, 0x03) }

// -- Stores (opcode 0x23) --
fn rv_sb(rs1: u32, rs2: u32, imm: i32) -> u32 { enc_s(imm, rs2, rs1, 0b000, 0x23) }
fn rv_sh(rs1: u32, rs2: u32, imm: i32) -> u32 { enc_s(imm, rs2, rs1, 0b001, 0x23) }
fn rv_sw(rs1: u32, rs2: u32, imm: i32) -> u32 { enc_s(imm, rs2, rs1, 0b010, 0x23) }

// -- Branches (opcode 0x63) --
fn rv_beq(rs1: u32, rs2: u32, imm: i32)  -> u32 { enc_b(imm, rs2, rs1, 0b000, 0x63) }
fn rv_bne(rs1: u32, rs2: u32, imm: i32)  -> u32 { enc_b(imm, rs2, rs1, 0b001, 0x63) }
fn rv_blt(rs1: u32, rs2: u32, imm: i32)  -> u32 { enc_b(imm, rs2, rs1, 0b100, 0x63) }
fn rv_bge(rs1: u32, rs2: u32, imm: i32)  -> u32 { enc_b(imm, rs2, rs1, 0b101, 0x63) }
fn rv_bltu(rs1: u32, rs2: u32, imm: i32) -> u32 { enc_b(imm, rs2, rs1, 0b110, 0x63) }
fn rv_bgeu(rs1: u32, rs2: u32, imm: i32) -> u32 { enc_b(imm, rs2, rs1, 0b111, 0x63) }

// -- LUI / AUIPC --
fn rv_lui(rd: u32, imm: i32)   -> u32 { enc_u(imm, rd, 0x37) }
fn rv_auipc(rd: u32, imm: i32) -> u32 { enc_u(imm, rd, 0x17) }

// -- JAL / JALR --
fn rv_jal(rd: u32, imm: i32)          -> u32 { enc_j(imm, rd, 0x6F) }
fn rv_jalr(rd: u32, rs1: u32, imm: i32) -> u32 { enc_i(imm, rs1, 0b000, rd, 0x67) }

// Pseudo-instructions built from the above
/// mv rd, rs  =  addi rd, rs, 0
fn rv_mv(rd: u32, rs: u32) -> u32 { rv_addi(rd, rs, 0) }
/// li rd, imm  -- for small (12-bit signed) immediates only
fn rv_li_small(rd: u32, imm: i32) -> u32 { rv_addi(rd, ZERO, imm) }
/// ret  =  jalr zero, ra, 0
fn rv_ret() -> u32 { rv_jalr(ZERO, RA, 0) }
/// jr rs  =  jalr zero, rs, 0
fn rv_jr(rs: u32) -> u32 { rv_jalr(ZERO, rs, 0) }

/// Emit a 32-bit immediate into rd using lui + addi (2 words).
/// Returns the two instruction words.
fn rv_li32(out: &mut Vec<u32>, rd: u32, imm: i32) {
    let hi = ((imm as u32).wrapping_add(0x800)) & 0xFFFF_F000;
    let lo = (imm as u32).wrapping_sub(hi) as i32;
    if hi != 0 {
        out.push(rv_lui(rd, hi as i32));
        if lo != 0 {
            out.push(rv_addi(rd, rd, lo));
        }
    } else {
        out.push(rv_addi(rd, ZERO, lo));
    }
}
// ---------------------------------------------------------------------------
// Jump patch records
// ---------------------------------------------------------------------------

/// Sentinel target_pc values for special jump targets.
pub const TARGET_PC_EXIT: isize = 0x7FFF_FFF0;

/// Records the location of a branch/jump instruction that needs its
/// offset back-patched in pass 2.
#[derive(Debug)]
struct PatchSite {
    /// Index into `out` Vec where the branch word lives.
    word_idx: usize,
    /// The eBPF PC index that is the branch target.
    /// Use TARGET_PC_EXIT for the epilogue.
    target_pc: isize,
    /// Which kind of branch word to regenerate during patching.
    kind: PatchKind,
    /// rs1 / rs2 used by the branch (needed to re-encode the B-type word).
    rs1: u32,
    rs2: u32,
}

#[derive(Debug)]
enum PatchKind {
    /// B-type branch: beq / bne / blt / bge / bltu / bgeu
    Branch { funct3: u32 },
    /// JAL rd=ZERO (unconditional jump)
    Jal,
}

// ---------------------------------------------------------------------------
// Prologue / Epilogue
// ---------------------------------------------------------------------------

/// Emit the function prologue.
///
/// Stack layout (grows downward, 4-byte aligned words, 64 bytes total):
///   sp+60  ra
///   sp+56  s0   (fp / R10 lo)
///   sp+52  s1   (helper-table ptr)
///   sp+48  s2   (R4 lo)    sp+44  s3  (R4 hi)
///   sp+40  s4   (R5 lo)    sp+36  s5  (R5 hi)
///   sp+32  s6   (R6 lo)    sp+28  s7  (R6 hi)
///   sp+24  s8   (R7 lo)    sp+20  s9  (R7 hi)
///   sp+16  s10  (R8 lo)    sp+12  s11 (R8 hi)
///   sp+ 8  t3   (R9 lo)    sp+ 4  t4  (R9 hi)
///   sp+ 0  (bottom of saved area; 512 bytes eBPF stack below)
///
/// Entry:
///   a0 (R1 lo) = first eBPF argument (e.g. XDP ctx ptr)
///   a1 (R1 hi) = must be 0 for 32-bit ptrs; or high word of 64-bit arg
///   a2 (R2 lo / helper table) = caller passes helper table ptr here
///
/// NOTE: Because we use a0/a1 for R1 lo/hi, the helper table pointer
/// is now passed in a2 and saved into s1.
fn emit_prologue(out: &mut Vec<u32>) {
    out.push(rv_addi(SP, SP, -64));   // allocate 64 bytes for callee-saved
    out.push(rv_sw(SP, RA,  60));
    out.push(rv_sw(SP, S0,  56));
    out.push(rv_sw(SP, S1,  52));
    out.push(rv_sw(SP, S2,  48));
    out.push(rv_sw(SP, S3,  44));
    out.push(rv_sw(SP, S4,  40));
    out.push(rv_sw(SP, S5,  36));
    out.push(rv_sw(SP, S6,  32));
    out.push(rv_sw(SP, S7,  28));
    out.push(rv_sw(SP, S8,  24));
    out.push(rv_sw(SP, S9,  20));
    out.push(rv_sw(SP, S10, 16));
    out.push(rv_sw(SP, S11, 12));
    out.push(rv_sw(SP, T3,   8));
    out.push(rv_sw(SP, T4,   4));
    // Set frame pointer (eBPF R10 lo) to top of this saved area
    out.push(rv_addi(S0, SP, 64));
    // eBPF R10 hi is always 0 (read-only fp, 32-bit address)
    // Save helper table pointer (passed in a2) into s1
    out.push(rv_mv(S1, A2));
    // Allocate 512-byte eBPF stack below saved area
    out.push(rv_addi(SP, SP, -(STACK_SIZE as i32)));
}

/// Emit the function epilogue. Restores callee-saved registers and returns.
fn emit_epilogue(out: &mut Vec<u32>) {
    out.push(rv_addi(SP, SP, STACK_SIZE as i32));  // release eBPF stack
    // Move eBPF R0 lo (a4) into C return register a0
    out.push(rv_mv(A0, A4));
    // (high word a5 is ignored by 32-bit callers; 64-bit callers read a1=a5+1 -- but
    //  on RV32 there is no standard 64-bit return; we leave a5 in place for inspection)
    out.push(rv_lw(RA,  SP, 60));
    out.push(rv_lw(S0,  SP, 56));
    out.push(rv_lw(S1,  SP, 52));
    out.push(rv_lw(S2,  SP, 48));
    out.push(rv_lw(S3,  SP, 44));
    out.push(rv_lw(S4,  SP, 40));
    out.push(rv_lw(S5,  SP, 36));
    out.push(rv_lw(S6,  SP, 32));
    out.push(rv_lw(S7,  SP, 28));
    out.push(rv_lw(S8,  SP, 24));
    out.push(rv_lw(S9,  SP, 20));
    out.push(rv_lw(S10, SP, 16));
    out.push(rv_lw(S11, SP, 12));
    out.push(rv_lw(T3,  SP,  8));
    out.push(rv_lw(T4,  SP,  4));
    out.push(rv_addi(SP, SP, 64));
    out.push(rv_ret());
}
// ---------------------------------------------------------------------------
// JIT compiler core
// ---------------------------------------------------------------------------

/// The main compiler state.
pub struct Rv32JitCompiler {
    /// RV32 instruction words emitted so far.
    pub out: Vec<u32>,
    /// Map from eBPF instruction index -> word index in `out`.
    pc_locs: Vec<usize>,
    /// Special target locations (e.g. epilogue).
    special_targets: HashMap<isize, usize>,
    /// Branch / jump sites that need back-patching.
    patches: Vec<PatchSite>,
}

impl Rv32JitCompiler {
    pub fn new() -> Self {
        Rv32JitCompiler {
            out: Vec::new(),
            pc_locs: Vec::new(),
            special_targets: HashMap::new(),
            patches: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Current word index (= next instruction position).
    #[inline]
    fn here(&self) -> usize { self.out.len() }

    /// Emit a single RV32 word.
    #[inline]
    fn emit(&mut self, word: u32) { self.out.push(word); }

    /// Emit `lui + addi` to load a 32-bit immediate into `rd`.
    fn emit_li(&mut self, rd: u32, imm: i32) {
        rv_li32(&mut self.out, rd, imm);
    }

    /// Emit a branch that needs to be back-patched.
    /// Emits a placeholder NOP-shaped word and records the patch site.
    fn emit_branch(&mut self, funct3: u32, rs1: u32, rs2: u32, target_pc: isize) {
        let word_idx = self.here();
        self.out.push(0u32); // placeholder
        self.patches.push(PatchSite {
            word_idx,
            target_pc,
            kind: PatchKind::Branch { funct3 },
            rs1,
            rs2,
        });
    }

    /// Emit an unconditional JAL that needs to be back-patched.
    fn emit_jal(&mut self, target_pc: isize) {
        let word_idx = self.here();
        self.out.push(0u32); // placeholder
        self.patches.push(PatchSite {
            word_idx,
            target_pc,
            kind: PatchKind::Jal,
            rs1: 0,
            rs2: 0,
        });
    }

    /// Record the current position as the RV32 translation of eBPF pc `target`.
    fn set_anchor(&mut self, target: isize) {
        self.special_targets.insert(target, self.here());
    }

    // -----------------------------------------------------------------------
    // Division / modulo helper
    // Handles div-by-zero semantics per eBPF spec:
    //   div-by-zero -> result = 0
    //   mod-by-zero -> result = dividend (unchanged)
    // -----------------------------------------------------------------------
    fn emit_divmod(&mut self, is_div: bool, is_mod: bool, is_signed: bool,
                   dst: u32, src_reg: Option<u32>, imm: i32) {
        match src_reg {
            Some(src) if is_div => {
                // If src == 0, skip div and zero dst
                // beq src, zero, +3 instructions forward
                let skip_idx = self.here();
                self.out.push(0); // placeholder beq
                // Normal: dst = dst / src (signed or unsigned)
                if is_signed {
                    self.emit(rv_div(dst, dst, src));
                } else {
                    self.emit(rv_divu(dst, dst, src));
                }
                // Jump past the zero-result path
                let jal_idx = self.here();
                self.out.push(0); // placeholder jal
                // Zero-result path: dst = 0
                let zero_path = self.here();
                self.emit(rv_mv(dst, ZERO));
                let after = self.here();
                // Patch beq: branch to zero_path if src == 0
                let beq_off = ((zero_path as i32) - (skip_idx as i32)) * 4;
                self.out[skip_idx] = enc_b(beq_off, ZERO, src, 0b000, 0x63);
                // Patch jal: skip the zero path
                let jal_off = ((after as i32) - (jal_idx as i32)) * 4;
                self.out[jal_idx] = enc_j(jal_off, ZERO, 0x6F);
            }
            Some(src) if is_mod => {
                // If src == 0, keep dst unchanged (skip rem)
                let skip_idx = self.here();
                self.out.push(0); // placeholder beq
                if is_signed {
                    self.emit(rv_rem(dst, dst, src));
                } else {
                    self.emit(rv_remu(dst, dst, src));
                }
                let after = self.here();
                let beq_off = ((after as i32) - (skip_idx as i32)) * 4;
                self.out[skip_idx] = enc_b(beq_off, ZERO, src, 0b000, 0x63);
            }
            None if is_div => {
                if imm == 0 {
                    self.emit(rv_mv(dst, ZERO));
                } else {
                    self.emit_li(T0, imm);
                    if is_signed {
                        self.emit(rv_div(dst, dst, T0));
                    } else {
                        self.emit(rv_divu(dst, dst, T0));
                    }
                }
            }
            None if is_mod => {
                if imm != 0 {
                    self.emit_li(T0, imm);
                    if is_signed {
                        self.emit(rv_rem(dst, dst, T0));
                    } else {
                        self.emit(rv_remu(dst, dst, T0));
                    }
                }
                // mod-by-zero: leave dst unchanged
            }
            _ => {}
        }
    }
    // -----------------------------------------------------------------------
    // 64-bit ALU helpers (register-pair arithmetic on RV32)
    // Each eBPF 64-bit register = (lo=map_reg_lo(r), hi=map_reg_hi(r)).
    // T5(x30)/T6(x31) are extra scratch for 64-bit ops.
    // -----------------------------------------------------------------------

    fn emit_add64_reg(&mut self, dst: u8, src: u8) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let (sl, sh) = (map_reg_lo(src), map_reg_hi(src));
        self.emit(rv_add(dl, dl, sl));
        self.emit(rv_sltu(T0, dl, sl));   // carry
        self.emit(rv_add(dh, dh, sh));
        self.emit(rv_add(dh, dh, T0));
    }

    fn emit_add64_imm(&mut self, dst: u8, imm: i32) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        self.emit_li(T0, imm);
        self.emit(rv_add(dl, dl, T0));
        self.emit(rv_sltu(T1, dl, T0));   // carry
        self.emit(rv_srai(T0, T0, 31));   // sign-extend imm into hi
        self.emit(rv_add(dh, dh, T0));
        self.emit(rv_add(dh, dh, T1));
    }

    fn emit_sub64_reg(&mut self, dst: u8, src: u8) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let (sl, sh) = (map_reg_lo(src), map_reg_hi(src));
        self.emit(rv_sltu(T0, dl, sl));   // borrow
        self.emit(rv_sub(dl, dl, sl));
        self.emit(rv_sub(dh, dh, sh));
        self.emit(rv_sub(dh, dh, T0));
    }

    fn emit_sub64_imm(&mut self, dst: u8, imm: i32) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        self.emit_li(T0, imm);
        self.emit(rv_sltu(T1, dl, T0));   // borrow
        self.emit(rv_sub(dl, dl, T0));
        self.emit(rv_srai(T0, T0, 31));   // sign-extend
        self.emit(rv_sub(dh, dh, T0));
        self.emit(rv_sub(dh, dh, T1));
    }

    fn emit_mul64_reg(&mut self, dst: u8, src: u8) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let (sl, sh) = (map_reg_lo(src), map_reg_hi(src));
        self.emit(rv_mulhu(T0, dl, sl));  // hi(dl*sl)
        self.emit(rv_mul(T1, dl, sh));    // lo(dl*sh)
        self.emit(rv_add(T0, T0, T1));
        self.emit(rv_mul(T1, dh, sl));    // lo(dh*sl)
        self.emit(rv_add(dh, T0, T1));
        self.emit(rv_mul(dl, dl, sl));
    }

    fn emit_mul64_imm(&mut self, dst: u8, imm: i32) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        self.emit_li(T5, imm);
        self.emit(rv_mulhu(T0, dl, T5));
        self.emit(rv_mul(T1, dh, T5));
        self.emit(rv_add(T0, T0, T1));
        if imm < 0 { self.emit(rv_add(T0, T0, dl)); } // imm_hi = 0xFFFF...
        self.emit(rv_mul(dl, dl, T5));
        self.emit(rv_mv(dh, T0));
    }
    fn emit_or64_reg(&mut self, dst: u8, src: u8) {
        self.emit(rv_or(map_reg_lo(dst), map_reg_lo(dst), map_reg_lo(src)));
        self.emit(rv_or(map_reg_hi(dst), map_reg_hi(dst), map_reg_hi(src)));
    }
    fn emit_or64_imm(&mut self, dst: u8, imm: i32) {
        self.emit_li(T0, imm);
        self.emit(rv_or(map_reg_lo(dst), map_reg_lo(dst), T0));
        if imm < 0 { self.emit(rv_ori(map_reg_hi(dst), map_reg_hi(dst), -1)); }
    }
    fn emit_and64_reg(&mut self, dst: u8, src: u8) {
        self.emit(rv_and(map_reg_lo(dst), map_reg_lo(dst), map_reg_lo(src)));
        self.emit(rv_and(map_reg_hi(dst), map_reg_hi(dst), map_reg_hi(src)));
    }
    fn emit_and64_imm(&mut self, dst: u8, imm: i32) {
        self.emit_li(T0, imm);
        self.emit(rv_and(map_reg_lo(dst), map_reg_lo(dst), T0));
        // sign-extended imm: if imm >= 0, hi becomes 0; if imm < 0, hi unchanged
        if imm >= 0 { self.emit(rv_mv(map_reg_hi(dst), ZERO)); }
    }
    fn emit_xor64_reg(&mut self, dst: u8, src: u8) {
        self.emit(rv_xor(map_reg_lo(dst), map_reg_lo(dst), map_reg_lo(src)));
        self.emit(rv_xor(map_reg_hi(dst), map_reg_hi(dst), map_reg_hi(src)));
    }
    fn emit_xor64_imm(&mut self, dst: u8, imm: i32) {
        self.emit_li(T0, imm);
        self.emit(rv_xor(map_reg_lo(dst), map_reg_lo(dst), T0));
        if imm < 0 { self.emit(rv_xori(map_reg_hi(dst), map_reg_hi(dst), -1)); }
    }
    fn emit_neg64(&mut self, dst: u8) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        // -x64 = ~lo+1, ~hi+carry
        self.emit(rv_xori(dh, dh, -1));
        self.emit(rv_xori(dl, dl, -1));
        self.emit(rv_addi(dl, dl, 1));
        // carry: if dl == 0 after +1
        self.emit(rv_sltu(T0, dl, T0));  // T0=1 if dl wrapped (dl < 1)
        // simpler: beq dl, zero -> T0=1
        // use sltiu: T0 = (dl < 1) = (dl == 0)
        self.emit(rv_sltiu(T0, dl, 1));
        self.emit(rv_add(dh, dh, T0));
    }
    fn emit_mov64_reg(&mut self, dst: u8, src: u8) {
        self.emit(rv_mv(map_reg_lo(dst), map_reg_lo(src)));
        self.emit(rv_mv(map_reg_hi(dst), map_reg_hi(src)));
    }
    fn emit_mov64_imm(&mut self, dst: u8, imm: i32) {
        let hi = if imm < 0 { -1i32 } else { 0i32 };
        rv_li32(&mut self.out, map_reg_lo(dst), imm);
        rv_li32(&mut self.out, map_reg_hi(dst), hi);
    }
    fn emit_lsh64_imm(&mut self, dst: u8, shamt: u32) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let s = shamt & 63;
        if s == 0 { return; }
        if s < 32 {
            self.emit(rv_slli(dh, dh, s));
            self.emit(rv_srli(T0, dl, 32 - s));
            self.emit(rv_or(dh, dh, T0));
            self.emit(rv_slli(dl, dl, s));
        } else {
            self.emit(rv_slli(dh, dl, s - 32));
            self.emit(rv_mv(dl, ZERO));
        }
    }
    fn emit_lsh64_reg(&mut self, dst: u8, src: u8) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let sl = map_reg_lo(src);
        // mask = sign(s-32): 0xFFFFFFFF if s<32, 0 if s>=32
        self.emit(rv_addi(T0, sl, -32));          // T0 = s-32
        self.emit(rv_srai(T5, T0, 31));           // mask: 0xFFF if s<32
        // lo_case: hi=(dh<<s)|(dl>>(32-s)), lo=dl<<s
        self.emit(rv_sll(T1, dh, sl));
        self.emit(rv_addi(T2, ZERO, 32));
        self.emit(rv_sub(T2, T2, sl));            // T2=32-s
        self.emit(rv_srl(T6, dl, T2));
        self.emit(rv_or(T1, T1, T6));             // T1 = hi_lo_case
        // hi_case: hi=dl<<(s-32)
        self.emit(rv_sll(T2, dl, T0));            // T2 = dl<<(s-32)
        // select
        self.emit(rv_and(T1, T1, T5));
        self.emit(rv_xori(T6, T5, -1));
        self.emit(rv_and(T2, T2, T6));
        self.emit(rv_or(dh, T1, T2));
        // lo: dl<<s if s<32, else 0
        self.emit(rv_sll(T1, dl, sl));
        self.emit(rv_and(dl, T1, T5));
    }
    fn emit_rsh64_imm(&mut self, dst: u8, shamt: u32) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let s = shamt & 63;
        if s == 0 { return; }
        if s < 32 {
            self.emit(rv_srli(dl, dl, s));
            self.emit(rv_slli(T0, dh, 32 - s));
            self.emit(rv_or(dl, dl, T0));
            self.emit(rv_srli(dh, dh, s));
        } else {
            self.emit(rv_srli(dl, dh, s - 32));
            self.emit(rv_mv(dh, ZERO));
        }
    }
    fn emit_rsh64_reg(&mut self, dst: u8, src: u8) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let sl = map_reg_lo(src);
        self.emit(rv_addi(T0, sl, -32));
        self.emit(rv_srai(T5, T0, 31));           // mask
        self.emit(rv_srl(T1, dh, T0));            // dh>>(s-32)
        self.emit(rv_srl(T2, dl, sl));            // dl>>s
        self.emit(rv_addi(T6, ZERO, 32));
        self.emit(rv_sub(T6, T6, sl));            // 32-s
        self.emit(rv_sll(T0, dh, T6));
        self.emit(rv_or(T2, T2, T0));             // lo_lo_case
        self.emit(rv_and(T2, T2, T5));
        self.emit(rv_xori(T6, T5, -1));
        self.emit(rv_and(T1, T1, T6));
        self.emit(rv_or(dl, T1, T2));
        self.emit(rv_srl(T1, dh, sl));
        self.emit(rv_and(dh, T1, T5));
    }
    fn emit_arsh64_imm(&mut self, dst: u8, shamt: u32) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let s = shamt & 63;
        if s == 0 { return; }
        if s < 32 {
            self.emit(rv_srli(dl, dl, s));
            self.emit(rv_slli(T0, dh, 32 - s));
            self.emit(rv_or(dl, dl, T0));
            self.emit(rv_srai(dh, dh, s));
        } else {
            self.emit(rv_srai(dl, dh, s - 32));
            self.emit(rv_srai(dh, dh, 31));       // fill with sign bit
        }
    }
    fn emit_arsh64_reg(&mut self, dst: u8, src: u8) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let sl = map_reg_lo(src);
        self.emit(rv_addi(T0, sl, -32));
        self.emit(rv_srai(T5, T0, 31));           // mask
        self.emit(rv_sra(T1, dh, T0));            // arithmetic dh>>(s-32)
        self.emit(rv_srl(T2, dl, sl));
        self.emit(rv_addi(T6, ZERO, 32));
        self.emit(rv_sub(T6, T6, sl));
        self.emit(rv_sll(T0, dh, T6));
        self.emit(rv_or(T2, T2, T0));
        self.emit(rv_and(T2, T2, T5));
        self.emit(rv_xori(T6, T5, -1));
        self.emit(rv_and(T1, T1, T6));
        self.emit(rv_or(dl, T1, T2));
        self.emit(rv_sra(T1, dh, sl));
        self.emit(rv_and(dh, T1, T5));
        // if s>=32, fill dh with sign
        self.emit(rv_xori(T5, T5, -1));           // inverted mask (1 if s>=32)
        self.emit(rv_srai(T6, dh, 31));           // sign bits
        self.emit(rv_and(T6, T6, T5));
        self.emit(rv_xori(T5, T5, -1));
        self.emit(rv_and(dh, dh, T5));
        self.emit(rv_or(dh, dh, T6));
    }
    fn emit_div64_reg(&mut self, dst: u8, src: u8) {
        // 64-bit unsigned divide: only practical for values that fit in 32 bits.
        // Full 64-bit division requires a software routine; for now use divu on lo
        // and handle div-by-zero per eBPF spec.
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let sl = map_reg_lo(src);
        let skip_idx = self.here(); self.out.push(0);
        self.emit(rv_divu(dl, dl, sl));
        self.emit(rv_mv(dh, ZERO));
        let jal_idx = self.here(); self.out.push(0);
        let zero_path = self.here();
        self.emit(rv_mv(dl, ZERO)); self.emit(rv_mv(dh, ZERO));
        let after = self.here();
        self.out[skip_idx] = enc_b(((zero_path as i32)-(skip_idx as i32))*4, ZERO, sl, 0b000, 0x63);
        self.out[jal_idx]  = enc_j(((after as i32)-(jal_idx as i32))*4, ZERO, 0x6F);
    }
    fn emit_div64_imm(&mut self, dst: u8, imm: i32) {
        let (dl, dh) = (map_reg_lo(dst), map_reg_hi(dst));
        if imm == 0 { self.emit(rv_mv(dl, ZERO)); self.emit(rv_mv(dh, ZERO)); return; }
        self.emit_li(T0, imm);
        self.emit(rv_divu(dl, dl, T0));
        self.emit(rv_mv(dh, ZERO));
    }
    fn emit_mod64_reg(&mut self, dst: u8, src: u8) {
        let (dl, _dh) = (map_reg_lo(dst), map_reg_hi(dst));
        let sl = map_reg_lo(src);
        let skip_idx = self.here(); self.out.push(0);
        self.emit(rv_remu(dl, dl, sl));
        let after = self.here();
        self.out[skip_idx] = enc_b(((after as i32)-(skip_idx as i32))*4, ZERO, sl, 0b000, 0x63);
    }
    fn emit_mod64_imm(&mut self, dst: u8, imm: i32) {
        if imm == 0 { return; }
        let dl = map_reg_lo(dst);
        self.emit_li(T0, imm);
        self.emit(rv_remu(dl, dl, T0));
    }

    pub fn compile(
        &mut self,
        prog: &[u8],
        _helpers: &HashMap<u32, usize>,  // used at runtime via S1; table built by caller
    ) -> Result<(), String> {
        assert_eq!(prog.len() % INSN_SIZE, 0);
        let num_insns = prog.len() / INSN_SIZE;

        emit_prologue(&mut self.out);
        self.pc_locs = vec![0usize; num_insns + 1];

        let mut pc = 0usize;
        while pc < num_insns {
            let insn = get_insn(prog, pc);
            self.pc_locs[pc] = self.here();
            let dst = map_reg(insn.dst);
            let src = map_reg(insn.src);
            let target_pc = pc as isize + insn.off as isize + 1;

            match insn.opc {
                // --- BPF_LD ---
                LD_DW_IMM => {
                    // 16-byte instruction: imm = lo32, next insn's imm = hi32
                    pc += 1;
                    let lo = insn.imm as u32;
                    let hi = get_insn(prog, pc).imm as u32;
                    rv_li32(&mut self.out, map_reg_lo(insn.dst), lo as i32);
                    rv_li32(&mut self.out, map_reg_hi(insn.dst), hi as i32);
                }
                LD_ABS_B  => { self.emit(rv_lbu(A5, S0, insn.imm)); }
                LD_ABS_H  => { self.emit(rv_lhu(A5, S0, insn.imm)); }
                LD_ABS_W  => { self.emit(rv_lw(A5,  S0, insn.imm)); }
                LD_ABS_DW => { self.emit(rv_lw(A5,  S0, insn.imm)); }
                LD_IND_B  => { self.emit(rv_add(T0, src, S0)); self.emit(rv_lbu(A5, T0, insn.imm)); }
                LD_IND_H  => { self.emit(rv_add(T0, src, S0)); self.emit(rv_lhu(A5, T0, insn.imm)); }
                LD_IND_W  => { self.emit(rv_add(T0, src, S0)); self.emit(rv_lw(A5,  T0, insn.imm)); }
                LD_IND_DW => { self.emit(rv_add(T0, src, S0)); self.emit(rv_lw(A5,  T0, insn.imm)); }

                // --- BPF_LDX ---
                LD_B_REG  => { self.emit(rv_lbu(dst, src, insn.off as i32)); }
                LD_H_REG  => { self.emit(rv_lhu(dst, src, insn.off as i32)); }
                LD_W_REG  => { self.emit(rv_lw(dst,  src, insn.off as i32)); }
                LD_DW_REG => {
                    // Load 64 bits: lo word then hi word at off+4
                    self.emit(rv_lw(map_reg_lo(insn.dst), src, insn.off as i32));
                    self.emit(rv_lw(map_reg_hi(insn.dst), src, insn.off as i32 + 4));
                }

                // --- BPF_ST ---
                ST_B_IMM  => { self.emit_li(T0, insn.imm); self.emit(rv_sb(dst, T0, insn.off as i32)); }
                ST_H_IMM  => { self.emit_li(T0, insn.imm); self.emit(rv_sh(dst, T0, insn.off as i32)); }
                ST_W_IMM  => { self.emit_li(T0, insn.imm); self.emit(rv_sw(dst, T0, insn.off as i32)); }
                ST_DW_IMM => { self.emit_li(T0, insn.imm); self.emit(rv_sw(dst, T0, insn.off as i32)); }

                // --- BPF_STX ---
                ST_B_REG  => { self.emit(rv_sb(dst, src, insn.off as i32)); }
                ST_H_REG  => { self.emit(rv_sh(dst, src, insn.off as i32)); }
                ST_W_REG  => { self.emit(rv_sw(dst, src, insn.off as i32)); }
                ST_DW_REG => { self.emit(rv_sw(dst, src, insn.off as i32)); }
                // --- BPF_ALU32 ---
                ADD32_IMM  => { self.emit_li(T0, insn.imm); self.emit(rv_add(dst, dst, T0)); }
                ADD32_REG  => { self.emit(rv_add(dst, dst, src)); }
                SUB32_IMM  => { self.emit_li(T0, insn.imm); self.emit(rv_sub(dst, dst, T0)); }
                SUB32_REG  => { self.emit(rv_sub(dst, dst, src)); }
                MUL32_IMM  => { self.emit_li(T0, insn.imm); self.emit(rv_mul(dst, dst, T0)); }
                MUL32_REG  => { self.emit(rv_mul(dst, dst, src)); }
                DIV32_IMM  => { self.emit_divmod(true,  false, false, dst, None,      insn.imm); }
                DIV32_REG  => { self.emit_divmod(true,  false, false, dst, Some(src), 0); }
                MOD32_IMM  => { self.emit_divmod(false, true,  false, dst, None,      insn.imm); }
                MOD32_REG  => { self.emit_divmod(false, true,  false, dst, Some(src), 0); }
                OR32_IMM   => { self.emit_li(T0, insn.imm); self.emit(rv_or(dst, dst, T0)); }
                OR32_REG   => { self.emit(rv_or(dst, dst, src)); }
                AND32_IMM  => { self.emit(rv_andi(dst, dst, insn.imm)); }
                AND32_REG  => { self.emit(rv_and(dst, dst, src)); }
                XOR32_IMM  => { self.emit_li(T0, insn.imm); self.emit(rv_xor(dst, dst, T0)); }
                XOR32_REG  => { self.emit(rv_xor(dst, dst, src)); }
                LSH32_IMM  => { self.emit(rv_slli(dst, dst, insn.imm as u32 & 0x1F)); }
                LSH32_REG  => { self.emit(rv_sll(dst, dst, src)); }
                RSH32_IMM  => { self.emit(rv_srli(dst, dst, insn.imm as u32 & 0x1F)); }
                RSH32_REG  => { self.emit(rv_srl(dst, dst, src)); }
                ARSH32_IMM => { self.emit(rv_srai(dst, dst, insn.imm as u32 & 0x1F)); }
                ARSH32_REG => { self.emit(rv_sra(dst, dst, src)); }
                NEG32      => { self.emit(rv_sub(dst, ZERO, dst)); }
                MOV32_IMM  => { self.emit_li(dst, insn.imm); }
                MOV32_REG  => { self.emit(rv_mv(dst, src)); }
                LE         => { /* no-op: target is little-endian */ }
                BE         => {
                    match insn.imm {
                        16 => {
                            self.emit(rv_andi(T0, dst, 0xFF));
                            self.emit(rv_slli(T0, T0, 8));
                            self.emit(rv_srli(T1, dst, 8));
                            self.emit(rv_andi(T1, T1, 0xFF));
                            self.emit(rv_or(dst, T0, T1));
                        }
                        32 | 64 => {
                            // bswap32 via shifts and masks
                            self.emit(rv_srli(T0, dst, 24));          // byte3 -> pos0
                            self.emit(rv_andi(T1, dst, 0xFF));
                            self.emit(rv_slli(T1, T1, 24));           // byte0 -> pos3
                            self.emit(rv_or(T0, T0, T1));
                            self.emit(rv_srli(T1, dst, 8));
                            self.emit(rv_andi(T1, T1, 0xFF00));       // byte2 in place
                            self.emit(rv_slli(T2, dst, 8));
                            self.emit(rv_andi(T2, T2, 0x00FF_0000u32 as i32)); // byte1
                            self.emit(rv_or(T1, T1, T2));
                            self.emit(rv_or(dst, T0, T1));
                        }
                        _ => return Err(format!("BE: invalid width {}", insn.imm)),
                    }
                }

                // --- BPF_ALU64 (full 64-bit via register pairs) ---
                ADD64_IMM  => { self.emit_add64_imm(insn.dst, insn.imm); }
                ADD64_REG  => { self.emit_add64_reg(insn.dst, insn.src); }
                SUB64_IMM  => { self.emit_sub64_imm(insn.dst, insn.imm); }
                SUB64_REG  => { self.emit_sub64_reg(insn.dst, insn.src); }
                MUL64_IMM  => { self.emit_mul64_imm(insn.dst, insn.imm); }
                MUL64_REG  => { self.emit_mul64_reg(insn.dst, insn.src); }
                DIV64_IMM  => { self.emit_div64_imm(insn.dst, insn.imm); }
                DIV64_REG  => { self.emit_div64_reg(insn.dst, insn.src); }
                MOD64_IMM  => { self.emit_mod64_imm(insn.dst, insn.imm); }
                MOD64_REG  => { self.emit_mod64_reg(insn.dst, insn.src); }
                OR64_IMM   => { self.emit_or64_imm(insn.dst, insn.imm); }
                OR64_REG   => { self.emit_or64_reg(insn.dst, insn.src); }
                AND64_IMM  => { self.emit_and64_imm(insn.dst, insn.imm); }
                AND64_REG  => { self.emit_and64_reg(insn.dst, insn.src); }
                XOR64_IMM  => { self.emit_xor64_imm(insn.dst, insn.imm); }
                XOR64_REG  => { self.emit_xor64_reg(insn.dst, insn.src); }
                LSH64_IMM  => { self.emit_lsh64_imm(insn.dst, insn.imm as u32); }
                LSH64_REG  => { self.emit_lsh64_reg(insn.dst, insn.src); }
                RSH64_IMM  => { self.emit_rsh64_imm(insn.dst, insn.imm as u32); }
                RSH64_REG  => { self.emit_rsh64_reg(insn.dst, insn.src); }
                ARSH64_IMM => { self.emit_arsh64_imm(insn.dst, insn.imm as u32); }
                ARSH64_REG => { self.emit_arsh64_reg(insn.dst, insn.src); }
                NEG64      => { self.emit_neg64(insn.dst); }
                MOV64_IMM  => { self.emit_mov64_imm(insn.dst, insn.imm); }
                MOV64_REG  => { self.emit_mov64_reg(insn.dst, insn.src); }

                // --- BPF_JMP ---
                JA       => { self.emit_jal(target_pc); }
                JEQ_IMM  => { self.emit_li(T0, insn.imm); self.emit_branch(0b000, dst, T0,  target_pc); }
                JEQ_REG  => { self.emit_branch(0b000, dst, src, target_pc); }
                JNE_IMM  => { self.emit_li(T0, insn.imm); self.emit_branch(0b001, dst, T0,  target_pc); }
                JNE_REG  => { self.emit_branch(0b001, dst, src, target_pc); }
                // unsigned: dst > imm  ≡  imm < dst
                JGT_IMM  => { self.emit_li(T0, insn.imm); self.emit_branch(0b110, T0,  dst, target_pc); }
                JGT_REG  => { self.emit_branch(0b110, src, dst, target_pc); }
                JGE_IMM  => { self.emit_li(T0, insn.imm); self.emit_branch(0b111, dst, T0,  target_pc); }
                JGE_REG  => { self.emit_branch(0b111, dst, src, target_pc); }
                JLT_IMM  => { self.emit_li(T0, insn.imm); self.emit_branch(0b110, dst, T0,  target_pc); }
                JLT_REG  => { self.emit_branch(0b110, dst, src, target_pc); }
                JLE_IMM  => { self.emit_li(T0, insn.imm); self.emit_branch(0b111, T0,  dst, target_pc); }
                JLE_REG  => { self.emit_branch(0b111, src, dst, target_pc); }
                JSGT_IMM => { self.emit_li(T0, insn.imm); self.emit_branch(0b100, T0,  dst, target_pc); }
                JSGT_REG => { self.emit_branch(0b100, src, dst, target_pc); }
                JSGE_IMM => { self.emit_li(T0, insn.imm); self.emit_branch(0b101, dst, T0,  target_pc); }
                JSGE_REG => { self.emit_branch(0b101, dst, src, target_pc); }
                JSLT_IMM => { self.emit_li(T0, insn.imm); self.emit_branch(0b100, dst, T0,  target_pc); }
                JSLT_REG => { self.emit_branch(0b100, dst, src, target_pc); }
                JSLE_IMM => { self.emit_li(T0, insn.imm); self.emit_branch(0b101, T0,  dst, target_pc); }
                JSLE_REG => { self.emit_branch(0b101, src, dst, target_pc); }
                JSET_IMM => { self.emit_li(T0, insn.imm); self.emit(rv_and(T1, dst, T0)); self.emit_branch(0b001, T1, ZERO, target_pc); }
                JSET_REG => { self.emit(rv_and(T1, dst, src)); self.emit_branch(0b001, T1, ZERO, target_pc); }

                // --- BPF_JMP32 (same encoding, 32-bit operands) ---
                JEQ_IMM32  => { self.emit_li(T0, insn.imm); self.emit_branch(0b000, dst, T0,  target_pc); }
                JEQ_REG32  => { self.emit_branch(0b000, dst, src, target_pc); }
                JNE_IMM32  => { self.emit_li(T0, insn.imm); self.emit_branch(0b001, dst, T0,  target_pc); }
                JNE_REG32  => { self.emit_branch(0b001, dst, src, target_pc); }
                JGT_IMM32  => { self.emit_li(T0, insn.imm); self.emit_branch(0b110, T0,  dst, target_pc); }
                JGT_REG32  => { self.emit_branch(0b110, src, dst, target_pc); }
                JGE_IMM32  => { self.emit_li(T0, insn.imm); self.emit_branch(0b111, dst, T0,  target_pc); }
                JGE_REG32  => { self.emit_branch(0b111, dst, src, target_pc); }
                JLT_IMM32  => { self.emit_li(T0, insn.imm); self.emit_branch(0b110, dst, T0,  target_pc); }
                JLT_REG32  => { self.emit_branch(0b110, dst, src, target_pc); }
                JLE_IMM32  => { self.emit_li(T0, insn.imm); self.emit_branch(0b111, T0,  dst, target_pc); }
                JLE_REG32  => { self.emit_branch(0b111, src, dst, target_pc); }
                JSGT_IMM32 => { self.emit_li(T0, insn.imm); self.emit_branch(0b100, T0,  dst, target_pc); }
                JSGT_REG32 => { self.emit_branch(0b100, src, dst, target_pc); }
                JSGE_IMM32 => { self.emit_li(T0, insn.imm); self.emit_branch(0b101, dst, T0,  target_pc); }
                JSGE_REG32 => { self.emit_branch(0b101, dst, src, target_pc); }
                JSLT_IMM32 => { self.emit_li(T0, insn.imm); self.emit_branch(0b100, dst, T0,  target_pc); }
                JSLT_REG32 => { self.emit_branch(0b100, dst, src, target_pc); }
                JSLE_IMM32 => { self.emit_li(T0, insn.imm); self.emit_branch(0b101, T0,  dst, target_pc); }
                JSLE_REG32 => { self.emit_branch(0b101, src, dst, target_pc); }
                JSET_IMM32 => { self.emit_li(T0, insn.imm); self.emit(rv_and(T1, dst, T0)); self.emit_branch(0b001, T1, ZERO, target_pc); }
                JSET_REG32 => { self.emit(rv_and(T1, dst, src)); self.emit_branch(0b001, T1, ZERO, target_pc); }

                // --- CALL ---
                CALL => {
                    match insn.src {
                        0 => {
                            // External helper call
                            // Load fn ptr from helper table: lw t0, (imm*4)(s1)
                            let offset = insn.imm.wrapping_mul(4);
                            self.emit(rv_lw(T0, S1, offset));
                            // jalr ra, t0, 0
                            self.emit(rv_jalr(RA, T0, 0));
                            // Move return value (a0) into eBPF R0 (a5)
                            self.emit(rv_mv(A5, A0));
                        }
                        1 => {
                            // Local call (BPF-to-BPF)
                            let local_target = pc as isize + insn.imm as isize + 1;
                            // Save callee-saved eBPF regs R6-R9 around local call
                            self.emit(rv_addi(SP, SP, -16));
                            self.emit(rv_sw(SP, S2, 12));
                            self.emit(rv_sw(SP, S3,  8));
                            self.emit(rv_sw(SP, S4,  4));
                            self.emit(rv_sw(SP, S5,  0));
                            self.emit_jal(local_target);
                            self.emit(rv_lw(S2, SP, 12));
                            self.emit(rv_lw(S3, SP,  8));
                            self.emit(rv_lw(S4, SP,  4));
                            self.emit(rv_lw(S5, SP,  0));
                            self.emit(rv_addi(SP, SP, 16));
                        }
                        _ => return Err(format!("CALL: unknown src type {}", insn.src)),
                    }
                }
                TAIL_CALL => { return Err("TAIL_CALL not supported on RV32".into()); }
                EXIT => {
                    self.emit_jal(TARGET_PC_EXIT);
                }
                _ => {
                    return Err(format!("unknown eBPF opcode 0x{:02x} at pc {}", insn.opc, pc));
                }
            } // match
            pc += 1;
        } // while

        // Record epilogue location
        self.pc_locs[num_insns] = self.here();
        self.set_anchor(TARGET_PC_EXIT);
        emit_epilogue(&mut self.out);

        Ok(())
    } // fn compile
} // impl Rv32JitCompiler
// ---------------------------------------------------------------------------
// Pass 2: back-patch jump offsets
// ---------------------------------------------------------------------------

impl Rv32JitCompiler {
    /// Resolve all recorded branch/jump patch sites.
    /// Must be called after `compile()` succeeds.
    pub fn resolve_jumps(&mut self) -> Result<(), String> {
        for patch in &self.patches {
            // Find the RV32 word index of the target.
            let target_word = if let Some(&w) = self.special_targets.get(&patch.target_pc) {
                w
            } else {
                let tpc = patch.target_pc as usize;
                if tpc >= self.pc_locs.len() {
                    return Err(format!("jump target pc {} out of range", tpc));
                }
                self.pc_locs[tpc]
            };

            // Byte offset from the patched instruction to the target.
            let byte_off = (target_word as i32 - patch.word_idx as i32) * 4;

            self.out[patch.word_idx] = match &patch.kind {
                PatchKind::Branch { funct3 } => {
                    enc_b(byte_off, patch.rs2, patch.rs1, *funct3, 0x63)
                }
                PatchKind::Jal => {
                    enc_j(byte_off, ZERO, 0x6F)
                }
            };
        }
        Ok(())
    }
}
// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Compile an eBPF program to a `Vec<u32>` of RV32 machine words.
///
/// # Arguments
/// * `prog`    - raw eBPF bytecode (multiple of 8 bytes)
/// * `helpers` - map from eBPF helper ID to function pointer (as `usize`);
///               the caller is responsible for building and maintaining this
///               table; at runtime S1 must point to an array of `u32`-sized
///               slots each holding the helper function address.
///
/// # Returns
/// `Ok(Vec<u32>)` containing the RV32 machine words in program order.
/// Each word is little-endian (as stored in memory on a LE target).
pub fn bpf_to_rv32(
    prog: &[u8],
    helpers: &HashMap<u32, usize>,
) -> Result<Vec<u32>, String> {
    let mut jit = Rv32JitCompiler::new();
    jit.compile(prog, helpers)?;
    jit.resolve_jumps()?;
    Ok(jit.out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_helpers() -> HashMap<u32, usize> { HashMap::new() }

    /// Helper: build a minimal eBPF program that does `mov r0, imm; exit`
    fn mov_exit(imm: i32) -> Vec<u8> {
        let mut p = vec![
            // mov64 r0, imm  (opcode 0xb7, dst=0, src=0, off=0, imm)
            0xb7u8, 0x00, 0x00, 0x00,
        ];
        p.extend_from_slice(&imm.to_le_bytes());
        // exit
        p.extend_from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        p
    }

    #[test]
    fn test_encoders_rtype() {
        // add x1, x2, x3  should encode as 0x003100B3
        let w = rv_add(1, 2, 3);
        assert_eq!(w & 0x7F, 0x33);          // opcode
        assert_eq!((w >> 7) & 0x1F, 1);       // rd
        assert_eq!((w >> 12) & 0x7, 0b000);   // funct3 ADD
        assert_eq!((w >> 15) & 0x1F, 2);      // rs1
        assert_eq!((w >> 20) & 0x1F, 3);      // rs2
        assert_eq!((w >> 25) & 0x7F, 0);      // funct7
    }

    #[test]
    fn test_encoders_itype() {
        // addi x1, x2, -1
        let w = rv_addi(1, 2, -1);
        assert_eq!(w & 0x7F, 0x13);
        assert_eq!((w >> 7) & 0x1F, 1);
        assert_eq!((w >> 12) & 0x7, 0);
        assert_eq!((w >> 15) & 0x1F, 2);
        // imm[11:0] = 0xFFF for -1
        assert_eq!((w >> 20) & 0xFFF, 0xFFF);
    }

    #[test]
    fn test_encoders_stype() {
        // sw x2, 8(x1)   (store x2 at [x1+8])
        let w = rv_sw(1, 2, 8);
        assert_eq!(w & 0x7F, 0x23);
        assert_eq!((w >> 12) & 0x7, 0b010);
        assert_eq!((w >> 15) & 0x1F, 1);  // rs1
        assert_eq!((w >> 20) & 0x1F, 2);  // rs2
        // imm[4:0] in bits 11:7, imm[11:5] in bits 31:25
        let imm_4_0  = (w >> 7)  & 0x1F;
        let imm_11_5 = (w >> 25) & 0x7F;
        let reconstructed = (imm_11_5 << 5) | imm_4_0;
        assert_eq!(reconstructed, 8);
    }

    #[test]
    fn test_btype_roundtrip() {
        // beq x1, x2, +16  (byte offset 16)
        let w = rv_beq(1, 2, 16);
        assert_eq!(w & 0x7F, 0x63);
        // Reconstruct the immediate from the B-type encoding
        let b12   = (w >> 31) & 1;
        let b10_5 = (w >> 25) & 0x3F;
        let b4_1  = (w >>  8) & 0xF;
        let b11   = (w >>  7) & 1;
        let imm = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
        assert_eq!(imm, 16);
    }

    #[test]
    fn test_li32_small() {
        let mut out = Vec::new();
        rv_li32(&mut out, 1, 42);
        // Small imm fits in one addi
        assert_eq!(out.len(), 1);
        let w = out[0];
        assert_eq!(w & 0x7F, 0x13); // addi
        // extract the 12-bit signed immediate from bits [31:20]
        let imm12 = ((w >> 20) & 0xFFF) as i32;
        let imm_signed = (imm12 << 20) >> 20; // sign-extend from bit 11
        assert_eq!(imm_signed, 42);
    }

    #[test]
    fn test_li32_large() {
        let mut out = Vec::new();
        rv_li32(&mut out, 5, 0x1234_5678u32 as i32);
        // Large imm needs lui + addi
        assert!(out.len() <= 2);
    }

    #[test]
    fn test_compile_mov_exit() {
        let prog = mov_exit(42);
        let result = bpf_to_rv32(&prog, &empty_helpers());
        assert!(result.is_ok(), "{:?}", result);
        let words = result.unwrap();
        // Should produce some instructions (prologue + mov + jal-to-epilogue + epilogue)
        assert!(!words.is_empty());
        // All words should be valid (non-zero; prologue at least has addi sp,sp,-N)
        assert_ne!(words[0], 0);
    }

    #[test]
    fn test_compile_add_reg() {
        // add32 r0, r1   (r0 += r1)
        let prog = vec![
            ADD32_REG, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 dst=0 src=1
            EXIT,      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = bpf_to_rv32(&prog, &empty_helpers());
        assert!(result.is_ok(), "{:?}", result);
    }

    #[test]
    fn test_compile_jump_forward() {
        // ja +1 (skip one insn), then two exits
        let _prog = vec![
            JA,   0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // ja +1
            0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // invalid (should be skipped)
            EXIT, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        // The compile should succeed even if the skipped insn is "unknown",
        // because we never translate it in a real run - but our compiler
        // does translate all insns in pass 1.  Use a valid insn instead.
        let prog2 = vec![
            JA,        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            MOV32_IMM, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, 0 (skipped)
            EXIT,      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = bpf_to_rv32(&prog2, &empty_helpers());
        assert!(result.is_ok(), "{:?}", result);
    }

    #[test]
    fn test_register_map() {
        assert_eq!(map_reg(0),  A4); // return value lo (new pair mapping)
        assert_eq!(map_reg(1),  A0); // arg1
        assert_eq!(map_reg(10), S0); // frame pointer
    }
}
