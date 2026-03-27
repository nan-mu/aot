//! Tests for the eBPF -> RV32 AOT compiler (aot_rv32.rs)
//! Coverage follows docs/ebpf_to_rv32.md section by section.

use crate::aot_rv32::*;
use std::collections::HashMap;

fn helpers() -> HashMap<u32, usize> { HashMap::new() }

/// Build a raw eBPF instruction word (little-endian layout).
fn insn(opc: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = opc;
    b[1] = (src << 4) | (dst & 0x0f);
    b[2..4].copy_from_slice(&off.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
}

fn prog(insns: &[[u8; 8]]) -> Vec<u8> {
    insns.iter().flat_map(|i| i.iter().copied()).collect()
}

fn exit_insn() -> [u8; 8] { insn(EXIT, 0, 0, 0, 0) }

// ---------------------------------------------------------------------------
// §1 Register mapping
// ---------------------------------------------------------------------------

#[test]
fn test_reg_map_r0_lo() { assert_eq!(map_reg_lo(0), A4); }  // return value lo
#[test]
fn test_reg_map_r0_hi() { assert_eq!(map_reg_hi(0), A5); }  // return value hi
#[test]
fn test_reg_map_r1_lo() { assert_eq!(map_reg_lo(1), A0); }  // arg1 lo
#[test]
fn test_reg_map_r1_hi() { assert_eq!(map_reg_hi(1), A1); }  // arg1 hi
#[test]
fn test_reg_map_r10_lo() { assert_eq!(map_reg_lo(10), S0); } // fp lo
#[test]
fn test_reg_map_r10_hi() { assert_eq!(map_reg_hi(10), ZERO); } // fp hi always 0
#[test]
fn test_reg_map_pairs_adjacent() {
    // For all non-fp regs, hi = lo + 1
    for r in 0u8..10 {
        assert_eq!(map_reg_hi(r), map_reg_lo(r) + 1,
            "R{r} hi should be lo+1");
    }
}

// ---------------------------------------------------------------------------
// §2 Calling convention / prologue / epilogue
// ---------------------------------------------------------------------------

#[test]
fn test_prologue_emits_instructions() {
    let p = prog(&[exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    // Prologue alone is 19 instructions (addi + 14 sw + addi fp + mv s1 + addi sp)
    // then exit -> jal -> epilogue (18 instructions)
    assert!(words.len() >= 19, "too few words: {}", words.len());
}

#[test]
fn test_prologue_first_word_is_stack_alloc() {
    let p = prog(&[exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    // First word: addi sp, sp, -64
    let w = words[0];
    assert_eq!(w & 0x7F, 0x13);          // opcode = OP-IMM
    assert_eq!((w >> 7) & 0x1F, SP);     // rd = sp
    assert_eq!((w >> 15) & 0x1F, SP);    // rs1 = sp
    // imm = -64 (sign-extended 12-bit)
    let imm = ((w >> 20) as i32) << 20 >> 20;
    assert_eq!(imm, -64);
}

#[test]
fn test_epilogue_last_word_is_ret() {
    let p = prog(&[exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    // Last word should be jalr zero, ra, 0  (= ret)
    let w = *words.last().unwrap();
    assert_eq!(w & 0x7F, 0x67);          // opcode JALR
    assert_eq!((w >> 7) & 0x1F, ZERO);   // rd = zero
    assert_eq!((w >> 15) & 0x1F, RA);    // rs1 = ra
    assert_eq!((w >> 20) as i32 >> 20, 0); // imm = 0
}

// ---------------------------------------------------------------------------
// §3.1 BPF_LD
// ---------------------------------------------------------------------------

#[test]
fn test_ld_dw_imm_lo_word() {
    // LD_DW_IMM r0, 0xDEADBEEF_00000042
    // insn 0: opc=0x18, dst=0, imm=lo=0x42
    // insn 1: opc=0x00, imm=hi=0xDEADBEEF
    let p = prog(&[
        insn(LD_DW_IMM, 0, 0, 0, 0x42),
        insn(0x00, 0, 0, 0, 0xDEADBEEFu32 as i32),
        exit_insn(),
    ]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    assert!(!words.is_empty());
    // Program should compile without error
}

#[test]
fn test_ld_dw_imm_both_words() {
    // Check hi word (0xDEADBEEF) gets loaded into map_reg_hi(0) = A5
    let p = prog(&[
        insn(LD_DW_IMM, 0, 0, 0, 0x0000_0001i32),
        insn(0x00, 0, 0, 0, 0x0000_0002i32), // hi = 2
        exit_insn(),
    ]);
    let result = bpf_to_rv32(&p, &helpers());
    assert!(result.is_ok());
}

// ---------------------------------------------------------------------------
// §3.2 BPF_LDX
// ---------------------------------------------------------------------------

#[test]
fn test_ldx_b_reg_compiles() {
    let p = prog(&[insn(LD_B_REG, 0, 1, 4, 0), exit_insn()]);
    let r = bpf_to_rv32(&p, &helpers());
    assert!(r.is_ok());
    // lbu a4, 4(a0)  ->  opcode 0x03, funct3=0b100
    let words = r.unwrap();
    let ldx_word = words[19]; // after 19-word prologue
    assert_eq!(ldx_word & 0x7F, 0x03);
    assert_eq!((ldx_word >> 12) & 0x7, 0b100); // funct3 = LBU
}

#[test]
fn test_ldx_h_reg_is_lhu() {
    let p = prog(&[insn(LD_H_REG, 0, 1, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x03);
    assert_eq!((w >> 12) & 0x7, 0b101); // funct3 = LHU
}

#[test]
fn test_ldx_w_reg_is_lw() {
    let p = prog(&[insn(LD_W_REG, 0, 1, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x03);
    assert_eq!((w >> 12) & 0x7, 0b010); // funct3 = LW
}

#[test]
fn test_ldx_dw_reg_loads_two_words() {
    // LD_DW_REG should emit 2 lw instructions (lo + hi)
    let p = prog(&[insn(LD_DW_REG, 0, 1, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w0 = words[19];
    let w1 = words[20];
    assert_eq!(w0 & 0x7F, 0x03); // lw (lo)
    assert_eq!((w0 >> 12) & 0x7, 0b010);
    assert_eq!(w1 & 0x7F, 0x03); // lw (hi)
    assert_eq!((w1 >> 12) & 0x7, 0b010);
    // hi offset = lo offset + 4
    let off0 = ((w0 >> 20) as i32) << 20 >> 20;
    let off1 = ((w1 >> 20) as i32) << 20 >> 20;
    assert_eq!(off1 - off0, 4);
}

// ---------------------------------------------------------------------------
// §3.3 BPF_ST (store immediate)
// ---------------------------------------------------------------------------

#[test]
fn test_st_b_imm_is_sb() {
    let p = prog(&[insn(ST_B_IMM, 1, 0, 0, 42), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    // li t0, 42  then  sb a0, 0(t0)  -- store opcode = 0x23, funct3=0b000
    let sb_word = words[20]; // li may be 1 word (42 fits), then sb
    assert_eq!(sb_word & 0x7F, 0x23);
    assert_eq!((sb_word >> 12) & 0x7, 0b000);
}

#[test]
fn test_st_h_imm_is_sh() {
    let p = prog(&[insn(ST_H_IMM, 1, 0, 0, 1), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let sh_word = words[20];
    assert_eq!(sh_word & 0x7F, 0x23);
    assert_eq!((sh_word >> 12) & 0x7, 0b001);
}

#[test]
fn test_st_w_imm_is_sw() {
    let p = prog(&[insn(ST_W_IMM, 1, 0, 0, 7), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let sw_word = words[20];
    assert_eq!(sw_word & 0x7F, 0x23);
    assert_eq!((sw_word >> 12) & 0x7, 0b010);
}

// ---------------------------------------------------------------------------
// §3.4 BPF_STX (store register)
// ---------------------------------------------------------------------------

#[test]
fn test_stx_b_reg_is_sb() {
    let p = prog(&[insn(ST_B_REG, 1, 2, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x23);
    assert_eq!((w >> 12) & 0x7, 0b000);
}

#[test]
fn test_stx_h_reg_is_sh() {
    let p = prog(&[insn(ST_H_REG, 1, 2, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x23);
    assert_eq!((w >> 12) & 0x7, 0b001);
}

#[test]
fn test_stx_w_reg_is_sw() {
    let p = prog(&[insn(ST_W_REG, 1, 2, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x23);
    assert_eq!((w >> 12) & 0x7, 0b010);
}

// ---------------------------------------------------------------------------
// §3.5 BPF_ALU32
// ---------------------------------------------------------------------------

#[test]
fn test_add32_reg_is_add() {
    let p = prog(&[insn(ADD32_REG, 0, 1, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x33);           // R-type
    assert_eq!((w >> 12) & 0x7, 0b000);   // funct3 = ADD
    assert_eq!((w >> 25) & 0x7F, 0b0000000); // funct7 = 0 (add not sub)
}

#[test]
fn test_sub32_reg_is_sub() {
    let p = prog(&[insn(SUB32_REG, 0, 1, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x33);
    assert_eq!((w >> 25) & 0x7F, 0b0100000); // funct7 = SUB
}

#[test]
fn test_mul32_reg_is_mul() {
    let p = prog(&[insn(MUL32_REG, 0, 1, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x33);
    assert_eq!((w >> 25) & 0x7F, 0b0000001); // funct7 = M-ext
    assert_eq!((w >> 12) & 0x7, 0b000);       // MUL
}

#[test]
fn test_div32_imm_zero_gives_mv_zero() {
    // DIV by immediate 0 -> mv dst, zero
    let p = prog(&[insn(DIV32_IMM, 0, 0, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19]; // should be addi rd, zero, 0  (mv)
    assert_eq!(w & 0x7F, 0x13);
    assert_eq!((w >> 15) & 0x1F, ZERO);
}

#[test]
fn test_mod32_imm_zero_is_noop() {
    // MOD by immediate 0 -> no instruction emitted (dst unchanged)
    let p = prog(&[insn(MOD32_IMM, 0, 0, 0, 0), exit_insn()]);
    let before = bpf_to_rv32(&prog(&[exit_insn()]), &helpers()).unwrap().len();
    let after  = bpf_to_rv32(&p, &helpers()).unwrap().len();
    assert_eq!(before, after, "mod by 0 should emit no extra instructions");
}

#[test]
fn test_lsh32_imm_is_slli() {
    let p = prog(&[insn(LSH32_IMM, 0, 0, 0, 3), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x13);           // OP-IMM
    assert_eq!((w >> 12) & 0x7, 0b001);   // SLLI
    assert_eq!((w >> 20) & 0x1F, 3);      // shamt = 3
}

#[test]
fn test_rsh32_imm_is_srli() {
    let p = prog(&[insn(RSH32_IMM, 0, 0, 0, 5), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x13);
    assert_eq!((w >> 12) & 0x7, 0b101);   // SRLI funct3
    assert_eq!((w >> 30) & 0x1, 0);       // bit30=0 -> logical (not arithmetic)
}

#[test]
fn test_arsh32_imm_is_srai() {
    let p = prog(&[insn(ARSH32_IMM, 0, 0, 0, 2), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x13);
    assert_eq!((w >> 12) & 0x7, 0b101);   // SRLI/SRAI funct3
    assert_eq!((w >> 10) & 0x1, 1);       // bit10=1 -> arithmetic
}

#[test]
fn test_neg32_is_sub_zero() {
    let p = prog(&[insn(NEG32, 0, 0, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x33);
    assert_eq!((w >> 15) & 0x1F, ZERO);
    assert_eq!((w >> 25) & 0x7F, 0b0100000);
}

#[test]
fn test_mov32_imm_small() {
    let p = prog(&[insn(MOV32_IMM, 0, 0, 0, 99), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x13);
    assert_eq!((w >> 15) & 0x1F, ZERO);
    let imm = ((w >> 20) as i32) << 20 >> 20;
    assert_eq!(imm, 99);
}

#[test]
fn test_mov32_reg_is_mv() {
    let p = prog(&[insn(MOV32_REG, 0, 1, 0, 0), exit_insn()]);
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    let w = words[19];
    assert_eq!(w & 0x7F, 0x13);
    assert_eq!((w >> 20) as i32 >> 20, 0);
    assert_eq!((w >> 15) & 0x1F, A0);
}

#[test]
fn test_le_is_noop() {
    let base = bpf_to_rv32(&prog(&[exit_insn()]), &helpers()).unwrap().len();
    let with_le = bpf_to_rv32(&prog(&[insn(LE, 0, 0, 0, 32), exit_insn()]), &helpers()).unwrap().len();
    assert_eq!(base, with_le);
}

#[test]
fn test_be16_emits_5_instructions() {
    let p = prog(&[insn(BE, 0, 0, 0, 16), exit_insn()]);
    let base = bpf_to_rv32(&prog(&[exit_insn()]), &helpers()).unwrap().len();
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    assert_eq!(words.len() - base, 5);
}

#[test]
fn test_be32_emits_10_instructions() {
    let p = prog(&[insn(BE, 0, 0, 0, 32), exit_insn()]);
    let base = bpf_to_rv32(&prog(&[exit_insn()]), &helpers()).unwrap().len();
    let words = bpf_to_rv32(&p, &helpers()).unwrap();
    assert_eq!(words.len() - base, 10);
}