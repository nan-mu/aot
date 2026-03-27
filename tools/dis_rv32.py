#!/usr/bin/env python3
"""
Minimal RV32I/M disassembler for .word directives in assembly files.
Usage:
    python3 dis_rv32.py res
    cat res | python3 dis_rv32.py
"""

import sys
import re

# Register ABI names
ABI = [
    "zero", "ra", "sp", "gp", "tp",
    "t0",  "t1", "t2",
    "s0",  "s1",
    "a0",  "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "s2",  "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    "t3",  "t4", "t5", "t6",
]

def reg(r):
    return ABI[r & 0x1f]

def sign_ext(val, bits):
    """Sign-extend val from 'bits' wide to Python int."""
    if val & (1 << (bits - 1)):
        val -= (1 << bits)
    return val

def imm_i(w):
    return sign_ext((w >> 20) & 0xFFF, 12)

def imm_s(w):
    hi = (w >> 25) & 0x7F
    lo = (w >>  7) & 0x1F
    return sign_ext((hi << 5) | lo, 12)

def imm_b(w):
    b12   = (w >> 31) & 1
    b11   = (w >>  7) & 1
    b10_5 = (w >> 25) & 0x3F
    b4_1  = (w >>  8) & 0xF
    val   = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1)
    return sign_ext(val, 13)

def imm_u(w):
    return w & 0xFFFFF000

def imm_j(w):
    b20    = (w >> 31) & 1
    b19_12 = (w >> 12) & 0xFF
    b11    = (w >> 20) & 1
    b10_1  = (w >> 21) & 0x3FF
    val    = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1)
    return sign_ext(val, 21)

FUNCT3_ALU = {0b000: "add", 0b001: "sll", 0b010: "slt", 0b011: "sltu",
              0b100: "xor", 0b101: "srl", 0b110: "or",  0b111: "and"}
FUNCT3_ALUI = {0b000: "addi", 0b001: "slli", 0b010: "slti", 0b011: "sltiu",
               0b100: "xori", 0b101: "srli", 0b110: "ori",  0b111: "andi"}
FUNCT3_LOAD = {0b000: "lb", 0b001: "lh", 0b010: "lw",
               0b100: "lbu", 0b101: "lhu"}
FUNCT3_STORE = {0b000: "sb", 0b001: "sh", 0b010: "sw"}
FUNCT3_BRANCH = {0b000: "beq", 0b001: "bne", 0b100: "blt",
                 0b101: "bge", 0b110: "bltu", 0b111: "bgeu"}
FUNCT3_MUL = {0b000: "mul", 0b001: "mulh", 0b010: "mulhsu", 0b011: "mulhu",
              0b100: "div", 0b101: "divu", 0b110: "rem",    0b111: "remu"}

def disasm(w, pc):
    opc    = w & 0x7F
    rd     = (w >>  7) & 0x1F
    funct3 = (w >> 12) & 0x7
    rs1    = (w >> 15) & 0x1F
    rs2    = (w >> 20) & 0x1F
    funct7 = (w >> 25) & 0x7F

    if opc == 0x37:  # LUI
        return f"lui     {reg(rd)}, 0x{imm_u(w) >> 12:x}"
    if opc == 0x17:  # AUIPC
        return f"auipc   {reg(rd)}, 0x{imm_u(w) >> 12:x}"
    if opc == 0x6F:  # JAL
        off = imm_j(w)
        tgt = pc + off
        return f"jal     {reg(rd)}, {off:+d}  # -> 0x{tgt:x}"
    if opc == 0x67:  # JALR
        imm = imm_i(w)
        if rd == 0 and rs1 == 1 and imm == 0:
            return "ret"
        if rd == 0 and imm == 0:
            return f"jr      {reg(rs1)}"
        return f"jalr    {reg(rd)}, {reg(rs1)}, {imm}"
    if opc == 0x63:  # BRANCH
        mn = FUNCT3_BRANCH.get(funct3, f"b??{funct3}")
        off = imm_b(w)
        tgt = pc + off
        return f"{mn:<7} {reg(rs1)}, {reg(rs2)}, {off:+d}  # -> 0x{tgt:x}"
    if opc == 0x03:  # LOAD
        mn = FUNCT3_LOAD.get(funct3, f"l??{funct3}")
        imm = imm_i(w)
        return f"{mn:<7} {reg(rd)}, {imm}({reg(rs1)})"
    if opc == 0x23:  # STORE
        mn = FUNCT3_STORE.get(funct3, f"s??{funct3}")
        imm = imm_s(w)
        return f"{mn:<7} {reg(rs2)}, {imm}({reg(rs1)})"
    if opc == 0x13:  # OP-IMM
        imm = imm_i(w)
        if funct3 == 0b001:  # SLLI
            shamt = rs2
            return f"slli    {reg(rd)}, {reg(rs1)}, {shamt}"
        if funct3 == 0b101:  # SRLI / SRAI
            shamt = rs2
            if funct7 == 0x20:
                return f"srai    {reg(rd)}, {reg(rs1)}, {shamt}"
            return f"srli    {reg(rd)}, {reg(rs1)}, {shamt}"
        mn = FUNCT3_ALUI.get(funct3, f"alui??{funct3}")
        # pseudo: mv, li, nop
        if funct3 == 0 and rs1 == 0:
            if rd == 0 and imm == 0:
                return "nop"
            return f"li      {reg(rd)}, {imm}"
        if funct3 == 0 and imm == 0:
            return f"mv      {reg(rd)}, {reg(rs1)}"
        return f"{mn:<7} {reg(rd)}, {reg(rs1)}, {imm}"
    if opc == 0x33:  # OP
        if funct7 == 0x01:  # RV32M
            mn = FUNCT3_MUL.get(funct3, f"m??{funct3}")
            return f"{mn:<7} {reg(rd)}, {reg(rs1)}, {reg(rs2)}"
        mn = FUNCT3_ALU.get(funct3, f"alu??{funct3}")
        if funct3 == 0b000 and funct7 == 0x20:
            mn = "sub"
        if funct3 == 0b101 and funct7 == 0x20:
            mn = "sra"
        # pseudo: mv
        if mn == "add" and rs2 == 0:
            return f"mv      {reg(rd)}, {reg(rs1)}"
        return f"{mn:<7} {reg(rd)}, {reg(rs1)}, {reg(rs2)}"
    if opc == 0x0F:  # FENCE
        return "fence"
    if opc == 0x73:  # SYSTEM
        if w == 0x00000073: return "ecall"
        if w == 0x00100073: return "ebreak"
        return f".word   0x{w:08x}  # system"
    return f".word   0x{w:08x}  # unknown opcode 0x{opc:02x}"

def process(lines):
    pc = 0
    for line in lines:
        line = line.strip()
        # Match .word 0x... or .word N
        m = re.match(r'\.word\s+(0x[0-9a-fA-F]+|[0-9]+)', line)
        if m:
            w = int(m.group(1), 0) & 0xFFFFFFFF
            dis = disasm(w, pc)
            print(f"  {pc:4x}:  {w:08x}    {dis}")
            pc += 4
        elif line and not line.startswith('#') and not line.startswith('//'):
            # Print labels / directives as-is
            print(line)

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        with open(sys.argv[1]) as f:
            process(f.readlines())
    else:
        process(sys.stdin.readlines())
