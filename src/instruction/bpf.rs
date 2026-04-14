#![allow(dead_code)]

pub const BPF_MAP_KEY_POISON: u64 = 1u64 << 63;
pub const BPF_MAP_KEY_SEEN: u64 = 1u64 << 62;

pub const BPF_REG_0: usize = 0;
pub const CALLER_SAVED_REGS: usize = 6;

pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_JMP32: u8 = 0x06;
pub const BPF_ALU64: u8 = 0x07;

pub const BPF_IMM: u8 = 0x00;
pub const BPF_MEM: u8 = 0x60;
pub const BPF_MEMSX: u8 = 0x80;
pub const BPF_ATOMIC: u8 = 0xc0;

pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;
pub const BPF_DW: u8 = 0x18;

pub const BPF_JA: u8 = 0x00;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;
pub const BPF_END: u8 = 0xd0;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_JCOND: u8 = 0xe0;

pub const BPF_CMPXCHG: i32 = 0xf0;
pub const BPF_FETCH: i32 = 0x01;
pub const BPF_LOAD_ACQ: i32 = 0x100;
pub const BPF_STORE_REL: i32 = 0x110;

pub const BPF_PSEUDO_CALL: u8 = 1;
pub const BPF_PSEUDO_KFUNC_CALL: u8 = 2;

#[derive(Clone, Copy, Debug, Default)]
pub struct BpfInsn {
    pub code: u8,
    pub dst_reg: u8,
    pub src_reg: u8,
    pub off: i16,
    pub imm: i32,
}
