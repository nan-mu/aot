#![allow(dead_code)]

use crate::instruction::bpf::{
    BpfInsn, CALLER_SAVED_REGS, BPF_ALU, BPF_ALU64, BPF_ATOMIC, BPF_CALL, BPF_CMPXCHG, BPF_DW,
    BPF_END, BPF_EXIT, BPF_FETCH, BPF_IMM, BPF_JA, BPF_JCOND, BPF_JMP, BPF_JMP32, BPF_K,
    BPF_LD, BPF_LDX, BPF_LOAD_ACQ, BPF_MEM, BPF_MEMSX, BPF_MOV, BPF_PSEUDO_CALL,
    BPF_PSEUDO_KFUNC_CALL, BPF_ST, BPF_STORE_REL, BPF_STX, BPF_X,
};

const ALL_CALLER_SAVED_REGS: u16 = (1u16 << CALLER_SAVED_REGS) - 1;
const BPF_REG_0: u8 = 0;

#[derive(Clone, Debug, Default)]
pub struct BpfInsnAuxData {
    pub live_regs_before: u16,
    pub scc: u32,
}

#[derive(Clone, Debug, Default)]
pub struct VerifierProgram {
    pub insns: Vec<BpfInsn>,
    pub successors: Vec<Vec<usize>>,
}

#[derive(Clone, Debug, Default)]
pub struct VerifierEnv {
    pub prog: VerifierProgram,
    pub insn_aux_data: Vec<BpfInsnAuxData>,
    pub postorder: Vec<usize>,
    pub reachable: Vec<bool>,
}

#[derive(Clone, Copy, Debug, Default)]
struct InsnLiveRegs {
    use_mask: u16,
    def_mask: u16,
    in_mask: u16,
    out_mask: u16,
}

#[inline]
fn bit(reg: u8) -> u16 {
    1u16 << reg
}

#[inline]
fn bpf_class(code: u8) -> u8 {
    code & 0x07
}

#[inline]
fn bpf_mode(code: u8) -> u8 {
    code & 0xe0
}

#[inline]
fn bpf_op(code: u8) -> u8 {
    code & 0xf0
}

#[inline]
fn bpf_src(code: u8) -> u8 {
    code & BPF_X
}

#[inline]
fn bpf_size(code: u8) -> u8 {
    code & BPF_DW
}

pub fn bpf_helper_call(insn: &BpfInsn) -> bool {
    insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == 0
}

pub fn bpf_pseudo_call(insn: &BpfInsn) -> bool {
    insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == BPF_PSEUDO_CALL
}

pub fn bpf_pseudo_kfunc_call(insn: &BpfInsn) -> bool {
    insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == BPF_PSEUDO_KFUNC_CALL
}

fn compute_insn_live_regs(insn: &BpfInsn) -> InsnLiveRegs {
    let class = bpf_class(insn.code);
    let code = bpf_op(insn.code);
    let mode = bpf_mode(insn.code);
    let src = bit(insn.src_reg);
    let dst = bit(insn.dst_reg);
    let r0 = bit(BPF_REG_0);

    let mut def = 0u16;
    let mut use_mask = 0xffffu16;

    match class {
        BPF_LD => {
            if mode == BPF_IMM && bpf_size(insn.code) == BPF_DW {
                def = dst;
                use_mask = 0;
            }
        }
        BPF_LDX => {
            if mode == BPF_MEM || mode == BPF_MEMSX {
                def = dst;
                use_mask = src;
            }
        }
        BPF_ST => {
            if mode == BPF_MEM {
                def = 0;
                use_mask = dst;
            }
        }
        BPF_STX => {
            if mode == BPF_MEM {
                def = 0;
                use_mask = dst | src;
            } else if mode == BPF_ATOMIC {
                match insn.imm {
                    BPF_CMPXCHG => {
                        use_mask = r0 | dst | src;
                        def = r0;
                    }
                    BPF_LOAD_ACQ => {
                        def = dst;
                        use_mask = src;
                    }
                    BPF_STORE_REL => {
                        def = 0;
                        use_mask = dst | src;
                    }
                    _ => {
                        use_mask = dst | src;
                        def = if insn.imm & BPF_FETCH != 0 { src } else { 0 };
                    }
                }
            }
        }
        BPF_ALU | BPF_ALU64 => match code {
            BPF_END => {
                use_mask = dst;
                def = dst;
            }
            BPF_MOV => {
                def = dst;
                use_mask = if bpf_src(insn.code) == BPF_K { 0 } else { src };
            }
            _ => {
                def = dst;
                use_mask = if bpf_src(insn.code) == BPF_K { dst } else { dst | src };
            }
        },
        BPF_JMP | BPF_JMP32 => match code {
            BPF_JA => {
                def = 0;
                use_mask = if bpf_src(insn.code) == BPF_X { dst } else { 0 };
            }
            BPF_JCOND => {
                def = 0;
                use_mask = 0;
            }
            BPF_EXIT => {
                def = 0;
                use_mask = r0;
            }
            BPF_CALL => {
                def = ALL_CALLER_SAVED_REGS;
                use_mask = def & !bit(BPF_REG_0);
            }
            _ => {
                def = 0;
                use_mask = if bpf_src(insn.code) == BPF_K { dst } else { dst | src };
            }
        },
        _ => {}
    }

    InsnLiveRegs {
        use_mask,
        def_mask: def,
        in_mask: 0,
        out_mask: 0,
    }
}

pub fn compute_postorder_and_reachable(prog: &VerifierProgram) -> (Vec<usize>, Vec<bool>) {
    let n = prog.insns.len();
    let mut reachable = vec![false; n];
    let mut postorder = Vec::with_capacity(n);

    if n == 0 {
        return (postorder, reachable);
    }

    let mut iter_pos = vec![0usize; n];
    let mut stack = vec![0usize];
    reachable[0] = true;

    while let Some(&node) = stack.last() {
        if iter_pos[node] < prog.successors[node].len() {
            let succ = prog.successors[node][iter_pos[node]];
            iter_pos[node] += 1;
            if !reachable[succ] {
                reachable[succ] = true;
                stack.push(succ);
            }
        } else {
            stack.pop();
            postorder.push(node);
        }
    }

    (postorder, reachable)
}

pub fn compute_live_registers(env: &mut VerifierEnv) {
    let mut state: Vec<InsnLiveRegs> = env.prog.insns.iter().map(compute_insn_live_regs).collect();

    let mut changed = true;
    while changed {
        changed = false;

        for &insn_idx in &env.postorder {
            let mut new_out = 0u16;
            for succ in &env.prog.successors[insn_idx] {
                new_out |= state[*succ].in_mask;
            }

            let current = state[insn_idx];
            let new_in = (new_out & !current.def_mask) | current.use_mask;
            if new_out != current.out_mask || new_in != current.in_mask {
                state[insn_idx].out_mask = new_out;
                state[insn_idx].in_mask = new_in;
                changed = true;
            }
        }
    }

    for (i, s) in state.into_iter().enumerate() {
        env.insn_aux_data[i].live_regs_before = s.in_mask;
    }
}

pub fn compute_scc(env: &mut VerifierEnv) {
    let n = env.prog.insns.len();
    let mut index = 0usize;
    let mut stack: Vec<usize> = Vec::new();
    let mut on_stack = vec![false; n];
    let mut indices: Vec<Option<usize>> = vec![None; n];
    let mut lowlink = vec![0usize; n];
    let mut next_scc_id = 1u32;

    fn strong_connect(
        v: usize,
        env: &mut VerifierEnv,
        index: &mut usize,
        stack: &mut Vec<usize>,
        on_stack: &mut [bool],
        indices: &mut [Option<usize>],
        lowlink: &mut [usize],
        next_scc_id: &mut u32,
    ) {
        indices[v] = Some(*index);
        lowlink[v] = *index;
        *index += 1;

        stack.push(v);
        on_stack[v] = true;

        let succs = env.prog.successors[v].clone();
        for w in succs {
            if indices[w].is_none() {
                strong_connect(w, env, index, stack, on_stack, indices, lowlink, next_scc_id);
                lowlink[v] = lowlink[v].min(lowlink[w]);
            } else if on_stack[w] {
                lowlink[v] = lowlink[v].min(indices[w].expect("index exists"));
            }
        }

        if lowlink[v] == indices[v].expect("index exists") {
            let mut comp: Vec<usize> = Vec::new();
            while let Some(w) = stack.pop() {
                on_stack[w] = false;
                comp.push(w);
                if w == v {
                    break;
                }
            }

            let has_self_loop = env.prog.successors[v].contains(&v);
            let assign_scc = comp.len() > 1 || has_self_loop;
            if assign_scc {
                for node in comp {
                    env.insn_aux_data[node].scc = *next_scc_id;
                }
                *next_scc_id += 1;
            }
        }
    }

    for v in 0..n {
        if indices[v].is_none() {
            strong_connect(
                v,
                env,
                &mut index,
                &mut stack,
                &mut on_stack,
                &mut indices,
                &mut lowlink,
                &mut next_scc_id,
            );
        }
    }
}
