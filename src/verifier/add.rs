#![allow(dead_code)]

pub const EINVAL: i32 = 22;
pub const ENOMEM: i32 = 12;
pub const E2BIG: i32 = 7;
pub const EFAULT: i32 = 14;
pub const EPERM: i32 = 1;

#[derive(Clone, Debug, Default)]
pub struct BpfSubprogInfo {
    pub start: i32,
}

#[derive(Clone, Debug, Default)]
pub struct BpfProg {
    pub len: i32,
}

#[derive(Clone, Debug, Default)]
pub struct BpfInsn {
    pub imm: i32,
    pub off: i16,
    pub pseudo_func: bool,
    pub pseudo_call: bool,
    pub pseudo_kfunc_call: bool,
}

#[derive(Clone, Debug, Default)]
pub struct BpfVerifierState {
    pub insn_idx: i32,
}

#[derive(Clone, Debug, Default)]
pub struct BpfSccBackedge {
    pub next: Option<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct BpfVerifierEnv {
    pub prog: BpfProg,
    pub subprog_info: Vec<BpfSubprogInfo>,
    pub subprog_cnt: i32,
    pub hidden_subprog_cnt: i32,
    pub exception_callback_subprog: i32,
    pub bpf_capable: bool,
    pub num_backedges: i32,
}

pub fn add_fd_from_fd_array(_env: &mut BpfVerifierEnv, _fd: i32) -> i32 {
    0
}

pub fn add_hidden_subprog(env: &mut BpfVerifierEnv, _patch: &[BpfInsn], len: i32) -> i32 {
    if env.hidden_subprog_cnt != 0 {
        return -EFAULT;
    }
    if len <= 0 {
        return -EINVAL;
    }

    let cnt = env.subprog_cnt as usize;
    if env.subprog_info.len() <= cnt + 1 {
        env.subprog_info.resize(cnt + 2, BpfSubprogInfo::default());
    }

    env.subprog_info[cnt + 1].start = env.subprog_info[cnt].start;
    env.subprog_info[cnt].start = env.prog.len - len + 1;
    env.subprog_cnt += 1;
    env.hidden_subprog_cnt += 1;
    0
}

pub fn add_kfunc_call(_env: &mut BpfVerifierEnv, _func_id: u32, _offset: i16) -> i32 {
    0
}

pub fn add_kfunc_in_insns(env: &mut BpfVerifierEnv, insns: &[BpfInsn]) -> i32 {
    for insn in insns {
        if insn.pseudo_kfunc_call {
            let ret = add_kfunc_call(env, insn.imm as u32, insn.off);
            if ret < 0 {
                return ret;
            }
        }
    }
    0
}

pub fn add_scc_backedge(
    env: &mut BpfVerifierEnv,
    _st: &BpfVerifierState,
    _backedge: &mut BpfSccBackedge,
) -> i32 {
    env.num_backedges += 1;
    0
}

pub fn add_subprog(env: &mut BpfVerifierEnv, off: i32) -> i32 {
    let insn_cnt = env.prog.len;
    if off >= insn_cnt || off < 0 {
        return -EINVAL;
    }

    let idx = env.subprog_cnt as usize;
    if env.subprog_info.len() <= idx {
        env.subprog_info.resize(idx + 1, BpfSubprogInfo::default());
    }
    env.subprog_info[idx].start = off;
    env.subprog_cnt += 1;
    env.subprog_cnt - 1
}

pub fn add_subprog_and_kfunc(env: &mut BpfVerifierEnv, insns: &[BpfInsn]) -> i32 {
    let ret = add_subprog(env, 0);
    if ret < 0 {
        return ret;
    }

    for (i, insn) in insns.iter().enumerate() {
        if !(insn.pseudo_func || insn.pseudo_call || insn.pseudo_kfunc_call) {
            continue;
        }

        if !env.bpf_capable {
            return -EPERM;
        }

        let ret = if insn.pseudo_func || insn.pseudo_call {
            add_subprog(env, i as i32 + insn.imm + 1)
        } else {
            add_kfunc_call(env, insn.imm as u32, insn.off)
        };

        if ret < 0 {
            return ret;
        }
    }

    let fake_exit = env.subprog_cnt as usize;
    if env.subprog_info.len() <= fake_exit {
        env.subprog_info.resize(fake_exit + 1, BpfSubprogInfo::default());
    }
    env.subprog_info[fake_exit].start = env.prog.len;

    0
}

pub fn add_used_map(_env: &mut BpfVerifierEnv, _fd: i32) -> i32 {
    0
}
