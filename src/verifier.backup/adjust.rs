#![allow(dead_code)]

pub const ERANGE: i32 = 34;

#[derive(Clone, Debug, Default)]
pub struct FuncInfo {
    pub insn_off: i32,
}

#[derive(Clone, Debug, Default)]
pub struct BpfProgAux {
    pub func_info: Vec<FuncInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct BpfInsnAuxData {
    pub seen: u32,
    pub zext_dst: bool,
}

#[derive(Clone, Debug, Default)]
pub struct BpfJitPokeDescriptor {
    pub insn_idx: u32,
}

#[derive(Clone, Debug, Default)]
pub struct BpfProg {
    pub len: u32,
    pub aux: BpfProgAux,
    pub poke_tab: Vec<BpfJitPokeDescriptor>,
}

#[derive(Clone, Debug, Default)]
pub struct BpfSubprogInfo {
    pub start: u32,
}

#[derive(Clone, Debug, Default)]
pub struct BpfVerifierEnv {
    pub prog: BpfProg,
    pub subprog_cnt: usize,
    pub hidden_subprog_cnt: usize,
    pub subprog_info: Vec<BpfSubprogInfo>,
    pub insn_array_map_cnt: usize,
    pub insn_aux_data: Vec<BpfInsnAuxData>,
}

pub fn adjust_btf_func(env: &mut BpfVerifierEnv) {
    let count = env.subprog_cnt.saturating_sub(env.hidden_subprog_cnt);
    let count = count.min(env.prog.aux.func_info.len()).min(env.subprog_info.len());

    for i in 0..count {
        env.prog.aux.func_info[i].insn_off = env.subprog_info[i].start as i32;
    }
}

pub fn adjust_insn_arrays(_env: &mut BpfVerifierEnv, _off: u32, _len: u32) {}

pub fn adjust_insn_arrays_after_remove(_env: &mut BpfVerifierEnv, _off: u32, _len: u32) {}

pub fn adjust_insn_aux_data(env: &mut BpfVerifierEnv, new_prog: &BpfProg, off: u32, cnt: u32) {
    if env.insn_aux_data.is_empty() || off as usize >= env.insn_aux_data.len() || cnt == 0 {
        return;
    }

    let old_seen = env.insn_aux_data[off as usize].seen;
    env.insn_aux_data[off as usize].zext_dst = true;

    if cnt == 1 {
        return;
    }

    let end = (off + cnt - 1).min(new_prog.len.saturating_sub(1));
    for i in off..=end {
        if let Some(aux) = env.insn_aux_data.get_mut(i as usize) {
            aux.seen = old_seen;
            aux.zext_dst = true;
        }
    }
}

pub fn adjust_jmp_off(_prog: &mut BpfProg, _tgt_idx: u32, _delta: u32) -> i32 {
    0
}

pub fn adjust_poke_descs(prog: &mut BpfProg, off: u32, len: u32) {
    for desc in &mut prog.poke_tab {
        if desc.insn_idx > off {
            desc.insn_idx = desc.insn_idx.saturating_add(len.saturating_sub(1));
        }
    }
}

pub fn adjust_ptr_min_max_vals() -> i32 {
    0
}

pub fn adjust_reg_min_max_vals() -> i32 {
    0
}

pub fn adjust_scalar_min_max_vals() -> i32 {
    0
}

pub fn adjust_subprog_starts(env: &mut BpfVerifierEnv, off: u32, len: u32) {
    if len == 1 {
        return;
    }

    for i in 0..=env.subprog_cnt {
        if i < env.subprog_info.len() && env.subprog_info[i].start > off {
            env.subprog_info[i].start += len - 1;
        }
    }
}

pub fn adjust_subprog_starts_after_remove(env: &mut BpfVerifierEnv, _off: u32, cnt: u32) -> i32 {
    for i in 0..=env.subprog_cnt {
        if i < env.subprog_info.len() {
            env.subprog_info[i].start = env.subprog_info[i].start.saturating_sub(cnt);
        }
    }
    0
}
