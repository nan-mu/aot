#![allow(dead_code)]

pub const ENOMEM: i32 = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefStateType {
    Invalid,
    Ptr,
    Irq,
    Lock,
}

impl Default for RefStateType {
    fn default() -> Self {
        Self::Invalid
    }
}

#[derive(Clone, Debug, Default)]
pub struct BpfReferenceState {
    pub typ: RefStateType,
    pub id: i32,
    pub insn_idx: i32,
    pub ptr: usize,
}

#[derive(Clone, Debug, Default)]
pub struct BpfVerifierState {
    pub acquired_refs: usize,
    pub refs: Vec<BpfReferenceState>,
    pub active_irq_id: i32,
    pub active_locks: i32,
    pub active_lock_id: i32,
    pub active_lock_ptr: usize,
}

#[derive(Clone, Debug, Default)]
pub struct BpfVerifierEnv {
    pub cur_state: BpfVerifierState,
    pub id_gen: i32,
}

pub fn resize_reference_state(state: &mut BpfVerifierState, new_len: usize) -> Result<(), i32> {
    if state.refs.len() < new_len {
        state.refs.resize(new_len, BpfReferenceState::default());
    }
    state.acquired_refs = new_len;
    Ok(())
}

pub fn acquire_reference_state(env: &mut BpfVerifierEnv, insn_idx: i32) -> Option<usize> {
    let state = &mut env.cur_state;
    let new_ofs = state.acquired_refs;

    if resize_reference_state(state, state.acquired_refs + 1).is_err() {
        return None;
    }

    state.refs[new_ofs].insn_idx = insn_idx;
    Some(new_ofs)
}

pub fn acquire_reference(env: &mut BpfVerifierEnv, insn_idx: i32) -> i32 {
    let Some(idx) = acquire_reference_state(env, insn_idx) else {
        return -ENOMEM;
    };

    env.id_gen += 1;
    let new_id = env.id_gen;

    let s = &mut env.cur_state.refs[idx];
    s.typ = RefStateType::Ptr;
    s.id = new_id;
    new_id
}

pub fn acquire_irq_state(env: &mut BpfVerifierEnv, insn_idx: i32) -> i32 {
    let Some(idx) = acquire_reference_state(env, insn_idx) else {
        return -ENOMEM;
    };

    env.id_gen += 1;
    let new_id = env.id_gen;

    {
        let s = &mut env.cur_state.refs[idx];
        s.typ = RefStateType::Irq;
        s.id = new_id;
    }

    env.cur_state.active_irq_id = new_id;
    new_id
}

pub fn acquire_lock_state(
    env: &mut BpfVerifierEnv,
    insn_idx: i32,
    typ: RefStateType,
    id: i32,
    ptr: usize,
) -> i32 {
    let Some(idx) = acquire_reference_state(env, insn_idx) else {
        return -ENOMEM;
    };

    {
        let s = &mut env.cur_state.refs[idx];
        s.typ = typ;
        s.id = id;
        s.ptr = ptr;
    }

    let state = &mut env.cur_state;
    state.active_locks += 1;
    state.active_lock_id = id;
    state.active_lock_ptr = ptr;
    0
}
