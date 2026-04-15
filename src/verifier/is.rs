//! Missing types: BpfMap, BpfVerifierEnv, BpfInsn, BpfRegState, BpfKfuncCallArgMeta, Btf, BtfParam, BtfType

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(map))]
pub fn is_acquire_function(func_id: BpfFuncId, map: Option<&BpfMap>) -> Result<bool> {
    let map_type = map.map(|m| m.map_type).unwrap_or(BPF_MAP_TYPE_UNSPEC);

    if matches!(
        func_id,
        BPF_FUNC_sk_lookup_tcp
            | BPF_FUNC_sk_lookup_udp
            | BPF_FUNC_skc_lookup_tcp
            | BPF_FUNC_ringbuf_reserve
            | BPF_FUNC_kptr_xchg
    ) {
        return Ok(true);
    }

    if func_id == BPF_FUNC_map_lookup_elem && matches!(map_type, BPF_MAP_TYPE_SOCKMAP | BPF_MAP_TYPE_SOCKHASH) {
        return Ok(true);
    }

    Ok(false)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn is_arena_reg(env: &mut BpfVerifierEnv, regno: i32) -> Result<bool> {
    let reg = reg_state(env, regno);
    Ok(reg.r#type == PTR_TO_ARENA)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn is_async_callback_calling_function(func_id: BpfFuncId) -> Result<bool> {
    Ok(func_id == BPF_FUNC_timer_set_callback)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(insn))]
pub fn is_async_callback_calling_insn(insn: &BpfInsn) -> Result<bool> {
    Ok((bpf_helper_call(insn) && is_async_callback_calling_function(insn.imm)? )
        || (bpf_pseudo_kfunc_call(insn) && is_async_callback_calling_kfunc(insn.imm as u32)?))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn is_async_callback_calling_kfunc(btf_id: u32) -> Result<bool> {
    Ok(is_bpf_wq_set_callback_kfunc(btf_id)? || is_task_work_add_kfunc(btf_id))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn))]
pub fn is_async_cb_sleepable(env: &mut BpfVerifierEnv, insn: &BpfInsn) -> Result<bool> {
    if bpf_helper_call(insn) && insn.imm == BPF_FUNC_timer_set_callback {
        return Ok(false);
    }
    if bpf_pseudo_kfunc_call(insn)
        && insn.off == 0
        && (is_bpf_wq_set_callback_kfunc(insn.imm as u32)? || is_task_work_add_kfunc(insn.imm as u32))
    {
        return Ok(true);
    }
    verifier_bug(env, "unhandled async callback in is_async_cb_sleepable");
    Ok(false)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(insn))]
pub fn is_atomic_fetch_insn(insn: &BpfInsn) -> Result<bool> {
    Ok(BPF_CLASS(insn.code) == BPF_STX && BPF_MODE(insn.code) == BPF_ATOMIC && (insn.imm & BPF_FETCH) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(insn))]
pub fn is_atomic_load_insn(insn: &BpfInsn) -> Result<bool> {
    Ok(BPF_CLASS(insn.code) == BPF_STX && BPF_MODE(insn.code) == BPF_ATOMIC && insn.imm == BPF_LOAD_ACQ)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn is_bpf_loop_call(insn: &BpfInsn) -> Result<bool> {
    Ok(insn.code == (BPF_JMP | BPF_CALL) && insn.src_reg == 0 && insn.imm == BPF_FUNC_loop)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(insn))]
pub fn is_bpf_throw_kfunc(insn: &BpfInsn) -> Result<bool> {
    Ok(bpf_pseudo_kfunc_call(insn) && insn.off == 0 && insn.imm as u32 == special_kfunc_list[KF_bpf_throw])
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn is_ctx_reg(env: &mut BpfVerifierEnv, regno: i32) -> Result<bool> {
    Ok(reg_state(env, regno).r#type == PTR_TO_CTX)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn is_dynptr_ref_function(func_id: BpfFuncId) -> Result<bool> {
    Ok(func_id == BPF_FUNC_dynptr_data)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn is_flow_key_reg(env: &mut BpfVerifierEnv, regno: i32) -> Result<bool> {
    Ok(reg_state(env, regno).r#type == PTR_TO_FLOW_KEYS)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn is_force_checkpoint(env: &mut BpfVerifierEnv, insn_idx: i32) -> Result<bool> {
    Ok(env.insn_aux_data[insn_idx as usize].force_checkpoint)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(meta))]
pub fn is_iter_destroy_kfunc(meta: &BpfKfuncCallArgMeta) -> Result<bool> {
    Ok((meta.kfunc_flags & KF_ITER_DESTROY) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(meta))]
pub fn is_iter_kfunc(meta: &BpfKfuncCallArgMeta) -> Result<bool> {
    Ok((meta.kfunc_flags & (KF_ITER_NEW | KF_ITER_NEXT | KF_ITER_DESTROY)) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(meta))]
pub fn is_iter_new_kfunc(meta: &BpfKfuncCallArgMeta) -> Result<bool> {
    Ok((meta.kfunc_flags & KF_ITER_NEW) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn is_iter_next_insn(env: &mut BpfVerifierEnv, insn_idx: i32) -> Result<bool> {
    Ok(env.insn_aux_data[insn_idx as usize].is_iter_next)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(meta))]
pub fn is_iter_next_kfunc(meta: &BpfKfuncCallArgMeta) -> Result<bool> {
    Ok((meta.kfunc_flags & KF_ITER_NEXT) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn is_jmp_point(env: &mut BpfVerifierEnv, insn_idx: i32) -> Result<bool> {
    Ok(env.insn_aux_data[insn_idx as usize].jmp_point)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(meta))]
pub fn is_kfunc_acquire(meta: &BpfKfuncCallArgMeta) -> Result<bool> {
    Ok((meta.kfunc_flags & KF_ACQUIRE) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(btf, arg))]
pub fn is_kfunc_arg_alloc_obj(btf: &Btf, arg: &BtfParam) -> Result<bool> {
    Ok(btf_param_match_suffix(btf, arg, "__alloc"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(btf, arg))]
pub fn is_kfunc_arg_const_str(btf: &Btf, arg: &BtfParam) -> Result<bool> {
    Ok(btf_param_match_suffix(btf, arg, "__str"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(btf, arg))]
pub fn is_kfunc_arg_map(btf: &Btf, arg: &BtfParam) -> Result<bool> {
    Ok(btf_param_match_suffix(btf, arg, "__map"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(btf, arg))]
pub fn is_kfunc_arg_nullable(btf: &Btf, arg: &BtfParam) -> Result<bool> {
    Ok(btf_param_match_suffix(btf, arg, "__nullable"))
}
