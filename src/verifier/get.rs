//! Missing types: BpfVerifierEnv, BpfInsn, CallSummary, BpfKfuncCallArgMeta, BpfFuncProto, BpfRegState, BpfProg, BpfRetvalRange, BpfKfuncCallArgMeta, BtfType, BtfParam, BpfTypeFlag

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, call, cs))]
pub fn get_call_summary(env: &mut BpfVerifierEnv, call: &BpfInsn, cs: &mut CallSummary) -> Result<bool> {
    if bpf_helper_call(call) {
        let mut fn_proto: Option<&BpfFuncProto> = None;
        if get_helper_proto(env, call.imm, &mut fn_proto)? < 0 {
            return Ok(false);
        }
        let fn_proto = fn_proto.ok_or_else(|| anyhow!("get_call_summary failed"))?;

        cs.fastcall = fn_proto.allow_fastcall
            && (verifier_inlines_helper_call(env, call.imm) || bpf_jit_inlines_helper_call(call.imm));
        cs.is_void = fn_proto.ret_type == RET_VOID;
        cs.num_params = 0;
        for arg in fn_proto.arg_type.iter() {
            if *arg == ARG_DONTCARE {
                break;
            }
            cs.num_params += 1;
        }
        return Ok(true);
    }

    if bpf_pseudo_kfunc_call(call) {
        let mut meta = BpfKfuncCallArgMeta::default();
        let err = fetch_kfunc_arg_meta(env, call.imm, call.off, &mut meta)?;
        if err < 0 {
            return Ok(false);
        }
        cs.num_params = btf_type_vlen(meta.func_proto);
        cs.fastcall = (meta.kfunc_flags & KF_FASTCALL) != 0;
        cs.is_void = btf_type_is_void(btf_type_by_id(meta.btf, meta.func_proto.r#type));
        return Ok(true);
    }

    Ok(false)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn))]
pub fn get_callee_stack_depth(env: &mut BpfVerifierEnv, insn: &BpfInsn, idx: i32) -> Result<i32> {
    let start = idx + insn.imm + 1;
    let subprog = find_subprog(env, start)?;
    Ok(env.subprog_info[subprog as usize].stack_depth)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, key, value))]
pub fn get_constant_map_key(
    env: &mut BpfVerifierEnv,
    key: &BpfRegState,
    key_size: u32,
    value: &mut i64,
) -> Result<i32> {
    let state = func(env, key)?;

    if !env.bpf_capable || key.r#type != PTR_TO_STACK || !tnum_is_const(key.var_off) {
        return Err(anyhow!("get_constant_map_key failed"));
    }

    let stack_off = key.off + key.var_off.value as i32;
    let slot = -stack_off - 1;
    let spi = slot / BPF_REG_SIZE as i32;
    let off = (slot % BPF_REG_SIZE as i32) as usize;
    let stype = &state.stack[spi as usize].slot_type;

    let mut zero_size = 0u32;
    let mut i = off as i32;
    while i >= 0 && stype[i as usize] == STACK_ZERO {
        zero_size += 1;
        i -= 1;
    }
    if zero_size >= key_size {
        *value = 0;
        return Ok(0);
    }

    if !is_spilled_scalar_reg(&state.stack[spi as usize]) {
        return Err(anyhow!("get_constant_map_key failed"));
    }

    let mut spill_size = 0u32;
    let mut j = off as i32;
    while j >= 0 && stype[j as usize] == STACK_SPILL {
        spill_size += 1;
        j -= 1;
    }
    if spill_size != key_size {
        return Err(anyhow!("get_constant_map_key failed"));
    }

    let reg = &state.stack[spi as usize].spilled_ptr;
    if !tnum_is_const(reg.var_off) {
        return Err(anyhow!("get_constant_map_key failed"));
    }

    bt_set_frame_slot(&mut env.bt, key.frameno, spi as u32);
    let err = mark_chain_precision_batch(env, env.cur_state)?;
    if err < 0 {
        return Err(anyhow!("get_constant_map_key failed"));
    }

    *value = reg.var_off.value as i64;
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, fn_proto, regs))]
pub fn get_dynptr_arg_reg(
    env: &mut BpfVerifierEnv,
    fn_proto: &BpfFuncProto,
    regs: &mut [BpfRegState],
) -> Result<Option<&mut BpfRegState>> {
    let mut idx: Option<usize> = None;
    for i in 0..MAX_BPF_FUNC_REG_ARGS as usize {
        if arg_type_is_dynptr(fn_proto.arg_type[i])? {
            if idx.is_some() {
                verbose(env, "verifier internal error: multiple dynptr args\n");
                return Ok(None);
            }
            idx = Some((BPF_REG_1 as usize) + i);
        }
    }

    if idx.is_none() {
        verbose(env, "verifier internal error: no dynptr arg found\n");
        return Ok(None);
    }

    Ok(Some(&mut regs[idx.unwrap()]))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn get_dynptr_type_flag(r#type: BpfDynptrType) -> Result<BpfTypeFlag> {
    Ok(match r#type {
        BPF_DYNPTR_TYPE_LOCAL => DYNPTR_TYPE_LOCAL,
        BPF_DYNPTR_TYPE_RINGBUF => DYNPTR_TYPE_RINGBUF,
        BPF_DYNPTR_TYPE_SKB => DYNPTR_TYPE_SKB,
        BPF_DYNPTR_TYPE_XDP => DYNPTR_TYPE_XDP,
        BPF_DYNPTR_TYPE_SKB_META => DYNPTR_TYPE_SKB_META,
        BPF_DYNPTR_TYPE_FILE => DYNPTR_TYPE_FILE,
        _ => 0,
    })
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(prog, range))]
pub fn get_func_retval_range(prog: &BpfProg, range: &mut BpfRetvalRange) -> Result<bool> {
    if prog.r#type == BPF_PROG_TYPE_LSM
        && prog.expected_attach_type == BPF_LSM_MAC
        && !bpf_lsm_get_retval_range(prog, range)
    {
        return Ok(true);
    }
    Ok(false)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, ptr))]
pub fn get_helper_proto(env: &mut BpfVerifierEnv, func_id: i32, ptr: &mut Option<&BpfFuncProto>) -> Result<i32> {
    if func_id < 0 || func_id >= __BPF_FUNC_MAX_ID as i32 {
        return Err(anyhow!("get_helper_proto failed"));
    }
    if env.ops.get_func_proto.is_none() {
        return Err(anyhow!("get_helper_proto failed"));
    }

    *ptr = env.ops.get_func_proto.unwrap()(func_id, env.prog);
    if ptr.is_some() && ptr.unwrap().func.is_some() {
        Ok(0)
    } else {
        Err(anyhow!("get_helper_proto failed"))
    }
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(cur_st, meta))]
pub fn get_iter_from_state(cur_st: &mut BpfVerifierState, meta: &BpfKfuncCallArgMeta) -> Result<&mut BpfRegState> {
    let iter_frameno = meta.iter.frameno as usize;
    let iter_spi = meta.iter.spi as usize;
    Ok(&mut cur_st.frame[iter_frameno].stack[iter_spi].spilled_ptr)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(st))]
pub fn get_jmp_hist_entry(
    st: &mut BpfVerifierState,
    hist_end: u32,
    insn_idx: i32,
) -> Result<Option<&mut BpfJmpHistoryEntry>> {
    if hist_end > 0 && st.jmp_history[(hist_end - 1) as usize].idx == insn_idx {
        return Ok(Some(&mut st.jmp_history[(hist_end - 1) as usize]));
    }
    Ok(None)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn get_reg_width(reg: &BpfRegState) -> Result<i32> {
    Ok(fls64(reg.umax_value as u64) as i32)
}

#[instrument]
pub fn inner_get_spi(off: i32) -> Result<i32> {
    Ok((-off - 1) / BPF_REG_SIZE as i32)
}
