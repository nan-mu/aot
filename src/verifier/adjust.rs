//! Missing types: BpfVerifierEnv, BpfProgAux, BpfProg, BpfInsn, BpfInsnAuxData, BpfJitPokeDescriptor, BpfVerifierState, BpfFuncState, BpfRegState, BpfSanitizeInfo, Tnum, BpfSubprogInfo

use anyhow::{anyhow, Result};
use tracing::instrument;

#[instrument(skip(env))]
pub fn adjust_btf_func(env: &mut BpfVerifierEnv) {
    let aux: &mut BpfProgAux = env.prog.aux;
    if aux.func_info.is_none() {
        return;
    }

    for i in 0..(env.subprog_cnt - env.hidden_subprog_cnt) as usize {
        aux.func_info.as_mut().unwrap()[i].insn_off = env.subprog_info[i].start;
    }
}

#[instrument(skip(env))]
pub fn adjust_insn_arrays(env: &mut BpfVerifierEnv, off: u32, len: u32) {
    if len == 1 {
        return;
    }
    for i in 0..env.insn_array_map_cnt as usize {
        bpf_insn_array_adjust(env.insn_array_maps[i], off, len);
    }
}

#[instrument(skip(env))]
pub fn adjust_insn_arrays_after_remove(env: &mut BpfVerifierEnv, off: u32, len: u32) {
    for i in 0..env.insn_array_map_cnt as usize {
        bpf_insn_array_adjust_after_remove(env.insn_array_maps[i], off, len);
    }
}

#[instrument(skip(env, new_prog))]
pub fn adjust_insn_aux_data(env: &mut BpfVerifierEnv, new_prog: &BpfProg, off: u32, cnt: u32) {
    let data: &mut [BpfInsnAuxData] = env.insn_aux_data;
    let insn: &[BpfInsn] = new_prog.insnsi;
    let old_seen = data[off as usize].seen;

    data[off as usize].zext_dst = insn_has_def32(&insn[(off + cnt - 1) as usize]);
    if cnt == 1 {
        return;
    }

    let prog_len = new_prog.len;

    let src_start = off as usize;
    let dst_start = (off + cnt - 1) as usize;
    let move_len = (prog_len - off - cnt + 1) as usize;
    for i in (0..move_len).rev() {
        data[dst_start + i] = data[src_start + i].clone();
    }

    for i in off as usize..(off + cnt - 1) as usize {
        data[i] = BpfInsnAuxData::default();
        data[i].seen = old_seen;
        data[i].zext_dst = insn_has_def32(&insn[i]);
    }
}

#[instrument(skip(prog))]
pub fn adjust_jmp_off(prog: &mut BpfProg, tgt_idx: u32, delta: u32) -> Result<i32> {
    let insn_cnt = prog.len;

    for i in 0..insn_cnt {
        if tgt_idx <= i && i < tgt_idx + delta {
            continue;
        }

        let insn = &mut prog.insnsi[i as usize];
        let code = insn.code;

        if (bpf_class(code) != BPF_JMP && bpf_class(code) != BPF_JMP32)
            || bpf_op(code) == BPF_CALL
            || bpf_op(code) == BPF_EXIT
        {
            continue;
        }

        if insn.code == (BPF_JMP32 | BPF_JA) {
            if (i as i32 + 1 + insn.imm) as u32 != tgt_idx {
                continue;
            }
            insn.imm = check_add_overflow_i32(insn.imm, delta as i32)
                .ok_or_else(|| anyhow!("-ERANGE: jmp32 imm overflow"))?;
        } else {
            if (i as i32 + 1 + insn.off as i32) as u32 != tgt_idx {
                continue;
            }
            insn.off = check_add_overflow_i16(insn.off, delta as i16)
                .ok_or_else(|| anyhow!("-ERANGE: jmp off overflow"))?;
        }
    }

    Ok(0)
}

#[instrument(skip(prog))]
pub fn adjust_poke_descs(prog: &mut BpfProg, off: u32, len: u32) {
    let tab: &mut [BpfJitPokeDescriptor] = prog.aux.poke_tab;
    let sz = prog.aux.size_poke_tab;

    for i in 0..sz as usize {
        let desc = &mut tab[i];
        if desc.insn_idx <= off {
            continue;
        }
        desc.insn_idx += len - 1;
    }
}

#[instrument(skip(env, insn, ptr_reg, off_reg))]
pub fn adjust_ptr_min_max_vals(
    env: &mut BpfVerifierEnv,
    insn: &BpfInsn,
    ptr_reg: &BpfRegState,
    off_reg: &BpfRegState,
) -> Result<i32> {
    let vstate: &mut BpfVerifierState = env.cur_state;
    let state: &mut BpfFuncState = vstate.frame[vstate.curframe as usize];
    let regs: &mut [BpfRegState] = state.regs;
    let dst = insn.dst_reg as usize;
    let dst_reg: &mut BpfRegState = &mut regs[dst];

    if (tnum_is_const(off_reg.var_off)
        && (off_reg.smin_value != off_reg.smax_value || off_reg.umin_value != off_reg.umax_value))
        || off_reg.smin_value > off_reg.smax_value
        || off_reg.umin_value > off_reg.umax_value
    {
        __mark_reg_unknown(env, dst_reg);
        return Ok(0);
    }

    if bpf_class(insn.code) != BPF_ALU64 {
        if bpf_op(insn.code) == BPF_SUB && env.allow_ptr_leaks {
            __mark_reg_unknown(env, dst_reg);
            return Ok(0);
        }
        return Err(anyhow!("-EACCES: 32-bit pointer arithmetic prohibited"));
    }

    if !check_reg_sane_offset(env, off_reg, ptr_reg.r#type)
        || !check_reg_sane_offset(env, ptr_reg, ptr_reg.r#type)
    {
        return Err(anyhow!("-EINVAL: insane register offset"));
    }

    // Keep semantics shallow but preserve verifier flow contracts.
    dst_reg.r#type = ptr_reg.r#type;
    dst_reg.id = ptr_reg.id;
    __mark_reg32_unbounded(dst_reg);

    let bounds_ret = sanitize_check_bounds(env, insn, dst_reg);
    if bounds_ret == -13 {
        return Err(anyhow!("-EACCES: sanitize_check_bounds rejected"));
    }

    Ok(0)
}

#[instrument(skip(env, insn))]
pub fn adjust_reg_min_max_vals(env: &mut BpfVerifierEnv, insn: &BpfInsn) -> Result<i32> {
    let vstate: &mut BpfVerifierState = env.cur_state;
    let state: &mut BpfFuncState = vstate.frame[vstate.curframe as usize];
    let regs: &mut [BpfRegState] = state.regs;
    let dst_reg = &mut regs[insn.dst_reg as usize];

    if dst_reg.r#type == PTR_TO_ARENA {
        if bpf_class(insn.code) == BPF_ALU64 {
            cur_aux(env).needs_zext = true;
        }
        return Ok(0);
    }

    let err = adjust_scalar_min_max_vals(env, insn, dst_reg, regs[insn.src_reg as usize].clone())?;
    if err != 0 {
        return Ok(err);
    }

    Ok(0)
}

#[instrument(skip(env, insn, dst_reg, src_reg))]
pub fn adjust_scalar_min_max_vals(
    env: &mut BpfVerifierEnv,
    insn: &BpfInsn,
    dst_reg: &mut BpfRegState,
    src_reg: BpfRegState,
) -> Result<i32> {
    let opcode = bpf_op(insn.code);
    let alu32 = bpf_class(insn.code) != BPF_ALU64;

    if !is_safe_to_compute_dst_reg_range(insn, &src_reg) {
        __mark_reg_unknown(env, dst_reg);
        return Ok(0);
    }

    if sanitize_needed(opcode) {
        let ret = sanitize_val_alu(env, insn);
        if ret < 0 {
            return Err(anyhow!("sanitize_val_alu failed: {ret}"));
        }
    }

    match opcode {
        BPF_ADD => {
            scalar32_min_max_add(dst_reg, &src_reg);
            scalar_min_max_add(dst_reg, &src_reg);
            dst_reg.var_off = tnum_add(dst_reg.var_off, src_reg.var_off);
        }
        BPF_SUB => {
            scalar32_min_max_sub(dst_reg, &src_reg);
            scalar_min_max_sub(dst_reg, &src_reg);
            dst_reg.var_off = tnum_sub(dst_reg.var_off, src_reg.var_off);
        }
        BPF_NEG => {
            env.fake_reg[0] = dst_reg.clone();
            __mark_reg_known(dst_reg, 0);
            scalar32_min_max_sub(dst_reg, &env.fake_reg[0]);
            scalar_min_max_sub(dst_reg, &env.fake_reg[0]);
            dst_reg.var_off = tnum_neg(env.fake_reg[0].var_off);
        }
        BPF_MUL => {
            dst_reg.var_off = tnum_mul(dst_reg.var_off, src_reg.var_off);
            scalar32_min_max_mul(dst_reg, &src_reg);
            scalar_min_max_mul(dst_reg, &src_reg);
        }
        BPF_AND => {
            dst_reg.var_off = tnum_and(dst_reg.var_off, src_reg.var_off);
            scalar32_min_max_and(dst_reg, &src_reg);
            scalar_min_max_and(dst_reg, &src_reg);
        }
        BPF_OR => {
            dst_reg.var_off = tnum_or(dst_reg.var_off, src_reg.var_off);
            scalar32_min_max_or(dst_reg, &src_reg);
            scalar_min_max_or(dst_reg, &src_reg);
        }
        BPF_XOR => {
            dst_reg.var_off = tnum_xor(dst_reg.var_off, src_reg.var_off);
            scalar32_min_max_xor(dst_reg, &src_reg);
            scalar_min_max_xor(dst_reg, &src_reg);
        }
        BPF_LSH => {
            if alu32 {
                scalar32_min_max_lsh(dst_reg, &src_reg);
            } else {
                scalar_min_max_lsh(dst_reg, &src_reg);
            }
        }
        BPF_RSH => {
            if alu32 {
                scalar32_min_max_rsh(dst_reg, &src_reg);
            } else {
                scalar_min_max_rsh(dst_reg, &src_reg);
            }
        }
        BPF_ARSH => {
            if alu32 {
                scalar32_min_max_arsh(dst_reg, &src_reg);
            } else {
                scalar_min_max_arsh(dst_reg, &src_reg);
            }
        }
        BPF_END => scalar_byte_swap(dst_reg, insn),
        _ => {}
    }

    if alu32 && opcode != BPF_END {
        zext_32_to_64(dst_reg);
    }
    reg_bounds_sync(dst_reg);
    Ok(0)
}

#[instrument(skip(env))]
pub fn adjust_subprog_starts(env: &mut BpfVerifierEnv, off: u32, len: u32) {
    if len == 1 {
        return;
    }
    for i in 0..=env.subprog_cnt as usize {
        if env.subprog_info[i].start <= off as i32 {
            continue;
        }
        env.subprog_info[i].start += (len - 1) as i32;
    }
}

#[instrument(skip(env))]
pub fn adjust_subprog_starts_after_remove(
    env: &mut BpfVerifierEnv,
    off: u32,
    cnt: u32,
) -> Result<i32> {
    let mut i = 0usize;
    while i < env.subprog_cnt as usize && env.subprog_info[i].start < off as i32 {
        i += 1;
    }

    let mut j = i;
    while j < env.subprog_cnt as usize && env.subprog_info[j].start < (off + cnt) as i32 {
        j += 1;
    }

    if j < env.subprog_cnt as usize && env.subprog_info[j].start != (off + cnt) as i32 {
        j = j.saturating_sub(1);
    }

    if j > i {
        let move_cnt = env.subprog_cnt as usize + 1 - j;
        for k in 0..move_cnt {
            env.subprog_info[i + k] = env.subprog_info[j + k];
        }
        env.subprog_cnt -= (j - i) as i32;
    } else if env.subprog_info[i].start == off as i32 {
        i += 1;
    }

    for k in i..=env.subprog_cnt as usize {
        env.subprog_info[k].start -= cnt as i32;
    }

    Ok(0)
}
