//! Missing types: BpfVerifierEnv, BpfInsn, BpfRegState, BpfSanitizeInfo, BpfInsnAuxData, BpfVerifierState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn, dst_reg))]
pub fn sanitize_check_bounds(
    env: &mut BpfVerifierEnv,
    insn: &BpfInsn,
    dst_reg: &BpfRegState,
) -> Result<i32> {
    let dst = insn.dst_reg as i32;

    if env.bypass_spec_v1 {
        return Ok(0);
    }

    match dst_reg.r#type {
        PTR_TO_STACK => {
            if check_stack_access_for_ptr_arithmetic(env, dst, dst_reg, dst_reg.off + dst_reg.var_off.value as i32) != 0 {
                return Err(anyhow!("sanitize_check_bounds failed"));
            }
        }
        PTR_TO_MAP_VALUE => {
            if check_map_access(env, dst, dst_reg.off, 1, false, ACCESS_HELPER) != 0 {
                verbose(env, format!("R{} pointer arithmetic of map value goes out of range, prohibited for !root\n", dst));
                return Err(anyhow!("sanitize_check_bounds failed"));
            }
        }
        _ => return Err(anyhow!("sanitize_check_bounds failed")),
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn sanitize_dead_code(env: &mut BpfVerifierEnv) -> Result<()> {
    let trap = BPF_JMP_IMM(BPF_JA, 0, 0, -1);
    let insn_cnt = env.prog.len as usize;

    for i in 0..insn_cnt {
        if env.insn_aux_data[i].seen {
            continue;
        }
        env.prog.insnsi[i] = trap;
        env.insn_aux_data[i].zext_dst = false;
    }

    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn, off_reg, dst_reg))]
pub fn sanitize_err(
    env: &mut BpfVerifierEnv,
    insn: &BpfInsn,
    reason: i32,
    off_reg: &BpfRegState,
    dst_reg: &BpfRegState,
) -> Result<i32> {
    let err = "pointer arithmetic with it prohibited for !root";
    let op = if BPF_OP(insn.code) == BPF_ADD { "add" } else { "sub" };
    let dst = insn.dst_reg;
    let src = insn.src_reg;

    match reason {
        REASON_BOUNDS => verbose(env, format!("R{} has unknown scalar with mixed signed bounds, {}\n", if core::ptr::eq(off_reg, dst_reg) { dst } else { src }, err)),
        REASON_TYPE => verbose(env, format!("R{} has pointer with unsupported alu operation, {}\n", if core::ptr::eq(off_reg, dst_reg) { src } else { dst }, err)),
        REASON_PATHS => verbose(env, format!("R{} tried to {} from different maps, paths or scalars, {}\n", dst, op, err)),
        REASON_LIMIT => verbose(env, format!("R{} tried to {} beyond pointer bounds, {}\n", dst, op, err)),
        REASON_STACK => {
            verbose(env, format!("R{} could not be pushed for speculative verification, {}\n", dst, err));
            return Err(anyhow!("sanitize_err failed"));
        }
        _ => return Err(anyhow!("sanitize_err failed")),
    }

    Err(anyhow!("sanitize_err failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn sanitize_mark_insn_seen(env: &mut BpfVerifierEnv) -> Result<()> {
    if !env.cur_state.speculative {
        env.insn_aux_data[env.insn_idx as usize].seen = env.pass_cnt;
    }
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn sanitize_needed(opcode: u8) -> Result<bool> {
    Ok(opcode == BPF_ADD || opcode == BPF_SUB)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn, ptr_reg, off_reg, dst_reg, info))]
pub fn sanitize_ptr_alu(
    env: &mut BpfVerifierEnv,
    insn: &mut BpfInsn,
    ptr_reg: &BpfRegState,
    off_reg: &BpfRegState,
    dst_reg: &mut BpfRegState,
    info: &mut BpfSanitizeInfo,
    commit_window: bool,
) -> Result<i32> {
    let aux: &mut BpfInsnAuxData = if commit_window { cur_aux(env) } else { &mut info.aux };
    let vstate = &env.cur_state;
    let off_is_imm = tnum_is_const(off_reg.var_off);
    let off_is_neg = off_reg.smin_value < 0;
    let ptr_is_dst_reg = core::ptr::eq(ptr_reg, dst_reg);
    let opcode = BPF_OP(insn.code);

    if can_skip_alu_sanitation(env, insn) {
        return Ok(0);
    }

    if vstate.speculative {
        if commit_window || off_is_imm {
            return Ok(0);
        }
        if !ptr_is_dst_reg {
            let tmp = *dst_reg;
            copy_register_state(dst_reg, ptr_reg);
            let err = sanitize_speculative_path(env, None, env.insn_idx as u32 + 1, env.insn_idx as u32)?;
            *dst_reg = tmp;
            return Ok(err);
        }
        return sanitize_speculative_path(env, None, env.insn_idx as u32 + 1, env.insn_idx as u32);
    }

    if !commit_window {
        if !tnum_is_const(off_reg.var_off) && (off_reg.smin_value < 0) != (off_reg.smax_value < 0) {
            return Ok(REASON_BOUNDS);
        }
        info.mask_to_left = (opcode == BPF_ADD && off_is_neg) || (opcode == BPF_SUB && !off_is_neg);
    }

    let mut alu_limit = 0u32;
    let err = retrieve_ptr_limit(ptr_reg, &mut alu_limit, info.mask_to_left)?;
    if err < 0 {
        return Ok(err);
    }

    let alu_state = if commit_window {
        alu_limit = (info.aux.alu_limit as i64 - alu_limit as i64).abs() as u32;
        info.aux.alu_state
    } else {
        let mut s = if off_is_neg { BPF_ALU_NEG_VALUE } else { 0 };
        if off_is_imm {
            s |= BPF_ALU_IMMEDIATE;
        }
        s |= if ptr_is_dst_reg { BPF_ALU_SANITIZE_SRC } else { BPF_ALU_SANITIZE_DST };
        if !off_is_imm {
            env.explore_alu_limits = true;
        }
        s
    };

    update_alu_sanitation_state(aux, alu_state, alu_limit)?;

    if commit_window || off_is_imm {
        return Ok(0);
    }

    if !ptr_is_dst_reg {
        let tmp = *dst_reg;
        copy_register_state(dst_reg, ptr_reg);
        let err = sanitize_speculative_path(env, None, env.insn_idx as u32 + 1, env.insn_idx as u32)?;
        *dst_reg = tmp;
        if err < 0 {
            return Ok(REASON_STACK);
        }
        return Ok(0);
    }

    let err = sanitize_speculative_path(env, None, env.insn_idx as u32 + 1, env.insn_idx as u32)?;
    if err < 0 {
        return Ok(REASON_STACK);
    }
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn))]
pub fn sanitize_speculative_path(
    env: &mut BpfVerifierEnv,
    insn: Option<&BpfInsn>,
    next_idx: u32,
    curr_idx: u32,
) -> Result<i32> {
    let branch = push_stack(env, next_idx as i32, curr_idx as i32, true);
    if let Ok(b) = branch {
        if let Some(i) = insn {
            let regs = &mut b.frame[b.curframe as usize].regs;
            if BPF_SRC(i.code) == BPF_K {
                mark_reg_unknown(env, regs, i.dst_reg as u32)?;
            } else if BPF_SRC(i.code) == BPF_X {
                mark_reg_unknown(env, regs, i.dst_reg as u32)?;
                mark_reg_unknown(env, regs, i.src_reg as u32)?;
            }
        }
        return Ok(0);
    }
    Ok(-1)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn))]
pub fn sanitize_val_alu(env: &mut BpfVerifierEnv, insn: &mut BpfInsn) -> Result<i32> {
    if can_skip_alu_sanitation(env, insn) {
        return Ok(0);
    }
    update_alu_sanitation_state(cur_aux(env), BPF_ALU_NON_POINTER, 0)
}
