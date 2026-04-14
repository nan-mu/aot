//! Missing types: BpfVerifierEnv, BpfInsn, BpfRegState, BpfFuncProto

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn check_abnormal_return(env: &mut BpfVerifierEnv) -> Result<i32> {
    for i in 1..env.subprog_cnt as usize {
        if env.subprog_info[i].has_ld_abs {
            verbose(env, "LD_ABS is not allowed in subprogs without BTF\n");
            return Err(anyhow!("check_abnormal_return failed"));
        }
        if env.subprog_info[i].has_tail_call {
            verbose(env, "tail_call is not allowed in subprogs without BTF\n");
            return Err(anyhow!("check_abnormal_return failed"));
        }
    }
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn))]
pub fn check_alu_op(env: &mut BpfVerifierEnv, insn: &BpfInsn) -> Result<i32> {
    let regs: &mut [BpfRegState] = cur_regs(env);
    let opcode = BPF_OP(insn.code);

    if opcode == BPF_END || opcode == BPF_NEG {
        if is_pointer_value(env, insn.dst_reg as i32) {
            verbose(env, format!("R{} pointer arithmetic prohibited\n", insn.dst_reg));
            return Err(anyhow!("check_alu_op failed"));
        }

        if regs[insn.dst_reg as usize].r#type == SCALAR_VALUE {
            check_reg_arg(env, insn.dst_reg as i32, DST_OP_NO_MARK)?;
            adjust_scalar_min_max_vals(
                env,
                insn,
                &mut regs[insn.dst_reg as usize],
                regs[insn.dst_reg as usize].clone(),
            )?;
        } else {
            check_reg_arg(env, insn.dst_reg as i32, DST_OP)?;
        }

        return reg_bounds_sanity_check(env, &regs[insn.dst_reg as usize], "alu");
    }

    if opcode > BPF_END {
        verbose(env, format!("invalid BPF_ALU opcode {:x}\n", opcode));
        return Err(anyhow!("check_alu_op failed"));
    }

    check_reg_arg(env, insn.dst_reg as i32, DST_OP_NO_MARK)?;
    adjust_reg_min_max_vals(env, insn)?;
    reg_bounds_sanity_check(env, &regs[insn.dst_reg as usize], "alu")
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(fn_proto))]
pub fn check_arg_pair_ok(fn_proto: &BpfFuncProto) -> Result<bool> {
    let _ = fn_proto;
    Ok(true)
}
