//! Missing types: BpfVerifierEnv, BpfVerifierState, BpfInsn, BpfInsnAuxData, BpfSubprogInfo, BpfProgAux, BpfRegState, BpfSubprogArgInfo, BpfFuncState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn do_check(env: &mut BpfVerifierEnv) -> Result<i32> {
    let pop_log = (env.log.level & BPF_LOG_LEVEL2) == 0;
    let state: &mut BpfVerifierState = env.cur_state;
    let insn_cnt = env.prog.len;
    let mut do_print_state = false;
    let mut prev_insn_idx = -1;

    loop {
        /* reset current history entry on each new instruction */
        env.cur_hist_ent = None;
        env.prev_insn_idx = prev_insn_idx;

        if env.insn_idx >= insn_cnt {
            verbose(
                env,
                format!("invalid insn idx {} insn_cnt {}\n", env.insn_idx, insn_cnt),
            );
            return Err(anyhow!("do_check failed"));
        }

        let insn: &BpfInsn = &env.prog.insnsi[env.insn_idx as usize];
        let insn_aux: &mut BpfInsnAuxData = &mut env.insn_aux_data[env.insn_idx as usize];

        env.insn_processed += 1;
        if env.insn_processed > BPF_COMPLEXITY_LIMIT_INSNS {
            verbose(
                env,
                format!("BPF program is too large. Processed {} insn\n", env.insn_processed),
            );
            return Err(anyhow!("do_check failed"));
        }

        state.last_insn_idx = env.prev_insn_idx;
        state.insn_idx = env.insn_idx;

        sanitize_mark_insn_seen(env);
        prev_insn_idx = env.insn_idx;

        if state.speculative && insn_aux.nospec {
            mark_verifier_state_scratched(env);
            let err = pop_stack(env, &mut prev_insn_idx, &mut env.insn_idx, pop_log);
            if err < 0 {
                break;
            }
            do_print_state = true;
            continue;
        }

        let err = do_check_insn(env, &mut do_print_state)?;
        if err == PROCESS_BPF_EXIT {
            mark_verifier_state_scratched(env);
            let pop_err = pop_stack(env, &mut prev_insn_idx, &mut env.insn_idx, pop_log);
            if pop_err < 0 {
                break;
            }
            do_print_state = true;
            continue;
        }

        if state.speculative && insn_aux.nospec_result {
            if verifier_bug_if(
                (BPF_CLASS(insn.code) == BPF_JMP || BPF_CLASS(insn.code) == BPF_JMP32)
                    && BPF_OP(insn.code) != BPF_CALL,
                env,
                "speculation barrier after jump instruction may not have the desired effect",
            ) {
                return Err(anyhow!("do_check failed"));
            }
        }
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn do_check_common(env: &mut BpfVerifierEnv, subprog: i32) -> Result<i32> {
    let pop_log = (env.log.level & BPF_LOG_LEVEL2) == 0;
    let sub: &BpfSubprogInfo = subprog_info(env, subprog);
    let _aux: &mut BpfProgAux = env.prog.aux;

    env.prev_linfo = None;
    env.pass_cnt += 1;

    let state: &mut BpfVerifierState = alloc_verifier_state(env)?;
    env.cur_state = state;
    init_func_state(env, state.frame[0], BPF_MAIN_FUNC, 0, subprog);
    state.first_insn_idx = env.subprog_info[subprog as usize].start;
    state.last_insn_idx = -1;

    let regs: &mut [BpfRegState] = state.frame[state.curframe as usize].regs;
    if subprog != 0 || env.prog.r#type == BPF_PROG_TYPE_EXT {
        if env.log.level & BPF_LOG_LEVEL != 0 {
            verbose(env, format!("Validating {}() func#{}...\n", subprog_name(env, subprog), subprog));
        }

        btf_prepare_func_args(env, subprog)?;

        for i in BPF_REG_1..=sub.arg_cnt as i32 {
            let arg: &BpfSubprogArgInfo = &sub.args[(i - BPF_REG_1) as usize];
            let reg: &mut BpfRegState = &mut regs[i as usize];

            if arg.arg_type == ARG_PTR_TO_CTX {
                reg.r#type = PTR_TO_CTX;
                mark_reg_known_zero(env, regs, i as u32);
            } else if arg.arg_type == ARG_ANYTHING {
                reg.r#type = SCALAR_VALUE;
                mark_reg_unknown(env, regs, i as u32);
            } else {
                mark_reg_unknown(env, regs, i as u32);
            }
        }
    } else {
        regs[BPF_REG_1 as usize].r#type = PTR_TO_CTX;
        mark_reg_known_zero(env, regs, BPF_REG_1 as u32);
    }

    let ret = do_check(env)?;
    if ret == 0 && pop_log {
        bpf_vlog_reset(&mut env.log, 0);
    }
    free_states(env);
    Ok(ret)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, do_print_state))]
pub fn do_check_insn(env: &mut BpfVerifierEnv, do_print_state: &mut bool) -> Result<i32> {
    let insn: &BpfInsn = &env.prog.insnsi[env.insn_idx as usize];
    let class = BPF_CLASS(insn.code);

    if class == BPF_ALU || class == BPF_ALU64 {
        check_alu_op(env, insn)?;
    } else if class == BPF_LDX {
        let is_ldsx = BPF_MODE(insn.code) == BPF_MEMSX;
        check_load_mem(env, insn, false, is_ldsx, true, "ldx")?;
    } else if class == BPF_STX {
        if BPF_MODE(insn.code) == BPF_ATOMIC {
            check_atomic(env, insn)?;
            env.insn_idx += 1;
            return Ok(0);
        }
        if BPF_MODE(insn.code) != BPF_MEM || insn.imm != 0 {
            verbose(env, "BPF_STX uses reserved fields\n");
            return Err(anyhow!("do_check_insn failed"));
        }
        check_store_reg(env, insn, false)?;
    } else if class == BPF_ST {
        if BPF_MODE(insn.code) != BPF_MEM || insn.src_reg != BPF_REG_0 {
            verbose(env, "BPF_ST uses reserved fields\n");
            return Err(anyhow!("do_check_insn failed"));
        }
        check_reg_arg(env, insn.dst_reg as i32, SRC_OP)?;
    } else if class == BPF_JMP || class == BPF_JMP32 {
        let opcode = BPF_OP(insn.code);
        env.jmps_processed += 1;

        if opcode == BPF_CALL {
            check_helper_call(env, insn, &mut env.insn_idx)?;
            mark_reg_scratched(env, BPF_REG_0 as u32);
        } else if opcode == BPF_EXIT {
            return process_bpf_exit_full(env, do_print_state, false);
        } else {
            check_cond_jmp_op(env, insn, &mut env.insn_idx)?;
        }
    } else if class == BPF_LD {
        let mode = BPF_MODE(insn.code);
        if mode == BPF_ABS || mode == BPF_IND {
            check_ld_abs(env, insn)?;
        } else if mode == BPF_IMM {
            check_ld_imm(env, insn)?;
            env.insn_idx += 1;
            sanitize_mark_insn_seen(env);
        } else {
            verbose(env, "invalid BPF_LD mode\n");
            return Err(anyhow!("do_check_insn failed"));
        }
    } else {
        verbose(env, format!("unknown insn class {}\n", class));
        return Err(anyhow!("do_check_insn failed"));
    }

    env.insn_idx += 1;
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn do_check_main(env: &mut BpfVerifierEnv) -> Result<i32> {
    env.insn_idx = 0;
    let ret = do_check_common(env, 0)?;
    if ret == 0 {
        env.prog.aux.stack_depth = env.subprog_info[0].stack_depth;
    }
    Ok(ret)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn do_check_subprogs(env: &mut BpfVerifierEnv) -> Result<i32> {
    if env.prog.aux.func_info.is_none() {
        return Ok(0);
    }

    if env.exception_callback_subprog != 0 {
        subprog_aux(env, env.exception_callback_subprog).called = true;
    }

    loop {
        let mut new_cnt = 0;
        for i in 1..env.subprog_cnt as usize {
            if !subprog_is_global(env, i as i32) {
                continue;
            }

            let sub_aux = subprog_aux(env, i as i32);
            if !sub_aux.called || sub_aux.verified {
                continue;
            }

            env.insn_idx = env.subprog_info[i].start;
            let ret = do_check_common(env, i as i32)?;
            if ret != 0 {
                return Err(anyhow!("do_check_subprogs failed"));
            }

            if env.log.level & BPF_LOG_LEVEL != 0 {
                verbose(
                    env,
                    format!(
                        "Func#{} ('{}') is safe for any args that match its prototype\n",
                        i,
                        subprog_name(env, i as i32)
                    ),
                );
            }

            sub_aux.verified = true;
            new_cnt += 1;
        }

        /* We can't loop forever as we verify at least one global subprog on each pass. */
        if new_cnt == 0 {
            break;
        }
    }

    Ok(0)
}
