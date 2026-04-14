// Extracted from /Users/nan/bs/aot/src/verifier.c
static int do_check(struct bpf_verifier_env *env)
{
	bool pop_log = !(env->log.level & BPF_LOG_LEVEL2);
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_insn *insns = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	bool do_print_state = false;
	int prev_insn_idx = -1;

	for (;;) {
		struct bpf_insn *insn;
		struct bpf_insn_aux_data *insn_aux;
		int err, marks_err;

		/* reset current history entry on each new instruction */
		env->cur_hist_ent = NULL;

		env->prev_insn_idx = prev_insn_idx;
		if (env->insn_idx >= insn_cnt) {
			verbose(env, "invalid insn idx %d insn_cnt %d\n",
				env->insn_idx, insn_cnt);
			return -EFAULT;
		}

		insn = &insns[env->insn_idx];
		insn_aux = &env->insn_aux_data[env->insn_idx];

		if (++env->insn_processed > BPF_COMPLEXITY_LIMIT_INSNS) {
			verbose(env,
				"BPF program is too large. Processed %d insn\n",
				env->insn_processed);
			return -E2BIG;
		}

		state->last_insn_idx = env->prev_insn_idx;
		state->insn_idx = env->insn_idx;

		if (is_prune_point(env, env->insn_idx)) {
			err = is_state_visited(env, env->insn_idx);
			if (err < 0)
				return err;
			if (err == 1) {
				/* found equivalent state, can prune the search */
				if (env->log.level & BPF_LOG_LEVEL) {
					if (do_print_state)
						verbose(env, "\nfrom %d to %d%s: safe\n",
							env->prev_insn_idx, env->insn_idx,
							env->cur_state->speculative ?
							" (speculative execution)" : "");
					else
						verbose(env, "%d: safe\n", env->insn_idx);
				}
				goto process_bpf_exit;
			}
		}

		if (is_jmp_point(env, env->insn_idx)) {
			err = push_jmp_history(env, state, 0, 0);
			if (err)
				return err;
		}

		if (signal_pending(current))
			return -EAGAIN;

		if (need_resched())
			cond_resched();

		if (env->log.level & BPF_LOG_LEVEL2 && do_print_state) {
			verbose(env, "\nfrom %d to %d%s:",
				env->prev_insn_idx, env->insn_idx,
				env->cur_state->speculative ?
				" (speculative execution)" : "");
			print_verifier_state(env, state, state->curframe, true);
			do_print_state = false;
		}

		if (env->log.level & BPF_LOG_LEVEL) {
			if (verifier_state_scratched(env))
				print_insn_state(env, state, state->curframe);

			verbose_linfo(env, env->insn_idx, "; ");
			env->prev_log_pos = env->log.end_pos;
			verbose(env, "%d: ", env->insn_idx);
			verbose_insn(env, insn);
			env->prev_insn_print_pos = env->log.end_pos - env->prev_log_pos;
			env->prev_log_pos = env->log.end_pos;
		}

		if (bpf_prog_is_offloaded(env->prog->aux)) {
			err = bpf_prog_offload_verify_insn(env, env->insn_idx,
							   env->prev_insn_idx);
			if (err)
				return err;
		}

		sanitize_mark_insn_seen(env);
		prev_insn_idx = env->insn_idx;

		/* Reduce verification complexity by stopping speculative path
		 * verification when a nospec is encountered.
		 */
		if (state->speculative && insn_aux->nospec)
			goto process_bpf_exit;

		err = bpf_reset_stack_write_marks(env, env->insn_idx);
		if (err)
			return err;
		err = do_check_insn(env, &do_print_state);
		if (err >= 0 || error_recoverable_with_nospec(err)) {
			marks_err = bpf_commit_stack_write_marks(env);
			if (marks_err)
				return marks_err;
		}
		if (error_recoverable_with_nospec(err) && state->speculative) {
			/* Prevent this speculative path from ever reaching the
			 * insn that would have been unsafe to execute.
			 */
			insn_aux->nospec = true;
			/* If it was an ADD/SUB insn, potentially remove any
			 * markings for alu sanitization.
			 */
			insn_aux->alu_state = 0;
			goto process_bpf_exit;
		} else if (err < 0) {
			return err;
		} else if (err == PROCESS_BPF_EXIT) {
			goto process_bpf_exit;
		}
		WARN_ON_ONCE(err);

		if (state->speculative && insn_aux->nospec_result) {
			/* If we are on a path that performed a jump-op, this
			 * may skip a nospec patched-in after the jump. This can
			 * currently never happen because nospec_result is only
			 * used for the write-ops
			 * `*(size*)(dst_reg+off)=src_reg|imm32` and helper
			 * calls. These must never skip the following insn
			 * (i.e., bpf_insn_successors()'s opcode_info.can_jump
			 * is false). Still, add a warning to document this in
			 * case nospec_result is used elsewhere in the future.
			 *
			 * All non-branch instructions have a single
			 * fall-through edge. For these, nospec_result should
			 * already work.
			 */
			if (verifier_bug_if((BPF_CLASS(insn->code) == BPF_JMP ||
					     BPF_CLASS(insn->code) == BPF_JMP32) &&
					    BPF_OP(insn->code) != BPF_CALL, env,
					    "speculation barrier after jump instruction may not have the desired effect"))
				return -EFAULT;
process_bpf_exit:
			mark_verifier_state_scratched(env);
			err = update_branch_counts(env, env->cur_state);
			if (err)
				return err;
			err = bpf_update_live_stack(env);
			if (err)
				return err;
			err = pop_stack(env, &prev_insn_idx, &env->insn_idx,
					pop_log);
			if (err < 0) {
				if (err != -ENOENT)
					return err;
				break;
			} else {
				do_print_state = true;
				continue;
			}
		}
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int do_check_common(struct bpf_verifier_env *env, int subprog)
{
	bool pop_log = !(env->log.level & BPF_LOG_LEVEL2);
	struct bpf_subprog_info *sub = subprog_info(env, subprog);
	struct bpf_prog_aux *aux = env->prog->aux;
	struct bpf_verifier_state *state;
	struct bpf_reg_state *regs;
	int ret, i;

	env->prev_linfo = NULL;
	env->pass_cnt++;

	state = kzalloc_obj(struct bpf_verifier_state, GFP_KERNEL_ACCOUNT);
	if (!state)
		return -ENOMEM;
	state->curframe = 0;
	state->speculative = false;
	state->branches = 1;
	state->in_sleepable = env->prog->sleepable;
	state->frame[0] = kzalloc_obj(struct bpf_func_state, GFP_KERNEL_ACCOUNT);
	if (!state->frame[0]) {
		kfree(state);
		return -ENOMEM;
	}
	env->cur_state = state;
	init_func_state(env, state->frame[0],
			BPF_MAIN_FUNC /* callsite */,
			0 /* frameno */,
			subprog);
	state->first_insn_idx = env->subprog_info[subprog].start;
	state->last_insn_idx = -1;

	regs = state->frame[state->curframe]->regs;
	if (subprog || env->prog->type == BPF_PROG_TYPE_EXT) {
		const char *sub_name = subprog_name(env, subprog);
		struct bpf_subprog_arg_info *arg;
		struct bpf_reg_state *reg;

		if (env->log.level & BPF_LOG_LEVEL)
			verbose(env, "Validating %s() func#%d...\n", sub_name, subprog);
		ret = btf_prepare_func_args(env, subprog);
		if (ret)
			goto out;

		if (subprog_is_exc_cb(env, subprog)) {
			state->frame[0]->in_exception_callback_fn = true;
			/* We have already ensured that the callback returns an integer, just
			 * like all global subprogs. We need to determine it only has a single
			 * scalar argument.
			 */
			if (sub->arg_cnt != 1 || sub->args[0].arg_type != ARG_ANYTHING) {
				verbose(env, "exception cb only supports single integer argument\n");
				ret = -EINVAL;
				goto out;
			}
		}
		for (i = BPF_REG_1; i <= sub->arg_cnt; i++) {
			arg = &sub->args[i - BPF_REG_1];
			reg = &regs[i];

			if (arg->arg_type == ARG_PTR_TO_CTX) {
				reg->type = PTR_TO_CTX;
				mark_reg_known_zero(env, regs, i);
			} else if (arg->arg_type == ARG_ANYTHING) {
				reg->type = SCALAR_VALUE;
				mark_reg_unknown(env, regs, i);
			} else if (arg->arg_type == (ARG_PTR_TO_DYNPTR | MEM_RDONLY)) {
				/* assume unspecial LOCAL dynptr type */
				inner_mark_dynptr_reg(reg, BPF_DYNPTR_TYPE_LOCAL, true, ++env->id_gen);
			} else if (base_type(arg->arg_type) == ARG_PTR_TO_MEM) {
				reg->type = PTR_TO_MEM;
				reg->type |= arg->arg_type &
					     (PTR_MAYBE_NULL | PTR_UNTRUSTED | MEM_RDONLY);
				mark_reg_known_zero(env, regs, i);
				reg->mem_size = arg->mem_size;
				if (arg->arg_type & PTR_MAYBE_NULL)
					reg->id = ++env->id_gen;
			} else if (base_type(arg->arg_type) == ARG_PTR_TO_BTF_ID) {
				reg->type = PTR_TO_BTF_ID;
				if (arg->arg_type & PTR_MAYBE_NULL)
					reg->type |= PTR_MAYBE_NULL;
				if (arg->arg_type & PTR_UNTRUSTED)
					reg->type |= PTR_UNTRUSTED;
				if (arg->arg_type & PTR_TRUSTED)
					reg->type |= PTR_TRUSTED;
				mark_reg_known_zero(env, regs, i);
				reg->btf = bpf_get_btf_vmlinux(); /* can't fail at this point */
				reg->btf_id = arg->btf_id;
				reg->id = ++env->id_gen;
			} else if (base_type(arg->arg_type) == ARG_PTR_TO_ARENA) {
				/* caller can pass either PTR_TO_ARENA or SCALAR */
				mark_reg_unknown(env, regs, i);
			} else {
				verifier_bug(env, "unhandled arg#%d type %d",
					     i - BPF_REG_1, arg->arg_type);
				ret = -EFAULT;
				goto out;
			}
		}
	} else {
		/* if main BPF program has associated BTF info, validate that
		 * it's matching expected signature, and otherwise mark BTF
		 * info for main program as unreliable
		 */
		if (env->prog->aux->func_info_aux) {
			ret = btf_prepare_func_args(env, 0);
			if (ret || sub->arg_cnt != 1 || sub->args[0].arg_type != ARG_PTR_TO_CTX)
				env->prog->aux->func_info_aux[0].unreliable = true;
		}

		/* 1st arg to a function */
		regs[BPF_REG_1].type = PTR_TO_CTX;
		mark_reg_known_zero(env, regs, BPF_REG_1);
	}

	/* Acquire references for struct_ops program arguments tagged with "__ref" */
	if (!subprog && env->prog->type == BPF_PROG_TYPE_STRUCT_OPS) {
		for (i = 0; i < aux->ctx_arg_info_size; i++)
			aux->ctx_arg_info[i].ref_obj_id = aux->ctx_arg_info[i].refcounted ?
							  acquire_reference(env, 0) : 0;
	}

	ret = do_check(env);
out:
	if (!ret && pop_log)
		bpf_vlog_reset(&env->log, 0);
	free_states(env);
	return ret;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int do_check_insn(struct bpf_verifier_env *env, bool *do_print_state)
{
	int err;
	struct bpf_insn *insn = &env->prog->insnsi[env->insn_idx];
	u8 class = BPF_CLASS(insn->code);

	if (class == BPF_ALU || class == BPF_ALU64) {
		err = check_alu_op(env, insn);
		if (err)
			return err;

	} else if (class == BPF_LDX) {
		bool is_ldsx = BPF_MODE(insn->code) == BPF_MEMSX;

		/* Check for reserved fields is already done in
		 * resolve_pseudo_ldimm64().
		 */
		err = check_load_mem(env, insn, false, is_ldsx, true, "ldx");
		if (err)
			return err;
	} else if (class == BPF_STX) {
		if (BPF_MODE(insn->code) == BPF_ATOMIC) {
			err = check_atomic(env, insn);
			if (err)
				return err;
			env->insn_idx++;
			return 0;
		}

		if (BPF_MODE(insn->code) != BPF_MEM || insn->imm != 0) {
			verbose(env, "BPF_STX uses reserved fields\n");
			return -EINVAL;
		}

		err = check_store_reg(env, insn, false);
		if (err)
			return err;
	} else if (class == BPF_ST) {
		enum bpf_reg_type dst_reg_type;

		if (BPF_MODE(insn->code) != BPF_MEM ||
		    insn->src_reg != BPF_REG_0) {
			verbose(env, "BPF_ST uses reserved fields\n");
			return -EINVAL;
		}
		/* check src operand */
		err = check_reg_arg(env, insn->dst_reg, SRC_OP);
		if (err)
			return err;

		dst_reg_type = cur_regs(env)[insn->dst_reg].type;

		/* check that memory (dst_reg + off) is writeable */
		err = check_mem_access(env, env->insn_idx, insn->dst_reg,
				       insn->off, BPF_SIZE(insn->code),
				       BPF_WRITE, -1, false, false);
		if (err)
			return err;

		err = save_aux_ptr_type(env, dst_reg_type, false);
		if (err)
			return err;
	} else if (class == BPF_JMP || class == BPF_JMP32) {
		u8 opcode = BPF_OP(insn->code);

		env->jmps_processed++;
		if (opcode == BPF_CALL) {
			if (BPF_SRC(insn->code) != BPF_K ||
			    (insn->src_reg != BPF_PSEUDO_KFUNC_CALL &&
			     insn->off != 0) ||
			    (insn->src_reg != BPF_REG_0 &&
			     insn->src_reg != BPF_PSEUDO_CALL &&
			     insn->src_reg != BPF_PSEUDO_KFUNC_CALL) ||
			    insn->dst_reg != BPF_REG_0 || class == BPF_JMP32) {
				verbose(env, "BPF_CALL uses reserved fields\n");
				return -EINVAL;
			}

			if (env->cur_state->active_locks) {
				if ((insn->src_reg == BPF_REG_0 &&
				     insn->imm != BPF_FUNC_spin_unlock) ||
				    (insn->src_reg == BPF_PSEUDO_KFUNC_CALL &&
				     (insn->off != 0 || !kfunc_spin_allowed(insn->imm)))) {
					verbose(env,
						"function calls are not allowed while holding a lock\n");
					return -EINVAL;
				}
			}
			if (insn->src_reg == BPF_PSEUDO_CALL) {
				err = check_func_call(env, insn, &env->insn_idx);
			} else if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL) {
				err = check_kfunc_call(env, insn, &env->insn_idx);
				if (!err && is_bpf_throw_kfunc(insn))
					return process_bpf_exit_full(env, do_print_state, true);
			} else {
				err = check_helper_call(env, insn, &env->insn_idx);
			}
			if (err)
				return err;

			mark_reg_scratched(env, BPF_REG_0);
		} else if (opcode == BPF_JA) {
			if (BPF_SRC(insn->code) == BPF_X) {
				if (insn->src_reg != BPF_REG_0 ||
				    insn->imm != 0 || insn->off != 0) {
					verbose(env, "BPF_JA|BPF_X uses reserved fields\n");
					return -EINVAL;
				}
				return check_indirect_jump(env, insn);
			}

			if (BPF_SRC(insn->code) != BPF_K ||
			    insn->src_reg != BPF_REG_0 ||
			    insn->dst_reg != BPF_REG_0 ||
			    (class == BPF_JMP && insn->imm != 0) ||
			    (class == BPF_JMP32 && insn->off != 0)) {
				verbose(env, "BPF_JA uses reserved fields\n");
				return -EINVAL;
			}

			if (class == BPF_JMP)
				env->insn_idx += insn->off + 1;
			else
				env->insn_idx += insn->imm + 1;
			return 0;
		} else if (opcode == BPF_EXIT) {
			if (BPF_SRC(insn->code) != BPF_K ||
			    insn->imm != 0 ||
			    insn->src_reg != BPF_REG_0 ||
			    insn->dst_reg != BPF_REG_0 ||
			    class == BPF_JMP32) {
				verbose(env, "BPF_EXIT uses reserved fields\n");
				return -EINVAL;
			}
			return process_bpf_exit_full(env, do_print_state, false);
		} else {
			err = check_cond_jmp_op(env, insn, &env->insn_idx);
			if (err)
				return err;
		}
	} else if (class == BPF_LD) {
		u8 mode = BPF_MODE(insn->code);

		if (mode == BPF_ABS || mode == BPF_IND) {
			err = check_ld_abs(env, insn);
			if (err)
				return err;

		} else if (mode == BPF_IMM) {
			err = check_ld_imm(env, insn);
			if (err)
				return err;

			env->insn_idx++;
			sanitize_mark_insn_seen(env);
		} else {
			verbose(env, "invalid BPF_LD mode\n");
			return -EINVAL;
		}
	} else {
		verbose(env, "unknown insn class %d\n", class);
		return -EINVAL;
	}

	env->insn_idx++;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int do_check_main(struct bpf_verifier_env *env)
{
	int ret;

	env->insn_idx = 0;
	ret = do_check_common(env, 0);
	if (!ret)
		env->prog->aux->stack_depth = env->subprog_info[0].stack_depth;
	return ret;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int do_check_subprogs(struct bpf_verifier_env *env)
{
	struct bpf_prog_aux *aux = env->prog->aux;
	struct bpf_func_info_aux *sub_aux;
	int i, ret, new_cnt;

	if (!aux->func_info)
		return 0;

	/* exception callback is presumed to be always called */
	if (env->exception_callback_subprog)
		subprog_aux(env, env->exception_callback_subprog)->called = true;

again:
	new_cnt = 0;
	for (i = 1; i < env->subprog_cnt; i++) {
		if (!subprog_is_global(env, i))
			continue;

		sub_aux = subprog_aux(env, i);
		if (!sub_aux->called || sub_aux->verified)
			continue;

		env->insn_idx = env->subprog_info[i].start;
		WARN_ON_ONCE(env->insn_idx == 0);
		ret = do_check_common(env, i);
		if (ret) {
			return ret;
		} else if (env->log.level & BPF_LOG_LEVEL) {
			verbose(env, "Func#%d ('%s') is safe for any args that match its prototype\n",
				i, subprog_name(env, i));
		}

		/* We verified new global subprog, it might have called some
		 * more global subprogs that we haven't verified yet, so we
		 * need to do another pass over subprogs to verify those.
		 */
		sub_aux->verified = true;
		new_cnt++;
	}

	/* We can't loop forever as we verify at least one global subprog on
	 * each pass.
	 */
	if (new_cnt)
		goto again;

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int do_misc_fixups(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog;
	enum bpf_attach_type eatype = prog->expected_attach_type;
	enum bpf_prog_type prog_type = resolve_prog_type(prog);
	struct bpf_insn *insn = prog->insnsi;
	const struct bpf_func_proto *fn;
	const int insn_cnt = prog->len;
	const struct bpf_map_ops *ops;
	struct bpf_insn_aux_data *aux;
	struct bpf_insn *insn_buf = env->insn_buf;
	struct bpf_prog *new_prog;
	struct bpf_map *map_ptr;
	int i, ret, cnt, delta = 0, cur_subprog = 0;
	struct bpf_subprog_info *subprogs = env->subprog_info;
	u16 stack_depth = subprogs[cur_subprog].stack_depth;
	u16 stack_depth_extra = 0;

	if (env->seen_exception && !env->exception_callback_subprog) {
		struct bpf_insn *patch = insn_buf;

		*patch++ = env->prog->insnsi[insn_cnt - 1];
		*patch++ = BPF_MOV64_REG(BPF_REG_0, BPF_REG_1);
		*patch++ = BPF_EXIT_INSN();
		ret = add_hidden_subprog(env, insn_buf, patch - insn_buf);
		if (ret < 0)
			return ret;
		prog = env->prog;
		insn = prog->insnsi;

		env->exception_callback_subprog = env->subprog_cnt - 1;
		/* Don't update insn_cnt, as add_hidden_subprog always appends insns */
		mark_subprog_exc_cb(env, env->exception_callback_subprog);
	}

	for (i = 0; i < insn_cnt;) {
		if (insn->code == (BPF_ALU64 | BPF_MOV | BPF_X) && insn->imm) {
			if ((insn->off == BPF_ADDR_SPACE_CAST && insn->imm == 1) ||
			    (((struct bpf_map *)env->prog->aux->arena)->map_flags & BPF_F_NO_USER_CONV)) {
				/* convert to 32-bit mov that clears upper 32-bit */
				insn->code = BPF_ALU | BPF_MOV | BPF_X;
				/* clear off and imm, so it's a normal 'wX = wY' from JIT pov */
				insn->off = 0;
				insn->imm = 0;
			} /* cast from as(0) to as(1) should be handled by JIT */
			goto next_insn;
		}

		if (env->insn_aux_data[i + delta].needs_zext)
			/* Convert BPF_CLASS(insn->code) == BPF_ALU64 to 32-bit ALU */
			insn->code = BPF_ALU | BPF_OP(insn->code) | BPF_SRC(insn->code);

		/* Make sdiv/smod divide-by-minus-one exceptions impossible. */
		if ((insn->code == (BPF_ALU64 | BPF_MOD | BPF_K) ||
		     insn->code == (BPF_ALU64 | BPF_DIV | BPF_K) ||
		     insn->code == (BPF_ALU | BPF_MOD | BPF_K) ||
		     insn->code == (BPF_ALU | BPF_DIV | BPF_K)) &&
		    insn->off == 1 && insn->imm == -1) {
			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;
			bool isdiv = BPF_OP(insn->code) == BPF_DIV;
			struct bpf_insn *patch = insn_buf;

			if (isdiv)
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_NEG | BPF_K, insn->dst_reg,
							0, 0, 0);
			else
				*patch++ = BPF_MOV32_IMM(insn->dst_reg, 0);

			cnt = patch - insn_buf;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Make divide-by-zero and divide-by-minus-one exceptions impossible. */
		if (insn->code == (BPF_ALU64 | BPF_MOD | BPF_X) ||
		    insn->code == (BPF_ALU64 | BPF_DIV | BPF_X) ||
		    insn->code == (BPF_ALU | BPF_MOD | BPF_X) ||
		    insn->code == (BPF_ALU | BPF_DIV | BPF_X)) {
			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;
			bool isdiv = BPF_OP(insn->code) == BPF_DIV;
			bool is_sdiv = isdiv && insn->off == 1;
			bool is_smod = !isdiv && insn->off == 1;
			struct bpf_insn *patch = insn_buf;

			if (is_sdiv) {
				/* [R,W]x sdiv 0 -> 0
				 * LLONG_MIN sdiv -1 -> LLONG_MIN
				 * INT_MIN sdiv -1 -> INT_MIN
				 */
				*patch++ = BPF_MOV64_REG(BPF_REG_AX, insn->src_reg);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_ADD | BPF_K, BPF_REG_AX,
							0, 0, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JGT | BPF_K, BPF_REG_AX,
							0, 4, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JEQ | BPF_K, BPF_REG_AX,
							0, 1, 0);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_MOV | BPF_K, insn->dst_reg,
							0, 0, 0);
				/* BPF_NEG(LLONG_MIN) == -LLONG_MIN == LLONG_MIN */
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_NEG | BPF_K, insn->dst_reg,
							0, 0, 0);
				*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
				*patch++ = *insn;
				cnt = patch - insn_buf;
			} else if (is_smod) {
				/* [R,W]x mod 0 -> [R,W]x */
				/* [R,W]x mod -1 -> 0 */
				*patch++ = BPF_MOV64_REG(BPF_REG_AX, insn->src_reg);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_ALU64 : BPF_ALU) |
							BPF_ADD | BPF_K, BPF_REG_AX,
							0, 0, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JGT | BPF_K, BPF_REG_AX,
							0, 3, 1);
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JEQ | BPF_K, BPF_REG_AX,
							0, 3 + (is64 ? 0 : 1), 1);
				*patch++ = BPF_MOV32_IMM(insn->dst_reg, 0);
				*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
				*patch++ = *insn;

				if (!is64) {
					*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
					*patch++ = BPF_MOV32_REG(insn->dst_reg, insn->dst_reg);
				}
				cnt = patch - insn_buf;
			} else if (isdiv) {
				/* [R,W]x div 0 -> 0 */
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JNE | BPF_K, insn->src_reg,
							0, 2, 0);
				*patch++ = BPF_ALU32_REG(BPF_XOR, insn->dst_reg, insn->dst_reg);
				*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
				*patch++ = *insn;
				cnt = patch - insn_buf;
			} else {
				/* [R,W]x mod 0 -> [R,W]x */
				*patch++ = BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
							BPF_JEQ | BPF_K, insn->src_reg,
							0, 1 + (is64 ? 0 : 1), 0);
				*patch++ = *insn;

				if (!is64) {
					*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
					*patch++ = BPF_MOV32_REG(insn->dst_reg, insn->dst_reg);
				}
				cnt = patch - insn_buf;
			}

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Make it impossible to de-reference a userspace address */
		if (BPF_CLASS(insn->code) == BPF_LDX &&
		    (BPF_MODE(insn->code) == BPF_PROBE_MEM ||
		     BPF_MODE(insn->code) == BPF_PROBE_MEMSX)) {
			struct bpf_insn *patch = insn_buf;
			u64 uaddress_limit = bpf_arch_uaddress_limit();

			if (!uaddress_limit)
				goto next_insn;

			*patch++ = BPF_MOV64_REG(BPF_REG_AX, insn->src_reg);
			if (insn->off)
				*patch++ = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, insn->off);
			*patch++ = BPF_ALU64_IMM(BPF_RSH, BPF_REG_AX, 32);
			*patch++ = BPF_JMP_IMM(BPF_JLE, BPF_REG_AX, uaddress_limit >> 32, 2);
			*patch++ = *insn;
			*patch++ = BPF_JMP_IMM(BPF_JA, 0, 0, 1);
			*patch++ = BPF_MOV64_IMM(insn->dst_reg, 0);

			cnt = patch - insn_buf;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement LD_ABS and LD_IND with a rewrite, if supported by the program type. */
		if (BPF_CLASS(insn->code) == BPF_LD &&
		    (BPF_MODE(insn->code) == BPF_ABS ||
		     BPF_MODE(insn->code) == BPF_IND)) {
			cnt = env->ops->gen_ld_abs(insn, insn_buf);
			if (cnt == 0 || cnt >= INSN_BUF_SIZE) {
				verifier_bug(env, "%d insns generated for ld_abs", cnt);
				return -EFAULT;
			}

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Rewrite pointer arithmetic to mitigate speculation attacks. */
		if (insn->code == (BPF_ALU64 | BPF_ADD | BPF_X) ||
		    insn->code == (BPF_ALU64 | BPF_SUB | BPF_X)) {
			const u8 code_add = BPF_ALU64 | BPF_ADD | BPF_X;
			const u8 code_sub = BPF_ALU64 | BPF_SUB | BPF_X;
			struct bpf_insn *patch = insn_buf;
			bool issrc, isneg, isimm;
			u32 off_reg;

			aux = &env->insn_aux_data[i + delta];
			if (!aux->alu_state ||
			    aux->alu_state == BPF_ALU_NON_POINTER)
				goto next_insn;

			isneg = aux->alu_state & BPF_ALU_NEG_VALUE;
			issrc = (aux->alu_state & BPF_ALU_SANITIZE) ==
				BPF_ALU_SANITIZE_SRC;
			isimm = aux->alu_state & BPF_ALU_IMMEDIATE;

			off_reg = issrc ? insn->src_reg : insn->dst_reg;
			if (isimm) {
				*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);
			} else {
				if (isneg)
					*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);
				*patch++ = BPF_MOV32_IMM(BPF_REG_AX, aux->alu_limit);
				*patch++ = BPF_ALU64_REG(BPF_SUB, BPF_REG_AX, off_reg);
				*patch++ = BPF_ALU64_REG(BPF_OR, BPF_REG_AX, off_reg);
				*patch++ = BPF_ALU64_IMM(BPF_NEG, BPF_REG_AX, 0);
				*patch++ = BPF_ALU64_IMM(BPF_ARSH, BPF_REG_AX, 63);
				*patch++ = BPF_ALU64_REG(BPF_AND, BPF_REG_AX, off_reg);
			}
			if (!issrc)
				*patch++ = BPF_MOV64_REG(insn->dst_reg, insn->src_reg);
			insn->src_reg = BPF_REG_AX;
			if (isneg)
				insn->code = insn->code == code_add ?
					     code_sub : code_add;
			*patch++ = *insn;
			if (issrc && isneg && !isimm)
				*patch++ = BPF_ALU64_IMM(BPF_MUL, off_reg, -1);
			cnt = patch - insn_buf;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		if (is_may_goto_insn(insn) && bpf_jit_supports_timed_may_goto()) {
			int stack_off_cnt = -stack_depth - 16;

			/*
			 * Two 8 byte slots, depth-16 stores the count, and
			 * depth-8 stores the start timestamp of the loop.
			 *
			 * The starting value of count is BPF_MAX_TIMED_LOOPS
			 * (0xffff).  Every iteration loads it and subs it by 1,
			 * until the value becomes 0 in AX (thus, 1 in stack),
			 * after which we call arch_bpf_timed_may_goto, which
			 * either sets AX to 0xffff to keep looping, or to 0
			 * upon timeout. AX is then stored into the stack. In
			 * the next iteration, we either see 0 and break out, or
			 * continue iterating until the next time value is 0
			 * after subtraction, rinse and repeat.
			 */
			stack_depth_extra = 16;
			insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_10, stack_off_cnt);
			if (insn->off >= 0)
				insn_buf[1] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, insn->off + 5);
			else
				insn_buf[1] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, insn->off - 1);
			insn_buf[2] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_AX, 1);
			insn_buf[3] = BPF_JMP_IMM(BPF_JNE, BPF_REG_AX, 0, 2);
			/*
			 * AX is used as an argument to pass in stack_off_cnt
			 * (to add to r10/fp), and also as the return value of
			 * the call to arch_bpf_timed_may_goto.
			 */
			insn_buf[4] = BPF_MOV64_IMM(BPF_REG_AX, stack_off_cnt);
			insn_buf[5] = BPF_EMIT_CALL(arch_bpf_timed_may_goto);
			insn_buf[6] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_AX, stack_off_cnt);
			cnt = 7;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta += cnt - 1;
			env->prog = prog = new_prog;
			insn = new_prog->insnsi + i + delta;
			goto next_insn;
		} else if (is_may_goto_insn(insn)) {
			int stack_off = -stack_depth - 8;

			stack_depth_extra = 8;
			insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_10, stack_off);
			if (insn->off >= 0)
				insn_buf[1] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, insn->off + 2);
			else
				insn_buf[1] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, insn->off - 1);
			insn_buf[2] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_AX, 1);
			insn_buf[3] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_AX, stack_off);
			cnt = 4;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta += cnt - 1;
			env->prog = prog = new_prog;
			insn = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		if (insn->code != (BPF_JMP | BPF_CALL))
			goto next_insn;
		if (insn->src_reg == BPF_PSEUDO_CALL)
			goto next_insn;
		if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL) {
			ret = fixup_kfunc_call(env, insn, insn_buf, i + delta, &cnt);
			if (ret)
				return ret;
			if (cnt == 0)
				goto next_insn;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta	 += cnt - 1;
			env->prog = prog = new_prog;
			insn	  = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Skip inlining the helper call if the JIT does it. */
		if (bpf_jit_inlines_helper_call(insn->imm))
			goto next_insn;

		if (insn->imm == BPF_FUNC_get_route_realm)
			prog->dst_needed = 1;
		if (insn->imm == BPF_FUNC_get_prandom_u32)
			bpf_user_rnd_init_once();
		if (insn->imm == BPF_FUNC_override_return)
			prog->kprobe_override = 1;
		if (insn->imm == BPF_FUNC_tail_call) {
			/* If we tail call into other programs, we
			 * cannot make any assumptions since they can
			 * be replaced dynamically during runtime in
			 * the program array.
			 */
			prog->cb_access = 1;
			if (!allow_tail_call_in_subprogs(env))
				prog->aux->stack_depth = MAX_BPF_STACK;
			prog->aux->max_pkt_offset = MAX_PACKET_OFF;

			/* mark bpf_tail_call as different opcode to avoid
			 * conditional branch in the interpreter for every normal
			 * call and to prevent accidental JITing by JIT compiler
			 * that doesn't support bpf_tail_call yet
			 */
			insn->imm = 0;
			insn->code = BPF_JMP | BPF_TAIL_CALL;

			aux = &env->insn_aux_data[i + delta];
			if (env->bpf_capable && !prog->blinding_requested &&
			    prog->jit_requested &&
			    !bpf_map_key_poisoned(aux) &&
			    !bpf_map_ptr_poisoned(aux) &&
			    !bpf_map_ptr_unpriv(aux)) {
				struct bpf_jit_poke_descriptor desc = {
					.reason = BPF_POKE_REASON_TAIL_CALL,
					.tail_call.map = aux->map_ptr_state.map_ptr,
					.tail_call.key = bpf_map_key_immediate(aux),
					.insn_idx = i + delta,
				};

				ret = bpf_jit_add_poke_descriptor(prog, &desc);
				if (ret < 0) {
					verbose(env, "adding tail call poke descriptor failed\n");
					return ret;
				}

				insn->imm = ret + 1;
				goto next_insn;
			}

			if (!bpf_map_ptr_unpriv(aux))
				goto next_insn;

			/* instead of changing every JIT dealing with tail_call
			 * emit two extra insns:
			 * if (index >= max_entries) goto out;
			 * index &= array->index_mask;
			 * to avoid out-of-bounds cpu speculation
			 */
			if (bpf_map_ptr_poisoned(aux)) {
				verbose(env, "tail_call abusing map_ptr\n");
				return -EINVAL;
			}

			map_ptr = aux->map_ptr_state.map_ptr;
			insn_buf[0] = BPF_JMP_IMM(BPF_JGE, BPF_REG_3,
						  map_ptr->max_entries, 2);
			insn_buf[1] = BPF_ALU32_IMM(BPF_AND, BPF_REG_3,
						    container_of(map_ptr,
								 struct bpf_array,
								 map)->index_mask);
			insn_buf[2] = *insn;
			cnt = 3;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		if (insn->imm == BPF_FUNC_timer_set_callback) {
			/* The verifier will process callback_fn as many times as necessary
			 * with different maps and the register states prepared by
			 * set_timer_callback_state will be accurate.
			 *
			 * The following use case is valid:
			 *   map1 is shared by prog1, prog2, prog3.
			 *   prog1 calls bpf_timer_init for some map1 elements
			 *   prog2 calls bpf_timer_set_callback for some map1 elements.
			 *     Those that were not bpf_timer_init-ed will return -EINVAL.
			 *   prog3 calls bpf_timer_start for some map1 elements.
			 *     Those that were not both bpf_timer_init-ed and
			 *     bpf_timer_set_callback-ed will return -EINVAL.
			 */
			struct bpf_insn ld_addrs[2] = {
				BPF_LD_IMM64(BPF_REG_3, (long)prog->aux),
			};

			insn_buf[0] = ld_addrs[0];
			insn_buf[1] = ld_addrs[1];
			insn_buf[2] = *insn;
			cnt = 3;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto patch_call_imm;
		}

		if (is_storage_get_function(insn->imm)) {
			if (env->insn_aux_data[i + delta].non_sleepable)
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_5, (__force __s32)GFP_ATOMIC);
			else
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_5, (__force __s32)GFP_KERNEL);
			insn_buf[1] = *insn;
			cnt = 2;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta += cnt - 1;
			env->prog = prog = new_prog;
			insn = new_prog->insnsi + i + delta;
			goto patch_call_imm;
		}

		/* bpf_per_cpu_ptr() and bpf_this_cpu_ptr() */
		if (env->insn_aux_data[i + delta].call_with_percpu_alloc_ptr) {
			/* patch with 'r1 = *(u64 *)(r1 + 0)' since for percpu data,
			 * bpf_mem_alloc() returns a ptr to the percpu data ptr.
			 */
			insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_1, 0);
			insn_buf[1] = *insn;
			cnt = 2;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta += cnt - 1;
			env->prog = prog = new_prog;
			insn = new_prog->insnsi + i + delta;
			goto patch_call_imm;
		}

		/* BPF_EMIT_CALL() assumptions in some of the map_gen_lookup
		 * and other inlining handlers are currently limited to 64 bit
		 * only.
		 */
		if (prog->jit_requested && BITS_PER_LONG == 64 &&
		    (insn->imm == BPF_FUNC_map_lookup_elem ||
		     insn->imm == BPF_FUNC_map_update_elem ||
		     insn->imm == BPF_FUNC_map_delete_elem ||
		     insn->imm == BPF_FUNC_map_push_elem   ||
		     insn->imm == BPF_FUNC_map_pop_elem    ||
		     insn->imm == BPF_FUNC_map_peek_elem   ||
		     insn->imm == BPF_FUNC_redirect_map    ||
		     insn->imm == BPF_FUNC_for_each_map_elem ||
		     insn->imm == BPF_FUNC_map_lookup_percpu_elem)) {
			aux = &env->insn_aux_data[i + delta];
			if (bpf_map_ptr_poisoned(aux))
				goto patch_call_imm;

			map_ptr = aux->map_ptr_state.map_ptr;
			ops = map_ptr->ops;
			if (insn->imm == BPF_FUNC_map_lookup_elem &&
			    ops->map_gen_lookup) {
				cnt = ops->map_gen_lookup(map_ptr, insn_buf);
				if (cnt == -EOPNOTSUPP)
					goto patch_map_ops_generic;
				if (cnt <= 0 || cnt >= INSN_BUF_SIZE) {
					verifier_bug(env, "%d insns generated for map lookup", cnt);
					return -EFAULT;
				}

				new_prog = bpf_patch_insn_data(env, i + delta,
							       insn_buf, cnt);
				if (!new_prog)
					return -ENOMEM;

				delta    += cnt - 1;
				env->prog = prog = new_prog;
				insn      = new_prog->insnsi + i + delta;
				goto next_insn;
			}

			BUILD_BUG_ON(!__same_type(ops->map_lookup_elem,
				     (void *(*)(struct bpf_map *map, void *key))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_delete_elem,
				     (long (*)(struct bpf_map *map, void *key))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_update_elem,
				     (long (*)(struct bpf_map *map, void *key, void *value,
					      u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_push_elem,
				     (long (*)(struct bpf_map *map, void *value,
					      u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_pop_elem,
				     (long (*)(struct bpf_map *map, void *value))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_peek_elem,
				     (long (*)(struct bpf_map *map, void *value))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_redirect,
				     (long (*)(struct bpf_map *map, u64 index, u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_for_each_callback,
				     (long (*)(struct bpf_map *map,
					      bpf_callback_t callback_fn,
					      void *callback_ctx,
					      u64 flags))NULL));
			BUILD_BUG_ON(!__same_type(ops->map_lookup_percpu_elem,
				     (void *(*)(struct bpf_map *map, void *key, u32 cpu))NULL));

patch_map_ops_generic:
			switch (insn->imm) {
			case BPF_FUNC_map_lookup_elem:
				insn->imm = BPF_CALL_IMM(ops->map_lookup_elem);
				goto next_insn;
			case BPF_FUNC_map_update_elem:
				insn->imm = BPF_CALL_IMM(ops->map_update_elem);
				goto next_insn;
			case BPF_FUNC_map_delete_elem:
				insn->imm = BPF_CALL_IMM(ops->map_delete_elem);
				goto next_insn;
			case BPF_FUNC_map_push_elem:
				insn->imm = BPF_CALL_IMM(ops->map_push_elem);
				goto next_insn;
			case BPF_FUNC_map_pop_elem:
				insn->imm = BPF_CALL_IMM(ops->map_pop_elem);
				goto next_insn;
			case BPF_FUNC_map_peek_elem:
				insn->imm = BPF_CALL_IMM(ops->map_peek_elem);
				goto next_insn;
			case BPF_FUNC_redirect_map:
				insn->imm = BPF_CALL_IMM(ops->map_redirect);
				goto next_insn;
			case BPF_FUNC_for_each_map_elem:
				insn->imm = BPF_CALL_IMM(ops->map_for_each_callback);
				goto next_insn;
			case BPF_FUNC_map_lookup_percpu_elem:
				insn->imm = BPF_CALL_IMM(ops->map_lookup_percpu_elem);
				goto next_insn;
			}

			goto patch_call_imm;
		}

		/* Implement bpf_jiffies64 inline. */
		if (prog->jit_requested && BITS_PER_LONG == 64 &&
		    insn->imm == BPF_FUNC_jiffies64) {
			struct bpf_insn ld_jiffies_addr[2] = {
				BPF_LD_IMM64(BPF_REG_0,
					     (unsigned long)&jiffies),
			};

			insn_buf[0] = ld_jiffies_addr[0];
			insn_buf[1] = ld_jiffies_addr[1];
			insn_buf[2] = BPF_LDX_MEM(BPF_DW, BPF_REG_0,
						  BPF_REG_0, 0);
			cnt = 3;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf,
						       cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

#if defined(CONFIG_X86_64) && !defined(CONFIG_UML)
		/* Implement bpf_get_smp_processor_id() inline. */
		if (insn->imm == BPF_FUNC_get_smp_processor_id &&
		    verifier_inlines_helper_call(env, insn->imm)) {
			/* BPF_FUNC_get_smp_processor_id inlining is an
			 * optimization, so if cpu_number is ever
			 * changed in some incompatible and hard to support
			 * way, it's fine to back out this inlining logic
			 */
#ifdef CONFIG_SMP
			insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, (u32)(unsigned long)&cpu_number);
			insn_buf[1] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
			insn_buf[2] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_0, 0);
			cnt = 3;
#else
			insn_buf[0] = BPF_ALU32_REG(BPF_XOR, BPF_REG_0, BPF_REG_0);
			cnt = 1;
#endif
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement bpf_get_current_task() and bpf_get_current_task_btf() inline. */
		if ((insn->imm == BPF_FUNC_get_current_task || insn->imm == BPF_FUNC_get_current_task_btf) &&
		    verifier_inlines_helper_call(env, insn->imm)) {
			insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, (u32)(unsigned long)&current_task);
			insn_buf[1] = BPF_MOV64_PERCPU_REG(BPF_REG_0, BPF_REG_0);
			insn_buf[2] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_0, 0);
			cnt = 3;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}
#endif
		/* Implement bpf_get_func_arg inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_arg) {
			if (eatype == BPF_TRACE_RAW_TP) {
				int nr_args = btf_type_vlen(prog->aux->attach_func_proto);

				/* skip 'void *__data' in btf_trace_##name() and save to reg0 */
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, nr_args - 1);
				cnt = 1;
			} else {
				/* Load nr_args from ctx - 8 */
				insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
				insn_buf[1] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xFF);
				cnt = 2;
			}
			insn_buf[cnt++] = BPF_JMP32_REG(BPF_JGE, BPF_REG_2, BPF_REG_0, 6);
			insn_buf[cnt++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 3);
			insn_buf[cnt++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_1);
			insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_2, 0);
			insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_0, 0);
			insn_buf[cnt++] = BPF_MOV64_IMM(BPF_REG_0, 0);
			insn_buf[cnt++] = BPF_JMP_A(1);
			insn_buf[cnt++] = BPF_MOV64_IMM(BPF_REG_0, -EINVAL);

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement bpf_get_func_ret inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_ret) {
			if (eatype == BPF_TRACE_FEXIT ||
			    eatype == BPF_TRACE_FSESSION ||
			    eatype == BPF_MODIFY_RETURN) {
				/* Load nr_args from ctx - 8 */
				insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
				insn_buf[1] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xFF);
				insn_buf[2] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 3);
				insn_buf[3] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);
				insn_buf[4] = BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_0, 0);
				insn_buf[5] = BPF_STX_MEM(BPF_DW, BPF_REG_2, BPF_REG_3, 0);
				insn_buf[6] = BPF_MOV64_IMM(BPF_REG_0, 0);
				cnt = 7;
			} else {
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, -EOPNOTSUPP);
				cnt = 1;
			}

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement get_func_arg_cnt inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_arg_cnt) {
			if (eatype == BPF_TRACE_RAW_TP) {
				int nr_args = btf_type_vlen(prog->aux->attach_func_proto);

				/* skip 'void *__data' in btf_trace_##name() and save to reg0 */
				insn_buf[0] = BPF_MOV64_IMM(BPF_REG_0, nr_args - 1);
				cnt = 1;
			} else {
				/* Load nr_args from ctx - 8 */
				insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
				insn_buf[1] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xFF);
				cnt = 2;
			}

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement bpf_get_func_ip inline. */
		if (prog_type == BPF_PROG_TYPE_TRACING &&
		    insn->imm == BPF_FUNC_get_func_ip) {
			/* Load IP address from ctx - 16 */
			insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -16);

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, 1);
			if (!new_prog)
				return -ENOMEM;

			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement bpf_get_branch_snapshot inline. */
		if (IS_ENABLED(CONFIG_PERF_EVENTS) &&
		    prog->jit_requested && BITS_PER_LONG == 64 &&
		    insn->imm == BPF_FUNC_get_branch_snapshot) {
			/* We are dealing with the following func protos:
			 * u64 bpf_get_branch_snapshot(void *buf, u32 size, u64 flags);
			 * int perf_snapshot_branch_stack(struct perf_branch_entry *entries, u32 cnt);
			 */
			const u32 br_entry_size = sizeof(struct perf_branch_entry);

			/* struct perf_branch_entry is part of UAPI and is
			 * used as an array element, so extremely unlikely to
			 * ever grow or shrink
			 */
			BUILD_BUG_ON(br_entry_size != 24);

			/* if (unlikely(flags)) return -EINVAL */
			insn_buf[0] = BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 0, 7);

			/* Transform size (bytes) into number of entries (cnt = size / 24).
			 * But to avoid expensive division instruction, we implement
			 * divide-by-3 through multiplication, followed by further
			 * division by 8 through 3-bit right shift.
			 * Refer to book "Hacker's Delight, 2nd ed." by Henry S. Warren, Jr.,
			 * p. 227, chapter "Unsigned Division by 3" for details and proofs.
			 *
			 * N / 3 <=> M * N / 2^33, where M = (2^33 + 1) / 3 = 0xaaaaaaab.
			 */
			insn_buf[1] = BPF_MOV32_IMM(BPF_REG_0, 0xaaaaaaab);
			insn_buf[2] = BPF_ALU64_REG(BPF_MUL, BPF_REG_2, BPF_REG_0);
			insn_buf[3] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 36);

			/* call perf_snapshot_branch_stack implementation */
			insn_buf[4] = BPF_EMIT_CALL(static_call_query(perf_snapshot_branch_stack));
			/* if (entry_cnt == 0) return -ENOENT */
			insn_buf[5] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4);
			/* return entry_cnt * sizeof(struct perf_branch_entry) */
			insn_buf[6] = BPF_ALU32_IMM(BPF_MUL, BPF_REG_0, br_entry_size);
			insn_buf[7] = BPF_JMP_A(3);
			/* return -EINVAL; */
			insn_buf[8] = BPF_MOV64_IMM(BPF_REG_0, -EINVAL);
			insn_buf[9] = BPF_JMP_A(1);
			/* return -ENOENT; */
			insn_buf[10] = BPF_MOV64_IMM(BPF_REG_0, -ENOENT);
			cnt = 11;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}

		/* Implement bpf_kptr_xchg inline */
		if (prog->jit_requested && BITS_PER_LONG == 64 &&
		    insn->imm == BPF_FUNC_kptr_xchg &&
		    bpf_jit_supports_ptr_xchg()) {
			insn_buf[0] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_2);
			insn_buf[1] = BPF_ATOMIC_OP(BPF_DW, BPF_XCHG, BPF_REG_1, BPF_REG_0, 0);
			cnt = 2;

			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			goto next_insn;
		}
patch_call_imm:
		fn = env->ops->get_func_proto(insn->imm, env->prog);
		/* all functions that have prototype and verifier allowed
		 * programs to call them, must be real in-kernel functions
		 */
		if (!fn->func) {
			verifier_bug(env,
				     "not inlined functions %s#%d is missing func",
				     func_id_name(insn->imm), insn->imm);
			return -EFAULT;
		}
		insn->imm = fn->func - __bpf_call_base;
next_insn:
		if (subprogs[cur_subprog + 1].start == i + delta + 1) {
			subprogs[cur_subprog].stack_depth += stack_depth_extra;
			subprogs[cur_subprog].stack_extra = stack_depth_extra;

			stack_depth = subprogs[cur_subprog].stack_depth;
			if (stack_depth > MAX_BPF_STACK && !prog->jit_requested) {
				verbose(env, "stack size %d(extra %d) is too large\n",
					stack_depth, stack_depth_extra);
				return -EINVAL;
			}
			cur_subprog++;
			stack_depth = subprogs[cur_subprog].stack_depth;
			stack_depth_extra = 0;
		}
		i++;
		insn++;
	}

	env->prog->aux->stack_depth = subprogs[0].stack_depth;
	for (i = 0; i < env->subprog_cnt; i++) {
		int delta = bpf_jit_supports_timed_may_goto() ? 2 : 1;
		int subprog_start = subprogs[i].start;
		int stack_slots = subprogs[i].stack_extra / 8;
		int slots = delta, cnt = 0;

		if (!stack_slots)
			continue;
		/* We need two slots in case timed may_goto is supported. */
		if (stack_slots > slots) {
			verifier_bug(env, "stack_slots supports may_goto only");
			return -EFAULT;
		}

		stack_depth = subprogs[i].stack_depth;
		if (bpf_jit_supports_timed_may_goto()) {
			insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, -stack_depth,
						     BPF_MAX_TIMED_LOOPS);
			insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, -stack_depth + 8, 0);
		} else {
			/* Add ST insn to subprog prologue to init extra stack */
			insn_buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, -stack_depth,
						     BPF_MAX_LOOPS);
		}
		/* Copy first actual insn to preserve it */
		insn_buf[cnt++] = env->prog->insnsi[subprog_start];

		new_prog = bpf_patch_insn_data(env, subprog_start, insn_buf, cnt);
		if (!new_prog)
			return -ENOMEM;
		env->prog = prog = new_prog;
		/*
		 * If may_goto is a first insn of a prog there could be a jmp
		 * insn that points to it, hence adjust all such jmps to point
		 * to insn after BPF_ST that inits may_goto count.
		 * Adjustment will succeed because bpf_patch_insn_data() didn't fail.
		 */
		WARN_ON(adjust_jmp_off(env->prog, subprog_start, delta));
	}

	/* Since poke tab is now finalized, publish aux to tracker. */
	for (i = 0; i < prog->aux->size_poke_tab; i++) {
		map_ptr = prog->aux->poke_tab[i].tail_call.map;
		if (!map_ptr->ops->map_poke_track ||
		    !map_ptr->ops->map_poke_untrack ||
		    !map_ptr->ops->map_poke_run) {
			verifier_bug(env, "poke tab is misconfigured");
			return -EFAULT;
		}

		ret = map_ptr->ops->map_poke_track(map_ptr, prog->aux);
		if (ret < 0) {
			verbose(env, "tracking tail call prog failed\n");
			return ret;
		}
	}

	ret = sort_kfunc_descs_by_imm_off(env);
	if (ret)
		return ret;

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int do_refine_retval_range(struct bpf_verifier_env *env,
				  struct bpf_reg_state *regs, int ret_type,
				  int func_id,
				  struct bpf_call_arg_meta *meta)
{
	struct bpf_reg_state *ret_reg = &regs[BPF_REG_0];

	if (ret_type != RET_INTEGER)
		return 0;

	switch (func_id) {
	case BPF_FUNC_get_stack:
	case BPF_FUNC_get_task_stack:
	case BPF_FUNC_probe_read_str:
	case BPF_FUNC_probe_read_kernel_str:
	case BPF_FUNC_probe_read_user_str:
		ret_reg->smax_value = meta->msize_max_value;
		ret_reg->s32_max_value = meta->msize_max_value;
		ret_reg->smin_value = -MAX_ERRNO;
		ret_reg->s32_min_value = -MAX_ERRNO;
		reg_bounds_sync(ret_reg);
		break;
	case BPF_FUNC_get_smp_processor_id:
		ret_reg->umax_value = nr_cpu_ids - 1;
		ret_reg->u32_max_value = nr_cpu_ids - 1;
		ret_reg->smax_value = nr_cpu_ids - 1;
		ret_reg->s32_max_value = nr_cpu_ids - 1;
		ret_reg->umin_value = 0;
		ret_reg->u32_min_value = 0;
		ret_reg->smin_value = 0;
		ret_reg->s32_min_value = 0;
		reg_bounds_sync(ret_reg);
		break;
	}

	return reg_bounds_sanity_check(env, ret_reg, "retval");
}


