// Extracted from /Users/nan/bs/aot/src/verifier.c
static int bpf_adj_linfo_after_remove(struct bpf_verifier_env *env, u32 off,
				      u32 cnt)
{
	struct bpf_prog *prog = env->prog;
	u32 i, l_off, l_cnt, nr_linfo;
	struct bpf_line_info *linfo;

	nr_linfo = prog->aux->nr_linfo;
	if (!nr_linfo)
		return 0;

	linfo = prog->aux->linfo;

	/* find first line info to remove, count lines to be removed */
	for (i = 0; i < nr_linfo; i++)
		if (linfo[i].insn_off >= off)
			break;

	l_off = i;
	l_cnt = 0;
	for (; i < nr_linfo; i++)
		if (linfo[i].insn_off < off + cnt)
			l_cnt++;
		else
			break;

	/* First live insn doesn't match first live linfo, it needs to "inherit"
	 * last removed linfo.  prog is already modified, so prog->len == off
	 * means no live instructions after (tail of the program was removed).
	 */
	if (prog->len != off && l_cnt &&
	    (i == nr_linfo || linfo[i].insn_off != off + cnt)) {
		l_cnt--;
		linfo[--i].insn_off = off + cnt;
	}

	/* remove the line info which refer to the removed instructions */
	if (l_cnt) {
		memmove(linfo + l_off, linfo + i,
			sizeof(*linfo) * (nr_linfo - i));

		prog->aux->nr_linfo -= l_cnt;
		nr_linfo = prog->aux->nr_linfo;
	}

	/* pull all linfo[i].insn_off >= off + cnt in by cnt */
	for (i = l_off; i < nr_linfo; i++)
		linfo[i].insn_off -= cnt;

	/* fix up all subprogs (incl. 'exit') which start >= off */
	for (i = 0; i <= env->subprog_cnt; i++)
		if (env->subprog_info[i].linfo_idx > l_off) {
			/* program may have started in the removed region but
			 * may not be fully removed
			 */
			if (env->subprog_info[i].linfo_idx >= l_off + l_cnt)
				env->subprog_info[i].linfo_idx -= l_cnt;
			else
				env->subprog_info[i].linfo_idx = l_off;
		}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
bool bpf_calls_callback(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data[insn_idx].calls_callback;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
int bpf_check(struct bpf_prog **prog, union bpf_attr *attr, bpfptr_t uattr, __u32 uattr_size)
{
	u64 start_time = ktime_get_ns();
	struct bpf_verifier_env *env;
	int i, len, ret = -EINVAL, err;
	u32 log_true_size;
	bool is_priv;

	BTF_TYPE_EMIT(enum bpf_features);

	/* no program is valid */
	if (ARRAY_SIZE(bpf_verifier_ops) == 0)
		return -EINVAL;

	/* 'struct bpf_verifier_env' can be global, but since it's not small,
	 * allocate/free it every time bpf_check() is called
	 */
	env = kvzalloc_obj(struct bpf_verifier_env, GFP_KERNEL_ACCOUNT);
	if (!env)
		return -ENOMEM;

	env->bt.env = env;

	len = (*prog)->len;
	env->insn_aux_data =
		vzalloc(array_size(sizeof(struct bpf_insn_aux_data), len));
	ret = -ENOMEM;
	if (!env->insn_aux_data)
		goto err_free_env;
	for (i = 0; i < len; i++)
		env->insn_aux_data[i].orig_idx = i;
	env->succ = iarray_realloc(NULL, 2);
	if (!env->succ)
		goto err_free_env;
	env->prog = *prog;
	env->ops = bpf_verifier_ops[env->prog->type];

	env->allow_ptr_leaks = bpf_allow_ptr_leaks(env->prog->aux->token);
	env->allow_uninit_stack = bpf_allow_uninit_stack(env->prog->aux->token);
	env->bypass_spec_v1 = bpf_bypass_spec_v1(env->prog->aux->token);
	env->bypass_spec_v4 = bpf_bypass_spec_v4(env->prog->aux->token);
	env->bpf_capable = is_priv = bpf_token_capable(env->prog->aux->token, CAP_BPF);

	bpf_get_btf_vmlinux();

	/* grab the mutex to protect few globals used by verifier */
	if (!is_priv)
		mutex_lock(&bpf_verifier_lock);

	/* user could have requested verbose verifier output
	 * and supplied buffer to store the verification trace
	 */
	ret = bpf_vlog_init(&env->log, attr->log_level,
			    (char __user *) (unsigned long) attr->log_buf,
			    attr->log_size);
	if (ret)
		goto err_unlock;

	ret = process_fd_array(env, attr, uattr);
	if (ret)
		goto skip_full_check;

	mark_verifier_state_clean(env);

	if (IS_ERR(btf_vmlinux)) {
		/* Either gcc or pahole or kernel are broken. */
		verbose(env, "in-kernel BTF is malformed\n");
		ret = PTR_ERR(btf_vmlinux);
		goto skip_full_check;
	}

	env->strict_alignment = !!(attr->prog_flags & BPF_F_STRICT_ALIGNMENT);
	if (!IS_ENABLED(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS))
		env->strict_alignment = true;
	if (attr->prog_flags & BPF_F_ANY_ALIGNMENT)
		env->strict_alignment = false;

	if (is_priv)
		env->test_state_freq = attr->prog_flags & BPF_F_TEST_STATE_FREQ;
	env->test_reg_invariants = attr->prog_flags & BPF_F_TEST_REG_INVARIANTS;

	env->explored_states = kvzalloc_objs(struct list_head,
					     state_htab_size(env),
					     GFP_KERNEL_ACCOUNT);
	ret = -ENOMEM;
	if (!env->explored_states)
		goto skip_full_check;

	for (i = 0; i < state_htab_size(env); i++)
		INIT_LIST_HEAD(&env->explored_states[i]);
	INIT_LIST_HEAD(&env->free_list);

	ret = check_btf_info_early(env, attr, uattr);
	if (ret < 0)
		goto skip_full_check;

	ret = add_subprog_and_kfunc(env);
	if (ret < 0)
		goto skip_full_check;

	ret = check_subprogs(env);
	if (ret < 0)
		goto skip_full_check;

	ret = check_btf_info(env, attr, uattr);
	if (ret < 0)
		goto skip_full_check;

	ret = resolve_pseudo_ldimm64(env);
	if (ret < 0)
		goto skip_full_check;

	if (bpf_prog_is_offloaded(env->prog->aux)) {
		ret = bpf_prog_offload_verifier_prep(env->prog);
		if (ret)
			goto skip_full_check;
	}

	ret = check_cfg(env);
	if (ret < 0)
		goto skip_full_check;

	ret = compute_postorder(env);
	if (ret < 0)
		goto skip_full_check;

	ret = bpf_stack_liveness_init(env);
	if (ret)
		goto skip_full_check;

	ret = check_attach_btf_id(env);
	if (ret)
		goto skip_full_check;

	ret = compute_scc(env);
	if (ret < 0)
		goto skip_full_check;

	ret = compute_live_registers(env);
	if (ret < 0)
		goto skip_full_check;

	ret = mark_fastcall_patterns(env);
	if (ret < 0)
		goto skip_full_check;

	ret = do_check_main(env);
	ret = ret ?: do_check_subprogs(env);

	if (ret == 0 && bpf_prog_is_offloaded(env->prog->aux))
		ret = bpf_prog_offload_finalize(env);

skip_full_check:
	kvfree(env->explored_states);

	/* might decrease stack depth, keep it before passes that
	 * allocate additional slots.
	 */
	if (ret == 0)
		ret = remove_fastcall_spills_fills(env);

	if (ret == 0)
		ret = check_max_stack_depth(env);

	/* instruction rewrites happen after this point */
	if (ret == 0)
		ret = optimize_bpf_loop(env);

	if (is_priv) {
		if (ret == 0)
			opt_hard_wire_dead_code_branches(env);
		if (ret == 0)
			ret = opt_remove_dead_code(env);
		if (ret == 0)
			ret = opt_remove_nops(env);
	} else {
		if (ret == 0)
			sanitize_dead_code(env);
	}

	if (ret == 0)
		/* program is valid, convert *(u32*)(ctx + off) accesses */
		ret = convert_ctx_accesses(env);

	if (ret == 0)
		ret = do_misc_fixups(env);

	/* do 32-bit optimization after insn patching has done so those patched
	 * insns could be handled correctly.
	 */
	if (ret == 0 && !bpf_prog_is_offloaded(env->prog->aux)) {
		ret = opt_subreg_zext_lo32_rnd_hi32(env, attr);
		env->prog->aux->verifier_zext = bpf_jit_needs_zext() ? !ret
								     : false;
	}

	if (ret == 0)
		ret = fixup_call_args(env);

	env->verification_time = ktime_get_ns() - start_time;
	print_verification_stats(env);
	env->prog->aux->verified_insns = env->insn_processed;

	/* preserve original error even if log finalization is successful */
	err = bpf_vlog_finalize(&env->log, &log_true_size);
	if (err)
		ret = err;

	if (uattr_size >= offsetofend(union bpf_attr, log_true_size) &&
	    copy_to_bpfptr_offset(uattr, offsetof(union bpf_attr, log_true_size),
				  &log_true_size, sizeof(log_true_size))) {
		ret = -EFAULT;
		goto err_release_maps;
	}

	if (ret)
		goto err_release_maps;

	if (env->used_map_cnt) {
		/* if program passed verifier, update used_maps in bpf_prog_info */
		env->prog->aux->used_maps = kmalloc_objs(env->used_maps[0],
							 env->used_map_cnt,
							 GFP_KERNEL_ACCOUNT);

		if (!env->prog->aux->used_maps) {
			ret = -ENOMEM;
			goto err_release_maps;
		}

		memcpy(env->prog->aux->used_maps, env->used_maps,
		       sizeof(env->used_maps[0]) * env->used_map_cnt);
		env->prog->aux->used_map_cnt = env->used_map_cnt;
	}
	if (env->used_btf_cnt) {
		/* if program passed verifier, update used_btfs in bpf_prog_aux */
		env->prog->aux->used_btfs = kmalloc_objs(env->used_btfs[0],
							 env->used_btf_cnt,
							 GFP_KERNEL_ACCOUNT);
		if (!env->prog->aux->used_btfs) {
			ret = -ENOMEM;
			goto err_release_maps;
		}

		memcpy(env->prog->aux->used_btfs, env->used_btfs,
		       sizeof(env->used_btfs[0]) * env->used_btf_cnt);
		env->prog->aux->used_btf_cnt = env->used_btf_cnt;
	}
	if (env->used_map_cnt || env->used_btf_cnt) {
		/* program is valid. Convert pseudo bpf_ld_imm64 into generic
		 * bpf_ld_imm64 instructions
		 */
		convert_pseudo_ld_imm64(env);
	}

	adjust_btf_func(env);

err_release_maps:
	if (ret)
		release_insn_arrays(env);
	if (!env->prog->aux->used_maps)
		/* if we didn't copy map pointers into bpf_prog_info, release
		 * them now. Otherwise free_used_maps() will release them.
		 */
		release_maps(env);
	if (!env->prog->aux->used_btfs)
		release_btfs(env);

	/* extension progs temporarily inherit the attach_type of their targets
	   for verification purposes, so set it back to zero before returning
	 */
	if (env->prog->type == BPF_PROG_TYPE_EXT)
		env->prog->expected_attach_type = 0;

	*prog = env->prog;

	module_put(env->attach_btf_mod);
err_unlock:
	if (!is_priv)
		mutex_unlock(&bpf_verifier_lock);
	clear_insn_aux_data(env, 0, env->prog->len);
	vfree(env->insn_aux_data);
err_free_env:
	bpf_stack_liveness_free(env);
	kvfree(env->cfg.insn_postorder);
	kvfree(env->scc_info);
	kvfree(env->succ);
	kvfree(env->gotox_tmp_buf);
	kvfree(env);
	return ret;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
int bpf_check_attach_target(struct bpf_verifier_log *log,
			    const struct bpf_prog *prog,
			    const struct bpf_prog *tgt_prog,
			    u32 btf_id,
			    struct bpf_attach_target_info *tgt_info)
{
	bool prog_extension = prog->type == BPF_PROG_TYPE_EXT;
	bool prog_tracing = prog->type == BPF_PROG_TYPE_TRACING;
	char trace_symbol[KSYM_SYMBOL_LEN];
	const char prefix[] = "btf_trace_";
	struct bpf_raw_event_map *btp;
	int ret = 0, subprog = -1, i;
	const struct btf_type *t;
	bool conservative = true;
	const char *tname, *fname;
	struct btf *btf;
	long addr = 0;
	struct module *mod = NULL;

	if (!btf_id) {
		bpf_log(log, "Tracing programs must provide btf_id\n");
		return -EINVAL;
	}
	btf = tgt_prog ? tgt_prog->aux->btf : prog->aux->attach_btf;
	if (!btf) {
		bpf_log(log,
			"FENTRY/FEXIT program can only be attached to another program annotated with BTF\n");
		return -EINVAL;
	}
	t = btf_type_by_id(btf, btf_id);
	if (!t) {
		bpf_log(log, "attach_btf_id %u is invalid\n", btf_id);
		return -EINVAL;
	}
	tname = btf_name_by_offset(btf, t->name_off);
	if (!tname) {
		bpf_log(log, "attach_btf_id %u doesn't have a name\n", btf_id);
		return -EINVAL;
	}
	if (tgt_prog) {
		struct bpf_prog_aux *aux = tgt_prog->aux;
		bool tgt_changes_pkt_data;
		bool tgt_might_sleep;

		if (bpf_prog_is_dev_bound(prog->aux) &&
		    !bpf_prog_dev_bound_match(prog, tgt_prog)) {
			bpf_log(log, "Target program bound device mismatch");
			return -EINVAL;
		}

		for (i = 0; i < aux->func_info_cnt; i++)
			if (aux->func_info[i].type_id == btf_id) {
				subprog = i;
				break;
			}
		if (subprog == -1) {
			bpf_log(log, "Subprog %s doesn't exist\n", tname);
			return -EINVAL;
		}
		if (aux->func && aux->func[subprog]->aux->exception_cb) {
			bpf_log(log,
				"%s programs cannot attach to exception callback\n",
				prog_extension ? "Extension" : "FENTRY/FEXIT");
			return -EINVAL;
		}
		conservative = aux->func_info_aux[subprog].unreliable;
		if (prog_extension) {
			if (conservative) {
				bpf_log(log,
					"Cannot replace static functions\n");
				return -EINVAL;
			}
			if (!prog->jit_requested) {
				bpf_log(log,
					"Extension programs should be JITed\n");
				return -EINVAL;
			}
			tgt_changes_pkt_data = aux->func
					       ? aux->func[subprog]->aux->changes_pkt_data
					       : aux->changes_pkt_data;
			if (prog->aux->changes_pkt_data && !tgt_changes_pkt_data) {
				bpf_log(log,
					"Extension program changes packet data, while original does not\n");
				return -EINVAL;
			}

			tgt_might_sleep = aux->func
					  ? aux->func[subprog]->aux->might_sleep
					  : aux->might_sleep;
			if (prog->aux->might_sleep && !tgt_might_sleep) {
				bpf_log(log,
					"Extension program may sleep, while original does not\n");
				return -EINVAL;
			}
		}
		if (!tgt_prog->jited) {
			bpf_log(log, "Can attach to only JITed progs\n");
			return -EINVAL;
		}
		if (prog_tracing) {
			if (aux->attach_tracing_prog) {
				/*
				 * Target program is an fentry/fexit which is already attached
				 * to another tracing program. More levels of nesting
				 * attachment are not allowed.
				 */
				bpf_log(log, "Cannot nest tracing program attach more than once\n");
				return -EINVAL;
			}
		} else if (tgt_prog->type == prog->type) {
			/*
			 * To avoid potential call chain cycles, prevent attaching of a
			 * program extension to another extension. It's ok to attach
			 * fentry/fexit to extension program.
			 */
			bpf_log(log, "Cannot recursively attach\n");
			return -EINVAL;
		}
		if (tgt_prog->type == BPF_PROG_TYPE_TRACING &&
		    prog_extension &&
		    (tgt_prog->expected_attach_type == BPF_TRACE_FENTRY ||
		     tgt_prog->expected_attach_type == BPF_TRACE_FEXIT ||
		     tgt_prog->expected_attach_type == BPF_TRACE_FSESSION)) {
			/* Program extensions can extend all program types
			 * except fentry/fexit. The reason is the following.
			 * The fentry/fexit programs are used for performance
			 * analysis, stats and can be attached to any program
			 * type. When extension program is replacing XDP function
			 * it is necessary to allow performance analysis of all
			 * functions. Both original XDP program and its program
			 * extension. Hence attaching fentry/fexit to
			 * BPF_PROG_TYPE_EXT is allowed. If extending of
			 * fentry/fexit was allowed it would be possible to create
			 * long call chain fentry->extension->fentry->extension
			 * beyond reasonable stack size. Hence extending fentry
			 * is not allowed.
			 */
			bpf_log(log, "Cannot extend fentry/fexit/fsession\n");
			return -EINVAL;
		}
	} else {
		if (prog_extension) {
			bpf_log(log, "Cannot replace kernel functions\n");
			return -EINVAL;
		}
	}

	switch (prog->expected_attach_type) {
	case BPF_TRACE_RAW_TP:
		if (tgt_prog) {
			bpf_log(log,
				"Only FENTRY/FEXIT progs are attachable to another BPF prog\n");
			return -EINVAL;
		}
		if (!btf_type_is_typedef(t)) {
			bpf_log(log, "attach_btf_id %u is not a typedef\n",
				btf_id);
			return -EINVAL;
		}
		if (strncmp(prefix, tname, sizeof(prefix) - 1)) {
			bpf_log(log, "attach_btf_id %u points to wrong type name %s\n",
				btf_id, tname);
			return -EINVAL;
		}
		tname += sizeof(prefix) - 1;

		/* The func_proto of "btf_trace_##tname" is generated from typedef without argument
		 * names. Thus using bpf_raw_event_map to get argument names.
		 */
		btp = bpf_get_raw_tracepoint(tname);
		if (!btp)
			return -EINVAL;
		fname = kallsyms_lookup((unsigned long)btp->bpf_func, NULL, NULL, NULL,
					trace_symbol);
		bpf_put_raw_tracepoint(btp);

		if (fname)
			ret = btf_find_by_name_kind(btf, fname, BTF_KIND_FUNC);

		if (!fname || ret < 0) {
			bpf_log(log, "Cannot find btf of tracepoint template, fall back to %s%s.\n",
				prefix, tname);
			t = btf_type_by_id(btf, t->type);
			if (!btf_type_is_ptr(t))
				/* should never happen in valid vmlinux build */
				return -EINVAL;
		} else {
			t = btf_type_by_id(btf, ret);
			if (!btf_type_is_func(t))
				/* should never happen in valid vmlinux build */
				return -EINVAL;
		}

		t = btf_type_by_id(btf, t->type);
		if (!btf_type_is_func_proto(t))
			/* should never happen in valid vmlinux build */
			return -EINVAL;

		break;
	case BPF_TRACE_ITER:
		if (!btf_type_is_func(t)) {
			bpf_log(log, "attach_btf_id %u is not a function\n",
				btf_id);
			return -EINVAL;
		}
		t = btf_type_by_id(btf, t->type);
		if (!btf_type_is_func_proto(t))
			return -EINVAL;
		ret = btf_distill_func_proto(log, btf, t, tname, &tgt_info->fmodel);
		if (ret)
			return ret;
		break;
	default:
		if (!prog_extension)
			return -EINVAL;
		fallthrough;
	case BPF_MODIFY_RETURN:
	case BPF_LSM_MAC:
	case BPF_LSM_CGROUP:
	case BPF_TRACE_FENTRY:
	case BPF_TRACE_FEXIT:
	case BPF_TRACE_FSESSION:
		if (prog->expected_attach_type == BPF_TRACE_FSESSION &&
		    !bpf_jit_supports_fsession()) {
			bpf_log(log, "JIT does not support fsession\n");
			return -EOPNOTSUPP;
		}
		if (!btf_type_is_func(t)) {
			bpf_log(log, "attach_btf_id %u is not a function\n",
				btf_id);
			return -EINVAL;
		}
		if (prog_extension &&
		    btf_check_type_match(log, prog, btf, t))
			return -EINVAL;
		t = btf_type_by_id(btf, t->type);
		if (!btf_type_is_func_proto(t))
			return -EINVAL;

		if ((prog->aux->saved_dst_prog_type || prog->aux->saved_dst_attach_type) &&
		    (!tgt_prog || prog->aux->saved_dst_prog_type != tgt_prog->type ||
		     prog->aux->saved_dst_attach_type != tgt_prog->expected_attach_type))
			return -EINVAL;

		if (tgt_prog && conservative)
			t = NULL;

		ret = btf_distill_func_proto(log, btf, t, tname, &tgt_info->fmodel);
		if (ret < 0)
			return ret;

		if (tgt_prog) {
			if (subprog == 0)
				addr = (long) tgt_prog->bpf_func;
			else
				addr = (long) tgt_prog->aux->func[subprog]->bpf_func;
		} else {
			if (btf_is_module(btf)) {
				mod = btf_try_get_module(btf);
				if (mod)
					addr = find_kallsyms_symbol_value(mod, tname);
				else
					addr = 0;
			} else {
				addr = kallsyms_lookup_name(tname);
			}
			if (!addr) {
				module_put(mod);
				bpf_log(log,
					"The address of function %s cannot be found\n",
					tname);
				return -ENOENT;
			}
		}

		if (prog->sleepable) {
			ret = -EINVAL;
			switch (prog->type) {
			case BPF_PROG_TYPE_TRACING:

				/* fentry/fexit/fmod_ret progs can be sleepable if they are
				 * attached to ALLOW_ERROR_INJECTION and are not in denylist.
				 */
				if (!check_non_sleepable_error_inject(btf_id) &&
				    within_error_injection_list(addr))
					ret = 0;
				/* fentry/fexit/fmod_ret progs can also be sleepable if they are
				 * in the fmodret id set with the KF_SLEEPABLE flag.
				 */
				else {
					u32 *flags = btf_kfunc_is_modify_return(btf, btf_id,
										prog);

					if (flags && (*flags & KF_SLEEPABLE))
						ret = 0;
				}
				break;
			case BPF_PROG_TYPE_LSM:
				/* LSM progs check that they are attached to bpf_lsm_*() funcs.
				 * Only some of them are sleepable.
				 */
				if (bpf_lsm_is_sleepable_hook(btf_id))
					ret = 0;
				break;
			default:
				break;
			}
			if (ret) {
				module_put(mod);
				bpf_log(log, "%s is not sleepable\n", tname);
				return ret;
			}
		} else if (prog->expected_attach_type == BPF_MODIFY_RETURN) {
			if (tgt_prog) {
				module_put(mod);
				bpf_log(log, "can't modify return codes of BPF programs\n");
				return -EINVAL;
			}
			ret = -EINVAL;
			if (btf_kfunc_is_modify_return(btf, btf_id, prog) ||
			    !check_attach_modify_return(addr, tname))
				ret = 0;
			if (ret) {
				module_put(mod);
				bpf_log(log, "%s() is not modifiable\n", tname);
				return ret;
			}
		}

		break;
	}
	tgt_info->tgt_addr = addr;
	tgt_info->tgt_name = tname;
	tgt_info->tgt_type = t;
	tgt_info->tgt_mod = mod;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static enum priv_stack_mode bpf_enable_priv_stack(struct bpf_prog *prog)
{
	if (!bpf_jit_supports_private_stack())
		return NO_PRIV_STACK;

	/* bpf_prog_check_recur() checks all prog types that use bpf trampoline
	 * while kprobe/tp/perf_event/raw_tp don't use trampoline hence checked
	 * explicitly.
	 */
	switch (prog->type) {
	case BPF_PROG_TYPE_KPROBE:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
		return PRIV_STACK_ADAPTIVE;
	case BPF_PROG_TYPE_TRACING:
	case BPF_PROG_TYPE_LSM:
	case BPF_PROG_TYPE_STRUCT_OPS:
		if (prog->aux->priv_stack_requested || bpf_prog_check_recur(prog))
			return PRIV_STACK_ADAPTIVE;
		fallthrough;
	default:
		break;
	}

	return NO_PRIV_STACK;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
struct bpf_subprog_info *bpf_find_containing_subprog(struct bpf_verifier_env *env, int off)
{
	struct bpf_subprog_info *vals = env->subprog_info;
	int l, r, m;

	if (off >= env->prog->len || off < 0 || env->subprog_cnt == 0)
		return NULL;

	l = 0;
	r = env->subprog_cnt - 1;
	while (l < r) {
		m = l + (r - l + 1) / 2;
		if (vals[m].start <= off)
			l = m;
		else
			r = m - 1;
	}
	return &vals[l];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int bpf_find_exception_callback_insn_off(struct bpf_verifier_env *env)
{
	struct bpf_prog_aux *aux = env->prog->aux;
	struct btf *btf = aux->btf;
	const struct btf_type *t;
	u32 main_btf_id, id;
	const char *name;
	int ret, i;

	/* Non-zero func_info_cnt implies valid btf */
	if (!aux->func_info_cnt)
		return 0;
	main_btf_id = aux->func_info[0].type_id;

	t = btf_type_by_id(btf, main_btf_id);
	if (!t) {
		verbose(env, "invalid btf id for main subprog in func_info\n");
		return -EINVAL;
	}

	name = btf_find_decl_tag_value(btf, t, -1, "exception_callback:");
	if (IS_ERR(name)) {
		ret = PTR_ERR(name);
		/* If there is no tag present, there is no exception callback */
		if (ret == -ENOENT)
			ret = 0;
		else if (ret == -EEXIST)
			verbose(env, "multiple exception callback tags for main subprog\n");
		return ret;
	}

	ret = btf_find_by_name_kind(btf, name, BTF_KIND_FUNC);
	if (ret < 0) {
		verbose(env, "exception callback '%s' could not be found in BTF\n", name);
		return ret;
	}
	id = ret;
	t = btf_type_by_id(btf, id);
	if (btf_func_linkage(t) != BTF_FUNC_GLOBAL) {
		verbose(env, "exception callback '%s' must have global linkage\n", name);
		return -EINVAL;
	}
	ret = 0;
	for (i = 0; i < aux->func_info_cnt; i++) {
		if (aux->func_info[i].type_id != id)
			continue;
		ret = aux->func_info[i].insn_off;
		/* Further func_info and subprog checks will also happen
		 * later, so assume this is the right insn_off for now.
		 */
		if (!ret) {
			verbose(env, "invalid exception callback insn_off in func_info: 0\n");
			ret = -EINVAL;
		}
	}
	if (!ret) {
		verbose(env, "exception callback type id not found in func_info\n");
		ret = -EINVAL;
	}
	return ret;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
void bpf_fmt_stack_mask(char *buf, ssize_t buf_sz, u64 stack_mask)
{
	DECLARE_BITMAP(mask, 64);
	bool first = true;
	int i, n;

	buf[0] = '\0';

	bitmap_from_u64(mask, stack_mask);
	for_each_set_bit(i, mask, 64) {
		n = snprintf(buf, buf_sz, "%s%d", first ? "" : ",", -(i + 1) * 8);
		first = false;
		buf += n;
		buf_sz -= n;
		if (buf_sz < 0)
			break;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
void bpf_free_kfunc_btf_tab(struct bpf_kfunc_btf_tab *tab)
{
	if (!tab)
		return;

	while (tab->nr_descs--) {
		module_put(tab->descs[tab->nr_descs].module);
		btf_put(tab->descs[tab->nr_descs].btf);
	}
	kfree(tab);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
struct btf *bpf_get_btf_vmlinux(void)
{
	if (!btf_vmlinux && IS_ENABLED(CONFIG_DEBUG_INFO_BTF)) {
		mutex_lock(&bpf_verifier_lock);
		if (!btf_vmlinux)
			btf_vmlinux = btf_parse_vmlinux();
		mutex_unlock(&bpf_verifier_lock);
	}
	return btf_vmlinux;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
int bpf_get_kfunc_addr(const struct bpf_prog *prog, u32 func_id,
		       u16 btf_fd_idx, u8 **func_addr)
{
	const struct bpf_kfunc_desc *desc;

	desc = find_kfunc_desc(prog, func_id, btf_fd_idx);
	if (!desc)
		return -EFAULT;

	*func_addr = (u8 *)desc->addr;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool bpf_helper_call(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
bpf_jit_find_kfunc_model(const struct bpf_prog *prog,
			 const struct bpf_insn *insn)
{
	const struct bpf_kfunc_desc desc = {
		.imm = insn->imm,
		.offset = insn->off,
	};
	const struct bpf_kfunc_desc *res;
	struct bpf_kfunc_desc_tab *tab;

	tab = prog->aux->kfunc_tab;
	res = bsearch(&desc, tab->descs, tab->nr_descs,
		      sizeof(tab->descs[0]), kfunc_desc_cmp_by_imm_off);

	return res ? &res->func_model : NULL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int bpf_map_direct_read(struct bpf_map *map, int off, int size, u64 *val,
			       bool is_ldsx)
{
	void *ptr;
	u64 addr;
	int err;

	err = map->ops->map_direct_value_addr(map, &addr, off);
	if (err)
		return err;
	ptr = (void *)(long)addr + off;

	switch (size) {
	case sizeof(u8):
		*val = is_ldsx ? (s64)*(s8 *)ptr : (u64)*(u8 *)ptr;
		break;
	case sizeof(u16):
		*val = is_ldsx ? (s64)*(s16 *)ptr : (u64)*(u16 *)ptr;
		break;
	case sizeof(u32):
		*val = is_ldsx ? (s64)*(s32 *)ptr : (u64)*(u32 *)ptr;
		break;
	case sizeof(u64):
		*val = *(u64 *)ptr;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool bpf_map_is_cgroup_storage(struct bpf_map *map)
{
	return (map->map_type == BPF_MAP_TYPE_CGROUP_STORAGE ||
		map->map_type == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool bpf_map_is_rdonly(const struct bpf_map *map)
{
	/* A map is considered read-only if the following condition are true:
	 *
	 * 1) BPF program side cannot change any of the map content. The
	 *    BPF_F_RDONLY_PROG flag is throughout the lifetime of a map
	 *    and was set at map creation time.
	 * 2) The map value(s) have been initialized from user space by a
	 *    loader and then "frozen", such that no new map update/delete
	 *    operations from syscall side are possible for the rest of
	 *    the map's lifetime from that point onwards.
	 * 3) Any parallel/pending map update/delete operations from syscall
	 *    side have been completed. Only after that point, it's safe to
	 *    assume that map value(s) are immutable.
	 */
	return (map->map_flags & BPF_F_RDONLY_PROG) &&
	       READ_ONCE(map->frozen) &&
	       !bpf_map_write_active(map);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static u64 bpf_map_key_immediate(const struct bpf_insn_aux_data *aux)
{
	return aux->map_key_state & ~(BPF_MAP_KEY_SEEN | BPF_MAP_KEY_POISON);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool bpf_map_key_poisoned(const struct bpf_insn_aux_data *aux)
{
	return aux->map_key_state & BPF_MAP_KEY_POISON;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void bpf_map_key_store(struct bpf_insn_aux_data *aux, u64 state)
{
	bool poisoned = bpf_map_key_poisoned(aux);

	aux->map_key_state = state | BPF_MAP_KEY_SEEN |
			     (poisoned ? BPF_MAP_KEY_POISON : 0ULL);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool bpf_map_key_unseen(const struct bpf_insn_aux_data *aux)
{
	return !(aux->map_key_state & BPF_MAP_KEY_SEEN);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool bpf_map_ptr_poisoned(const struct bpf_insn_aux_data *aux)
{
	return aux->map_ptr_state.poison;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void bpf_map_ptr_store(struct bpf_insn_aux_data *aux,
			      struct bpf_map *map,
			      bool unpriv, bool poison)
{
	unpriv |= bpf_map_ptr_unpriv(aux);
	aux->map_ptr_state.unpriv = unpriv;
	aux->map_ptr_state.poison = poison;
	aux->map_ptr_state.map_ptr = map;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool bpf_map_ptr_unpriv(const struct bpf_insn_aux_data *aux)
{
	return aux->map_ptr_state.unpriv;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_prog *bpf_patch_insn_data(struct bpf_verifier_env *env, u32 off,
					    const struct bpf_insn *patch, u32 len)
{
	struct bpf_prog *new_prog;
	struct bpf_insn_aux_data *new_data = NULL;

	if (len > 1) {
		new_data = vrealloc(env->insn_aux_data,
				    array_size(env->prog->len + len - 1,
					       sizeof(struct bpf_insn_aux_data)),
				    GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!new_data)
			return NULL;

		env->insn_aux_data = new_data;
	}

	new_prog = bpf_patch_insn_single(env->prog, off, patch, len);
	if (IS_ERR(new_prog)) {
		if (PTR_ERR(new_prog) == -ERANGE)
			verbose(env,
				"insn %d cannot be patched due to 16-bit range\n",
				env->insn_aux_data[off].orig_idx);
		return NULL;
	}
	adjust_insn_aux_data(env, new_prog, off, len);
	adjust_subprog_starts(env, off, len);
	adjust_insn_arrays(env, off, len);
	adjust_poke_descs(new_prog, off, len);
	return new_prog;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
int bpf_prog_ctx_arg_info_init(struct bpf_prog *prog,
			       const struct bpf_ctx_arg_aux *info, u32 cnt)
{
	prog->aux->ctx_arg_info = kmemdup_array(info, cnt, sizeof(*info), GFP_KERNEL_ACCOUNT);
	prog->aux->ctx_arg_info_size = cnt;

	return prog->aux->ctx_arg_info ? 0 : -ENOMEM;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
bool bpf_prog_has_kfunc_call(const struct bpf_prog *prog)
{
	return !!prog->aux->kfunc_tab;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool bpf_pseudo_call(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_CALL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool bpf_pseudo_kfunc_call(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_KFUNC_CALL;
}


