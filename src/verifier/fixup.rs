// Extracted from /Users/nan/bs/aot/src/verifier.c
static int fixup_call_args(struct bpf_verifier_env *env)
{
#ifndef CONFIG_BPF_JIT_ALWAYS_ON
	struct bpf_prog *prog = env->prog;
	struct bpf_insn *insn = prog->insnsi;
	bool has_kfunc_call = bpf_prog_has_kfunc_call(prog);
	int i, depth;
#endif
	int err = 0;

	if (env->prog->jit_requested &&
	    !bpf_prog_is_offloaded(env->prog->aux)) {
		err = jit_subprogs(env);
		if (err == 0)
			return 0;
		if (err == -EFAULT)
			return err;
	}
#ifndef CONFIG_BPF_JIT_ALWAYS_ON
	if (has_kfunc_call) {
		verbose(env, "calling kernel functions are not allowed in non-JITed programs\n");
		return -EINVAL;
	}
	if (env->subprog_cnt > 1 && env->prog->aux->tail_call_reachable) {
		/* When JIT fails the progs with bpf2bpf calls and tail_calls
		 * have to be rejected, since interpreter doesn't support them yet.
		 */
		verbose(env, "tail_calls are not allowed in non-JITed programs with bpf-to-bpf calls\n");
		return -EINVAL;
	}
	for (i = 0; i < prog->len; i++, insn++) {
		if (bpf_pseudo_func(insn)) {
			/* When JIT fails the progs with callback calls
			 * have to be rejected, since interpreter doesn't support them yet.
			 */
			verbose(env, "callbacks are not allowed in non-JITed programs\n");
			return -EINVAL;
		}

		if (!bpf_pseudo_call(insn))
			continue;
		depth = get_callee_stack_depth(env, insn, i);
		if (depth < 0)
			return depth;
		bpf_patch_call_args(insn, depth);
	}
	err = 0;
#endif
	return err;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int fixup_kfunc_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
			    struct bpf_insn *insn_buf, int insn_idx, int *cnt)
{
	struct bpf_kfunc_desc *desc;
	int err;

	if (!insn->imm) {
		verbose(env, "invalid kernel function call not eliminated in verifier pass\n");
		return -EINVAL;
	}

	*cnt = 0;

	/* insn->imm has the btf func_id. Replace it with an offset relative to
	 * __bpf_call_base, unless the JIT needs to call functions that are
	 * further than 32 bits away (bpf_jit_supports_far_kfunc_call()).
	 */
	desc = find_kfunc_desc(env->prog, insn->imm, insn->off);
	if (!desc) {
		verifier_bug(env, "kernel function descriptor not found for func_id %u",
			     insn->imm);
		return -EFAULT;
	}

	err = specialize_kfunc(env, desc, insn_idx);
	if (err)
		return err;

	if (!bpf_jit_supports_far_kfunc_call())
		insn->imm = BPF_CALL_IMM(desc->addr);

	if (desc->func_id == special_kfunc_list[KF_bpf_obj_new_impl] ||
	    desc->func_id == special_kfunc_list[KF_bpf_percpu_obj_new_impl]) {
		struct btf_struct_meta *kptr_struct_meta = env->insn_aux_data[insn_idx].kptr_struct_meta;
		struct bpf_insn addr[2] = { BPF_LD_IMM64(BPF_REG_2, (long)kptr_struct_meta) };
		u64 obj_new_size = env->insn_aux_data[insn_idx].obj_new_size;

		if (desc->func_id == special_kfunc_list[KF_bpf_percpu_obj_new_impl] && kptr_struct_meta) {
			verifier_bug(env, "NULL kptr_struct_meta expected at insn_idx %d",
				     insn_idx);
			return -EFAULT;
		}

		insn_buf[0] = BPF_MOV64_IMM(BPF_REG_1, obj_new_size);
		insn_buf[1] = addr[0];
		insn_buf[2] = addr[1];
		insn_buf[3] = *insn;
		*cnt = 4;
	} else if (desc->func_id == special_kfunc_list[KF_bpf_obj_drop_impl] ||
		   desc->func_id == special_kfunc_list[KF_bpf_percpu_obj_drop_impl] ||
		   desc->func_id == special_kfunc_list[KF_bpf_refcount_acquire_impl]) {
		struct btf_struct_meta *kptr_struct_meta = env->insn_aux_data[insn_idx].kptr_struct_meta;
		struct bpf_insn addr[2] = { BPF_LD_IMM64(BPF_REG_2, (long)kptr_struct_meta) };

		if (desc->func_id == special_kfunc_list[KF_bpf_percpu_obj_drop_impl] && kptr_struct_meta) {
			verifier_bug(env, "NULL kptr_struct_meta expected at insn_idx %d",
				     insn_idx);
			return -EFAULT;
		}

		if (desc->func_id == special_kfunc_list[KF_bpf_refcount_acquire_impl] &&
		    !kptr_struct_meta) {
			verifier_bug(env, "kptr_struct_meta expected at insn_idx %d",
				     insn_idx);
			return -EFAULT;
		}

		insn_buf[0] = addr[0];
		insn_buf[1] = addr[1];
		insn_buf[2] = *insn;
		*cnt = 3;
	} else if (desc->func_id == special_kfunc_list[KF_bpf_list_push_back_impl] ||
		   desc->func_id == special_kfunc_list[KF_bpf_list_push_front_impl] ||
		   desc->func_id == special_kfunc_list[KF_bpf_rbtree_add_impl]) {
		struct btf_struct_meta *kptr_struct_meta = env->insn_aux_data[insn_idx].kptr_struct_meta;
		int struct_meta_reg = BPF_REG_3;
		int node_offset_reg = BPF_REG_4;

		/* rbtree_add has extra 'less' arg, so args-to-fixup are in diff regs */
		if (desc->func_id == special_kfunc_list[KF_bpf_rbtree_add_impl]) {
			struct_meta_reg = BPF_REG_4;
			node_offset_reg = BPF_REG_5;
		}

		if (!kptr_struct_meta) {
			verifier_bug(env, "kptr_struct_meta expected at insn_idx %d",
				     insn_idx);
			return -EFAULT;
		}

		__fixup_collection_insert_kfunc(&env->insn_aux_data[insn_idx], struct_meta_reg,
						node_offset_reg, insn, insn_buf, cnt);
	} else if (desc->func_id == special_kfunc_list[KF_bpf_cast_to_kern_ctx] ||
		   desc->func_id == special_kfunc_list[KF_bpf_rdonly_cast]) {
		insn_buf[0] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_1);
		*cnt = 1;
	} else if (desc->func_id == special_kfunc_list[KF_bpf_session_is_return] &&
		   env->prog->expected_attach_type == BPF_TRACE_FSESSION) {
		/*
		 * inline the bpf_session_is_return() for fsession:
		 *   bool bpf_session_is_return(void *ctx)
		 *   {
		 *       return (((u64 *)ctx)[-1] >> BPF_TRAMP_IS_RETURN_SHIFT) & 1;
		 *   }
		 */
		insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
		insn_buf[1] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, BPF_TRAMP_IS_RETURN_SHIFT);
		insn_buf[2] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1);
		*cnt = 3;
	} else if (desc->func_id == special_kfunc_list[KF_bpf_session_cookie] &&
		   env->prog->expected_attach_type == BPF_TRACE_FSESSION) {
		/*
		 * inline bpf_session_cookie() for fsession:
		 *   __u64 *bpf_session_cookie(void *ctx)
		 *   {
		 *       u64 off = (((u64 *)ctx)[-1] >> BPF_TRAMP_COOKIE_INDEX_SHIFT) & 0xFF;
		 *       return &((u64 *)ctx)[-off];
		 *   }
		 */
		insn_buf[0] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_1, -8);
		insn_buf[1] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, BPF_TRAMP_COOKIE_INDEX_SHIFT);
		insn_buf[2] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xFF);
		insn_buf[3] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 3);
		insn_buf[4] = BPF_ALU64_REG(BPF_SUB, BPF_REG_0, BPF_REG_1);
		insn_buf[5] = BPF_ALU64_IMM(BPF_NEG, BPF_REG_0, 0);
		*cnt = 6;
	}

	if (env->insn_aux_data[insn_idx].arg_prog) {
		u32 regno = env->insn_aux_data[insn_idx].arg_prog;
		struct bpf_insn ld_addrs[2] = { BPF_LD_IMM64(regno, (long)env->prog->aux) };
		int idx = *cnt;

		insn_buf[idx++] = ld_addrs[0];
		insn_buf[idx++] = ld_addrs[1];
		insn_buf[idx++] = *insn;
		*cnt = idx;
	}
	return 0;
}


