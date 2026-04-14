// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool get_call_summary(struct bpf_verifier_env *env, struct bpf_insn *call,
			     struct call_summary *cs)
{
	struct bpf_kfunc_call_arg_meta meta;
	const struct bpf_func_proto *fn;
	int i;

	if (bpf_helper_call(call)) {

		if (get_helper_proto(env, call->imm, &fn) < 0)
			/* error would be reported later */
			return false;
		cs->fastcall = fn->allow_fastcall &&
			       (verifier_inlines_helper_call(env, call->imm) ||
				bpf_jit_inlines_helper_call(call->imm));
		cs->is_void = fn->ret_type == RET_VOID;
		cs->num_params = 0;
		for (i = 0; i < ARRAY_SIZE(fn->arg_type); ++i) {
			if (fn->arg_type[i] == ARG_DONTCARE)
				break;
			cs->num_params++;
		}
		return true;
	}

	if (bpf_pseudo_kfunc_call(call)) {
		int err;

		err = fetch_kfunc_arg_meta(env, call->imm, call->off, &meta);
		if (err < 0)
			/* error would be reported later */
			return false;
		cs->num_params = btf_type_vlen(meta.func_proto);
		cs->fastcall = meta.kfunc_flags & KF_FASTCALL;
		cs->is_void = btf_type_is_void(btf_type_by_id(meta.btf, meta.func_proto->type));
		return true;
	}

	return false;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int get_callee_stack_depth(struct bpf_verifier_env *env,
				  const struct bpf_insn *insn, int idx)
{
	int start = idx + insn->imm + 1, subprog;

	subprog = find_subprog(env, start);
	if (verifier_bug_if(subprog < 0, env, "get stack depth: no program at insn %d", start))
		return -EFAULT;
	return env->subprog_info[subprog].stack_depth;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int get_constant_map_key(struct bpf_verifier_env *env,
				struct bpf_reg_state *key,
				u32 key_size,
				s64 *value)
{
	struct bpf_func_state *state = func(env, key);
	struct bpf_reg_state *reg;
	int slot, spi, off;
	int spill_size = 0;
	int zero_size = 0;
	int stack_off;
	int i, err;
	u8 *stype;

	if (!env->bpf_capable)
		return -EOPNOTSUPP;
	if (key->type != PTR_TO_STACK)
		return -EOPNOTSUPP;
	if (!tnum_is_const(key->var_off))
		return -EOPNOTSUPP;

	stack_off = key->off + key->var_off.value;
	slot = -stack_off - 1;
	spi = slot / BPF_REG_SIZE;
	off = slot % BPF_REG_SIZE;
	stype = state->stack[spi].slot_type;

	/* First handle precisely tracked STACK_ZERO */
	for (i = off; i >= 0 && stype[i] == STACK_ZERO; i--)
		zero_size++;
	if (zero_size >= key_size) {
		*value = 0;
		return 0;
	}

	/* Check that stack contains a scalar spill of expected size */
	if (!is_spilled_scalar_reg(&state->stack[spi]))
		return -EOPNOTSUPP;
	for (i = off; i >= 0 && stype[i] == STACK_SPILL; i--)
		spill_size++;
	if (spill_size != key_size)
		return -EOPNOTSUPP;

	reg = &state->stack[spi].spilled_ptr;
	if (!tnum_is_const(reg->var_off))
		/* Stack value not statically known */
		return -EOPNOTSUPP;

	/* We are relying on a constant value. So mark as precise
	 * to prevent pruning on it.
	 */
	bt_set_frame_slot(&env->bt, key->frameno, spi);
	err = mark_chain_precision_batch(env, env->cur_state);
	if (err < 0)
		return err;

	*value = reg->var_off.value;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_reg_state *get_dynptr_arg_reg(struct bpf_verifier_env *env,
						const struct bpf_func_proto *fn,
						struct bpf_reg_state *regs)
{
	struct bpf_reg_state *state = NULL;
	int i;

	for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++)
		if (arg_type_is_dynptr(fn->arg_type[i])) {
			if (state) {
				verbose(env, "verifier internal error: multiple dynptr args\n");
				return NULL;
			}
			state = &regs[BPF_REG_1 + i];
		}

	if (!state)
		verbose(env, "verifier internal error: no dynptr arg found\n");

	return state;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static enum bpf_type_flag get_dynptr_type_flag(enum bpf_dynptr_type type)
{
	switch (type) {
	case BPF_DYNPTR_TYPE_LOCAL:
		return DYNPTR_TYPE_LOCAL;
	case BPF_DYNPTR_TYPE_RINGBUF:
		return DYNPTR_TYPE_RINGBUF;
	case BPF_DYNPTR_TYPE_SKB:
		return DYNPTR_TYPE_SKB;
	case BPF_DYNPTR_TYPE_XDP:
		return DYNPTR_TYPE_XDP;
	case BPF_DYNPTR_TYPE_SKB_META:
		return DYNPTR_TYPE_SKB_META;
	case BPF_DYNPTR_TYPE_FILE:
		return DYNPTR_TYPE_FILE;
	default:
		return 0;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool get_func_retval_range(struct bpf_prog *prog,
				  struct bpf_retval_range *range)
{
	if (prog->type == BPF_PROG_TYPE_LSM &&
		prog->expected_attach_type == BPF_LSM_MAC &&
		!bpf_lsm_get_retval_range(prog, range)) {
		return true;
	}
	return false;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int get_helper_proto(struct bpf_verifier_env *env, int func_id,
			    const struct bpf_func_proto **ptr)
{
	if (func_id < 0 || func_id >= __BPF_FUNC_MAX_ID)
		return -ERANGE;

	if (!env->ops->get_func_proto)
		return -EINVAL;

	*ptr = env->ops->get_func_proto(func_id, env->prog);
	return *ptr && (*ptr)->func ? 0 : -EINVAL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_reg_state *get_iter_from_state(struct bpf_verifier_state *cur_st,
						 struct bpf_kfunc_call_arg_meta *meta)
{
	int iter_frameno = meta->iter.frameno;
	int iter_spi = meta->iter.spi;

	return &cur_st->frame[iter_frameno]->stack[iter_spi].spilled_ptr;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_jmp_history_entry *get_jmp_hist_entry(struct bpf_verifier_state *st,
						        u32 hist_end, int insn_idx)
{
	if (hist_end > 0 && st->jmp_history[hist_end - 1].idx == insn_idx)
		return &st->jmp_history[hist_end - 1];
	return NULL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
get_kfunc_ptr_arg_type(struct bpf_verifier_env *env,
		       struct bpf_kfunc_call_arg_meta *meta,
		       const struct btf_type *t, const struct btf_type *ref_t,
		       const char *ref_tname, const struct btf_param *args,
		       int argno, int nargs)
{
	u32 regno = argno + 1;
	struct bpf_reg_state *regs = cur_regs(env);
	struct bpf_reg_state *reg = &regs[regno];
	bool arg_mem_size = false;

	if (meta->func_id == special_kfunc_list[KF_bpf_cast_to_kern_ctx] ||
	    meta->func_id == special_kfunc_list[KF_bpf_session_is_return] ||
	    meta->func_id == special_kfunc_list[KF_bpf_session_cookie])
		return KF_ARG_PTR_TO_CTX;

	if (argno + 1 < nargs &&
	    (is_kfunc_arg_mem_size(meta->btf, &args[argno + 1], &regs[regno + 1]) ||
	     is_kfunc_arg_const_mem_size(meta->btf, &args[argno + 1], &regs[regno + 1])))
		arg_mem_size = true;

	/* In this function, we verify the kfunc's BTF as per the argument type,
	 * leaving the rest of the verification with respect to the register
	 * type to our caller. When a set of conditions hold in the BTF type of
	 * arguments, we resolve it to a known kfunc_ptr_arg_type.
	 */
	if (btf_is_prog_ctx_type(&env->log, meta->btf, t, resolve_prog_type(env->prog), argno))
		return KF_ARG_PTR_TO_CTX;

	if (is_kfunc_arg_nullable(meta->btf, &args[argno]) && register_is_null(reg) &&
	    !arg_mem_size)
		return KF_ARG_PTR_TO_NULL;

	if (is_kfunc_arg_alloc_obj(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_ALLOC_BTF_ID;

	if (is_kfunc_arg_refcounted_kptr(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_REFCOUNTED_KPTR;

	if (is_kfunc_arg_dynptr(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_DYNPTR;

	if (is_kfunc_arg_iter(meta, argno, &args[argno]))
		return KF_ARG_PTR_TO_ITER;

	if (is_kfunc_arg_list_head(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_LIST_HEAD;

	if (is_kfunc_arg_list_node(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_LIST_NODE;

	if (is_kfunc_arg_rbtree_root(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_RB_ROOT;

	if (is_kfunc_arg_rbtree_node(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_RB_NODE;

	if (is_kfunc_arg_const_str(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_CONST_STR;

	if (is_kfunc_arg_map(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_MAP;

	if (is_kfunc_arg_wq(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_WORKQUEUE;

	if (is_kfunc_arg_timer(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_TIMER;

	if (is_kfunc_arg_task_work(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_TASK_WORK;

	if (is_kfunc_arg_irq_flag(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_IRQ_FLAG;

	if (is_kfunc_arg_res_spin_lock(meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_RES_SPIN_LOCK;

	if ((base_type(reg->type) == PTR_TO_BTF_ID || reg2btf_ids[base_type(reg->type)])) {
		if (!btf_type_is_struct(ref_t)) {
			verbose(env, "kernel function %s args#%d pointer type %s %s is not supported\n",
				meta->func_name, argno, btf_type_str(ref_t), ref_tname);
			return -EINVAL;
		}
		return KF_ARG_PTR_TO_BTF_ID;
	}

	if (is_kfunc_arg_callback(env, meta->btf, &args[argno]))
		return KF_ARG_PTR_TO_CALLBACK;

	/* This is the catch all argument type of register types supported by
	 * check_helper_mem_access. However, we only allow when argument type is
	 * pointer to scalar, or struct composed (recursively) of scalars. When
	 * arg_mem_size is true, the pointer can be void *.
	 */
	if (!btf_type_is_scalar(ref_t) && !__btf_type_is_scalar_struct(env, meta->btf, ref_t, 0) &&
	    (arg_mem_size ? !btf_type_is_void(ref_t) : 1)) {
		verbose(env, "arg#%d pointer type %s %s must point to %sscalar, or struct with scalar\n",
			argno, btf_type_str(ref_t), ref_tname, arg_mem_size ? "void, " : "");
		return -EINVAL;
	}
	return arg_mem_size ? KF_ARG_PTR_TO_MEM_SIZE : KF_ARG_PTR_TO_MEM;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int get_prev_insn_idx(struct bpf_verifier_state *st, int i,
			     u32 *history)
{
	u32 cnt = *history;

	if (i == st->first_insn_idx) {
		if (cnt == 0)
			return -ENOENT;
		if (cnt == 1 && st->jmp_history[0].idx == i)
			return -ENOENT;
	}

	if (cnt && st->jmp_history[cnt - 1].idx == i) {
		i = st->jmp_history[cnt - 1].prev_idx;
		(*history)--;
	} else {
		i--;
	}
	return i;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int get_reg_width(struct bpf_reg_state *reg)
{
	return fls64(reg->umax_value);
}


