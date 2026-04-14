// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_acquire_function(enum bpf_func_id func_id,
				const struct bpf_map *map)
{
	enum bpf_map_type map_type = map ? map->map_type : BPF_MAP_TYPE_UNSPEC;

	if (func_id == BPF_FUNC_sk_lookup_tcp ||
	    func_id == BPF_FUNC_sk_lookup_udp ||
	    func_id == BPF_FUNC_skc_lookup_tcp ||
	    func_id == BPF_FUNC_ringbuf_reserve ||
	    func_id == BPF_FUNC_kptr_xchg)
		return true;

	if (func_id == BPF_FUNC_map_lookup_elem &&
	    (map_type == BPF_MAP_TYPE_SOCKMAP ||
	     map_type == BPF_MAP_TYPE_SOCKHASH))
		return true;

	return false;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_arena_reg(struct bpf_verifier_env *env, int regno)
{
	const struct bpf_reg_state *reg = reg_state(env, regno);

	return reg->type == PTR_TO_ARENA;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_async_callback_calling_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_timer_set_callback;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_async_callback_calling_insn(struct bpf_insn *insn)
{
	return (bpf_helper_call(insn) && is_async_callback_calling_function(insn->imm)) ||
	       (bpf_pseudo_kfunc_call(insn) && is_async_callback_calling_kfunc(insn->imm));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_async_callback_calling_kfunc(u32 btf_id)
{
	return is_bpf_wq_set_callback_kfunc(btf_id) ||
	       is_task_work_add_kfunc(btf_id);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_async_cb_sleepable(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	/* bpf_timer callbacks are never sleepable. */
	if (bpf_helper_call(insn) && insn->imm == BPF_FUNC_timer_set_callback)
		return false;

	/* bpf_wq and bpf_task_work callbacks are always sleepable. */
	if (bpf_pseudo_kfunc_call(insn) && insn->off == 0 &&
	    (is_bpf_wq_set_callback_kfunc(insn->imm) || is_task_work_add_kfunc(insn->imm)))
		return true;

	verifier_bug(env, "unhandled async callback in is_async_cb_sleepable");
	return false;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_atomic_fetch_insn(const struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_STX &&
	       BPF_MODE(insn->code) == BPF_ATOMIC &&
	       (insn->imm & BPF_FETCH);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_atomic_load_insn(const struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_STX &&
	       BPF_MODE(insn->code) == BPF_ATOMIC &&
	       insn->imm == BPF_LOAD_ACQ;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_arena_kfunc(u32 btf_id)
{
	return btf_id == special_kfunc_list[KF_bpf_arena_alloc_pages] ||
	       btf_id == special_kfunc_list[KF_bpf_arena_free_pages] ||
	       btf_id == special_kfunc_list[KF_bpf_arena_reserve_pages];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_graph_api_kfunc(u32 btf_id)
{
	return is_bpf_list_api_kfunc(btf_id) || is_bpf_rbtree_api_kfunc(btf_id) ||
	       btf_id == special_kfunc_list[KF_bpf_refcount_acquire_impl];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_iter_num_api_kfunc(u32 btf_id)
{
	return btf_id == special_kfunc_list[KF_bpf_iter_num_new] ||
	       btf_id == special_kfunc_list[KF_bpf_iter_num_next] ||
	       btf_id == special_kfunc_list[KF_bpf_iter_num_destroy];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_list_api_kfunc(u32 btf_id)
{
	return btf_id == special_kfunc_list[KF_bpf_list_push_front_impl] ||
	       btf_id == special_kfunc_list[KF_bpf_list_push_back_impl] ||
	       btf_id == special_kfunc_list[KF_bpf_list_pop_front] ||
	       btf_id == special_kfunc_list[KF_bpf_list_pop_back] ||
	       btf_id == special_kfunc_list[KF_bpf_list_front] ||
	       btf_id == special_kfunc_list[KF_bpf_list_back];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_loop_call(struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
		insn->src_reg == 0 &&
		insn->imm == BPF_FUNC_loop;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_rbtree_api_kfunc(u32 btf_id)
{
	return btf_id == special_kfunc_list[KF_bpf_rbtree_add_impl] ||
	       btf_id == special_kfunc_list[KF_bpf_rbtree_remove] ||
	       btf_id == special_kfunc_list[KF_bpf_rbtree_first] ||
	       btf_id == special_kfunc_list[KF_bpf_rbtree_root] ||
	       btf_id == special_kfunc_list[KF_bpf_rbtree_left] ||
	       btf_id == special_kfunc_list[KF_bpf_rbtree_right];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_res_spin_lock_kfunc(u32 btf_id)
{
	return btf_id == special_kfunc_list[KF_bpf_res_spin_lock] ||
	       btf_id == special_kfunc_list[KF_bpf_res_spin_unlock] ||
	       btf_id == special_kfunc_list[KF_bpf_res_spin_lock_irqsave] ||
	       btf_id == special_kfunc_list[KF_bpf_res_spin_unlock_irqrestore];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_st_mem(struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_ST && BPF_MODE(insn->code) == BPF_MEM;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_stream_kfunc(u32 btf_id)
{
	return btf_id == special_kfunc_list[KF_bpf_stream_vprintk] ||
	       btf_id == special_kfunc_list[KF_bpf_stream_print_stack];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_throw_kfunc(struct bpf_insn *insn)
{
	return bpf_pseudo_kfunc_call(insn) && insn->off == 0 &&
	       insn->imm == special_kfunc_list[KF_bpf_throw];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_bpf_wq_set_callback_kfunc(u32 btf_id)
{
	return btf_id == special_kfunc_list[KF_bpf_wq_set_callback];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int is_branch_taken(struct bpf_reg_state *reg1, struct bpf_reg_state *reg2,
			   u8 opcode, bool is_jmp32)
{
	if (reg_is_pkt_pointer_any(reg1) && reg_is_pkt_pointer_any(reg2) && !is_jmp32)
		return is_pkt_ptr_branch_taken(reg1, reg2, opcode);

	if (__is_pointer_value(false, reg1) || __is_pointer_value(false, reg2)) {
		u64 val;

		/* arrange that reg2 is a scalar, and reg1 is a pointer */
		if (!is_reg_const(reg2, is_jmp32)) {
			opcode = flip_opcode(opcode);
			swap(reg1, reg2);
		}
		/* and ensure that reg2 is a constant */
		if (!is_reg_const(reg2, is_jmp32))
			return -1;

		if (!reg_not_null(reg1))
			return -1;

		/* If pointer is valid tests against zero will fail so we can
		 * use this to direct branch taken.
		 */
		val = reg_const_value(reg2, is_jmp32);
		if (val != 0)
			return -1;

		switch (opcode) {
		case BPF_JEQ:
			return 0;
		case BPF_JNE:
			return 1;
		default:
			return -1;
		}
	}

	/* now deal with two scalars, but not necessarily constants */
	return is_scalar_branch_taken(reg1, reg2, opcode, is_jmp32);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_callback_calling_function(enum bpf_func_id func_id)
{
	return is_sync_callback_calling_function(func_id) ||
	       is_async_callback_calling_function(func_id);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_callback_calling_kfunc(u32 btf_id)
{
	return is_sync_callback_calling_kfunc(btf_id) ||
	       is_async_callback_calling_kfunc(btf_id);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_cmpxchg_insn(const struct bpf_insn *insn)
{
	return BPF_CLASS(insn->code) == BPF_STX &&
	       BPF_MODE(insn->code) == BPF_ATOMIC &&
	       insn->imm == BPF_CMPXCHG;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_ctx_reg(struct bpf_verifier_env *env, int regno)
{
	const struct bpf_reg_state *reg = reg_state(env, regno);

	return reg->type == PTR_TO_CTX;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_dynptr_ref_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_dynptr_data;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_dynptr_reg_valid_init(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = func(env, reg);
	int i, spi;

	/* This already represents first slot of initialized bpf_dynptr.
	 *
	 * CONST_PTR_TO_DYNPTR already has fixed and var_off as 0 due to
	 * check_func_arg_reg_off's logic, so we don't need to check its
	 * offset and alignment.
	 */
	if (reg->type == CONST_PTR_TO_DYNPTR)
		return true;

	spi = dynptr_get_spi(env, reg);
	if (spi < 0)
		return false;
	if (!state->stack[spi].spilled_ptr.dynptr.first_slot)
		return false;

	for (i = 0; i < BPF_REG_SIZE; i++) {
		if (state->stack[spi].slot_type[i] != STACK_DYNPTR ||
		    state->stack[spi - 1].slot_type[i] != STACK_DYNPTR)
			return false;
	}

	return true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_dynptr_reg_valid_uninit(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	int spi;

	if (reg->type == CONST_PTR_TO_DYNPTR)
		return false;

	spi = dynptr_get_spi(env, reg);

	/* -ERANGE (i.e. spi not falling into allocated stack slots) isn't an
	 * error because this just means the stack state hasn't been updated yet.
	 * We will do check_mem_access to check and update stack bounds later.
	 */
	if (spi < 0 && spi != -ERANGE)
		return false;

	/* We don't need to check if the stack slots are marked by previous
	 * dynptr initializations because we allow overwriting existing unreferenced
	 * STACK_DYNPTR slots, see mark_stack_slots_dynptr which calls
	 * destroy_if_dynptr_stack_slot to ensure dynptr objects at the slots we are
	 * touching are completely destructed before we reinitialize them for a new
	 * one. For referenced ones, destroy_if_dynptr_stack_slot returns an error early
	 * instead of delaying it until the end where the user will get "Unreleased
	 * reference" error.
	 */
	return true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_dynptr_type_expected(struct bpf_verifier_env *env, struct bpf_reg_state *reg,
				    enum bpf_arg_type arg_type)
{
	struct bpf_func_state *state = func(env, reg);
	enum bpf_dynptr_type dynptr_type;
	int spi;

	/* ARG_PTR_TO_DYNPTR takes any type of dynptr */
	if (arg_type == ARG_PTR_TO_DYNPTR)
		return true;

	dynptr_type = arg_to_dynptr_type(arg_type);
	if (reg->type == CONST_PTR_TO_DYNPTR) {
		return reg->dynptr.type == dynptr_type;
	} else {
		spi = dynptr_get_spi(env, reg);
		if (spi < 0)
			return false;
		return state->stack[spi].spilled_ptr.dynptr.type == dynptr_type;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_flow_key_reg(struct bpf_verifier_env *env, int regno)
{
	const struct bpf_reg_state *reg = reg_state(env, regno);

	/* Separate to is_ctx_reg() since we still want to allow BPF_ST here. */
	return reg->type == PTR_TO_FLOW_KEYS;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_force_checkpoint(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data[insn_idx].force_checkpoint;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int is_irq_flag_reg_valid_init(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = func(env, reg);
	struct bpf_stack_state *slot;
	struct bpf_reg_state *st;
	int spi, i;

	spi = irq_flag_get_spi(env, reg);
	if (spi < 0)
		return -EINVAL;

	slot = &state->stack[spi];
	st = &slot->spilled_ptr;

	if (!st->ref_obj_id)
		return -EINVAL;

	for (i = 0; i < BPF_REG_SIZE; i++)
		if (slot->slot_type[i] != STACK_IRQ_FLAG)
			return -EINVAL;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_irq_flag_reg_valid_uninit(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = func(env, reg);
	struct bpf_stack_state *slot;
	int spi, i;

	/* For -ERANGE (i.e. spi not falling into allocated stack slots), we
	 * will do check_mem_access to check and update stack bounds later, so
	 * return true for that case.
	 */
	spi = irq_flag_get_spi(env, reg);
	if (spi == -ERANGE)
		return true;
	if (spi < 0)
		return false;

	slot = &state->stack[spi];

	for (i = 0; i < BPF_REG_SIZE; i++)
		if (slot->slot_type[i] == STACK_IRQ_FLAG)
			return false;
	return true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_iter_destroy_kfunc(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_ITER_DESTROY;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_iter_kfunc(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & (KF_ITER_NEW | KF_ITER_NEXT | KF_ITER_DESTROY);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_iter_new_kfunc(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_ITER_NEW;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_iter_next_insn(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data[insn_idx].is_iter_next;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_iter_next_kfunc(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_ITER_NEXT;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int is_iter_reg_valid_init(struct bpf_verifier_env *env, struct bpf_reg_state *reg,
				   struct btf *btf, u32 btf_id, int nr_slots)
{
	struct bpf_func_state *state = func(env, reg);
	int spi, i, j;

	spi = iter_get_spi(env, reg, nr_slots);
	if (spi < 0)
		return -EINVAL;

	for (i = 0; i < nr_slots; i++) {
		struct bpf_stack_state *slot = &state->stack[spi - i];
		struct bpf_reg_state *st = &slot->spilled_ptr;

		if (st->type & PTR_UNTRUSTED)
			return -EPROTO;
		/* only main (first) slot has ref_obj_id set */
		if (i == 0 && !st->ref_obj_id)
			return -EINVAL;
		if (i != 0 && st->ref_obj_id)
			return -EINVAL;
		if (st->iter.btf != btf || st->iter.btf_id != btf_id)
			return -EINVAL;

		for (j = 0; j < BPF_REG_SIZE; j++)
			if (slot->slot_type[j] != STACK_ITER)
				return -EINVAL;
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_iter_reg_valid_uninit(struct bpf_verifier_env *env,
				     struct bpf_reg_state *reg, int nr_slots)
{
	struct bpf_func_state *state = func(env, reg);
	int spi, i, j;

	/* For -ERANGE (i.e. spi not falling into allocated stack slots), we
	 * will do check_mem_access to check and update stack bounds later, so
	 * return true for that case.
	 */
	spi = iter_get_spi(env, reg, nr_slots);
	if (spi == -ERANGE)
		return true;
	if (spi < 0)
		return false;

	for (i = 0; i < nr_slots; i++) {
		struct bpf_stack_state *slot = &state->stack[spi - i];

		for (j = 0; j < BPF_REG_SIZE; j++)
			if (slot->slot_type[j] == STACK_ITER)
				return false;
	}

	return true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_jmp_point(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data[insn_idx].jmp_point;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_acquire(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_ACQUIRE;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_alloc_obj(const struct btf *btf, const struct btf_param *arg)
{
	return btf_param_match_suffix(btf, arg, "__alloc");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_callback(struct bpf_verifier_env *env, const struct btf *btf,
				  const struct btf_param *arg)
{
	const struct btf_type *t;

	t = btf_type_resolve_func_ptr(btf, arg->type, NULL);
	if (!t)
		return false;

	return true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_const_mem_size(const struct btf *btf,
					const struct btf_param *arg,
					const struct bpf_reg_state *reg)
{
	const struct btf_type *t;

	t = btf_type_skip_modifiers(btf, arg->type, NULL);
	if (!btf_type_is_scalar(t) || reg->type != SCALAR_VALUE)
		return false;

	return btf_param_match_suffix(btf, arg, "__szk");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_const_str(const struct btf *btf, const struct btf_param *arg)
{
	return btf_param_match_suffix(btf, arg, "__str");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_constant(const struct btf *btf, const struct btf_param *arg)
{
	return btf_param_match_suffix(btf, arg, "__k");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_dynptr(const struct btf *btf, const struct btf_param *arg)
{
	return __is_kfunc_ptr_arg_type(btf, arg, KF_ARG_DYNPTR_ID);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_ignore(const struct btf *btf, const struct btf_param *arg)
{
	return btf_param_match_suffix(btf, arg, "__ign");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_irq_flag(const struct btf *btf, const struct btf_param *arg)
{
	return btf_param_match_suffix(btf, arg, "__irq_flag");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_iter(struct bpf_kfunc_call_arg_meta *meta, int arg_idx,
			      const struct btf_param *arg)
{
	/* btf_check_iter_kfuncs() guarantees that first argument of any iter
	 * kfunc is iter state pointer
	 */
	if (is_iter_kfunc(meta))
		return arg_idx == 0;

	/* iter passed as an argument to a generic kfunc */
	return btf_param_match_suffix(meta->btf, arg, "__iter");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_list_head(const struct btf *btf, const struct btf_param *arg)
{
	return __is_kfunc_ptr_arg_type(btf, arg, KF_ARG_LIST_HEAD_ID);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_list_node(const struct btf *btf, const struct btf_param *arg)
{
	return __is_kfunc_ptr_arg_type(btf, arg, KF_ARG_LIST_NODE_ID);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_map(const struct btf *btf, const struct btf_param *arg)
{
	return btf_param_match_suffix(btf, arg, "__map");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_mem_size(const struct btf *btf,
				  const struct btf_param *arg,
				  const struct bpf_reg_state *reg)
{
	const struct btf_type *t;

	t = btf_type_skip_modifiers(btf, arg->type, NULL);
	if (!btf_type_is_scalar(t) || reg->type != SCALAR_VALUE)
		return false;

	return btf_param_match_suffix(btf, arg, "__sz");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_nullable(const struct btf *btf, const struct btf_param *arg)
{
	return btf_param_match_suffix(btf, arg, "__nullable");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_prog_aux(const struct btf *btf, const struct btf_param *arg)
{
	return __is_kfunc_ptr_arg_type(btf, arg, KF_ARG_PROG_AUX_ID);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_rbtree_node(const struct btf *btf, const struct btf_param *arg)
{
	return __is_kfunc_ptr_arg_type(btf, arg, KF_ARG_RB_NODE_ID);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_rbtree_root(const struct btf *btf, const struct btf_param *arg)
{
	return __is_kfunc_ptr_arg_type(btf, arg, KF_ARG_RB_ROOT_ID);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_refcounted_kptr(const struct btf *btf, const struct btf_param *arg)
{
	return btf_param_match_suffix(btf, arg, "__refcounted_kptr");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_res_spin_lock(const struct btf *btf, const struct btf_param *arg)
{
	return __is_kfunc_ptr_arg_type(btf, arg, KF_ARG_RES_SPIN_LOCK_ID);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_scalar_with_name(const struct btf *btf,
					  const struct btf_param *arg,
					  const char *name)
{
	int len, target_len = strlen(name);
	const char *param_name;

	param_name = btf_name_by_offset(btf, arg->name_off);
	if (str_is_empty(param_name))
		return false;
	len = strlen(param_name);
	if (len != target_len)
		return false;
	if (strcmp(param_name, name))
		return false;

	return true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_task_work(const struct btf *btf, const struct btf_param *arg)
{
	return __is_kfunc_ptr_arg_type(btf, arg, KF_ARG_TASK_WORK_ID);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_timer(const struct btf *btf, const struct btf_param *arg)
{
	return __is_kfunc_ptr_arg_type(btf, arg, KF_ARG_TIMER_ID);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_uninit(const struct btf *btf, const struct btf_param *arg)
{
	return btf_param_match_suffix(btf, arg, "__uninit");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_arg_wq(const struct btf *btf, const struct btf_param *arg)
{
	return __is_kfunc_ptr_arg_type(btf, arg, KF_ARG_WORKQUEUE_ID);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_bpf_preempt_disable(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->func_id == special_kfunc_list[KF_bpf_preempt_disable];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_bpf_preempt_enable(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->func_id == special_kfunc_list[KF_bpf_preempt_enable];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_bpf_rcu_read_lock(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->func_id == special_kfunc_list[KF_bpf_rcu_read_lock];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_bpf_rcu_read_unlock(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->func_id == special_kfunc_list[KF_bpf_rcu_read_unlock];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_destructive(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_DESTRUCTIVE;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_pkt_changing(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->func_id == special_kfunc_list[KF_bpf_xdp_pull_data];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_rcu(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_RCU;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_rcu_protected(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_RCU_PROTECTED;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_release(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_RELEASE;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_ret_null(struct bpf_kfunc_call_arg_meta *meta)
{
	if (meta->func_id == special_kfunc_list[KF_bpf_refcount_acquire_impl] &&
	    meta->arg_owning_ref) {
		return false;
	}

	return meta->kfunc_flags & KF_RET_NULL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_kfunc_sleepable(struct bpf_kfunc_call_arg_meta *meta)
{
	return meta->kfunc_flags & KF_SLEEPABLE;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_list_node_type(const struct btf_type *t)
{
	return t == btf_type_by_id(btf_vmlinux, kf_arg_btf_ids[KF_ARG_LIST_NODE_ID]);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_may_goto_insn(struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_JCOND) && insn->src_reg == BPF_MAY_GOTO;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_may_goto_insn_at(struct bpf_verifier_env *env, int insn_idx)
{
	return is_may_goto_insn(&env->prog->insnsi[insn_idx]);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int is_pkt_ptr_branch_taken(struct bpf_reg_state *dst_reg,
				   struct bpf_reg_state *src_reg,
				   u8 opcode)
{
	struct bpf_reg_state *pkt;

	if (src_reg->type == PTR_TO_PACKET_END) {
		pkt = dst_reg;
	} else if (dst_reg->type == PTR_TO_PACKET_END) {
		pkt = src_reg;
		opcode = flip_opcode(opcode);
	} else {
		return -1;
	}

	if (pkt->range >= 0)
		return -1;

	switch (opcode) {
	case BPF_JLE:
		/* pkt <= pkt_end */
		fallthrough;
	case BPF_JGT:
		/* pkt > pkt_end */
		if (pkt->range == BEYOND_PKT_END)
			/* pkt has at last one extra byte beyond pkt_end */
			return opcode == BPF_JGT;
		break;
	case BPF_JLT:
		/* pkt < pkt_end */
		fallthrough;
	case BPF_JGE:
		/* pkt >= pkt_end */
		if (pkt->range == BEYOND_PKT_END || pkt->range == AT_PKT_END)
			return opcode == BPF_JGE;
		break;
	}
	return -1;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_pkt_reg(struct bpf_verifier_env *env, int regno)
{
	const struct bpf_reg_state *reg = reg_state(env, regno);

	return type_is_pkt_pointer(reg->type);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_pointer_value(struct bpf_verifier_env *env, int regno)
{
	return __is_pointer_value(env->allow_ptr_leaks, reg_state(env, regno));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_prune_point(struct bpf_verifier_env *env, int insn_idx)
{
	return env->insn_aux_data[insn_idx].prune_point;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_ptr_cast_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_tcp_sock ||
		func_id == BPF_FUNC_sk_fullsock ||
		func_id == BPF_FUNC_skc_to_tcp_sock ||
		func_id == BPF_FUNC_skc_to_tcp6_sock ||
		func_id == BPF_FUNC_skc_to_udp6_sock ||
		func_id == BPF_FUNC_skc_to_mptcp_sock ||
		func_id == BPF_FUNC_skc_to_tcp_timewait_sock ||
		func_id == BPF_FUNC_skc_to_tcp_request_sock;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_ptr_to_mem(enum bpf_reg_type type)
{
	return base_type(type) == PTR_TO_MEM;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_ptr_to_mem_or_btf_id(enum bpf_reg_type type)
{
	switch (base_type(type)) {
	case PTR_TO_MEM:
	case PTR_TO_BTF_ID:
		return true;
	default:
		return false;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_rbtree_lock_required_kfunc(u32 btf_id)
{
	return is_bpf_rbtree_api_kfunc(btf_id);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_rbtree_node_type(const struct btf_type *t)
{
	return t == btf_type_by_id(btf_vmlinux, kf_arg_btf_ids[KF_ARG_RB_NODE_ID]);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_rcu_reg(const struct bpf_reg_state *reg)
{
	return reg->type & MEM_RCU;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_reg64(struct bpf_insn *insn,
		     u32 regno, struct bpf_reg_state *reg, enum reg_arg_type t)
{
	u8 code, class, op;

	code = insn->code;
	class = BPF_CLASS(code);
	op = BPF_OP(code);
	if (class == BPF_JMP) {
		/* BPF_EXIT for "main" will reach here. Return TRUE
		 * conservatively.
		 */
		if (op == BPF_EXIT)
			return true;
		if (op == BPF_CALL) {
			/* BPF to BPF call will reach here because of marking
			 * caller saved clobber with DST_OP_NO_MARK for which we
			 * don't care the register def because they are anyway
			 * marked as NOT_INIT already.
			 */
			if (insn->src_reg == BPF_PSEUDO_CALL)
				return false;
			/* Helper call will reach here because of arg type
			 * check, conservatively return TRUE.
			 */
			if (t == SRC_OP)
				return true;

			return false;
		}
	}

	if (class == BPF_ALU64 && op == BPF_END && (insn->imm == 16 || insn->imm == 32))
		return false;

	if (class == BPF_ALU64 || class == BPF_JMP ||
	    (class == BPF_ALU && op == BPF_END && insn->imm == 64))
		return true;

	if (class == BPF_ALU || class == BPF_JMP32)
		return false;

	if (class == BPF_LDX) {
		if (t != SRC_OP)
			return BPF_SIZE(code) == BPF_DW || BPF_MODE(code) == BPF_MEMSX;
		/* LDX source must be ptr. */
		return true;
	}

	if (class == BPF_STX) {
		/* BPF_STX (including atomic variants) has one or more source
		 * operands, one of which is a ptr. Check whether the caller is
		 * asking about it.
		 */
		if (t == SRC_OP && reg->type != SCALAR_VALUE)
			return true;
		return BPF_SIZE(code) == BPF_DW;
	}

	if (class == BPF_LD) {
		u8 mode = BPF_MODE(code);

		/* LD_IMM64 */
		if (mode == BPF_IMM)
			return true;

		/* Both LD_IND and LD_ABS return 32-bit data. */
		if (t != SRC_OP)
			return  false;

		/* Implicit ctx ptr. */
		if (regno == BPF_REG_6)
			return true;

		/* Explicit source could be any width. */
		return true;
	}

	if (class == BPF_ST)
		/* The only source register for BPF_ST is a ptr. */
		return true;

	/* Conservatively return true at default. */
	return true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_reg_const(struct bpf_reg_state *reg, bool subreg32)
{
	return reg->type == SCALAR_VALUE &&
	       tnum_is_const(subreg32 ? tnum_subreg(reg->var_off) : reg->var_off);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_safe_to_compute_dst_reg_range(struct bpf_insn *insn,
					     const struct bpf_reg_state *src_reg)
{
	bool src_is_const = false;
	u64 insn_bitness = (BPF_CLASS(insn->code) == BPF_ALU64) ? 64 : 32;

	if (insn_bitness == 32) {
		if (tnum_subreg_is_const(src_reg->var_off)
		    && src_reg->s32_min_value == src_reg->s32_max_value
		    && src_reg->u32_min_value == src_reg->u32_max_value)
			src_is_const = true;
	} else {
		if (tnum_is_const(src_reg->var_off)
		    && src_reg->smin_value == src_reg->smax_value
		    && src_reg->umin_value == src_reg->umax_value)
			src_is_const = true;
	}

	switch (BPF_OP(insn->code)) {
	case BPF_ADD:
	case BPF_SUB:
	case BPF_NEG:
	case BPF_AND:
	case BPF_XOR:
	case BPF_OR:
	case BPF_MUL:
	case BPF_END:
		return true;

	/*
	 * Division and modulo operators range is only safe to compute when the
	 * divisor is a constant.
	 */
	case BPF_DIV:
	case BPF_MOD:
		return src_is_const;

	/* Shift operators range is only computable if shift dimension operand
	 * is a constant. Shifts greater than 31 or 63 are undefined. This
	 * includes shifts by a negative number.
	 */
	case BPF_LSH:
	case BPF_RSH:
	case BPF_ARSH:
		return (src_is_const && src_reg->umax_value < insn_bitness);
	default:
		return false;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int is_scalar_branch_taken(struct bpf_reg_state *reg1, struct bpf_reg_state *reg2,
				  u8 opcode, bool is_jmp32)
{
	struct tnum t1 = is_jmp32 ? tnum_subreg(reg1->var_off) : reg1->var_off;
	struct tnum t2 = is_jmp32 ? tnum_subreg(reg2->var_off) : reg2->var_off;
	u64 umin1 = is_jmp32 ? (u64)reg1->u32_min_value : reg1->umin_value;
	u64 umax1 = is_jmp32 ? (u64)reg1->u32_max_value : reg1->umax_value;
	s64 smin1 = is_jmp32 ? (s64)reg1->s32_min_value : reg1->smin_value;
	s64 smax1 = is_jmp32 ? (s64)reg1->s32_max_value : reg1->smax_value;
	u64 umin2 = is_jmp32 ? (u64)reg2->u32_min_value : reg2->umin_value;
	u64 umax2 = is_jmp32 ? (u64)reg2->u32_max_value : reg2->umax_value;
	s64 smin2 = is_jmp32 ? (s64)reg2->s32_min_value : reg2->smin_value;
	s64 smax2 = is_jmp32 ? (s64)reg2->s32_max_value : reg2->smax_value;

	if (reg1 == reg2) {
		switch (opcode) {
		case BPF_JGE:
		case BPF_JLE:
		case BPF_JSGE:
		case BPF_JSLE:
		case BPF_JEQ:
			return 1;
		case BPF_JGT:
		case BPF_JLT:
		case BPF_JSGT:
		case BPF_JSLT:
		case BPF_JNE:
			return 0;
		case BPF_JSET:
			if (tnum_is_const(t1))
				return t1.value != 0;
			else
				return (smin1 <= 0 && smax1 >= 0) ? -1 : 1;
		default:
			return -1;
		}
	}

	switch (opcode) {
	case BPF_JEQ:
		/* constants, umin/umax and smin/smax checks would be
		 * redundant in this case because they all should match
		 */
		if (tnum_is_const(t1) && tnum_is_const(t2))
			return t1.value == t2.value;
		if (!tnum_overlap(t1, t2))
			return 0;
		/* non-overlapping ranges */
		if (umin1 > umax2 || umax1 < umin2)
			return 0;
		if (smin1 > smax2 || smax1 < smin2)
			return 0;
		if (!is_jmp32) {
			/* if 64-bit ranges are inconclusive, see if we can
			 * utilize 32-bit subrange knowledge to eliminate
			 * branches that can't be taken a priori
			 */
			if (reg1->u32_min_value > reg2->u32_max_value ||
			    reg1->u32_max_value < reg2->u32_min_value)
				return 0;
			if (reg1->s32_min_value > reg2->s32_max_value ||
			    reg1->s32_max_value < reg2->s32_min_value)
				return 0;
		}
		break;
	case BPF_JNE:
		/* constants, umin/umax and smin/smax checks would be
		 * redundant in this case because they all should match
		 */
		if (tnum_is_const(t1) && tnum_is_const(t2))
			return t1.value != t2.value;
		if (!tnum_overlap(t1, t2))
			return 1;
		/* non-overlapping ranges */
		if (umin1 > umax2 || umax1 < umin2)
			return 1;
		if (smin1 > smax2 || smax1 < smin2)
			return 1;
		if (!is_jmp32) {
			/* if 64-bit ranges are inconclusive, see if we can
			 * utilize 32-bit subrange knowledge to eliminate
			 * branches that can't be taken a priori
			 */
			if (reg1->u32_min_value > reg2->u32_max_value ||
			    reg1->u32_max_value < reg2->u32_min_value)
				return 1;
			if (reg1->s32_min_value > reg2->s32_max_value ||
			    reg1->s32_max_value < reg2->s32_min_value)
				return 1;
		}
		break;
	case BPF_JSET:
		if (!is_reg_const(reg2, is_jmp32)) {
			swap(reg1, reg2);
			swap(t1, t2);
		}
		if (!is_reg_const(reg2, is_jmp32))
			return -1;
		if ((~t1.mask & t1.value) & t2.value)
			return 1;
		if (!((t1.mask | t1.value) & t2.value))
			return 0;
		break;
	case BPF_JGT:
		if (umin1 > umax2)
			return 1;
		else if (umax1 <= umin2)
			return 0;
		break;
	case BPF_JSGT:
		if (smin1 > smax2)
			return 1;
		else if (smax1 <= smin2)
			return 0;
		break;
	case BPF_JLT:
		if (umax1 < umin2)
			return 1;
		else if (umin1 >= umax2)
			return 0;
		break;
	case BPF_JSLT:
		if (smax1 < smin2)
			return 1;
		else if (smin1 >= smax2)
			return 0;
		break;
	case BPF_JGE:
		if (umin1 >= umax2)
			return 1;
		else if (umax1 < umin2)
			return 0;
		break;
	case BPF_JSGE:
		if (smin1 >= smax2)
			return 1;
		else if (smax1 < smin2)
			return 0;
		break;
	case BPF_JLE:
		if (umax1 <= umin2)
			return 1;
		else if (umin1 > umax2)
			return 0;
		break;
	case BPF_JSLE:
		if (smax1 <= smin2)
			return 1;
		else if (smin1 > smax2)
			return 0;
		break;
	}

	return -1;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_sk_reg(struct bpf_verifier_env *env, int regno)
{
	const struct bpf_reg_state *reg = reg_state(env, regno);

	return type_is_sk_pointer(reg->type);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_spi_bounds_valid(struct bpf_func_state *state, int spi, int nr_slots)
{
       int allocated_slots = state->allocated_stack / BPF_REG_SIZE;

       /* We need to check that slots between [spi - nr_slots + 1, spi] are
	* within [0, allocated_stack).
	*
	* Please note that the spi grows downwards. For example, a dynptr
	* takes the size of two stack slots; the first slot will be at
	* spi and the second slot will be at spi - 1.
	*/
       return spi - nr_slots + 1 >= 0 && spi < allocated_slots;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_spillable_regtype(enum bpf_reg_type type)
{
	switch (base_type(type)) {
	case PTR_TO_MAP_VALUE:
	case PTR_TO_STACK:
	case PTR_TO_CTX:
	case PTR_TO_PACKET:
	case PTR_TO_PACKET_META:
	case PTR_TO_PACKET_END:
	case PTR_TO_FLOW_KEYS:
	case CONST_PTR_TO_MAP:
	case PTR_TO_SOCKET:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_TCP_SOCK:
	case PTR_TO_XDP_SOCK:
	case PTR_TO_BTF_ID:
	case PTR_TO_BUF:
	case PTR_TO_MEM:
	case PTR_TO_FUNC:
	case PTR_TO_MAP_KEY:
	case PTR_TO_ARENA:
		return true;
	default:
		return false;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_spilled_reg(const struct bpf_stack_state *stack)
{
	return stack->slot_type[BPF_REG_SIZE - 1] == STACK_SPILL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_spilled_scalar_reg(const struct bpf_stack_state *stack)
{
	return stack->slot_type[BPF_REG_SIZE - 1] == STACK_SPILL &&
	       stack->spilled_ptr.type == SCALAR_VALUE;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_spilled_scalar_reg64(const struct bpf_stack_state *stack)
{
	return stack->slot_type[0] == STACK_SPILL &&
	       stack->spilled_ptr.type == SCALAR_VALUE;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_stack_all_misc(struct bpf_verifier_env *env,
			      struct bpf_stack_state *stack)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(stack->slot_type); ++i) {
		if ((stack->slot_type[i] == STACK_MISC) ||
		    (stack->slot_type[i] == STACK_INVALID && env->allow_uninit_stack))
			continue;
		return false;
	}

	return true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_stack_slot_special(const struct bpf_stack_state *stack)
{
	enum bpf_stack_slot_type type = stack->slot_type[BPF_REG_SIZE - 1];

	switch (type) {
	case STACK_SPILL:
	case STACK_DYNPTR:
	case STACK_ITER:
	case STACK_IRQ_FLAG:
		return true;
	case STACK_INVALID:
	case STACK_MISC:
	case STACK_ZERO:
		return false;
	default:
		WARN_ONCE(1, "unknown stack slot type %d\n", type);
		return true;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int is_state_visited(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_verifier_state_list *new_sl;
	struct bpf_verifier_state_list *sl;
	struct bpf_verifier_state *cur = env->cur_state, *new;
	bool force_new_state, add_new_state, loop;
	int n, err, states_cnt = 0;
	struct list_head *pos, *tmp, *head;

	force_new_state = env->test_state_freq || is_force_checkpoint(env, insn_idx) ||
			  /* Avoid accumulating infinitely long jmp history */
			  cur->jmp_history_cnt > 40;

	/* bpf progs typically have pruning point every 4 instructions
	 * http://vger.kernel.org/bpfconf2019.html#session-1
	 * Do not add new state for future pruning if the verifier hasn't seen
	 * at least 2 jumps and at least 8 instructions.
	 * This heuristics helps decrease 'total_states' and 'peak_states' metric.
	 * In tests that amounts to up to 50% reduction into total verifier
	 * memory consumption and 20% verifier time speedup.
	 */
	add_new_state = force_new_state;
	if (env->jmps_processed - env->prev_jmps_processed >= 2 &&
	    env->insn_processed - env->prev_insn_processed >= 8)
		add_new_state = true;

	clean_live_states(env, insn_idx, cur);

	loop = false;
	head = explored_state(env, insn_idx);
	list_for_each_safe(pos, tmp, head) {
		sl = container_of(pos, struct bpf_verifier_state_list, node);
		states_cnt++;
		if (sl->state.insn_idx != insn_idx)
			continue;

		if (sl->state.branches) {
			struct bpf_func_state *frame = sl->state.frame[sl->state.curframe];

			if (frame->in_async_callback_fn &&
			    frame->async_entry_cnt != cur->frame[cur->curframe]->async_entry_cnt) {
				/* Different async_entry_cnt means that the verifier is
				 * processing another entry into async callback.
				 * Seeing the same state is not an indication of infinite
				 * loop or infinite recursion.
				 * But finding the same state doesn't mean that it's safe
				 * to stop processing the current state. The previous state
				 * hasn't yet reached bpf_exit, since state.branches > 0.
				 * Checking in_async_callback_fn alone is not enough either.
				 * Since the verifier still needs to catch infinite loops
				 * inside async callbacks.
				 */
				goto skip_inf_loop_check;
			}
			/* BPF open-coded iterators loop detection is special.
			 * states_maybe_looping() logic is too simplistic in detecting
			 * states that *might* be equivalent, because it doesn't know
			 * about ID remapping, so don't even perform it.
			 * See process_iter_next_call() and iter_active_depths_differ()
			 * for overview of the logic. When current and one of parent
			 * states are detected as equivalent, it's a good thing: we prove
			 * convergence and can stop simulating further iterations.
			 * It's safe to assume that iterator loop will finish, taking into
			 * account iter_next() contract of eventually returning
			 * sticky NULL result.
			 *
			 * Note, that states have to be compared exactly in this case because
			 * read and precision marks might not be finalized inside the loop.
			 * E.g. as in the program below:
			 *
			 *     1. r7 = -16
			 *     2. r6 = bpf_get_prandom_u32()
			 *     3. while (bpf_iter_num_next(&fp[-8])) {
			 *     4.   if (r6 != 42) {
			 *     5.     r7 = -32
			 *     6.     r6 = bpf_get_prandom_u32()
			 *     7.     continue
			 *     8.   }
			 *     9.   r0 = r10
			 *    10.   r0 += r7
			 *    11.   r8 = *(u64 *)(r0 + 0)
			 *    12.   r6 = bpf_get_prandom_u32()
			 *    13. }
			 *
			 * Here verifier would first visit path 1-3, create a checkpoint at 3
			 * with r7=-16, continue to 4-7,3. Existing checkpoint at 3 does
			 * not have read or precision mark for r7 yet, thus inexact states
			 * comparison would discard current state with r7=-32
			 * => unsafe memory access at 11 would not be caught.
			 */
			if (is_iter_next_insn(env, insn_idx)) {
				if (states_equal(env, &sl->state, cur, RANGE_WITHIN)) {
					struct bpf_func_state *cur_frame;
					struct bpf_reg_state *iter_state, *iter_reg;
					int spi;

					cur_frame = cur->frame[cur->curframe];
					/* btf_check_iter_kfuncs() enforces that
					 * iter state pointer is always the first arg
					 */
					iter_reg = &cur_frame->regs[BPF_REG_1];
					/* current state is valid due to states_equal(),
					 * so we can assume valid iter and reg state,
					 * no need for extra (re-)validations
					 */
					spi = __get_spi(iter_reg->off + iter_reg->var_off.value);
					iter_state = &func(env, iter_reg)->stack[spi].spilled_ptr;
					if (iter_state->iter.state == BPF_ITER_STATE_ACTIVE) {
						loop = true;
						goto hit;
					}
				}
				goto skip_inf_loop_check;
			}
			if (is_may_goto_insn_at(env, insn_idx)) {
				if (sl->state.may_goto_depth != cur->may_goto_depth &&
				    states_equal(env, &sl->state, cur, RANGE_WITHIN)) {
					loop = true;
					goto hit;
				}
			}
			if (bpf_calls_callback(env, insn_idx)) {
				if (states_equal(env, &sl->state, cur, RANGE_WITHIN)) {
					loop = true;
					goto hit;
				}
				goto skip_inf_loop_check;
			}
			/* attempt to detect infinite loop to avoid unnecessary doomed work */
			if (states_maybe_looping(&sl->state, cur) &&
			    states_equal(env, &sl->state, cur, EXACT) &&
			    !iter_active_depths_differ(&sl->state, cur) &&
			    sl->state.may_goto_depth == cur->may_goto_depth &&
			    sl->state.callback_unroll_depth == cur->callback_unroll_depth) {
				verbose_linfo(env, insn_idx, "; ");
				verbose(env, "infinite loop detected at insn %d\n", insn_idx);
				verbose(env, "cur state:");
				print_verifier_state(env, cur, cur->curframe, true);
				verbose(env, "old state:");
				print_verifier_state(env, &sl->state, cur->curframe, true);
				return -EINVAL;
			}
			/* if the verifier is processing a loop, avoid adding new state
			 * too often, since different loop iterations have distinct
			 * states and may not help future pruning.
			 * This threshold shouldn't be too low to make sure that
			 * a loop with large bound will be rejected quickly.
			 * The most abusive loop will be:
			 * r1 += 1
			 * if r1 < 1000000 goto pc-2
			 * 1M insn_procssed limit / 100 == 10k peak states.
			 * This threshold shouldn't be too high either, since states
			 * at the end of the loop are likely to be useful in pruning.
			 */
skip_inf_loop_check:
			if (!force_new_state &&
			    env->jmps_processed - env->prev_jmps_processed < 20 &&
			    env->insn_processed - env->prev_insn_processed < 100)
				add_new_state = false;
			goto miss;
		}
		/* See comments for mark_all_regs_read_and_precise() */
		loop = incomplete_read_marks(env, &sl->state);
		if (states_equal(env, &sl->state, cur, loop ? RANGE_WITHIN : NOT_EXACT)) {
hit:
			sl->hit_cnt++;

			/* if previous state reached the exit with precision and
			 * current state is equivalent to it (except precision marks)
			 * the precision needs to be propagated back in
			 * the current state.
			 */
			err = 0;
			if (is_jmp_point(env, env->insn_idx))
				err = push_jmp_history(env, cur, 0, 0);
			err = err ? : propagate_precision(env, &sl->state, cur, NULL);
			if (err)
				return err;
			/* When processing iterator based loops above propagate_liveness and
			 * propagate_precision calls are not sufficient to transfer all relevant
			 * read and precision marks. E.g. consider the following case:
			 *
			 *  .-> A --.  Assume the states are visited in the order A, B, C.
			 *  |   |   |  Assume that state B reaches a state equivalent to state A.
			 *  |   v   v  At this point, state C is not processed yet, so state A
			 *  '-- B   C  has not received any read or precision marks from C.
			 *             Thus, marks propagated from A to B are incomplete.
			 *
			 * The verifier mitigates this by performing the following steps:
			 *
			 * - Prior to the main verification pass, strongly connected components
			 *   (SCCs) are computed over the program's control flow graph,
			 *   intraprocedurally.
			 *
			 * - During the main verification pass, `maybe_enter_scc()` checks
			 *   whether the current verifier state is entering an SCC. If so, an
			 *   instance of a `bpf_scc_visit` object is created, and the state
			 *   entering the SCC is recorded as the entry state.
			 *
			 * - This instance is associated not with the SCC itself, but with a
			 *   `bpf_scc_callchain`: a tuple consisting of the call sites leading to
			 *   the SCC and the SCC id. See `compute_scc_callchain()`.
			 *
			 * - When a verification path encounters a `states_equal(...,
			 *   RANGE_WITHIN)` condition, there exists a call chain describing the
			 *   current state and a corresponding `bpf_scc_visit` instance. A copy
			 *   of the current state is created and added to
			 *   `bpf_scc_visit->backedges`.
			 *
			 * - When a verification path terminates, `maybe_exit_scc()` is called
			 *   from `update_branch_counts()`. For states with `branches == 0`, it
			 *   checks whether the state is the entry state of any `bpf_scc_visit`
			 *   instance. If it is, this indicates that all paths originating from
			 *   this SCC visit have been explored. `propagate_backedges()` is then
			 *   called, which propagates read and precision marks through the
			 *   backedges until a fixed point is reached.
			 *   (In the earlier example, this would propagate marks from A to B,
			 *    from C to A, and then again from A to B.)
			 *
			 * A note on callchains
			 * --------------------
			 *
			 * Consider the following example:
			 *
			 *     void foo() { loop { ... SCC#1 ... } }
			 *     void main() {
			 *       A: foo();
			 *       B: ...
			 *       C: foo();
			 *     }
			 *
			 * Here, there are two distinct callchains leading to SCC#1:
			 * - (A, SCC#1)
			 * - (C, SCC#1)
			 *
			 * Each callchain identifies a separate `bpf_scc_visit` instance that
			 * accumulates backedge states. The `propagate_{liveness,precision}()`
			 * functions traverse the parent state of each backedge state, which
			 * means these parent states must remain valid (i.e., not freed) while
			 * the corresponding `bpf_scc_visit` instance exists.
			 *
			 * Associating `bpf_scc_visit` instances directly with SCCs instead of
			 * callchains would break this invariant:
			 * - States explored during `C: foo()` would contribute backedges to
			 *   SCC#1, but SCC#1 would only be exited once the exploration of
			 *   `A: foo()` completes.
			 * - By that time, the states explored between `A: foo()` and `C: foo()`
			 *   (i.e., `B: ...`) may have already been freed, causing the parent
			 *   links for states from `C: foo()` to become invalid.
			 */
			if (loop) {
				struct bpf_scc_backedge *backedge;

				backedge = kzalloc_obj(*backedge,
						       GFP_KERNEL_ACCOUNT);
				if (!backedge)
					return -ENOMEM;
				err = copy_verifier_state(&backedge->state, cur);
				backedge->state.equal_state = &sl->state;
				backedge->state.insn_idx = insn_idx;
				err = err ?: add_scc_backedge(env, &sl->state, backedge);
				if (err) {
					free_verifier_state(&backedge->state, false);
					kfree(backedge);
					return err;
				}
			}
			return 1;
		}
miss:
		/* when new state is not going to be added do not increase miss count.
		 * Otherwise several loop iterations will remove the state
		 * recorded earlier. The goal of these heuristics is to have
		 * states from some iterations of the loop (some in the beginning
		 * and some at the end) to help pruning.
		 */
		if (add_new_state)
			sl->miss_cnt++;
		/* heuristic to determine whether this state is beneficial
		 * to keep checking from state equivalence point of view.
		 * Higher numbers increase max_states_per_insn and verification time,
		 * but do not meaningfully decrease insn_processed.
		 * 'n' controls how many times state could miss before eviction.
		 * Use bigger 'n' for checkpoints because evicting checkpoint states
		 * too early would hinder iterator convergence.
		 */
		n = is_force_checkpoint(env, insn_idx) && sl->state.branches > 0 ? 64 : 3;
		if (sl->miss_cnt > sl->hit_cnt * n + n) {
			/* the state is unlikely to be useful. Remove it to
			 * speed up verification
			 */
			sl->in_free_list = true;
			list_del(&sl->node);
			list_add(&sl->node, &env->free_list);
			env->free_list_size++;
			env->explored_states_size--;
			maybe_free_verifier_state(env, sl);
		}
	}

	if (env->max_states_per_insn < states_cnt)
		env->max_states_per_insn = states_cnt;

	if (!env->bpf_capable && states_cnt > BPF_COMPLEXITY_LIMIT_STATES)
		return 0;

	if (!add_new_state)
		return 0;

	/* There were no equivalent states, remember the current one.
	 * Technically the current state is not proven to be safe yet,
	 * but it will either reach outer most bpf_exit (which means it's safe)
	 * or it will be rejected. When there are no loops the verifier won't be
	 * seeing this tuple (frame[0].callsite, frame[1].callsite, .. insn_idx)
	 * again on the way to bpf_exit.
	 * When looping the sl->state.branches will be > 0 and this state
	 * will not be considered for equivalence until branches == 0.
	 */
	new_sl = kzalloc_obj(struct bpf_verifier_state_list, GFP_KERNEL_ACCOUNT);
	if (!new_sl)
		return -ENOMEM;
	env->total_states++;
	env->explored_states_size++;
	update_peak_states(env);
	env->prev_jmps_processed = env->jmps_processed;
	env->prev_insn_processed = env->insn_processed;

	/* forget precise markings we inherited, see __mark_chain_precision */
	if (env->bpf_capable)
		mark_all_scalars_imprecise(env, cur);

	clear_singular_ids(env, cur);

	/* add new state to the head of linked list */
	new = &new_sl->state;
	err = copy_verifier_state(new, cur);
	if (err) {
		free_verifier_state(new, false);
		kfree(new_sl);
		return err;
	}
	new->insn_idx = insn_idx;
	verifier_bug_if(new->branches != 1, env,
			"%s:branches_to_explore=%d insn %d",
			__func__, new->branches, insn_idx);
	err = maybe_enter_scc(env, new);
	if (err) {
		free_verifier_state(new, false);
		kfree(new_sl);
		return err;
	}

	cur->parent = new;
	cur->first_insn_idx = insn_idx;
	cur->dfs_depth = new->dfs_depth + 1;
	clear_jmp_history(cur);
	list_add(&new_sl->node, head);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_storage_get_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_sk_storage_get ||
	       func_id == BPF_FUNC_inode_storage_get ||
	       func_id == BPF_FUNC_task_storage_get ||
	       func_id == BPF_FUNC_cgrp_storage_get;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_sync_callback_calling_function(enum bpf_func_id func_id)
{
	return func_id == BPF_FUNC_for_each_map_elem ||
	       func_id == BPF_FUNC_find_vma ||
	       func_id == BPF_FUNC_loop ||
	       func_id == BPF_FUNC_user_ringbuf_drain;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_sync_callback_calling_insn(struct bpf_insn *insn)
{
	return (bpf_helper_call(insn) && is_sync_callback_calling_function(insn->imm)) ||
	       (bpf_pseudo_kfunc_call(insn) && is_sync_callback_calling_kfunc(insn->imm));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_sync_callback_calling_kfunc(u32 btf_id)
{
	return btf_id == special_kfunc_list[KF_bpf_rbtree_add_impl];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_tracing_prog_type(enum bpf_prog_type type)
{
	switch (type) {
	case BPF_PROG_TYPE_KPROBE:
	case BPF_PROG_TYPE_TRACEPOINT:
	case BPF_PROG_TYPE_PERF_EVENT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT:
	case BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
		return true;
	default:
		return false;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool is_trusted_reg(const struct bpf_reg_state *reg)
{
	/* A referenced register is always trusted. */
	if (reg->ref_obj_id)
		return true;

	/* Types listed in the reg2btf_ids are always trusted */
	if (reg2btf_ids[base_type(reg->type)] &&
	    !bpf_type_has_unsafe_modifiers(reg->type))
		return true;

	/* If a register is not referenced, it is trusted if it has the
	 * MEM_ALLOC or PTR_TRUSTED type modifiers, and no others. Some of the
	 * other type modifiers may be safe, but we elect to take an opt-in
	 * approach here as some (e.g. PTR_UNTRUSTED and PTR_MAYBE_NULL) are
	 * not.
	 *
	 * Eventually, we should make PTR_TRUSTED the single source of truth
	 * for whether a register is trusted.
	 */
	return type_flag(reg->type) & BPF_REG_TRUSTED_MODIFIERS &&
	       !bpf_type_has_unsafe_modifiers(reg->type);
}


