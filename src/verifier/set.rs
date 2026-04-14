// Extracted from /Users/nan/bs/aot/src/verifier.c
static int set_callee_state(struct bpf_verifier_env *env,
			    struct bpf_func_state *caller,
			    struct bpf_func_state *callee, int insn_idx)
{
	int i;

	/* copy r1 - r5 args that callee can access.  The copy includes parent
	 * pointers, which connects us up to the liveness chain
	 */
	for (i = BPF_REG_1; i <= BPF_REG_5; i++)
		callee->regs[i] = caller->regs[i];
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int set_find_vma_callback_state(struct bpf_verifier_env *env,
				       struct bpf_func_state *caller,
				       struct bpf_func_state *callee,
				       int insn_idx)
{
	/* bpf_find_vma(struct task_struct *task, u64 addr,
	 *               void *callback_fn, void *callback_ctx, u64 flags)
	 * (callback_fn)(struct task_struct *task,
	 *               struct vm_area_struct *vma, void *callback_ctx);
	 */
	callee->regs[BPF_REG_1] = caller->regs[BPF_REG_1];

	callee->regs[BPF_REG_2].type = PTR_TO_BTF_ID;
	__mark_reg_known_zero(&callee->regs[BPF_REG_2]);
	callee->regs[BPF_REG_2].btf =  btf_vmlinux;
	callee->regs[BPF_REG_2].btf_id = btf_tracing_ids[BTF_TRACING_TYPE_VMA];

	/* pointer to stack or null */
	callee->regs[BPF_REG_3] = caller->regs[BPF_REG_4];

	/* unused */
	__mark_reg_not_init(env, &callee->regs[BPF_REG_4]);
	__mark_reg_not_init(env, &callee->regs[BPF_REG_5]);
	callee->in_callback_fn = true;
	callee->callback_ret_range = retval_range(0, 1);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int set_kfunc_desc_imm(struct bpf_verifier_env *env, struct bpf_kfunc_desc *desc)
{
	unsigned long call_imm;

	if (bpf_jit_supports_far_kfunc_call()) {
		call_imm = desc->func_id;
	} else {
		call_imm = BPF_CALL_IMM(desc->addr);
		/* Check whether the relative offset overflows desc->imm */
		if ((unsigned long)(s32)call_imm != call_imm) {
			verbose(env, "address of kernel func_id %u is out of range\n",
				desc->func_id);
			return -EINVAL;
		}
	}
	desc->imm = call_imm;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int set_loop_callback_state(struct bpf_verifier_env *env,
				   struct bpf_func_state *caller,
				   struct bpf_func_state *callee,
				   int insn_idx)
{
	/* bpf_loop(u32 nr_loops, void *callback_fn, void *callback_ctx,
	 *	    u64 flags);
	 * callback_fn(u64 index, void *callback_ctx);
	 */
	callee->regs[BPF_REG_1].type = SCALAR_VALUE;
	callee->regs[BPF_REG_2] = caller->regs[BPF_REG_3];

	/* unused */
	__mark_reg_not_init(env, &callee->regs[BPF_REG_3]);
	__mark_reg_not_init(env, &callee->regs[BPF_REG_4]);
	__mark_reg_not_init(env, &callee->regs[BPF_REG_5]);

	callee->in_callback_fn = true;
	callee->callback_ret_range = retval_range(0, 1);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int set_map_elem_callback_state(struct bpf_verifier_env *env,
				       struct bpf_func_state *caller,
				       struct bpf_func_state *callee,
				       int insn_idx)
{
	struct bpf_insn_aux_data *insn_aux = &env->insn_aux_data[insn_idx];
	struct bpf_map *map;
	int err;

	/* valid map_ptr and poison value does not matter */
	map = insn_aux->map_ptr_state.map_ptr;
	if (!map->ops->map_set_for_each_callback_args ||
	    !map->ops->map_for_each_callback) {
		verbose(env, "callback function not allowed for map\n");
		return -ENOTSUPP;
	}

	err = map->ops->map_set_for_each_callback_args(env, caller, callee);
	if (err)
		return err;

	callee->in_callback_fn = true;
	callee->callback_ret_range = retval_range(0, 1);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int set_rbtree_add_callback_state(struct bpf_verifier_env *env,
					 struct bpf_func_state *caller,
					 struct bpf_func_state *callee,
					 int insn_idx)
{
	/* void bpf_rbtree_add_impl(struct bpf_rb_root *root, struct bpf_rb_node *node,
	 *                     bool (less)(struct bpf_rb_node *a, const struct bpf_rb_node *b));
	 *
	 * 'struct bpf_rb_node *node' arg to bpf_rbtree_add_impl is the same PTR_TO_BTF_ID w/ offset
	 * that 'less' callback args will be receiving. However, 'node' arg was release_reference'd
	 * by this point, so look at 'root'
	 */
	struct btf_field *field;

	field = reg_find_field_offset(&caller->regs[BPF_REG_1], caller->regs[BPF_REG_1].off,
				      BPF_RB_ROOT);
	if (!field || !field->graph_root.value_btf_id)
		return -EFAULT;

	mark_reg_graph_node(callee->regs, BPF_REG_1, &field->graph_root);
	ref_set_non_owning(env, &callee->regs[BPF_REG_1]);
	mark_reg_graph_node(callee->regs, BPF_REG_2, &field->graph_root);
	ref_set_non_owning(env, &callee->regs[BPF_REG_2]);

	__mark_reg_not_init(env, &callee->regs[BPF_REG_3]);
	__mark_reg_not_init(env, &callee->regs[BPF_REG_4]);
	__mark_reg_not_init(env, &callee->regs[BPF_REG_5]);
	callee->in_callback_fn = true;
	callee->callback_ret_range = retval_range(0, 1);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void set_sext32_default_val(struct bpf_reg_state *reg, int size)
{
	if (size == 1) {
		reg->s32_min_value = S8_MIN;
		reg->s32_max_value = S8_MAX;
	} else {
		/* size == 2 */
		reg->s32_min_value = S16_MIN;
		reg->s32_max_value = S16_MAX;
	}
	reg->u32_min_value = 0;
	reg->u32_max_value = U32_MAX;
	reg->var_off = tnum_subreg(tnum_unknown);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void set_sext64_default_val(struct bpf_reg_state *reg, int size)
{
	if (size == 1) {
		reg->smin_value = reg->s32_min_value = S8_MIN;
		reg->smax_value = reg->s32_max_value = S8_MAX;
	} else if (size == 2) {
		reg->smin_value = reg->s32_min_value = S16_MIN;
		reg->smax_value = reg->s32_max_value = S16_MAX;
	} else {
		/* size == 4 */
		reg->smin_value = reg->s32_min_value = S32_MIN;
		reg->smax_value = reg->s32_max_value = S32_MAX;
	}
	reg->umin_value = reg->u32_min_value = 0;
	reg->umax_value = U64_MAX;
	reg->u32_max_value = U32_MAX;
	reg->var_off = tnum_unknown;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int set_task_work_schedule_callback_state(struct bpf_verifier_env *env,
						 struct bpf_func_state *caller,
						 struct bpf_func_state *callee,
						 int insn_idx)
{
	struct bpf_map *map_ptr = caller->regs[BPF_REG_3].map_ptr;

	/*
	 * callback_fn(struct bpf_map *map, void *key, void *value);
	 */
	callee->regs[BPF_REG_1].type = CONST_PTR_TO_MAP;
	__mark_reg_known_zero(&callee->regs[BPF_REG_1]);
	callee->regs[BPF_REG_1].map_ptr = map_ptr;

	callee->regs[BPF_REG_2].type = PTR_TO_MAP_KEY;
	__mark_reg_known_zero(&callee->regs[BPF_REG_2]);
	callee->regs[BPF_REG_2].map_ptr = map_ptr;

	callee->regs[BPF_REG_3].type = PTR_TO_MAP_VALUE;
	__mark_reg_known_zero(&callee->regs[BPF_REG_3]);
	callee->regs[BPF_REG_3].map_ptr = map_ptr;

	/* unused */
	__mark_reg_not_init(env, &callee->regs[BPF_REG_4]);
	__mark_reg_not_init(env, &callee->regs[BPF_REG_5]);
	callee->in_async_callback_fn = true;
	callee->callback_ret_range = retval_range(S32_MIN, S32_MAX);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int set_timer_callback_state(struct bpf_verifier_env *env,
				    struct bpf_func_state *caller,
				    struct bpf_func_state *callee,
				    int insn_idx)
{
	struct bpf_map *map_ptr = caller->regs[BPF_REG_1].map_ptr;

	/* bpf_timer_set_callback(struct bpf_timer *timer, void *callback_fn);
	 * callback_fn(struct bpf_map *map, void *key, void *value);
	 */
	callee->regs[BPF_REG_1].type = CONST_PTR_TO_MAP;
	__mark_reg_known_zero(&callee->regs[BPF_REG_1]);
	callee->regs[BPF_REG_1].map_ptr = map_ptr;

	callee->regs[BPF_REG_2].type = PTR_TO_MAP_KEY;
	__mark_reg_known_zero(&callee->regs[BPF_REG_2]);
	callee->regs[BPF_REG_2].map_ptr = map_ptr;

	callee->regs[BPF_REG_3].type = PTR_TO_MAP_VALUE;
	__mark_reg_known_zero(&callee->regs[BPF_REG_3]);
	callee->regs[BPF_REG_3].map_ptr = map_ptr;

	/* unused */
	__mark_reg_not_init(env, &callee->regs[BPF_REG_4]);
	__mark_reg_not_init(env, &callee->regs[BPF_REG_5]);
	callee->in_async_callback_fn = true;
	callee->callback_ret_range = retval_range(0, 0);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int set_user_ringbuf_callback_state(struct bpf_verifier_env *env,
					   struct bpf_func_state *caller,
					   struct bpf_func_state *callee,
					   int insn_idx)
{
	/* bpf_user_ringbuf_drain(struct bpf_map *map, void *callback_fn, void
	 *			  callback_ctx, u64 flags);
	 * callback_fn(const struct bpf_dynptr_t* dynptr, void *callback_ctx);
	 */
	__mark_reg_not_init(env, &callee->regs[BPF_REG_0]);
	mark_dynptr_cb_reg(env, &callee->regs[BPF_REG_1], BPF_DYNPTR_TYPE_LOCAL);
	callee->regs[BPF_REG_2] = caller->regs[BPF_REG_3];

	/* unused */
	__mark_reg_not_init(env, &callee->regs[BPF_REG_3]);
	__mark_reg_not_init(env, &callee->regs[BPF_REG_4]);
	__mark_reg_not_init(env, &callee->regs[BPF_REG_5]);

	callee->in_callback_fn = true;
	callee->callback_ret_range = retval_range(0, 1);
	return 0;
}


