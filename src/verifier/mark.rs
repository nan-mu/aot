// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_all_scalars_imprecise(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	struct bpf_func_state *func;
	struct bpf_reg_state *reg;
	int i, j;

	for (i = 0; i <= st->curframe; i++) {
		func = st->frame[i];
		for (j = 0; j < BPF_REG_FP; j++) {
			reg = &func->regs[j];
			if (reg->type != SCALAR_VALUE)
				continue;
			reg->precise = false;
		}
		for (j = 0; j < func->allocated_stack / BPF_REG_SIZE; j++) {
			if (!is_spilled_reg(&func->stack[j]))
				continue;
			reg = &func->stack[j].spilled_ptr;
			if (reg->type != SCALAR_VALUE)
				continue;
			reg->precise = false;
		}
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_all_scalars_precise(struct bpf_verifier_env *env,
				     struct bpf_verifier_state *st)
{
	struct bpf_func_state *func;
	struct bpf_reg_state *reg;
	int i, j;

	if (env->log.level & BPF_LOG_LEVEL2) {
		verbose(env, "mark_precise: frame%d: falling back to forcing all scalars precise\n",
			st->curframe);
	}

	/* big hammer: mark all scalars precise in this path.
	 * pop_stack may still get !precise scalars.
	 * We also skip current state and go straight to first parent state,
	 * because precision markings in current non-checkpointed state are
	 * not needed. See why in the comment in inner_mark_chain_precision below.
	 */
	for (st = st->parent; st; st = st->parent) {
		for (i = 0; i <= st->curframe; i++) {
			func = st->frame[i];
			for (j = 0; j < BPF_REG_FP; j++) {
				reg = &func->regs[j];
				if (reg->type != SCALAR_VALUE || reg->precise)
					continue;
				reg->precise = true;
				if (env->log.level & BPF_LOG_LEVEL2) {
					verbose(env, "force_precise: frame%d: forcing r%d to be precise\n",
						i, j);
				}
			}
			for (j = 0; j < func->allocated_stack / BPF_REG_SIZE; j++) {
				if (!is_spilled_reg(&func->stack[j]))
					continue;
				reg = &func->stack[j].spilled_ptr;
				if (reg->type != SCALAR_VALUE || reg->precise)
					continue;
				reg->precise = true;
				if (env->log.level & BPF_LOG_LEVEL2) {
					verbose(env, "force_precise: frame%d: forcing fp%d to be precise\n",
						i, -(j + 1) * 8);
				}
			}
		}
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_btf_func_reg_size(struct bpf_verifier_env *env, u32 regno,
				   size_t reg_size)
{
	return inner_mark_btf_func_reg_size(env, cur_regs(env), regno, reg_size);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_btf_ld_reg(struct bpf_verifier_env *env,
			   struct bpf_reg_state *regs, u32 regno,
			   enum bpf_reg_type reg_type,
			   struct btf *btf, u32 btf_id,
			   enum bpf_type_flag flag)
{
	switch (reg_type) {
	case SCALAR_VALUE:
		mark_reg_unknown(env, regs, regno);
		return 0;
	case PTR_TO_BTF_ID:
		mark_reg_known_zero(env, regs, regno);
		regs[regno].type = PTR_TO_BTF_ID | flag;
		regs[regno].btf = btf;
		regs[regno].btf_id = btf_id;
		if (type_may_be_null(flag))
			regs[regno].id = ++env->id_gen;
		return 0;
	case PTR_TO_MEM:
		mark_reg_known_zero(env, regs, regno);
		regs[regno].type = PTR_TO_MEM | flag;
		regs[regno].mem_size = 0;
		return 0;
	default:
		verifier_bug(env, "unexpected reg_type %d in %s\n", reg_type, __func__);
		return -EFAULT;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_calls_callback(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].calls_callback = true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
int mark_chain_precision(struct bpf_verifier_env *env, int regno)
{
	return inner_mark_chain_precision(env, env->cur_state, regno, NULL);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_chain_precision_batch(struct bpf_verifier_env *env,
				      struct bpf_verifier_state *starting_state)
{
	return inner_mark_chain_precision(env, starting_state, -1, NULL);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_dynptr_cb_reg(struct bpf_verifier_env *env,
			       struct bpf_reg_state *reg,
			       enum bpf_dynptr_type type)
{
	inner_mark_dynptr_reg(reg, type, true, ++env->id_gen);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_dynptr_read(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	int spi;

	/* For CONST_PTR_TO_DYNPTR, it must have already been done by
	 * check_reg_arg in check_helper_call and mark_btf_func_reg_size in
	 * check_kfunc_call.
	 */
	if (reg->type == CONST_PTR_TO_DYNPTR)
		return 0;
	spi = dynptr_get_spi(env, reg);
	if (spi < 0)
		return spi;
	/* Caller ensures dynptr is valid and initialized, which means spi is in
	 * bounds and spi is the first dynptr slot. Simply mark stack slot as
	 * read.
	 */
	return mark_stack_slot_obj_read(env, reg, spi, BPF_DYNPTR_NR_SLOTS);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_dynptr_stack_regs(struct bpf_verifier_env *env,
				   struct bpf_reg_state *sreg1,
				   struct bpf_reg_state *sreg2,
				   enum bpf_dynptr_type type)
{
	int id = ++env->id_gen;

	inner_mark_dynptr_reg(sreg1, type, true, id);
	inner_mark_dynptr_reg(sreg2, type, false, id);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_fastcall_pattern_for_call(struct bpf_verifier_env *env,
					   struct bpf_subprog_info *subprog,
					   int insn_idx, s16 lowest_off)
{
	struct bpf_insn *insns = env->prog->insnsi, *stx, *ldx;
	struct bpf_insn *call = &env->prog->insnsi[insn_idx];
	u32 clobbered_regs_mask;
	struct call_summary cs;
	u32 expected_regs_mask;
	s16 off;
	int i;

	if (!get_call_summary(env, call, &cs))
		return;

	/* A bitmask specifying which caller saved registers are clobbered
	 * by a call to a helper/kfunc *as if* this helper/kfunc follows
	 * bpf_fastcall contract:
	 * - includes R0 if function is non-void;
	 * - includes R1-R5 if corresponding parameter has is described
	 *   in the function prototype.
	 */
	clobbered_regs_mask = GENMASK(cs.num_params, cs.is_void ? 1 : 0);
	/* e.g. if helper call clobbers r{0,1}, expect r{2,3,4,5} in the pattern */
	expected_regs_mask = ~clobbered_regs_mask & ALL_CALLER_SAVED_REGS;

	/* match pairs of form:
	 *
	 * *(u64 *)(r10 - Y) = rX   (where Y % 8 == 0)
	 * ...
	 * call %[to_be_inlined]
	 * ...
	 * rX = *(u64 *)(r10 - Y)
	 */
	for (i = 1, off = lowest_off; i <= ARRAY_SIZE(caller_saved); ++i, off += BPF_REG_SIZE) {
		if (insn_idx - i < 0 || insn_idx + i >= env->prog->len)
			break;
		stx = &insns[insn_idx - i];
		ldx = &insns[insn_idx + i];
		/* must be a stack spill/fill pair */
		if (stx->code != (BPF_STX | BPF_MEM | BPF_DW) ||
		    ldx->code != (BPF_LDX | BPF_MEM | BPF_DW) ||
		    stx->dst_reg != BPF_REG_10 ||
		    ldx->src_reg != BPF_REG_10)
			break;
		/* must be a spill/fill for the same reg */
		if (stx->src_reg != ldx->dst_reg)
			break;
		/* must be one of the previously unseen registers */
		if ((BIT(stx->src_reg) & expected_regs_mask) == 0)
			break;
		/* must be a spill/fill for the same expected offset,
		 * no need to check offset alignment, BPF_DW stack access
		 * is always 8-byte aligned.
		 */
		if (stx->off != off || ldx->off != off)
			break;
		expected_regs_mask &= ~BIT(stx->src_reg);
		env->insn_aux_data[insn_idx - i].fastcall_pattern = 1;
		env->insn_aux_data[insn_idx + i].fastcall_pattern = 1;
	}
	if (i == 1)
		return;

	/* Conditionally set 'fastcall_spills_num' to allow forward
	 * compatibility when more helper functions are marked as
	 * bpf_fastcall at compile time than current kernel supports, e.g:
	 *
	 *   1: *(u64 *)(r10 - 8) = r1
	 *   2: call A                  ;; assume A is bpf_fastcall for current kernel
	 *   3: r1 = *(u64 *)(r10 - 8)
	 *   4: *(u64 *)(r10 - 8) = r1
	 *   5: call B                  ;; assume B is not bpf_fastcall for current kernel
	 *   6: r1 = *(u64 *)(r10 - 8)
	 *
	 * There is no need to block bpf_fastcall rewrite for such program.
	 * Set 'fastcall_pattern' for both calls to keep check_fastcall_stack_contract() happy,
	 * don't set 'fastcall_spills_num' for call B so that remove_fastcall_spills_fills()
	 * does not remove spill/fill pair {4,6}.
	 */
	if (cs.fastcall)
		env->insn_aux_data[insn_idx].fastcall_spills_num = i - 1;
	else
		subprog->keep_fastcall_stack = 1;
	subprog->fastcall_stack_off = min(subprog->fastcall_stack_off, off);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_fastcall_patterns(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprog = env->subprog_info;
	struct bpf_insn *insn;
	s16 lowest_off;
	int s, i;

	for (s = 0; s < env->subprog_cnt; ++s, ++subprog) {
		/* find lowest stack spill offset used in this subprog */
		lowest_off = 0;
		for (i = subprog->start; i < (subprog + 1)->start; ++i) {
			insn = env->prog->insnsi + i;
			if (insn->code != (BPF_STX | BPF_MEM | BPF_DW) ||
			    insn->dst_reg != BPF_REG_10)
				continue;
			lowest_off = min(lowest_off, insn->off);
		}
		/* use this offset to find fastcall patterns */
		for (i = subprog->start; i < (subprog + 1)->start; ++i) {
			insn = env->prog->insnsi + i;
			if (insn->code != (BPF_JMP | BPF_CALL))
				continue;
			mark_fastcall_pattern_for_call(env, subprog, i, lowest_off);
		}
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_force_checkpoint(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].force_checkpoint = true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_insn_zext(struct bpf_verifier_env *env,
			   struct bpf_reg_state *reg)
{
	s32 def_idx = reg->subreg_def;

	if (def_idx == DEF_NOT_SUBREG)
		return;

	env->insn_aux_data[def_idx - 1].zext_dst = true;
	/* The dst will be zero extended, so won't be sub-register anymore. */
	reg->subreg_def = DEF_NOT_SUBREG;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_irq_flag_read(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	int spi;

	spi = irq_flag_get_spi(env, reg);
	if (spi < 0)
		return spi;
	return mark_stack_slot_obj_read(env, reg, spi, 1);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_iter_read(struct bpf_verifier_env *env, struct bpf_reg_state *reg,
			  int spi, int nr_slots)
{
	return mark_stack_slot_obj_read(env, reg, spi, nr_slots);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_jmp_point(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].jmp_point = true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_pkt_end(struct bpf_verifier_state *vstate, int regn, bool range_open)
{
	struct bpf_func_state *state = vstate->frame[vstate->curframe];
	struct bpf_reg_state *reg = &state->regs[regn];

	if (reg->type != PTR_TO_PACKET)
		/* PTR_TO_PACKET_META is not supported yet */
		return;

	/* The 'reg' is pkt > pkt_end or pkt >= pkt_end.
	 * How far beyond pkt_end it goes is unknown.
	 * if (!range_open) it's the case of pkt >= pkt_end
	 * if (range_open) it's the case of pkt > pkt_end
	 * hence this pointer is at least 1 byte bigger than pkt_end
	 */
	if (range_open)
		reg->range = BEYOND_PKT_END;
	else
		reg->range = AT_PKT_END;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_prune_point(struct bpf_verifier_env *env, int idx)
{
	env->insn_aux_data[idx].prune_point = true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_ptr_not_null_reg(struct bpf_reg_state *reg)
{
	if (base_type(reg->type) == PTR_TO_MAP_VALUE) {
		const struct bpf_map *map = reg->map_ptr;

		if (map->inner_map_meta) {
			reg->type = CONST_PTR_TO_MAP;
			reg->map_ptr = map->inner_map_meta;
			/* transfer reg's id which is unique for every map_lookup_elem
			 * as UID of the inner map.
			 */
			if (btf_record_has_field(map->inner_map_meta->record,
						 BPF_TIMER | BPF_WORKQUEUE | BPF_TASK_WORK)) {
				reg->map_uid = reg->id;
			}
		} else if (map->map_type == BPF_MAP_TYPE_XSKMAP) {
			reg->type = PTR_TO_XDP_SOCK;
		} else if (map->map_type == BPF_MAP_TYPE_SOCKMAP ||
			   map->map_type == BPF_MAP_TYPE_SOCKHASH) {
			reg->type = PTR_TO_SOCKET;
		} else {
			reg->type = PTR_TO_MAP_VALUE;
		}
		return;
	}

	reg->type &= ~PTR_MAYBE_NULL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_ptr_or_null_reg(struct bpf_func_state *state,
				 struct bpf_reg_state *reg, u32 id,
				 bool is_null)
{
	if (type_may_be_null(reg->type) && reg->id == id &&
	    (is_rcu_reg(reg) || !WARN_ON_ONCE(!reg->id))) {
		/* Old offset (both fixed and variable parts) should have been
		 * known-zero, because we don't allow pointer arithmetic on
		 * pointers that might be NULL. If we see this happening, don't
		 * convert the register.
		 *
		 * But in some cases, some helpers that return local kptrs
		 * advance offset for the returned pointer. In those cases, it
		 * is fine to expect to see reg->off.
		 */
		if (WARN_ON_ONCE(reg->smin_value || reg->smax_value || !tnum_equals_const(reg->var_off, 0)))
			return;
		if (!(type_is_ptr_alloc_obj(reg->type) || type_is_non_owning_ref(reg->type)) &&
		    WARN_ON_ONCE(reg->off))
			return;

		if (is_null) {
			reg->type = SCALAR_VALUE;
			/* We don't need id and ref_obj_id from this point
			 * onwards anymore, thus we should better reset it,
			 * so that state pruning has chances to take effect.
			 */
			reg->id = 0;
			reg->ref_obj_id = 0;

			return;
		}

		mark_ptr_not_null_reg(reg);

		if (!reg_may_point_to_spin_lock(reg)) {
			/* For not-NULL ptr, reg->ref_obj_id will be reset
			 * in release_reference().
			 *
			 * reg->id is still used by spin_lock ptr. Other
			 * than spin_lock ptr type, reg->id can be reset.
			 */
			reg->id = 0;
		}
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_ptr_or_null_regs(struct bpf_verifier_state *vstate, u32 regno,
				  bool is_null)
{
	struct bpf_func_state *state = vstate->frame[vstate->curframe];
	struct bpf_reg_state *regs = state->regs, *reg;
	u32 ref_obj_id = regs[regno].ref_obj_id;
	u32 id = regs[regno].id;

	if (ref_obj_id && ref_obj_id == id && is_null)
		/* regs[regno] is in the " == NULL" branch.
		 * No one could have freed the reference state before
		 * doing the NULL check.
		 */
		WARN_ON_ONCE(release_reference_nomark(vstate, id));

	bpf_for_each_reg_in_vstate(vstate, state, reg, ({
		mark_ptr_or_null_reg(state, reg, id, is_null);
	}));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_reg_graph_node(struct bpf_reg_state *regs, u32 regno,
				struct btf_field_graph_root *ds_head)
{
	inner_mark_reg_known_zero(&regs[regno]);
	regs[regno].type = PTR_TO_BTF_ID | MEM_ALLOC;
	regs[regno].btf = ds_head->btf;
	regs[regno].btf_id = ds_head->value_btf_id;
	regs[regno].off = ds_head->node_offset;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_reg_invalid(const struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	if (!env->allow_ptr_leaks)
		inner_mark_reg_not_init(env, reg);
	else
		inner_mark_reg_unknown(env, reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_reg_known_zero(struct bpf_verifier_env *env,
				struct bpf_reg_state *regs, u32 regno)
{
	if (WARN_ON(regno >= MAX_BPF_REG)) {
		verbose(env, "mark_reg_known_zero(regs, %u)\n", regno);
		/* Something bad happened, let's kill all regs */
		for (regno = 0; regno < MAX_BPF_REG; regno++)
			inner_mark_reg_not_init(env, regs + regno);
		return;
	}
	inner_mark_reg_known_zero(regs + regno);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_reg_not_init(struct bpf_verifier_env *env,
			      struct bpf_reg_state *regs, u32 regno)
{
	if (WARN_ON(regno >= MAX_BPF_REG)) {
		verbose(env, "mark_reg_not_init(regs, %u)\n", regno);
		/* Something bad happened, let's kill all regs except FP */
		for (regno = 0; regno < BPF_REG_FP; regno++)
			inner_mark_reg_not_init(env, regs + regno);
		return;
	}
	inner_mark_reg_not_init(env, regs + regno);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_reg_stack_read(struct bpf_verifier_env *env,
				/* func where src register points to */
				struct bpf_func_state *ptr_state,
				int min_off, int max_off, int dst_regno)
{
	struct bpf_verifier_state *vstate = env->cur_state;
	struct bpf_func_state *state = vstate->frame[vstate->curframe];
	int i, slot, spi;
	u8 *stype;
	int zeros = 0;

	for (i = min_off; i < max_off; i++) {
		slot = -i - 1;
		spi = slot / BPF_REG_SIZE;
		mark_stack_slot_scratched(env, spi);
		stype = ptr_state->stack[spi].slot_type;
		if (stype[slot % BPF_REG_SIZE] != STACK_ZERO)
			break;
		zeros++;
	}
	if (zeros == max_off - min_off) {
		/* Any access_size read into register is zero extended,
		 * so the whole register == const_zero.
		 */
		inner_mark_reg_const_zero(env, &state->regs[dst_regno]);
	} else {
		/* have read misc data from the stack */
		mark_reg_unknown(env, state->regs, dst_regno);
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_reg_unknown(struct bpf_verifier_env *env,
			     struct bpf_reg_state *regs, u32 regno)
{
	if (WARN_ON(regno >= MAX_BPF_REG)) {
		verbose(env, "mark_reg_unknown(regs, %u)\n", regno);
		/* Something bad happened, let's kill all regs except FP */
		for (regno = 0; regno < BPF_REG_FP; regno++)
			inner_mark_reg_not_init(env, regs + regno);
		return;
	}
	inner_mark_reg_unknown(env, regs + regno);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_stack_slot_irq_flag(struct bpf_verifier_env *env,
				     struct bpf_kfunc_call_arg_meta *meta,
				     struct bpf_reg_state *reg, int insn_idx,
				     int kfunc_class)
{
	struct bpf_func_state *state = func(env, reg);
	struct bpf_stack_state *slot;
	struct bpf_reg_state *st;
	int spi, i, id;

	spi = irq_flag_get_spi(env, reg);
	if (spi < 0)
		return spi;

	id = acquire_irq_state(env, insn_idx);
	if (id < 0)
		return id;

	slot = &state->stack[spi];
	st = &slot->spilled_ptr;

	bpf_mark_stack_write(env, reg->frameno, BIT(spi));
	inner_mark_reg_known_zero(st);
	st->type = PTR_TO_STACK; /* we don't have dedicated reg type */
	st->ref_obj_id = id;
	st->irq.kfunc_class = kfunc_class;

	for (i = 0; i < BPF_REG_SIZE; i++)
		slot->slot_type[i] = STACK_IRQ_FLAG;

	mark_stack_slot_scratched(env, spi);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_stack_slot_misc(struct bpf_verifier_env *env, u8 *stype)
{
	if (*stype == STACK_ZERO)
		return;
	if (*stype == STACK_INVALID)
		return;
	*stype = STACK_MISC;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_stack_slot_obj_read(struct bpf_verifier_env *env, struct bpf_reg_state *reg,
				    int spi, int nr_slots)
{
	int err, i;

	for (i = 0; i < nr_slots; i++) {
		err = bpf_mark_stack_read(env, reg->frameno, env->insn_idx, BIT(spi - i));
		if (err)
			return err;
		mark_stack_slot_scratched(env, spi - i);
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_stack_slots_dynptr(struct bpf_verifier_env *env, struct bpf_reg_state *reg,
				   enum bpf_arg_type arg_type, int insn_idx, int clone_ref_obj_id)
{
	struct bpf_func_state *state = func(env, reg);
	enum bpf_dynptr_type type;
	int spi, i, err;

	spi = dynptr_get_spi(env, reg);
	if (spi < 0)
		return spi;

	/* We cannot assume both spi and spi - 1 belong to the same dynptr,
	 * hence we need to call destroy_if_dynptr_stack_slot twice for both,
	 * to ensure that for the following example:
	 *	[d1][d1][d2][d2]
	 * spi    3   2   1   0
	 * So marking spi = 2 should lead to destruction of both d1 and d2. In
	 * case they do belong to same dynptr, second call won't see slot_type
	 * as STACK_DYNPTR and will simply skip destruction.
	 */
	err = destroy_if_dynptr_stack_slot(env, state, spi);
	if (err)
		return err;
	err = destroy_if_dynptr_stack_slot(env, state, spi - 1);
	if (err)
		return err;

	for (i = 0; i < BPF_REG_SIZE; i++) {
		state->stack[spi].slot_type[i] = STACK_DYNPTR;
		state->stack[spi - 1].slot_type[i] = STACK_DYNPTR;
	}

	type = arg_to_dynptr_type(arg_type);
	if (type == BPF_DYNPTR_TYPE_INVALID)
		return -EINVAL;

	mark_dynptr_stack_regs(env, &state->stack[spi].spilled_ptr,
			       &state->stack[spi - 1].spilled_ptr, type);

	if (dynptr_type_refcounted(type)) {
		/* The id is used to track proper releasing */
		int id;

		if (clone_ref_obj_id)
			id = clone_ref_obj_id;
		else
			id = acquire_reference(env, insn_idx);

		if (id < 0)
			return id;

		state->stack[spi].spilled_ptr.ref_obj_id = id;
		state->stack[spi - 1].spilled_ptr.ref_obj_id = id;
	}

	bpf_mark_stack_write(env, state->frameno, BIT(spi - 1) | BIT(spi));

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_stack_slots_iter(struct bpf_verifier_env *env,
				 struct bpf_kfunc_call_arg_meta *meta,
				 struct bpf_reg_state *reg, int insn_idx,
				 struct btf *btf, u32 btf_id, int nr_slots)
{
	struct bpf_func_state *state = func(env, reg);
	int spi, i, j, id;

	spi = iter_get_spi(env, reg, nr_slots);
	if (spi < 0)
		return spi;

	id = acquire_reference(env, insn_idx);
	if (id < 0)
		return id;

	for (i = 0; i < nr_slots; i++) {
		struct bpf_stack_state *slot = &state->stack[spi - i];
		struct bpf_reg_state *st = &slot->spilled_ptr;

		inner_mark_reg_known_zero(st);
		st->type = PTR_TO_STACK; /* we don't have dedicated reg type */
		if (is_kfunc_rcu_protected(meta)) {
			if (in_rcu_cs(env))
				st->type |= MEM_RCU;
			else
				st->type |= PTR_UNTRUSTED;
		}
		st->ref_obj_id = i == 0 ? id : 0;
		st->iter.btf = btf;
		st->iter.btf_id = btf_id;
		st->iter.state = BPF_ITER_STATE_ACTIVE;
		st->iter.depth = 0;

		for (j = 0; j < BPF_REG_SIZE; j++)
			slot->slot_type[j] = STACK_ITER;

		bpf_mark_stack_write(env, state->frameno, BIT(spi - i));
		mark_stack_slot_scratched(env, spi - i);
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_subprog_changes_pkt_data(struct bpf_verifier_env *env, int off)
{
	struct bpf_subprog_info *subprog;

	subprog = bpf_find_containing_subprog(env, off);
	subprog->changes_pkt_data = true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_subprog_exc_cb(struct bpf_verifier_env *env, int subprog)
{
	struct bpf_subprog_info *info = subprog_info(env, subprog);

	info->is_cb = true;
	info->is_async_cb = true;
	info->is_exception_cb = true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void mark_subprog_might_sleep(struct bpf_verifier_env *env, int off)
{
	struct bpf_subprog_info *subprog;

	subprog = bpf_find_containing_subprog(env, off);
	subprog->might_sleep = true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int mark_uptr_ld_reg(struct bpf_verifier_env *env, u32 regno,
			    struct btf_field *field)
{
	struct bpf_reg_state *reg;
	const struct btf_type *t;

	t = btf_type_by_id(field->kptr.btf, field->kptr.btf_id);
	mark_reg_known_zero(env, cur_regs(env), regno);
	reg = reg_state(env, regno);
	reg->type = PTR_TO_MEM | PTR_MAYBE_NULL;
	reg->mem_size = t->size;
	reg->id = ++env->id_gen;

	return 0;
}

static void iinner_mark_reg_known(struct bpf_reg_state *reg, u64 imm)
{
	reg->var_off = tnum_const(imm);
	reg->smin_value = (s64)imm;
	reg->smax_value = (s64)imm;
	reg->umin_value = imm;
	reg->umax_value = imm;

	reg->s32_min_value = (s32)imm;
	reg->s32_max_value = (s32)imm;
	reg->u32_min_value = (u32)imm;
	reg->u32_max_value = (u32)imm;
}

static void inner_mark_reg32_known(struct bpf_reg_state *reg, u64 imm)
{
	reg->var_off = tnum_const_subreg(reg->var_off, imm);
	reg->s32_min_value = (s32)imm;
	reg->s32_max_value = (s32)imm;
	reg->u32_min_value = (u32)imm;
	reg->u32_max_value = (u32)imm;
}

static void inner_mark_reg32_unbounded(struct bpf_reg_state *reg)
{
	reg->s32_min_value = S32_MIN;
	reg->s32_max_value = S32_MAX;
	reg->u32_min_value = 0;
	reg->u32_max_value = U32_MAX;
}

static void inner_mark_reg64_unbounded(struct bpf_reg_state *reg)
{
	reg->smin_value = S64_MIN;
	reg->smax_value = S64_MAX;
	reg->umin_value = 0;
	reg->umax_value = U64_MAX;
}

static void inner_mark_reg_known(struct bpf_reg_state *reg, u64 imm)
{
	/* Clear off and union(map_ptr, range) */
	memset(((u8 *)reg) + sizeof(reg->type), 0,
	       offsetof(struct bpf_reg_state, var_off) - sizeof(reg->type));
	reg->id = 0;
	reg->ref_obj_id = 0;
	iinner_mark_reg_known(reg, imm);
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int inner_mark_reg_s32_range(struct bpf_verifier_env *env,
				struct bpf_reg_state *regs,
				u32 regno,
				s32 s32_min,
				s32 s32_max)
{
	struct bpf_reg_state *reg = regs + regno;

	reg->s32_min_value = max_t(s32, reg->s32_min_value, s32_min);
	reg->s32_max_value = min_t(s32, reg->s32_max_value, s32_max);

	reg->smin_value = max_t(s64, reg->smin_value, s32_min);
	reg->smax_value = min_t(s64, reg->smax_value, s32_max);

	reg_bounds_sync(reg);

	return reg_bounds_sanity_check(env, reg, "s32_range");
}

static void inner_mark_reg_unbounded(struct bpf_reg_state *reg)
{
	reg->smin_value = S64_MIN;
	reg->smax_value = S64_MAX;
	reg->umin_value = 0;
	reg->umax_value = U64_MAX;

	reg->s32_min_value = S32_MIN;
	reg->s32_max_value = S32_MAX;
	reg->u32_min_value = 0;
	reg->u32_max_value = U32_MAX;
}

static void inner_mark_reg_unknown_imprecise(struct bpf_reg_state *reg)
{
	/*
	 * Clear type, off, and union(map_ptr, range) and
	 * padding between 'type' and union
	 */
	memset(reg, 0, offsetof(struct bpf_reg_state, var_off));
	reg->type = SCALAR_VALUE;
	reg->id = 0;
	reg->ref_obj_id = 0;
	reg->var_off = tnum_unknown;
	reg->frameno = 0;
	reg->precise = false;
	inner_mark_reg_unbounded(reg);
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_mark_btf_func_reg_size(struct bpf_verifier_env *env, struct bpf_reg_state *regs,
				     u32 regno, size_t reg_size)
{
	struct bpf_reg_state *reg = &regs[regno];

	if (regno == BPF_REG_0) {
		/* Function return value */
		reg->subreg_def = reg_size == sizeof(u64) ?
			DEF_NOT_SUBREG : env->insn_idx + 1;
	} else if (reg_size == sizeof(u64)) {
		/* Function argument */
		mark_insn_zext(env, reg);
	}
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int inner_mark_chain_precision(struct bpf_verifier_env *env,
				  struct bpf_verifier_state *starting_state,
				  int regno,
				  bool *changed)
{
	struct bpf_verifier_state *st = starting_state;
	struct backtrack_state *bt = &env->bt;
	int first_idx = st->first_insn_idx;
	int last_idx = starting_state->insn_idx;
	int subseq_idx = -1;
	struct bpf_func_state *func;
	bool tmp, skip_first = true;
	struct bpf_reg_state *reg;
	int i, fr, err;

	if (!env->bpf_capable)
		return 0;

	changed = changed ?: &tmp;
	/* set frame number from which we are starting to backtrack */
	bt_init(bt, starting_state->curframe);

	/* Do sanity checks against current state of register and/or stack
	 * slot, but don't set precise flag in current state, as precision
	 * tracking in the current state is unnecessary.
	 */
	func = st->frame[bt->frame];
	if (regno >= 0) {
		reg = &func->regs[regno];
		if (reg->type != SCALAR_VALUE) {
			verifier_bug(env, "backtracking misuse");
			return -EFAULT;
		}
		bt_set_reg(bt, regno);
	}

	if (bt_empty(bt))
		return 0;

	for (;;) {
		DECLARE_BITMAP(mask, 64);
		u32 history = st->jmp_history_cnt;
		struct bpf_jmp_history_entry *hist;

		if (env->log.level & BPF_LOG_LEVEL2) {
			verbose(env, "mark_precise: frame%d: last_idx %d first_idx %d subseq_idx %d \n",
				bt->frame, last_idx, first_idx, subseq_idx);
		}

		if (last_idx < 0) {
			/* we are at the entry into subprog, which
			 * is expected for global funcs, but only if
			 * requested precise registers are R1-R5
			 * (which are global func's input arguments)
			 */
			if (st->curframe == 0 &&
			    st->frame[0]->subprogno > 0 &&
			    st->frame[0]->callsite == BPF_MAIN_FUNC &&
			    bt_stack_mask(bt) == 0 &&
			    (bt_reg_mask(bt) & ~BPF_REGMASK_ARGS) == 0) {
				bitmap_from_u64(mask, bt_reg_mask(bt));
				for_each_set_bit(i, mask, 32) {
					reg = &st->frame[0]->regs[i];
					bt_clear_reg(bt, i);
					if (reg->type == SCALAR_VALUE) {
						reg->precise = true;
						*changed = true;
					}
				}
				return 0;
			}

			verifier_bug(env, "backtracking func entry subprog %d reg_mask %x stack_mask %llx",
				     st->frame[0]->subprogno, bt_reg_mask(bt), bt_stack_mask(bt));
			return -EFAULT;
		}

		for (i = last_idx;;) {
			if (skip_first) {
				err = 0;
				skip_first = false;
			} else {
				hist = get_jmp_hist_entry(st, history, i);
				err = backtrack_insn(env, i, subseq_idx, hist, bt);
			}
			if (err == -ENOTSUPP) {
				mark_all_scalars_precise(env, starting_state);
				bt_reset(bt);
				return 0;
			} else if (err) {
				return err;
			}
			if (bt_empty(bt))
				/* Found assignment(s) into tracked register in this state.
				 * Since this state is already marked, just return.
				 * Nothing to be tracked further in the parent state.
				 */
				return 0;
			subseq_idx = i;
			i = get_prev_insn_idx(st, i, &history);
			if (i == -ENOENT)
				break;
			if (i >= env->prog->len) {
				/* This can happen if backtracking reached insn 0
				 * and there are still reg_mask or stack_mask
				 * to backtrack.
				 * It means the backtracking missed the spot where
				 * particular register was initialized with a constant.
				 */
				verifier_bug(env, "backtracking idx %d", i);
				return -EFAULT;
			}
		}
		st = st->parent;
		if (!st)
			break;

		for (fr = bt->frame; fr >= 0; fr--) {
			func = st->frame[fr];
			bitmap_from_u64(mask, bt_frame_reg_mask(bt, fr));
			for_each_set_bit(i, mask, 32) {
				reg = &func->regs[i];
				if (reg->type != SCALAR_VALUE) {
					bt_clear_frame_reg(bt, fr, i);
					continue;
				}
				if (reg->precise) {
					bt_clear_frame_reg(bt, fr, i);
				} else {
					reg->precise = true;
					*changed = true;
				}
			}

			bitmap_from_u64(mask, bt_frame_stack_mask(bt, fr));
			for_each_set_bit(i, mask, 64) {
				if (verifier_bug_if(i >= func->allocated_stack / BPF_REG_SIZE,
						    env, "stack slot %d, total slots %d",
						    i, func->allocated_stack / BPF_REG_SIZE))
					return -EFAULT;

				if (!is_spilled_scalar_reg(&func->stack[i])) {
					bt_clear_frame_slot(bt, fr, i);
					continue;
				}
				reg = &func->stack[i].spilled_ptr;
				if (reg->precise) {
					bt_clear_frame_slot(bt, fr, i);
				} else {
					reg->precise = true;
					*changed = true;
				}
			}
			if (env->log.level & BPF_LOG_LEVEL2) {
				fmt_reg_mask(env->tmp_str_buf, TMP_STR_BUF_LEN,
					     bt_frame_reg_mask(bt, fr));
				verbose(env, "mark_precise: frame%d: parent state regs=%s ",
					fr, env->tmp_str_buf);
				bpf_fmt_stack_mask(env->tmp_str_buf, TMP_STR_BUF_LEN,
					       bt_frame_stack_mask(bt, fr));
				verbose(env, "stack=%s: ", env->tmp_str_buf);
				print_verifier_state(env, st, fr, true);
			}
		}

		if (bt_empty(bt))
			return 0;

		subseq_idx = first_idx;
		last_idx = st->last_insn_idx;
		first_idx = st->first_insn_idx;
	}

	/* if we still have requested precise regs or slots, we missed
	 * something (e.g., stack access through non-r10 register), so
	 * fallback to marking all precise
	 */
	if (!bt_empty(bt)) {
		mark_all_scalars_precise(env, starting_state);
		bt_reset(bt);
	}

	return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_mark_dynptr_reg(struct bpf_reg_state *reg, enum bpf_dynptr_type type,
			      bool first_slot, int dynptr_id)
{
	/* reg->type has no meaning for STACK_DYNPTR, but when we set reg for
	 * callback arguments, it does need to be CONST_PTR_TO_DYNPTR, so simply
	 * set it unconditionally as it is ignored for STACK_DYNPTR anyway.
	 */
	inner_mark_reg_known_zero(reg);
	reg->type = CONST_PTR_TO_DYNPTR;
	/* Give each dynptr a unique id to uniquely associate slices to it. */
	reg->id = dynptr_id;
	reg->dynptr.type = type;
	reg->dynptr.first_slot = first_slot;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_mark_reg_const_zero(const struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	inner_mark_reg_known(reg, 0);
	reg->type = SCALAR_VALUE;
	/* all scalars are assumed imprecise initially (unless unprivileged,
	 * in which case everything is forced to be precise)
	 */
	reg->precise = !env->bpf_capable;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_mark_reg_known_zero(struct bpf_reg_state *reg)
{
	inner_mark_reg_known(reg, 0);
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_mark_reg_not_init(const struct bpf_verifier_env *env,
				struct bpf_reg_state *reg)
{
	inner_mark_reg_unknown(env, reg);
	reg->type = NOT_INIT;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_mark_reg_unknown(const struct bpf_verifier_env *env,
			       struct bpf_reg_state *reg)
{
	inner_mark_reg_unknown_imprecise(reg);
	reg->precise = !env->bpf_capable;
}