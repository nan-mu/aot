// Extracted from /Users/nan/bs/aot/src/verifier.c
static int unmark_stack_slot_irq_flag(struct bpf_verifier_env *env, struct bpf_reg_state *reg,
				      int kfunc_class)
{
	struct bpf_func_state *state = func(env, reg);
	struct bpf_stack_state *slot;
	struct bpf_reg_state *st;
	int spi, i, err;

	spi = irq_flag_get_spi(env, reg);
	if (spi < 0)
		return spi;

	slot = &state->stack[spi];
	st = &slot->spilled_ptr;

	if (st->irq.kfunc_class != kfunc_class) {
		const char *flag_kfunc = st->irq.kfunc_class == IRQ_NATIVE_KFUNC ? "native" : "lock";
		const char *used_kfunc = kfunc_class == IRQ_NATIVE_KFUNC ? "native" : "lock";

		verbose(env, "irq flag acquired by %s kfuncs cannot be restored with %s kfuncs\n",
			flag_kfunc, used_kfunc);
		return -EINVAL;
	}

	err = release_irq_state(env->cur_state, st->ref_obj_id);
	WARN_ON_ONCE(err && err != -EACCES);
	if (err) {
		int insn_idx = 0;

		for (int i = 0; i < env->cur_state->acquired_refs; i++) {
			if (env->cur_state->refs[i].id == env->cur_state->active_irq_id) {
				insn_idx = env->cur_state->refs[i].insn_idx;
				break;
			}
		}

		verbose(env, "cannot restore irq state out of order, expected id=%d acquired at insn_idx=%d\n",
			env->cur_state->active_irq_id, insn_idx);
		return err;
	}

	inner_mark_reg_not_init(env, st);

	bpf_mark_stack_write(env, reg->frameno, BIT(spi));

	for (i = 0; i < BPF_REG_SIZE; i++)
		slot->slot_type[i] = STACK_INVALID;

	mark_stack_slot_scratched(env, spi);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int unmark_stack_slots_dynptr(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = func(env, reg);
	int spi, ref_obj_id, i;

	/*
	 * This can only be set for PTR_TO_STACK, as CONST_PTR_TO_DYNPTR cannot
	 * be released by any dynptr helper. Hence, unmark_stack_slots_dynptr
	 * is safe to do directly.
	 */
	if (reg->type == CONST_PTR_TO_DYNPTR) {
		verifier_bug(env, "CONST_PTR_TO_DYNPTR cannot be released");
		return -EFAULT;
	}
	spi = dynptr_get_spi(env, reg);
	if (spi < 0)
		return spi;

	if (!dynptr_type_refcounted(state->stack[spi].spilled_ptr.dynptr.type)) {
		invalidate_dynptr(env, state, spi);
		return 0;
	}

	ref_obj_id = state->stack[spi].spilled_ptr.ref_obj_id;

	/* If the dynptr has a ref_obj_id, then we need to invalidate
	 * two things:
	 *
	 * 1) Any dynptrs with a matching ref_obj_id (clones)
	 * 2) Any slices derived from this dynptr.
	 */

	/* Invalidate any slices associated with this dynptr */
	WARN_ON_ONCE(release_reference(env, ref_obj_id));

	/* Invalidate any dynptr clones */
	for (i = 1; i < state->allocated_stack / BPF_REG_SIZE; i++) {
		if (state->stack[i].spilled_ptr.ref_obj_id != ref_obj_id)
			continue;

		/* it should always be the case that if the ref obj id
		 * matches then the stack slot also belongs to a
		 * dynptr
		 */
		if (state->stack[i].slot_type[0] != STACK_DYNPTR) {
			verifier_bug(env, "misconfigured ref_obj_id");
			return -EFAULT;
		}
		if (state->stack[i].spilled_ptr.dynptr.first_slot)
			invalidate_dynptr(env, state, i);
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int unmark_stack_slots_iter(struct bpf_verifier_env *env,
				   struct bpf_reg_state *reg, int nr_slots)
{
	struct bpf_func_state *state = func(env, reg);
	int spi, i, j;

	spi = iter_get_spi(env, reg, nr_slots);
	if (spi < 0)
		return spi;

	for (i = 0; i < nr_slots; i++) {
		struct bpf_stack_state *slot = &state->stack[spi - i];
		struct bpf_reg_state *st = &slot->spilled_ptr;

		if (i == 0)
			WARN_ON_ONCE(release_reference(env, st->ref_obj_id));

		inner_mark_reg_not_init(env, st);

		for (j = 0; j < BPF_REG_SIZE; j++)
			slot->slot_type[j] = STACK_INVALID;

		bpf_mark_stack_write(env, state->frameno, BIT(spi - i));
		mark_stack_slot_scratched(env, spi - i);
	}

	return 0;
}


