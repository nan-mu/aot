// Extracted from /Users/nan/bs/aot/src/verifier.c
static int destroy_if_dynptr_stack_slot(struct bpf_verifier_env *env,
				        struct bpf_func_state *state, int spi)
{
	struct bpf_func_state *fstate;
	struct bpf_reg_state *dreg;
	int i, dynptr_id;

	/* We always ensure that STACK_DYNPTR is never set partially,
	 * hence just checking for slot_type[0] is enough. This is
	 * different for STACK_SPILL, where it may be only set for
	 * 1 byte, so code has to use is_spilled_reg.
	 */
	if (state->stack[spi].slot_type[0] != STACK_DYNPTR)
		return 0;

	/* Reposition spi to first slot */
	if (!state->stack[spi].spilled_ptr.dynptr.first_slot)
		spi = spi + 1;

	if (dynptr_type_refcounted(state->stack[spi].spilled_ptr.dynptr.type)) {
		verbose(env, "cannot overwrite referenced dynptr\n");
		return -EINVAL;
	}

	mark_stack_slot_scratched(env, spi);
	mark_stack_slot_scratched(env, spi - 1);

	/* Writing partially to one dynptr stack slot destroys both. */
	for (i = 0; i < BPF_REG_SIZE; i++) {
		state->stack[spi].slot_type[i] = STACK_INVALID;
		state->stack[spi - 1].slot_type[i] = STACK_INVALID;
	}

	dynptr_id = state->stack[spi].spilled_ptr.id;
	/* Invalidate any slices associated with this dynptr */
	bpf_for_each_reg_in_vstate(env->cur_state, fstate, dreg, ({
		/* Dynptr slices are only PTR_TO_MEM_OR_NULL and PTR_TO_MEM */
		if (dreg->type != (PTR_TO_MEM | PTR_MAYBE_NULL) && dreg->type != PTR_TO_MEM)
			continue;
		if (dreg->dynptr_id == dynptr_id)
			mark_reg_invalid(env, dreg);
	}));

	/* Do not release reference state, we are destroying dynptr on stack,
	 * not using some helper to release it. Just reset register.
	 */
	inner_mark_reg_not_init(env, &state->stack[spi].spilled_ptr);
	inner_mark_reg_not_init(env, &state->stack[spi - 1].spilled_ptr);

	bpf_mark_stack_write(env, state->frameno, BIT(spi - 1) | BIT(spi));

	return 0;
}


