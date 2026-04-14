// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool iter_active_depths_differ(struct bpf_verifier_state *old, struct bpf_verifier_state *cur)
{
	struct bpf_reg_state *slot, *cur_slot;
	struct bpf_func_state *state;
	int i, fr;

	for (fr = old->curframe; fr >= 0; fr--) {
		state = old->frame[fr];
		for (i = 0; i < state->allocated_stack / BPF_REG_SIZE; i++) {
			if (state->stack[i].slot_type[0] != STACK_ITER)
				continue;

			slot = &state->stack[i].spilled_ptr;
			if (slot->iter.state != BPF_ITER_STATE_ACTIVE)
				continue;

			cur_slot = &cur->frame[fr]->stack[i].spilled_ptr;
			if (cur_slot->iter.depth != slot->iter.depth)
				return true;
		}
	}
	return false;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int iter_get_spi(struct bpf_verifier_env *env, struct bpf_reg_state *reg, int nr_slots)
{
	return stack_slot_obj_get_spi(env, reg, "iter", nr_slots);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static u32 iter_ref_obj_id(struct bpf_verifier_env *env, struct bpf_reg_state *reg, int spi)
{
	struct bpf_func_state *state = func(env, reg);

	return state->stack[spi].spilled_ptr.ref_obj_id;
}


