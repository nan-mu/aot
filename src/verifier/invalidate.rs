// Extracted from /Users/nan/bs/aot/src/verifier.c
static void invalidate_dynptr(struct bpf_verifier_env *env, struct bpf_func_state *state, int spi)
{
	int i;

	for (i = 0; i < BPF_REG_SIZE; i++) {
		state->stack[spi].slot_type[i] = STACK_INVALID;
		state->stack[spi - 1].slot_type[i] = STACK_INVALID;
	}

	inner_mark_reg_not_init(env, &state->stack[spi].spilled_ptr);
	inner_mark_reg_not_init(env, &state->stack[spi - 1].spilled_ptr);

	bpf_mark_stack_write(env, state->frameno, BIT(spi - 1) | BIT(spi));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void invalidate_non_owning_refs(struct bpf_verifier_env *env)
{
	struct bpf_func_state *unused;
	struct bpf_reg_state *reg;

	bpf_for_each_reg_in_vstate(env->cur_state, unused, reg, ({
		if (type_is_non_owning_ref(reg->type))
			mark_reg_invalid(env, reg);
	}));
}


