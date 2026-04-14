// Extracted from /Users/nan/bs/aot/src/verifier.c
static int dynptr_get_spi(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	return stack_slot_obj_get_spi(env, reg, "dynptr", BPF_DYNPTR_NR_SLOTS);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static enum bpf_dynptr_type dynptr_get_type(struct bpf_verifier_env *env,
					    struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = func(env, reg);
	int spi;

	if (reg->type == CONST_PTR_TO_DYNPTR)
		return reg->dynptr.type;

	spi = __get_spi(reg->off);
	if (spi < 0) {
		verbose(env, "verifier internal error: invalid spi when querying dynptr type\n");
		return BPF_DYNPTR_TYPE_INVALID;
	}

	return state->stack[spi].spilled_ptr.dynptr.type;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int dynptr_id(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = func(env, reg);
	int spi;

	if (reg->type == CONST_PTR_TO_DYNPTR)
		return reg->id;
	spi = dynptr_get_spi(env, reg);
	if (spi < 0)
		return spi;
	return state->stack[spi].spilled_ptr.id;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int dynptr_ref_obj_id(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct bpf_func_state *state = func(env, reg);
	int spi;

	if (reg->type == CONST_PTR_TO_DYNPTR)
		return reg->ref_obj_id;
	spi = dynptr_get_spi(env, reg);
	if (spi < 0)
		return spi;
	return state->stack[spi].spilled_ptr.ref_obj_id;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool dynptr_type_refcounted(enum bpf_dynptr_type type)
{
	return type == BPF_DYNPTR_TYPE_RINGBUF || type == BPF_DYNPTR_TYPE_FILE;
}


