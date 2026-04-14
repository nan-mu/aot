// Extracted from /Users/nan/bs/aot/src/verifier.c
static int grow_stack_state(struct bpf_verifier_env *env, struct bpf_func_state *state, int size)
{
	size_t old_n = state->allocated_stack / BPF_REG_SIZE, n;

	/* The stack size is always a multiple of BPF_REG_SIZE. */
	size = round_up(size, BPF_REG_SIZE);
	n = size / BPF_REG_SIZE;

	if (old_n >= n)
		return 0;

	state->stack = realloc_array(state->stack, old_n, n, sizeof(struct bpf_stack_state));
	if (!state->stack)
		return -ENOMEM;

	state->allocated_stack = size;

	/* update known max for given subprogram */
	if (env->subprog_info[state->subprogno].stack_depth < size)
		env->subprog_info[state->subprogno].stack_depth = size;

	return 0;
}


