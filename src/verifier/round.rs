// Extracted from /Users/nan/bs/aot/src/verifier.c
static int round_up_stack_depth(struct bpf_verifier_env *env, int stack_depth)
{
	if (env->prog->jit_requested)
		return round_up(stack_depth, 16);

	/* round up to 32-bytes, since this is granularity
	 * of interpreter stack size
	 */
	return round_up(max_t(u32, stack_depth, 1), 32);
}


