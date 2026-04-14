// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_func_state *func(struct bpf_verifier_env *env,
				   const struct bpf_reg_state *reg)
{
	struct bpf_verifier_state *cur = env->cur_state;

	return cur->frame[reg->frameno];
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool func_states_equal(struct bpf_verifier_env *env, struct bpf_func_state *old,
			      struct bpf_func_state *cur, u32 insn_idx, enum exact_level exact)
{
	u16 live_regs = env->insn_aux_data[insn_idx].live_regs_before;
	u16 i;

	if (old->callback_depth > cur->callback_depth)
		return false;

	for (i = 0; i < MAX_BPF_REG; i++)
		if (((1 << i) & live_regs) &&
		    !regsafe(env, &old->regs[i], &cur->regs[i],
			     &env->idmap_scratch, exact))
			return false;

	if (!stacksafe(env, old, cur, &env->idmap_scratch, exact))
		return false;

	return true;
}


