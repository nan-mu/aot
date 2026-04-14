// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool loop_flag_is_zero(struct bpf_verifier_env *env)
{
	struct bpf_reg_state *reg = reg_state(env, BPF_REG_4);
	bool reg_is_null = register_is_null(reg);

	if (reg_is_null)
		mark_chain_precision(env, BPF_REG_4);

	return reg_is_null;
}


