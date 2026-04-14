// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool atomic_ptr_type_ok(struct bpf_verifier_env *env, int regno,
			       struct bpf_insn *insn)
{
	if (is_ctx_reg(env, regno))
		return false;
	if (is_pkt_reg(env, regno))
		return false;
	if (is_flow_key_reg(env, regno))
		return false;
	if (is_sk_reg(env, regno))
		return false;
	if (is_arena_reg(env, regno))
		return bpf_jit_supports_insn(insn, true);

	return true;
}


