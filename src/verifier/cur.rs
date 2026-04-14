// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_insn_aux_data *cur_aux(const struct bpf_verifier_env *env)
{
	return &env->insn_aux_data[env->insn_idx];
}


