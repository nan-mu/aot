// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool can_elide_value_nullness(enum bpf_map_type type)
{
	switch (type) {
	case BPF_MAP_TYPE_ARRAY:
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		return true;
	default:
		return false;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool can_skip_alu_sanitation(const struct bpf_verifier_env *env,
				    const struct bpf_insn *insn)
{
	return env->bypass_spec_v1 ||
		BPF_SRC(insn->code) == BPF_K ||
		cur_aux(env)->nospec;
}


