// Extracted from /Users/nan/bs/aot/src/verifier.c
static void reset_idmap_scratch(struct bpf_verifier_env *env)
{
	struct bpf_idmap *idmap = &env->idmap_scratch;

	idmap->tmp_id_gen = env->id_gen;
	idmap->cnt = 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void reset_reg32_and_tnum(struct bpf_reg_state *reg)
{
	inner_mark_reg32_unbounded(reg);
	reg->var_off = tnum_unknown;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void reset_reg64_and_tnum(struct bpf_reg_state *reg)
{
	inner_mark_reg64_unbounded(reg);
	reg->var_off = tnum_unknown;
}


