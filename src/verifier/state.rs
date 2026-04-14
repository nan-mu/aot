// Extracted from /Users/nan/bs/aot/src/verifier.c
static u32 state_htab_size(struct bpf_verifier_env *env)
{
	return env->prog->len;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_verifier_state_list *state_parent_as_list(struct bpf_verifier_state *st)
{
	if (st->parent)
		return container_of(st->parent, struct bpf_verifier_state_list, state);
	return NULL;
}


