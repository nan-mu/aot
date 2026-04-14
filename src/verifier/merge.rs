// Extracted from /Users/nan/bs/aot/src/verifier.c
static void merge_callee_effects(struct bpf_verifier_env *env, int t, int w)
{
	struct bpf_subprog_info *caller, *callee;

	caller = bpf_find_containing_subprog(env, t);
	callee = bpf_find_containing_subprog(env, w);
	caller->changes_pkt_data |= callee->changes_pkt_data;
	caller->might_sleep |= callee->might_sleep;
}


