// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool incomplete_read_marks(struct bpf_verifier_env *env,
				  struct bpf_verifier_state *st)
{
	struct bpf_scc_callchain *callchain = &env->callchain_buf;
	struct bpf_scc_visit *visit;

	if (!compute_scc_callchain(env, st, callchain))
		return false;
	visit = scc_visit_lookup(env, callchain);
	if (!visit)
		return false;
	return !!visit->backedges;
}


