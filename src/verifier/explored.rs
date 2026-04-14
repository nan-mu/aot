// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct list_head *explored_state(struct bpf_verifier_env *env, int idx)
{
	struct bpf_verifier_state *cur = env->cur_state;
	struct bpf_func_state *state = cur->frame[cur->curframe];

	return &env->explored_states[(idx ^ state->callsite) % state_htab_size(env)];
}


