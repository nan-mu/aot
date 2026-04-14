// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool in_rbtree_lock_required_cb(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_insn *insn = env->prog->insnsi;
	struct bpf_func_state *callee;
	int kfunc_btf_id;

	if (!state->curframe)
		return false;

	callee = state->frame[state->curframe];

	if (!callee->in_callback_fn)
		return false;

	kfunc_btf_id = insn[callee->callsite].imm;
	return is_rbtree_lock_required_kfunc(kfunc_btf_id);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool in_rcu_cs(struct bpf_verifier_env *env)
{
	return env->cur_state->active_rcu_locks ||
	       env->cur_state->active_locks ||
	       !in_sleepable(env);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool in_sleepable(struct bpf_verifier_env *env)
{
	return env->cur_state->in_sleepable;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static inline bool in_sleepable_context(struct bpf_verifier_env *env)
{
	return !env->cur_state->active_rcu_locks &&
	       !env->cur_state->active_preempt_locks &&
	       !env->cur_state->active_locks &&
	       !env->cur_state->active_irq_id &&
	       in_sleepable(env);
}


