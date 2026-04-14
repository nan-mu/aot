// Extracted from /Users/nan/bs/aot/src/verifier.c
static int acquire_irq_state(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_reference_state *s;

	s = acquire_reference_state(env, insn_idx);
	if (!s)
		return -ENOMEM;
	s->type = REF_TYPE_IRQ;
	s->id = ++env->id_gen;

	state->active_irq_id = s->id;
	return s->id;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int acquire_lock_state(struct bpf_verifier_env *env, int insn_idx, enum ref_state_type type,
			      int id, void *ptr)
{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_reference_state *s;

	s = acquire_reference_state(env, insn_idx);
	if (!s)
		return -ENOMEM;
	s->type = type;
	s->id = id;
	s->ptr = ptr;

	state->active_locks++;
	state->active_lock_id = id;
	state->active_lock_ptr = ptr;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int acquire_reference(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_reference_state *s;

	s = acquire_reference_state(env, insn_idx);
	if (!s)
		return -ENOMEM;
	s->type = REF_TYPE_PTR;
	s->id = ++env->id_gen;
	return s->id;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_reference_state *acquire_reference_state(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_verifier_state *state = env->cur_state;
	int new_ofs = state->acquired_refs;
	int err;

	err = resize_reference_state(state, state->acquired_refs + 1);
	if (err)
		return NULL;
	state->refs[new_ofs].insn_idx = insn_idx;

	return &state->refs[new_ofs];
}


