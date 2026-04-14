// Extracted from /Users/nan/bs/aot/src/verifier.c
static void release_btfs(struct bpf_verifier_env *env)
{
	__bpf_free_used_btfs(env->used_btfs, env->used_btf_cnt);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void release_insn_arrays(struct bpf_verifier_env *env)
{
	int i;

	for (i = 0; i < env->insn_array_map_cnt; i++)
		bpf_insn_array_release(env->insn_array_maps[i]);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int release_irq_state(struct bpf_verifier_state *state, int id)
{
	u32 prev_id = 0;
	int i;

	if (id != state->active_irq_id)
		return -EACCES;

	for (i = 0; i < state->acquired_refs; i++) {
		if (state->refs[i].type != REF_TYPE_IRQ)
			continue;
		if (state->refs[i].id == id) {
			release_reference_state(state, i);
			state->active_irq_id = prev_id;
			return 0;
		} else {
			prev_id = state->refs[i].id;
		}
	}
	return -EINVAL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int release_lock_state(struct bpf_verifier_state *state, int type, int id, void *ptr)
{
	void *prev_ptr = NULL;
	u32 prev_id = 0;
	int i;

	for (i = 0; i < state->acquired_refs; i++) {
		if (state->refs[i].type == type && state->refs[i].id == id &&
		    state->refs[i].ptr == ptr) {
			release_reference_state(state, i);
			state->active_locks--;
			/* Reassign active lock (id, ptr). */
			state->active_lock_id = prev_id;
			state->active_lock_ptr = prev_ptr;
			return 0;
		}
		if (state->refs[i].type & REF_TYPE_LOCK_MASK) {
			prev_id = state->refs[i].id;
			prev_ptr = state->refs[i].ptr;
		}
	}
	return -EINVAL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void release_maps(struct bpf_verifier_env *env)
{
	__bpf_free_used_maps(env->prog->aux, env->used_maps,
			     env->used_map_cnt);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int release_reference(struct bpf_verifier_env *env, int ref_obj_id)
{
	struct bpf_verifier_state *vstate = env->cur_state;
	struct bpf_func_state *state;
	struct bpf_reg_state *reg;
	int err;

	err = release_reference_nomark(vstate, ref_obj_id);
	if (err)
		return err;

	bpf_for_each_reg_in_vstate(vstate, state, reg, ({
		if (reg->ref_obj_id == ref_obj_id)
			mark_reg_invalid(env, reg);
	}));

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int release_reference_nomark(struct bpf_verifier_state *state, int ref_obj_id)
{
	int i;

	for (i = 0; i < state->acquired_refs; i++) {
		if (state->refs[i].type != REF_TYPE_PTR)
			continue;
		if (state->refs[i].id == ref_obj_id) {
			release_reference_state(state, i);
			return 0;
		}
	}
	return -EINVAL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void release_reference_state(struct bpf_verifier_state *state, int idx)
{
	int last_idx;
	size_t rem;

	/* IRQ state requires the relative ordering of elements remaining the
	 * same, since it relies on the refs array to behave as a stack, so that
	 * it can detect out-of-order IRQ restore. Hence use memmove to shift
	 * the array instead of swapping the final element into the deleted idx.
	 */
	last_idx = state->acquired_refs - 1;
	rem = state->acquired_refs - idx - 1;
	if (last_idx && idx != last_idx)
		memmove(&state->refs[idx], &state->refs[idx + 1], sizeof(*state->refs) * rem);
	memset(&state->refs[last_idx], 0, sizeof(*state->refs));
	state->acquired_refs--;
	return;
}


