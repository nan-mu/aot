// Extracted from /Users/nan/bs/aot/src/verifier.c
static int update_alu_sanitation_state(struct bpf_insn_aux_data *aux,
				       u32 alu_state, u32 alu_limit)
{
	/* If we arrived here from different branches with different
	 * state or limits to sanitize, then this won't work.
	 */
	if (aux->alu_state &&
	    (aux->alu_state != alu_state ||
	     aux->alu_limit != alu_limit))
		return REASON_PATHS;

	/* Corresponding fixup done in do_misc_fixups(). */
	aux->alu_state = alu_state;
	aux->alu_limit = alu_limit;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int update_branch_counts(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	struct bpf_verifier_state_list *sl = NULL, *parent_sl;
	struct bpf_verifier_state *parent;
	int err;

	while (st) {
		u32 br = --st->branches;

		/* verifier_bug_if(br > 1, ...) technically makes sense here,
		 * but see comment in push_stack(), hence:
		 */
		verifier_bug_if((int)br < 0, env, "%s:branches_to_explore=%d", __func__, br);
		if (br)
			break;
		err = maybe_exit_scc(env, st);
		if (err)
			return err;
		parent = st->parent;
		parent_sl = state_parent_as_list(st);
		if (sl)
			maybe_free_verifier_state(env, sl);
		st = parent;
		sl = parent_sl;
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void update_loop_inline_state(struct bpf_verifier_env *env, u32 subprogno)
{
	struct bpf_loop_inline_state *state = &cur_aux(env)->loop_inline_state;

	if (!state->initialized) {
		state->initialized = 1;
		state->fit_for_inline = loop_flag_is_zero(env);
		state->callback_subprogno = subprogno;
		return;
	}

	if (!state->fit_for_inline)
		return;

	state->fit_for_inline = (loop_flag_is_zero(env) &&
				 state->callback_subprogno == subprogno);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void update_peak_states(struct bpf_verifier_env *env)
{
	u32 cur_states;

	cur_states = env->explored_states_size + env->free_list_size + env->num_backedges;
	env->peak_states = max(env->peak_states, cur_states);
}


