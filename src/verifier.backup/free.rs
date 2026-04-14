// Extracted from /Users/nan/bs/aot/src/verifier.c
static void free_backedges(struct bpf_scc_visit *visit)
{
	struct bpf_scc_backedge *backedge, *next;

	for (backedge = visit->backedges; backedge; backedge = next) {
		free_verifier_state(&backedge->state, false);
		next = backedge->next;
		kfree(backedge);
	}
	visit->backedges = NULL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void free_func_state(struct bpf_func_state *state)
{
	if (!state)
		return;
	kfree(state->stack);
	kfree(state);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void free_states(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state_list *sl;
	struct list_head *head, *pos, *tmp;
	struct bpf_scc_info *info;
	int i, j;

	free_verifier_state(env->cur_state, true);
	env->cur_state = NULL;
	while (!pop_stack(env, NULL, NULL, false));

	list_for_each_safe(pos, tmp, &env->free_list) {
		sl = container_of(pos, struct bpf_verifier_state_list, node);
		free_verifier_state(&sl->state, false);
		kfree(sl);
	}
	INIT_LIST_HEAD(&env->free_list);

	for (i = 0; i < env->scc_cnt; ++i) {
		info = env->scc_info[i];
		if (!info)
			continue;
		for (j = 0; j < info->num_visits; j++)
			free_backedges(&info->visits[j]);
		kvfree(info);
		env->scc_info[i] = NULL;
	}

	if (!env->explored_states)
		return;

	for (i = 0; i < state_htab_size(env); i++) {
		head = &env->explored_states[i];

		list_for_each_safe(pos, tmp, head) {
			sl = container_of(pos, struct bpf_verifier_state_list, node);
			free_verifier_state(&sl->state, false);
			kfree(sl);
		}
		INIT_LIST_HEAD(&env->explored_states[i]);
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void free_verifier_state(struct bpf_verifier_state *state,
				bool free_self)
{
	int i;

	for (i = 0; i <= state->curframe; i++) {
		free_func_state(state->frame[i]);
		state->frame[i] = NULL;
	}
	kfree(state->refs);
	clear_jmp_history(state);
	if (free_self)
		kfree(state);
}


