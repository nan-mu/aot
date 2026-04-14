// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_verifier_state *push_async_cb(struct bpf_verifier_env *env,
						int insn_idx, int prev_insn_idx,
						int subprog, bool is_sleepable)
{
	struct bpf_verifier_stack_elem *elem;
	struct bpf_func_state *frame;

	elem = kzalloc_obj(struct bpf_verifier_stack_elem, GFP_KERNEL_ACCOUNT);
	if (!elem)
		return ERR_PTR(-ENOMEM);

	elem->insn_idx = insn_idx;
	elem->prev_insn_idx = prev_insn_idx;
	elem->next = env->head;
	elem->log_pos = env->log.end_pos;
	env->head = elem;
	env->stack_size++;
	if (env->stack_size > BPF_COMPLEXITY_LIMIT_JMP_SEQ) {
		verbose(env,
			"The sequence of %d jumps is too complex for async cb.\n",
			env->stack_size);
		return ERR_PTR(-E2BIG);
	}
	/* Unlike push_stack() do not copy_verifier_state().
	 * The caller state doesn't matter.
	 * This is async callback. It starts in a fresh stack.
	 * Initialize it similar to do_check_common().
	 */
	elem->st.branches = 1;
	elem->st.in_sleepable = is_sleepable;
	frame = kzalloc_obj(*frame, GFP_KERNEL_ACCOUNT);
	if (!frame)
		return ERR_PTR(-ENOMEM);
	init_func_state(env, frame,
			BPF_MAIN_FUNC /* callsite */,
			0 /* frameno within this callchain */,
			subprog /* subprog number within this prog */);
	elem->st.frame[0] = frame;
	return &elem->st;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int push_callback_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
			      int insn_idx, int subprog,
			      set_callee_state_fn set_callee_state_cb)
{
	struct bpf_verifier_state *state = env->cur_state, *callback_state;
	struct bpf_func_state *caller, *callee;
	int err;

	caller = state->frame[state->curframe];
	err = btf_check_subprog_call(env, subprog, caller->regs);
	if (err == -EFAULT)
		return err;

	/* set_callee_state is used for direct subprog calls, but we are
	 * interested in validating only BPF helpers that can call subprogs as
	 * callbacks
	 */
	env->subprog_info[subprog].is_cb = true;
	if (bpf_pseudo_kfunc_call(insn) &&
	    !is_callback_calling_kfunc(insn->imm)) {
		verifier_bug(env, "kfunc %s#%d not marked as callback-calling",
			     func_id_name(insn->imm), insn->imm);
		return -EFAULT;
	} else if (!bpf_pseudo_kfunc_call(insn) &&
		   !is_callback_calling_function(insn->imm)) { /* helper */
		verifier_bug(env, "helper %s#%d not marked as callback-calling",
			     func_id_name(insn->imm), insn->imm);
		return -EFAULT;
	}

	if (is_async_callback_calling_insn(insn)) {
		struct bpf_verifier_state *async_cb;

		/* there is no real recursion here. timer and workqueue callbacks are async */
		env->subprog_info[subprog].is_async_cb = true;
		async_cb = push_async_cb(env, env->subprog_info[subprog].start,
					 insn_idx, subprog,
					 is_async_cb_sleepable(env, insn));
		if (IS_ERR(async_cb))
			return PTR_ERR(async_cb);
		callee = async_cb->frame[0];
		callee->async_entry_cnt = caller->async_entry_cnt + 1;

		/* Convert bpf_timer_set_callback() args into timer callback args */
		err = set_callee_state_cb(env, caller, callee, insn_idx);
		if (err)
			return err;

		return 0;
	}

	/* for callback functions enqueue entry to callback and
	 * proceed with next instruction within current frame.
	 */
	callback_state = push_stack(env, env->subprog_info[subprog].start, insn_idx, false);
	if (IS_ERR(callback_state))
		return PTR_ERR(callback_state);

	err = setup_func_entry(env, subprog, insn_idx, set_callee_state_cb,
			       callback_state);
	if (err)
		return err;

	callback_state->callback_unroll_depth++;
	callback_state->frame[callback_state->curframe - 1]->callback_depth++;
	caller->callback_depth = 0;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int push_insn(int t, int w, int e, struct bpf_verifier_env *env)
{
	int *insn_stack = env->cfg.insn_stack;
	int *insn_state = env->cfg.insn_state;

	if (e == FALLTHROUGH && insn_state[t] >= (DISCOVERED | FALLTHROUGH))
		return DONE_EXPLORING;

	if (e == BRANCH && insn_state[t] >= (DISCOVERED | BRANCH))
		return DONE_EXPLORING;

	if (w < 0 || w >= env->prog->len) {
		verbose_linfo(env, t, "%d: ", t);
		verbose(env, "jump out of range from insn %d to %d\n", t, w);
		return -EINVAL;
	}

	if (e == BRANCH) {
		/* mark branch target for state pruning */
		mark_prune_point(env, w);
		mark_jmp_point(env, w);
	}

	if (insn_state[w] == 0) {
		/* tree-edge */
		insn_state[t] = DISCOVERED | e;
		insn_state[w] = DISCOVERED;
		if (env->cfg.cur_stack >= env->prog->len)
			return -E2BIG;
		insn_stack[env->cfg.cur_stack++] = w;
		return KEEP_EXPLORING;
	} else if ((insn_state[w] & 0xF0) == DISCOVERED) {
		if (env->bpf_capable)
			return DONE_EXPLORING;
		verbose_linfo(env, t, "%d: ", t);
		verbose_linfo(env, w, "%d: ", w);
		verbose(env, "back-edge from insn %d to %d\n", t, w);
		return -EINVAL;
	} else if (insn_state[w] == EXPLORED) {
		/* forward- or cross-edge */
		insn_state[t] = DISCOVERED | e;
	} else {
		verifier_bug(env, "insn state internal bug");
		return -EFAULT;
	}
	return DONE_EXPLORING;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int push_jmp_history(struct bpf_verifier_env *env, struct bpf_verifier_state *cur,
			    int insn_flags, u64 linked_regs)
{
	u32 cnt = cur->jmp_history_cnt;
	struct bpf_jmp_history_entry *p;
	size_t alloc_size;

	/* combine instruction flags if we already recorded this instruction */
	if (env->cur_hist_ent) {
		/* atomic instructions push insn_flags twice, for READ and
		 * WRITE sides, but they should agree on stack slot
		 */
		verifier_bug_if((env->cur_hist_ent->flags & insn_flags) &&
				(env->cur_hist_ent->flags & insn_flags) != insn_flags,
				env, "insn history: insn_idx %d cur flags %x new flags %x",
				env->insn_idx, env->cur_hist_ent->flags, insn_flags);
		env->cur_hist_ent->flags |= insn_flags;
		verifier_bug_if(env->cur_hist_ent->linked_regs != 0, env,
				"insn history: insn_idx %d linked_regs: %#llx",
				env->insn_idx, env->cur_hist_ent->linked_regs);
		env->cur_hist_ent->linked_regs = linked_regs;
		return 0;
	}

	cnt++;
	alloc_size = kmalloc_size_roundup(size_mul(cnt, sizeof(*p)));
	p = krealloc(cur->jmp_history, alloc_size, GFP_KERNEL_ACCOUNT);
	if (!p)
		return -ENOMEM;
	cur->jmp_history = p;

	p = &cur->jmp_history[cnt - 1];
	p->idx = env->insn_idx;
	p->prev_idx = env->prev_insn_idx;
	p->flags = insn_flags;
	p->linked_regs = linked_regs;
	cur->jmp_history_cnt = cnt;
	env->cur_hist_ent = p;

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_verifier_state *push_stack(struct bpf_verifier_env *env,
					     int insn_idx, int prev_insn_idx,
					     bool speculative)
{
	struct bpf_verifier_state *cur = env->cur_state;
	struct bpf_verifier_stack_elem *elem;
	int err;

	elem = kzalloc_obj(struct bpf_verifier_stack_elem, GFP_KERNEL_ACCOUNT);
	if (!elem)
		return ERR_PTR(-ENOMEM);

	elem->insn_idx = insn_idx;
	elem->prev_insn_idx = prev_insn_idx;
	elem->next = env->head;
	elem->log_pos = env->log.end_pos;
	env->head = elem;
	env->stack_size++;
	err = copy_verifier_state(&elem->st, cur);
	if (err)
		return ERR_PTR(-ENOMEM);
	elem->st.speculative |= speculative;
	if (env->stack_size > BPF_COMPLEXITY_LIMIT_JMP_SEQ) {
		verbose(env, "The sequence of %d jumps is too complex.\n",
			env->stack_size);
		return ERR_PTR(-E2BIG);
	}
	if (elem->st.parent) {
		++elem->st.parent->branches;
		/* WARN_ON(branches > 2) technically makes sense here,
		 * but
		 * 1. speculative states will bump 'branches' for non-branch
		 * instructions
		 * 2. is_state_visited() heuristics may decide not to create
		 * a new state for a sequence of branches and all such current
		 * and cloned states will be pointing to a single parent state
		 * which might have large 'branches' count.
		 */
	}
	return &elem->st;
}


