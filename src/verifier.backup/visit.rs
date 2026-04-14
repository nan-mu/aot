// Extracted from /Users/nan/bs/aot/src/verifier.c
static int visit_func_call_insn(int t, struct bpf_insn *insns,
				struct bpf_verifier_env *env,
				bool visit_callee)
{
	int ret, insn_sz;
	int w;

	insn_sz = bpf_is_ldimm64(&insns[t]) ? 2 : 1;
	ret = push_insn(t, t + insn_sz, FALLTHROUGH, env);
	if (ret)
		return ret;

	mark_prune_point(env, t + insn_sz);
	/* when we exit from subprog, we need to record non-linear history */
	mark_jmp_point(env, t + insn_sz);

	if (visit_callee) {
		w = t + insns[t].imm + 1;
		mark_prune_point(env, t);
		merge_callee_effects(env, t, w);
		ret = push_insn(t, w, BRANCH, env);
	}
	return ret;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int visit_gotox_insn(int t, struct bpf_verifier_env *env)
{
	int *insn_stack = env->cfg.insn_stack;
	int *insn_state = env->cfg.insn_state;
	bool keep_exploring = false;
	struct bpf_iarray *jt;
	int i, w;

	jt = env->insn_aux_data[t].jt;
	if (!jt) {
		jt = create_jt(t, env);
		if (IS_ERR(jt))
			return PTR_ERR(jt);

		env->insn_aux_data[t].jt = jt;
	}

	mark_prune_point(env, t);
	for (i = 0; i < jt->cnt; i++) {
		w = jt->items[i];
		if (w < 0 || w >= env->prog->len) {
			verbose(env, "indirect jump out of range from insn %d to %d\n", t, w);
			return -EINVAL;
		}

		mark_jmp_point(env, w);

		/* EXPLORED || DISCOVERED */
		if (insn_state[w])
			continue;

		if (env->cfg.cur_stack >= env->prog->len)
			return -E2BIG;

		insn_stack[env->cfg.cur_stack++] = w;
		insn_state[w] |= DISCOVERED;
		keep_exploring = true;
	}

	return keep_exploring ? KEEP_EXPLORING : DONE_EXPLORING;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int visit_insn(int t, struct bpf_verifier_env *env)
{
	struct bpf_insn *insns = env->prog->insnsi, *insn = &insns[t];
	int ret, off, insn_sz;

	if (bpf_pseudo_func(insn))
		return visit_func_call_insn(t, insns, env, true);

	/* All non-branch instructions have a single fall-through edge. */
	if (BPF_CLASS(insn->code) != BPF_JMP &&
	    BPF_CLASS(insn->code) != BPF_JMP32) {
		insn_sz = bpf_is_ldimm64(insn) ? 2 : 1;
		return push_insn(t, t + insn_sz, FALLTHROUGH, env);
	}

	switch (BPF_OP(insn->code)) {
	case BPF_EXIT:
		return DONE_EXPLORING;

	case BPF_CALL:
		if (is_async_callback_calling_insn(insn))
			/* Mark this call insn as a prune point to trigger
			 * is_state_visited() check before call itself is
			 * processed by __check_func_call(). Otherwise new
			 * async state will be pushed for further exploration.
			 */
			mark_prune_point(env, t);
		/* For functions that invoke callbacks it is not known how many times
		 * callback would be called. Verifier models callback calling functions
		 * by repeatedly visiting callback bodies and returning to origin call
		 * instruction.
		 * In order to stop such iteration verifier needs to identify when a
		 * state identical some state from a previous iteration is reached.
		 * Check below forces creation of checkpoint before callback calling
		 * instruction to allow search for such identical states.
		 */
		if (is_sync_callback_calling_insn(insn)) {
			mark_calls_callback(env, t);
			mark_force_checkpoint(env, t);
			mark_prune_point(env, t);
			mark_jmp_point(env, t);
		}
		if (bpf_helper_call(insn)) {
			const struct bpf_func_proto *fp;

			ret = get_helper_proto(env, insn->imm, &fp);
			/* If called in a non-sleepable context program will be
			 * rejected anyway, so we should end up with precise
			 * sleepable marks on subprogs, except for dead code
			 * elimination.
			 */
			if (ret == 0 && fp->might_sleep)
				mark_subprog_might_sleep(env, t);
			if (bpf_helper_changes_pkt_data(insn->imm))
				mark_subprog_changes_pkt_data(env, t);
			if (insn->imm == BPF_FUNC_tail_call)
				visit_tailcall_insn(env, t);
		} else if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL) {
			struct bpf_kfunc_call_arg_meta meta;

			ret = fetch_kfunc_arg_meta(env, insn->imm, insn->off, &meta);
			if (ret == 0 && is_iter_next_kfunc(&meta)) {
				mark_prune_point(env, t);
				/* Checking and saving state checkpoints at iter_next() call
				 * is crucial for fast convergence of open-coded iterator loop
				 * logic, so we need to force it. If we don't do that,
				 * is_state_visited() might skip saving a checkpoint, causing
				 * unnecessarily long sequence of not checkpointed
				 * instructions and jumps, leading to exhaustion of jump
				 * history buffer, and potentially other undesired outcomes.
				 * It is expected that with correct open-coded iterators
				 * convergence will happen quickly, so we don't run a risk of
				 * exhausting memory.
				 */
				mark_force_checkpoint(env, t);
			}
			/* Same as helpers, if called in a non-sleepable context
			 * program will be rejected anyway, so we should end up
			 * with precise sleepable marks on subprogs, except for
			 * dead code elimination.
			 */
			if (ret == 0 && is_kfunc_sleepable(&meta))
				mark_subprog_might_sleep(env, t);
			if (ret == 0 && is_kfunc_pkt_changing(&meta))
				mark_subprog_changes_pkt_data(env, t);
		}
		return visit_func_call_insn(t, insns, env, insn->src_reg == BPF_PSEUDO_CALL);

	case BPF_JA:
		if (BPF_SRC(insn->code) == BPF_X)
			return visit_gotox_insn(t, env);

		if (BPF_CLASS(insn->code) == BPF_JMP)
			off = insn->off;
		else
			off = insn->imm;

		/* unconditional jump with single edge */
		ret = push_insn(t, t + off + 1, FALLTHROUGH, env);
		if (ret)
			return ret;

		mark_prune_point(env, t + off + 1);
		mark_jmp_point(env, t + off + 1);

		return ret;

	default:
		/* conditional jump with two edges */
		mark_prune_point(env, t);
		if (is_may_goto_insn(insn))
			mark_force_checkpoint(env, t);

		ret = push_insn(t, t + 1, FALLTHROUGH, env);
		if (ret)
			return ret;

		return push_insn(t, t + insn->off + 1, BRANCH, env);
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int visit_tailcall_insn(struct bpf_verifier_env *env, int t)
{
	static struct bpf_subprog_info *subprog;
	struct bpf_iarray *jt;

	if (env->insn_aux_data[t].jt)
		return 0;

	jt = iarray_realloc(NULL, 2);
	if (!jt)
		return -ENOMEM;

	subprog = bpf_find_containing_subprog(env, t);
	jt->items[0] = t + 1;
	jt->items[1] = subprog->exit_idx;
	env->insn_aux_data[t].jt = jt;
	return 0;
}


