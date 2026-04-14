// Extracted from /Users/nan/bs/aot/src/verifier.c
static int maybe_enter_scc(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	struct bpf_scc_callchain *callchain = &env->callchain_buf;
	struct bpf_scc_visit *visit;

	if (!compute_scc_callchain(env, st, callchain))
		return 0;
	visit = scc_visit_lookup(env, callchain);
	visit = visit ?: scc_visit_alloc(env, callchain);
	if (!visit)
		return -ENOMEM;
	if (!visit->entry_state) {
		visit->entry_state = st;
		if (env->log.level & BPF_LOG_LEVEL2)
			verbose(env, "SCC enter %s\n", format_callchain(env, callchain));
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int maybe_exit_scc(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	struct bpf_scc_callchain *callchain = &env->callchain_buf;
	struct bpf_scc_visit *visit;

	if (!compute_scc_callchain(env, st, callchain))
		return 0;
	visit = scc_visit_lookup(env, callchain);
	if (!visit) {
		/*
		 * If path traversal stops inside an SCC, corresponding bpf_scc_visit
		 * must exist for non-speculative paths. For non-speculative paths
		 * traversal stops when:
		 * a. Verification error is found, maybe_exit_scc() is not called.
		 * b. Top level BPF_EXIT is reached. Top level BPF_EXIT is not a member
		 *    of any SCC.
		 * c. A checkpoint is reached and matched. Checkpoints are created by
		 *    is_state_visited(), which calls maybe_enter_scc(), which allocates
		 *    bpf_scc_visit instances for checkpoints within SCCs.
		 * (c) is the only case that can reach this point.
		 */
		if (!st->speculative) {
			verifier_bug(env, "scc exit: no visit info for call chain %s",
				     format_callchain(env, callchain));
			return -EFAULT;
		}
		return 0;
	}
	if (visit->entry_state != st)
		return 0;
	if (env->log.level & BPF_LOG_LEVEL2)
		verbose(env, "SCC exit %s\n", format_callchain(env, callchain));
	visit->entry_state = NULL;
	env->num_backedges -= visit->num_backedges;
	visit->num_backedges = 0;
	update_peak_states(env);
	return propagate_backedges(env, visit);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int maybe_fork_scalars(struct bpf_verifier_env *env, struct bpf_insn *insn,
			      struct bpf_reg_state *dst_reg)
{
	struct bpf_verifier_state *branch;
	struct bpf_reg_state *regs;
	bool alu32;

	if (dst_reg->smin_value == -1 && dst_reg->smax_value == 0)
		alu32 = false;
	else if (dst_reg->s32_min_value == -1 && dst_reg->s32_max_value == 0)
		alu32 = true;
	else
		return 0;

	branch = push_stack(env, env->insn_idx, env->insn_idx, false);
	if (IS_ERR(branch))
		return PTR_ERR(branch);

	regs = branch->frame[branch->curframe]->regs;
	if (alu32) {
		inner_mark_reg32_known(&regs[insn->dst_reg], 0);
		inner_mark_reg32_known(dst_reg, -1ull);
	} else {
		inner_mark_reg_known(&regs[insn->dst_reg], 0);
		inner_mark_reg_known(dst_reg, -1ull);
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void maybe_free_verifier_state(struct bpf_verifier_env *env,
				      struct bpf_verifier_state_list *sl)
{
	if (!sl->in_free_list
	    || sl->state.branches != 0
	    || incomplete_read_marks(env, &sl->state))
		return;
	list_del(&sl->node);
	free_verifier_state(&sl->state, false);
	kfree(sl);
	env->free_list_size--;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void maybe_widen_reg(struct bpf_verifier_env *env,
			    struct bpf_reg_state *rold, struct bpf_reg_state *rcur)
{
	if (rold->type != SCALAR_VALUE)
		return;
	if (rold->type != rcur->type)
		return;
	if (rold->precise || rcur->precise || scalars_exact_for_widen(rold, rcur))
		return;
	inner_mark_reg_unknown(env, rcur);
}


