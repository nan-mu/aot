// Extracted from /Users/nan/bs/aot/src/verifier.c
static int propagate_backedges(struct bpf_verifier_env *env, struct bpf_scc_visit *visit)
{
	struct bpf_scc_backedge *backedge;
	struct bpf_verifier_state *st;
	bool changed;
	int i, err;

	i = 0;
	do {
		if (i++ > MAX_BACKEDGE_ITERS) {
			if (env->log.level & BPF_LOG_LEVEL2)
				verbose(env, "%s: too many iterations\n", __func__);
			for (backedge = visit->backedges; backedge; backedge = backedge->next)
				mark_all_scalars_precise(env, &backedge->state);
			break;
		}
		changed = false;
		for (backedge = visit->backedges; backedge; backedge = backedge->next) {
			st = &backedge->state;
			err = propagate_precision(env, st->equal_state, st, &changed);
			if (err)
				return err;
		}
	} while (changed);

	free_backedges(visit);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int propagate_precision(struct bpf_verifier_env *env,
			       const struct bpf_verifier_state *old,
			       struct bpf_verifier_state *cur,
			       bool *changed)
{
	struct bpf_reg_state *state_reg;
	struct bpf_func_state *state;
	int i, err = 0, fr;
	bool first;

	for (fr = old->curframe; fr >= 0; fr--) {
		state = old->frame[fr];
		state_reg = state->regs;
		first = true;
		for (i = 0; i < BPF_REG_FP; i++, state_reg++) {
			if (state_reg->type != SCALAR_VALUE ||
			    !state_reg->precise)
				continue;
			if (env->log.level & BPF_LOG_LEVEL2) {
				if (first)
					verbose(env, "frame %d: propagating r%d", fr, i);
				else
					verbose(env, ",r%d", i);
			}
			bt_set_frame_reg(&env->bt, fr, i);
			first = false;
		}

		for (i = 0; i < state->allocated_stack / BPF_REG_SIZE; i++) {
			if (!is_spilled_reg(&state->stack[i]))
				continue;
			state_reg = &state->stack[i].spilled_ptr;
			if (state_reg->type != SCALAR_VALUE ||
			    !state_reg->precise)
				continue;
			if (env->log.level & BPF_LOG_LEVEL2) {
				if (first)
					verbose(env, "frame %d: propagating fp%d",
						fr, (-i - 1) * BPF_REG_SIZE);
				else
					verbose(env, ",fp%d", (-i - 1) * BPF_REG_SIZE);
			}
			bt_set_frame_slot(&env->bt, fr, i);
			first = false;
		}
		if (!first && (env->log.level & BPF_LOG_LEVEL2))
			verbose(env, "\n");
	}

	err = inner_mark_chain_precision(env, cur, -1, changed);
	if (err < 0)
		return err;

	return 0;
}


