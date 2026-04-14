// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool states_equal(struct bpf_verifier_env *env,
			 struct bpf_verifier_state *old,
			 struct bpf_verifier_state *cur,
			 enum exact_level exact)
{
	u32 insn_idx;
	int i;

	if (old->curframe != cur->curframe)
		return false;

	reset_idmap_scratch(env);

	/* Verification state from speculative execution simulation
	 * must never prune a non-speculative execution one.
	 */
	if (old->speculative && !cur->speculative)
		return false;

	if (old->in_sleepable != cur->in_sleepable)
		return false;

	if (!refsafe(old, cur, &env->idmap_scratch))
		return false;

	/* for states to be equal callsites have to be the same
	 * and all frame states need to be equivalent
	 */
	for (i = 0; i <= old->curframe; i++) {
		insn_idx = frame_insn_idx(old, i);
		if (old->frame[i]->callsite != cur->frame[i]->callsite)
			return false;
		if (!func_states_equal(env, old->frame[i], cur->frame[i], insn_idx, exact))
			return false;
	}
	return true;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool states_maybe_looping(struct bpf_verifier_state *old,
				 struct bpf_verifier_state *cur)
{
	struct bpf_func_state *fold, *fcur;
	int i, fr = cur->curframe;

	if (old->curframe != fr)
		return false;

	fold = old->frame[fr];
	fcur = cur->frame[fr];
	for (i = 0; i < MAX_BPF_REG; i++)
		if (memcmp(&fold->regs[i], &fcur->regs[i],
			   offsetof(struct bpf_reg_state, frameno)))
			return false;
	return true;
}


