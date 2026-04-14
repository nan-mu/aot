// Extracted from /Users/nan/bs/aot/src/verifier.c
static int widen_imprecise_scalars(struct bpf_verifier_env *env,
				   struct bpf_verifier_state *old,
				   struct bpf_verifier_state *cur)
{
	struct bpf_func_state *fold, *fcur;
	int i, fr, num_slots;

	for (fr = old->curframe; fr >= 0; fr--) {
		fold = old->frame[fr];
		fcur = cur->frame[fr];

		for (i = 0; i < MAX_BPF_REG; i++)
			maybe_widen_reg(env,
					&fold->regs[i],
					&fcur->regs[i]);

		num_slots = min(fold->allocated_stack / BPF_REG_SIZE,
				fcur->allocated_stack / BPF_REG_SIZE);
		for (i = 0; i < num_slots; i++) {
			if (!is_spilled_reg(&fold->stack[i]) ||
			    !is_spilled_reg(&fcur->stack[i]))
				continue;

			maybe_widen_reg(env,
					&fold->stack[i].spilled_ptr,
					&fcur->stack[i].spilled_ptr);
		}
	}
	return 0;
}


