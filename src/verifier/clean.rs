// Extracted from /Users/nan/bs/aot/src/verifier.c
static void clean_func_state(struct bpf_verifier_env *env,
			     struct bpf_func_state *st,
			     u32 ip)
{
	u16 live_regs = env->insn_aux_data[ip].live_regs_before;
	int i, j;

	for (i = 0; i < BPF_REG_FP; i++) {
		/* liveness must not touch this register anymore */
		if (!(live_regs & BIT(i)))
			/* since the register is unused, clear its state
			 * to make further comparison simpler
			 */
			inner_mark_reg_not_init(env, &st->regs[i]);
	}

	for (i = 0; i < st->allocated_stack / BPF_REG_SIZE; i++) {
		if (!bpf_stack_slot_alive(env, st->frameno, i)) {
			inner_mark_reg_not_init(env, &st->stack[i].spilled_ptr);
			for (j = 0; j < BPF_REG_SIZE; j++)
				st->stack[i].slot_type[j] = STACK_INVALID;
		}
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void clean_live_states(struct bpf_verifier_env *env, int insn,
			      struct bpf_verifier_state *cur)
{
	struct bpf_verifier_state_list *sl;
	struct list_head *pos, *head;

	head = explored_state(env, insn);
	list_for_each(pos, head) {
		sl = container_of(pos, struct bpf_verifier_state_list, node);
		if (sl->state.branches)
			continue;
		if (sl->state.insn_idx != insn ||
		    !same_callsites(&sl->state, cur))
			continue;
		if (sl->state.cleaned)
			/* all regs in this state in all frames were already marked */
			continue;
		if (incomplete_read_marks(env, &sl->state))
			continue;
		clean_verifier_state(env, &sl->state);
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void clean_verifier_state(struct bpf_verifier_env *env,
				 struct bpf_verifier_state *st)
{
	int i, ip;

	bpf_live_stack_query_init(env, st);
	st->cleaned = true;
	for (i = 0; i <= st->curframe; i++) {
		ip = frame_insn_idx(st, i);
		clean_func_state(env, st->frame[i], ip);
	}
}


