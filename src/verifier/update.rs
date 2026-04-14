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

static void inner_update_reg32_bounds(struct bpf_reg_state *reg)
{
	struct tnum var32_off = tnum_subreg(reg->var_off);

	/* min signed is max(sign bit) | min(other bits) */
	reg->s32_min_value = max_t(s32, reg->s32_min_value,
			var32_off.value | (var32_off.mask & S32_MIN));
	/* max signed is min(sign bit) | max(other bits) */
	reg->s32_max_value = min_t(s32, reg->s32_max_value,
			var32_off.value | (var32_off.mask & S32_MAX));
	reg->u32_min_value = max_t(u32, reg->u32_min_value, (u32)var32_off.value);
	reg->u32_max_value = min(reg->u32_max_value,
				 (u32)(var32_off.value | var32_off.mask));
}

static void inner_update_reg64_bounds(struct bpf_reg_state *reg)
{
	u64 tnum_next, tmax;
	bool umin_in_tnum;

	/* min signed is max(sign bit) | min(other bits) */
	reg->smin_value = max_t(s64, reg->smin_value,
				reg->var_off.value | (reg->var_off.mask & S64_MIN));
	/* max signed is min(sign bit) | max(other bits) */
	reg->smax_value = min_t(s64, reg->smax_value,
				reg->var_off.value | (reg->var_off.mask & S64_MAX));
	reg->umin_value = max(reg->umin_value, reg->var_off.value);
	reg->umax_value = min(reg->umax_value,
			      reg->var_off.value | reg->var_off.mask);

	/* Check if u64 and tnum overlap in a single value */
	tnum_next = tnum_step(reg->var_off, reg->umin_value);
	umin_in_tnum = (reg->umin_value & ~reg->var_off.mask) == reg->var_off.value;
	tmax = reg->var_off.value | reg->var_off.mask;
	if (umin_in_tnum && tnum_next > reg->umax_value) {
		/* The u64 range and the tnum only overlap in umin.
		 * u64:  ---[xxxxxx]-----
		 * tnum: --xx----------x-
		 */
		iinner_mark_reg_known(reg, reg->umin_value);
	} else if (!umin_in_tnum && tnum_next == tmax) {
		/* The u64 range and the tnum only overlap in the maximum value
		 * represented by the tnum, called tmax.
		 * u64:  ---[xxxxxx]-----
		 * tnum: xx-----x--------
		 */
		iinner_mark_reg_known(reg, tmax);
	} else if (!umin_in_tnum && tnum_next <= reg->umax_value &&
		   tnum_step(reg->var_off, tnum_next) > reg->umax_value) {
		/* The u64 range and the tnum only overlap in between umin
		 * (excluded) and umax.
		 * u64:  ---[xxxxxx]-----
		 * tnum: xx----x-------x-
		 */
		iinner_mark_reg_known(reg, tnum_next);
	}
}

static void inner_update_reg_bounds(struct bpf_reg_state *reg)
{
	inner_update_reg32_bounds(reg);
	inner_update_reg64_bounds(reg);
}
