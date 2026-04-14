// Extracted from /Users/nan/bs/aot/src/verifier.c
static int prepare_func_exit(struct bpf_verifier_env *env, int *insn_idx)
{
	struct bpf_verifier_state *state = env->cur_state, *prev_st;
	struct bpf_func_state *caller, *callee;
	struct bpf_reg_state *r0;
	bool in_callback_fn;
	int err;

	err = bpf_update_live_stack(env);
	if (err)
		return err;

	callee = state->frame[state->curframe];
	r0 = &callee->regs[BPF_REG_0];
	if (r0->type == PTR_TO_STACK) {
		/* technically it's ok to return caller's stack pointer
		 * (or caller's caller's pointer) back to the caller,
		 * since these pointers are valid. Only current stack
		 * pointer will be invalid as soon as function exits,
		 * but let's be conservative
		 */
		verbose(env, "cannot return stack pointer to the caller\n");
		return -EINVAL;
	}

	caller = state->frame[state->curframe - 1];
	if (callee->in_callback_fn) {
		if (r0->type != SCALAR_VALUE) {
			verbose(env, "R0 not a scalar value\n");
			return -EACCES;
		}

		/* we are going to rely on register's precise value */
		err = mark_chain_precision(env, BPF_REG_0);
		if (err)
			return err;

		/* enforce R0 return value range, and bpf_callback_t returns 64bit */
		if (!retval_range_within(callee->callback_ret_range, r0, false)) {
			verbose_invalid_scalar(env, r0, callee->callback_ret_range,
					       "At callback return", "R0");
			return -EINVAL;
		}
		if (!bpf_calls_callback(env, callee->callsite)) {
			verifier_bug(env, "in callback at %d, callsite %d !calls_callback",
				     *insn_idx, callee->callsite);
			return -EFAULT;
		}
	} else {
		/* return to the caller whatever r0 had in the callee */
		caller->regs[BPF_REG_0] = *r0;
	}

	/* for callbacks like bpf_loop or bpf_for_each_map_elem go back to callsite,
	 * there function call logic would reschedule callback visit. If iteration
	 * converges is_state_visited() would prune that visit eventually.
	 */
	in_callback_fn = callee->in_callback_fn;
	if (in_callback_fn)
		*insn_idx = callee->callsite;
	else
		*insn_idx = callee->callsite + 1;

	if (env->log.level & BPF_LOG_LEVEL) {
		verbose(env, "returning from callee:\n");
		print_verifier_state(env, state, callee->frameno, true);
		verbose(env, "to caller at %d:\n", *insn_idx);
		print_verifier_state(env, state, caller->frameno, true);
	}
	/* clear everything in the callee. In case of exceptional exits using
	 * bpf_throw, this will be done by copy_verifier_state for extra frames. */
	free_func_state(callee);
	state->frame[state->curframe--] = NULL;

	/* for callbacks widen imprecise scalars to make programs like below verify:
	 *
	 *   struct ctx { int i; }
	 *   void cb(int idx, struct ctx *ctx) { ctx->i++; ... }
	 *   ...
	 *   struct ctx = { .i = 0; }
	 *   bpf_loop(100, cb, &ctx, 0);
	 *
	 * This is similar to what is done in process_iter_next_call() for open
	 * coded iterators.
	 */
	prev_st = in_callback_fn ? find_prev_entry(env, state, *insn_idx) : NULL;
	if (prev_st) {
		err = widen_imprecise_scalars(env, prev_st, state);
		if (err)
			return err;
	}
	return 0;
}


