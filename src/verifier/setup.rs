// Extracted from /Users/nan/bs/aot/src/verifier.c
static int setup_func_entry(struct bpf_verifier_env *env, int subprog, int callsite,
			    set_callee_state_fn set_callee_state_cb,
			    struct bpf_verifier_state *state)
{
	struct bpf_func_state *caller, *callee;
	int err;

	if (state->curframe + 1 >= MAX_CALL_FRAMES) {
		verbose(env, "the call stack of %d frames is too deep\n",
			state->curframe + 2);
		return -E2BIG;
	}

	if (state->frame[state->curframe + 1]) {
		verifier_bug(env, "Frame %d already allocated", state->curframe + 1);
		return -EFAULT;
	}

	caller = state->frame[state->curframe];
	callee = kzalloc_obj(*callee, GFP_KERNEL_ACCOUNT);
	if (!callee)
		return -ENOMEM;
	state->frame[state->curframe + 1] = callee;

	/* callee cannot access r0, r6 - r9 for reading and has to write
	 * into its own stack before reading from it.
	 * callee can read/write into caller's stack
	 */
	init_func_state(env, callee,
			/* remember the callsite, it will be used by bpf_exit */
			callsite,
			state->curframe + 1 /* frameno within this callchain */,
			subprog /* subprog number within this prog */);
	err = set_callee_state_cb(env, caller, callee, callsite);
	if (err)
		goto err_out;

	/* only increment it after check_reg_arg() finished */
	state->curframe++;

	return 0;

err_out:
	free_func_state(callee);
	state->frame[state->curframe + 1] = NULL;
	return err;
}


