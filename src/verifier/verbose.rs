// Extracted from /Users/nan/bs/aot/src/verifier.c
__printf(2, 3) static void verbose(void *private_data, const char *fmt, ...)
{
	struct bpf_verifier_env *env = private_data;
	va_list args;

	if (!bpf_verifier_log_needed(&env->log))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(&env->log, fmt, args);
	va_end(args);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void verbose_insn(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	const struct bpf_insn_cbs cbs = {
		.cb_call	= disasm_kfunc_name,
		.cb_print	= verbose,
		.private_data	= env,
	};

	print_bpf_insn(&cbs, insn, env->allow_ptr_leaks);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void verbose_invalid_scalar(struct bpf_verifier_env *env,
				   struct bpf_reg_state *reg,
				   struct bpf_retval_range range, const char *ctx,
				   const char *reg_name)
{
	bool unknown = true;

	verbose(env, "%s the register %s has", ctx, reg_name);
	if (reg->smin_value > S64_MIN) {
		verbose(env, " smin=%lld", reg->smin_value);
		unknown = false;
	}
	if (reg->smax_value < S64_MAX) {
		verbose(env, " smax=%lld", reg->smax_value);
		unknown = false;
	}
	if (unknown)
		verbose(env, " unknown scalar value");
	verbose(env, " should have been in [%d, %d]\n", range.minval, range.maxval);
}


