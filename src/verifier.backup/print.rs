// Extracted from /Users/nan/bs/aot/src/verifier.c
static void print_verification_stats(struct bpf_verifier_env *env)
{
	int i;

	if (env->log.level & BPF_LOG_STATS) {
		verbose(env, "verification time %lld usec\n",
			div_u64(env->verification_time, 1000));
		verbose(env, "stack depth ");
		for (i = 0; i < env->subprog_cnt; i++) {
			u32 depth = env->subprog_info[i].stack_depth;

			verbose(env, "%d", depth);
			if (i + 1 < env->subprog_cnt)
				verbose(env, "+");
		}
		verbose(env, "\n");
	}
	verbose(env, "processed %d insns (limit %d) max_states_per_insn %d "
		"total_states %d peak_states %d mark_read %d\n",
		env->insn_processed, BPF_COMPLEXITY_LIMIT_INSNS,
		env->max_states_per_insn, env->total_states,
		env->peak_states, env->longest_mark_read_walk);
}


