// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool verifier_inlines_helper_call(struct bpf_verifier_env *env, s32 imm)
{
	switch (imm) {
#ifdef CONFIG_X86_64
	case BPF_FUNC_get_smp_processor_id:
#ifdef CONFIG_SMP
	case BPF_FUNC_get_current_task_btf:
	case BPF_FUNC_get_current_task:
#endif
		return env->prog->jit_requested && bpf_jit_supports_percpu_insn();
#endif
	default:
		return false;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int verifier_remove_insns(struct bpf_verifier_env *env, u32 off, u32 cnt)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	unsigned int orig_prog_len = env->prog->len;
	int err;

	if (bpf_prog_is_offloaded(env->prog->aux))
		bpf_prog_offload_remove_insns(env, off, cnt);

	/* Should be called before bpf_remove_insns, as it uses prog->insnsi */
	clear_insn_aux_data(env, off, cnt);

	err = bpf_remove_insns(env->prog, off, cnt);
	if (err)
		return err;

	err = adjust_subprog_starts_after_remove(env, off, cnt);
	if (err)
		return err;

	err = bpf_adj_linfo_after_remove(env, off, cnt);
	if (err)
		return err;

	adjust_insn_arrays_after_remove(env, off, cnt);

	memmove(aux_data + off,	aux_data + off + cnt,
		sizeof(*aux_data) * (orig_prog_len - off - cnt));

	return 0;
}


