// Extracted from /Users/nan/bs/aot/src/verifier.c
static int remove_fastcall_spills_fills(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprog = env->subprog_info;
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	u32 spills_num;
	bool modified = false;
	int i, j;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (aux[i].fastcall_spills_num > 0) {
			spills_num = aux[i].fastcall_spills_num;
			/* NOPs would be removed by opt_remove_nops() */
			for (j = 1; j <= spills_num; ++j) {
				*(insn - j) = NOP;
				*(insn + j) = NOP;
			}
			modified = true;
		}
		if ((subprog + 1)->start == i + 1) {
			if (modified && !subprog->keep_fastcall_stack)
				subprog->stack_depth = -subprog->fastcall_stack_off;
			subprog++;
			modified = false;
		}
	}

	return 0;
}


