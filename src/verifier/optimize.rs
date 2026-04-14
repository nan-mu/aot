// Extracted from /Users/nan/bs/aot/src/verifier.c
static int optimize_bpf_loop(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprogs = env->subprog_info;
	int i, cur_subprog = 0, cnt, delta = 0;
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	u16 stack_depth = subprogs[cur_subprog].stack_depth;
	u16 stack_depth_roundup = round_up(stack_depth, 8) - stack_depth;
	u16 stack_depth_extra = 0;

	for (i = 0; i < insn_cnt; i++, insn++) {
		struct bpf_loop_inline_state *inline_state =
			&env->insn_aux_data[i + delta].loop_inline_state;

		if (is_bpf_loop_call(insn) && inline_state->fit_for_inline) {
			struct bpf_prog *new_prog;

			stack_depth_extra = BPF_REG_SIZE * 3 + stack_depth_roundup;
			new_prog = inline_bpf_loop(env,
						   i + delta,
						   -(stack_depth + stack_depth_extra),
						   inline_state->callback_subprogno,
						   &cnt);
			if (!new_prog)
				return -ENOMEM;

			delta     += cnt - 1;
			env->prog  = new_prog;
			insn       = new_prog->insnsi + i + delta;
		}

		if (subprogs[cur_subprog + 1].start == i + delta + 1) {
			subprogs[cur_subprog].stack_depth += stack_depth_extra;
			cur_subprog++;
			stack_depth = subprogs[cur_subprog].stack_depth;
			stack_depth_roundup = round_up(stack_depth, 8) - stack_depth;
			stack_depth_extra = 0;
		}
	}

	env->prog->aux->stack_depth = env->subprog_info[0].stack_depth;

	return 0;
}


