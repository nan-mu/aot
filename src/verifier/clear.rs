// Extracted from /Users/nan/bs/aot/src/verifier.c
static void clear_all_pkt_pointers(struct bpf_verifier_env *env)
{
	struct bpf_func_state *state;
	struct bpf_reg_state *reg;

	bpf_for_each_reg_in_vstate(env->cur_state, state, reg, ({
		if (reg_is_pkt_pointer_any(reg) || reg_is_dynptr_slice_pkt(reg))
			mark_reg_invalid(env, reg);
	}));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void clear_caller_saved_regs(struct bpf_verifier_env *env,
				    struct bpf_reg_state *regs)
{
	int i;

	/* after the call registers r0 - r5 were scratched */
	for (i = 0; i < CALLER_SAVED_REGS; i++) {
		mark_reg_not_init(env, regs, caller_saved[i]);
		inner_check_reg_arg(env, regs, caller_saved[i], DST_OP_NO_MARK);
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void clear_insn_aux_data(struct bpf_verifier_env *env, int start, int len)
{
	struct bpf_insn_aux_data *aux_data = env->insn_aux_data;
	struct bpf_insn *insns = env->prog->insnsi;
	int end = start + len;
	int i;

	for (i = start; i < end; i++) {
		if (aux_data[i].jt) {
			kvfree(aux_data[i].jt);
			aux_data[i].jt = NULL;
		}

		if (bpf_is_ldimm64(&insns[i]))
			i++;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void clear_jmp_history(struct bpf_verifier_state *state)
{
	kfree(state->jmp_history);
	state->jmp_history = NULL;
	state->jmp_history_cnt = 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void clear_singular_ids(struct bpf_verifier_env *env,
			       struct bpf_verifier_state *st)
{
	struct bpf_idset *idset = &env->idset_scratch;
	struct bpf_func_state *func;
	struct bpf_reg_state *reg;

	idset->num_ids = 0;

	bpf_for_each_reg_in_vstate(st, func, reg, ({
		if (reg->type != SCALAR_VALUE)
			continue;
		if (!reg->id)
			continue;
		idset_cnt_inc(idset, reg->id & ~BPF_ADD_CONST);
	}));

	bpf_for_each_reg_in_vstate(st, func, reg, ({
		if (reg->type != SCALAR_VALUE)
			continue;
		if (!reg->id)
			continue;
		if (idset_cnt_get(idset, reg->id & ~BPF_ADD_CONST) == 1) {
			reg->id = 0;
			reg->off = 0;
		}
	}));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void clear_trusted_flags(enum bpf_type_flag *flag)
{
	*flag &= ~(BPF_REG_TRUSTED_MODIFIERS | MEM_RCU);
}


