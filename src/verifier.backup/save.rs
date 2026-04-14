// Extracted from /Users/nan/bs/aot/src/verifier.c
static int save_aux_ptr_type(struct bpf_verifier_env *env, enum bpf_reg_type type,
			     bool allow_trust_mismatch)
{
	enum bpf_reg_type *prev_type = &env->insn_aux_data[env->insn_idx].ptr_type;
	enum bpf_reg_type merged_type;

	if (*prev_type == NOT_INIT) {
		/* Saw a valid insn
		 * dst_reg = *(u32 *)(src_reg + off)
		 * save type to validate intersecting paths
		 */
		*prev_type = type;
	} else if (reg_type_mismatch(type, *prev_type)) {
		/* Abuser program is trying to use the same insn
		 * dst_reg = *(u32*) (src_reg + off)
		 * with different pointer types:
		 * src_reg == ctx in one branch and
		 * src_reg == stack|map in some other branch.
		 * Reject it.
		 */
		if (allow_trust_mismatch &&
		    is_ptr_to_mem_or_btf_id(type) &&
		    is_ptr_to_mem_or_btf_id(*prev_type)) {
			/*
			 * Have to support a use case when one path through
			 * the program yields TRUSTED pointer while another
			 * is UNTRUSTED. Fallback to UNTRUSTED to generate
			 * BPF_PROBE_MEM/BPF_PROBE_MEMSX.
			 * Same behavior of MEM_RDONLY flag.
			 */
			if (is_ptr_to_mem(type) || is_ptr_to_mem(*prev_type))
				merged_type = PTR_TO_MEM;
			else
				merged_type = PTR_TO_BTF_ID;
			if ((type & PTR_UNTRUSTED) || (*prev_type & PTR_UNTRUSTED))
				merged_type |= PTR_UNTRUSTED;
			if ((type & MEM_RDONLY) || (*prev_type & MEM_RDONLY))
				merged_type |= MEM_RDONLY;
			*prev_type = merged_type;
		} else {
			verbose(env, "same insn cannot be used with different pointers\n");
			return -EINVAL;
		}
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void save_register_state(struct bpf_verifier_env *env,
				struct bpf_func_state *state,
				int spi, struct bpf_reg_state *reg,
				int size)
{
	int i;

	copy_register_state(&state->stack[spi].spilled_ptr, reg);

	for (i = BPF_REG_SIZE; i > BPF_REG_SIZE - size; i--)
		state->stack[spi].slot_type[i - 1] = STACK_SPILL;

	/* size < 8 bytes spill */
	for (; i; i--)
		mark_stack_slot_misc(env, &state->stack[spi].slot_type[i - 1]);
}


