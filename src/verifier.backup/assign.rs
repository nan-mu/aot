// Extracted from /Users/nan/bs/aot/src/verifier.c
static void assign_scalar_id_before_mov(struct bpf_verifier_env *env,
					struct bpf_reg_state *src_reg)
{
	if (src_reg->type != SCALAR_VALUE)
		return;

	if (src_reg->id & BPF_ADD_CONST) {
		/*
		 * The verifier is processing rX = rY insn and
		 * rY->id has special linked register already.
		 * Cleared it, since multiple rX += const are not supported.
		 */
		src_reg->id = 0;
		src_reg->off = 0;
	}

	if (!src_reg->id && !tnum_is_const(src_reg->var_off))
		/* Ensure that src_reg has a valid ID that will be copied to
		 * dst_reg and then will be used by sync_linked_regs() to
		 * propagate min/max range.
		 */
		src_reg->id = ++env->id_gen;
}


