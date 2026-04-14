// Extracted from /Users/nan/bs/aot/src/verifier.c
static void zext_32_to_64(struct bpf_reg_state *reg)
{
	reg->var_off = tnum_subreg(reg->var_off);
	inner_reg_assign_32_into_64(reg);
}


