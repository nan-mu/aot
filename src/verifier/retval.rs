// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_retval_range retval_range(s32 minval, s32 maxval)
{
	return (struct bpf_retval_range){ minval, maxval };
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool retval_range_within(struct bpf_retval_range range, const struct bpf_reg_state *reg,
				bool return_32bit)
{
	if (return_32bit)
		return range.minval <= reg->s32_min_value && reg->s32_max_value <= range.maxval;
	else
		return range.minval <= reg->smin_value && reg->smax_value <= range.maxval;
}


