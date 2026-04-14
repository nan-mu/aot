// Extracted from /Users/nan/bs/aot/src/verifier.c
static void coerce_reg_to_size(struct bpf_reg_state *reg, int size)
{
	u64 mask;

	/* clear high bits in bit representation */
	reg->var_off = tnum_cast(reg->var_off, size);

	/* fix arithmetic bounds */
	mask = ((u64)1 << (size * 8)) - 1;
	if ((reg->umin_value & ~mask) == (reg->umax_value & ~mask)) {
		reg->umin_value &= mask;
		reg->umax_value &= mask;
	} else {
		reg->umin_value = 0;
		reg->umax_value = mask;
	}
	reg->smin_value = reg->umin_value;
	reg->smax_value = reg->umax_value;

	/* If size is smaller than 32bit register the 32bit register
	 * values are also truncated so we push 64-bit bounds into
	 * 32-bit bounds. Above were truncated < 32-bits already.
	 */
	if (size < 4)
		__mark_reg32_unbounded(reg);

	reg_bounds_sync(reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void coerce_reg_to_size_sx(struct bpf_reg_state *reg, int size)
{
	s64 init_s64_max, init_s64_min, s64_max, s64_min, u64_cval;
	u64 top_smax_value, top_smin_value;
	u64 num_bits = size * 8;

	if (tnum_is_const(reg->var_off)) {
		u64_cval = reg->var_off.value;
		if (size == 1)
			reg->var_off = tnum_const((s8)u64_cval);
		else if (size == 2)
			reg->var_off = tnum_const((s16)u64_cval);
		else
			/* size == 4 */
			reg->var_off = tnum_const((s32)u64_cval);

		u64_cval = reg->var_off.value;
		reg->smax_value = reg->smin_value = u64_cval;
		reg->umax_value = reg->umin_value = u64_cval;
		reg->s32_max_value = reg->s32_min_value = u64_cval;
		reg->u32_max_value = reg->u32_min_value = u64_cval;
		return;
	}

	top_smax_value = ((u64)reg->smax_value >> num_bits) << num_bits;
	top_smin_value = ((u64)reg->smin_value >> num_bits) << num_bits;

	if (top_smax_value != top_smin_value)
		goto out;

	/* find the s64_min and s64_min after sign extension */
	if (size == 1) {
		init_s64_max = (s8)reg->smax_value;
		init_s64_min = (s8)reg->smin_value;
	} else if (size == 2) {
		init_s64_max = (s16)reg->smax_value;
		init_s64_min = (s16)reg->smin_value;
	} else {
		init_s64_max = (s32)reg->smax_value;
		init_s64_min = (s32)reg->smin_value;
	}

	s64_max = max(init_s64_max, init_s64_min);
	s64_min = min(init_s64_max, init_s64_min);

	/* both of s64_max/s64_min positive or negative */
	if ((s64_max >= 0) == (s64_min >= 0)) {
		reg->s32_min_value = reg->smin_value = s64_min;
		reg->s32_max_value = reg->smax_value = s64_max;
		reg->u32_min_value = reg->umin_value = s64_min;
		reg->u32_max_value = reg->umax_value = s64_max;
		reg->var_off = tnum_range(s64_min, s64_max);
		return;
	}

out:
	set_sext64_default_val(reg, size);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void coerce_subreg_to_size_sx(struct bpf_reg_state *reg, int size)
{
	s32 init_s32_max, init_s32_min, s32_max, s32_min, u32_val;
	u32 top_smax_value, top_smin_value;
	u32 num_bits = size * 8;

	if (tnum_is_const(reg->var_off)) {
		u32_val = reg->var_off.value;
		if (size == 1)
			reg->var_off = tnum_const((s8)u32_val);
		else
			reg->var_off = tnum_const((s16)u32_val);

		u32_val = reg->var_off.value;
		reg->s32_min_value = reg->s32_max_value = u32_val;
		reg->u32_min_value = reg->u32_max_value = u32_val;
		return;
	}

	top_smax_value = ((u32)reg->s32_max_value >> num_bits) << num_bits;
	top_smin_value = ((u32)reg->s32_min_value >> num_bits) << num_bits;

	if (top_smax_value != top_smin_value)
		goto out;

	/* find the s32_min and s32_min after sign extension */
	if (size == 1) {
		init_s32_max = (s8)reg->s32_max_value;
		init_s32_min = (s8)reg->s32_min_value;
	} else {
		/* size == 2 */
		init_s32_max = (s16)reg->s32_max_value;
		init_s32_min = (s16)reg->s32_min_value;
	}
	s32_max = max(init_s32_max, init_s32_min);
	s32_min = min(init_s32_max, init_s32_min);

	if ((s32_min >= 0) == (s32_max >= 0)) {
		reg->s32_min_value = s32_min;
		reg->s32_max_value = s32_max;
		reg->u32_min_value = (u32)s32_min;
		reg->u32_max_value = (u32)s32_max;
		reg->var_off = tnum_subreg(tnum_range(s32_min, s32_max));
		return;
	}

out:
	set_sext32_default_val(reg, size);
}


