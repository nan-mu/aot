// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_add(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	s32 *dst_smin = &dst_reg->s32_min_value;
	s32 *dst_smax = &dst_reg->s32_max_value;
	u32 *dst_umin = &dst_reg->u32_min_value;
	u32 *dst_umax = &dst_reg->u32_max_value;
	u32 umin_val = src_reg->u32_min_value;
	u32 umax_val = src_reg->u32_max_value;
	bool min_overflow, max_overflow;

	if (check_add_overflow(*dst_smin, src_reg->s32_min_value, dst_smin) ||
	    check_add_overflow(*dst_smax, src_reg->s32_max_value, dst_smax)) {
		*dst_smin = S32_MIN;
		*dst_smax = S32_MAX;
	}

	/* If either all additions overflow or no additions overflow, then
	 * it is okay to set: dst_umin = dst_umin + src_umin, dst_umax =
	 * dst_umax + src_umax. Otherwise (some additions overflow), set
	 * the output bounds to unbounded.
	 */
	min_overflow = check_add_overflow(*dst_umin, umin_val, dst_umin);
	max_overflow = check_add_overflow(*dst_umax, umax_val, dst_umax);

	if (!min_overflow && max_overflow) {
		*dst_umin = 0;
		*dst_umax = U32_MAX;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_and(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_subreg_is_const(src_reg->var_off);
	bool dst_known = tnum_subreg_is_const(dst_reg->var_off);
	struct tnum var32_off = tnum_subreg(dst_reg->var_off);
	u32 umax_val = src_reg->u32_max_value;

	if (src_known && dst_known) {
		__mark_reg32_known(dst_reg, var32_off.value);
		return;
	}

	/* We get our minimum from the var_off, since that's inherently
	 * bitwise.  Our maximum is the minimum of the operands' maxima.
	 */
	dst_reg->u32_min_value = var32_off.value;
	dst_reg->u32_max_value = min(dst_reg->u32_max_value, umax_val);

	/* Safe to set s32 bounds by casting u32 result into s32 when u32
	 * doesn't cross sign boundary. Otherwise set s32 bounds to unbounded.
	 */
	if ((s32)dst_reg->u32_min_value <= (s32)dst_reg->u32_max_value) {
		dst_reg->s32_min_value = dst_reg->u32_min_value;
		dst_reg->s32_max_value = dst_reg->u32_max_value;
	} else {
		dst_reg->s32_min_value = S32_MIN;
		dst_reg->s32_max_value = S32_MAX;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_arsh(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	u64 umin_val = src_reg->u32_min_value;

	/* Upon reaching here, src_known is true and
	 * umax_val is equal to umin_val.
	 */
	dst_reg->s32_min_value = (u32)(((s32)dst_reg->s32_min_value) >> umin_val);
	dst_reg->s32_max_value = (u32)(((s32)dst_reg->s32_max_value) >> umin_val);

	dst_reg->var_off = tnum_arshift(tnum_subreg(dst_reg->var_off), umin_val, 32);

	/* blow away the dst_reg umin_value/umax_value and rely on
	 * dst_reg var_off to refine the result.
	 */
	dst_reg->u32_min_value = 0;
	dst_reg->u32_max_value = U32_MAX;

	__mark_reg64_unbounded(dst_reg);
	__update_reg32_bounds(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_lsh(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	u32 umax_val = src_reg->u32_max_value;
	u32 umin_val = src_reg->u32_min_value;
	/* u32 alu operation will zext upper bits */
	struct tnum subreg = tnum_subreg(dst_reg->var_off);

	__scalar32_min_max_lsh(dst_reg, umin_val, umax_val);
	dst_reg->var_off = tnum_subreg(tnum_lshift(subreg, umin_val));
	/* Not required but being careful mark reg64 bounds as unknown so
	 * that we are forced to pick them up from tnum and zext later and
	 * if some path skips this step we are still safe.
	 */
	__mark_reg64_unbounded(dst_reg);
	__update_reg32_bounds(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_mul(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	s32 *dst_smin = &dst_reg->s32_min_value;
	s32 *dst_smax = &dst_reg->s32_max_value;
	u32 *dst_umin = &dst_reg->u32_min_value;
	u32 *dst_umax = &dst_reg->u32_max_value;
	s32 tmp_prod[4];

	if (check_mul_overflow(*dst_umax, src_reg->u32_max_value, dst_umax) ||
	    check_mul_overflow(*dst_umin, src_reg->u32_min_value, dst_umin)) {
		/* Overflow possible, we know nothing */
		*dst_umin = 0;
		*dst_umax = U32_MAX;
	}
	if (check_mul_overflow(*dst_smin, src_reg->s32_min_value, &tmp_prod[0]) ||
	    check_mul_overflow(*dst_smin, src_reg->s32_max_value, &tmp_prod[1]) ||
	    check_mul_overflow(*dst_smax, src_reg->s32_min_value, &tmp_prod[2]) ||
	    check_mul_overflow(*dst_smax, src_reg->s32_max_value, &tmp_prod[3])) {
		/* Overflow possible, we know nothing */
		*dst_smin = S32_MIN;
		*dst_smax = S32_MAX;
	} else {
		*dst_smin = min_array(tmp_prod, 4);
		*dst_smax = max_array(tmp_prod, 4);
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_or(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_subreg_is_const(src_reg->var_off);
	bool dst_known = tnum_subreg_is_const(dst_reg->var_off);
	struct tnum var32_off = tnum_subreg(dst_reg->var_off);
	u32 umin_val = src_reg->u32_min_value;

	if (src_known && dst_known) {
		__mark_reg32_known(dst_reg, var32_off.value);
		return;
	}

	/* We get our maximum from the var_off, and our minimum is the
	 * maximum of the operands' minima
	 */
	dst_reg->u32_min_value = max(dst_reg->u32_min_value, umin_val);
	dst_reg->u32_max_value = var32_off.value | var32_off.mask;

	/* Safe to set s32 bounds by casting u32 result into s32 when u32
	 * doesn't cross sign boundary. Otherwise set s32 bounds to unbounded.
	 */
	if ((s32)dst_reg->u32_min_value <= (s32)dst_reg->u32_max_value) {
		dst_reg->s32_min_value = dst_reg->u32_min_value;
		dst_reg->s32_max_value = dst_reg->u32_max_value;
	} else {
		dst_reg->s32_min_value = S32_MIN;
		dst_reg->s32_max_value = S32_MAX;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_rsh(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	struct tnum subreg = tnum_subreg(dst_reg->var_off);
	u32 umax_val = src_reg->u32_max_value;
	u32 umin_val = src_reg->u32_min_value;

	/* BPF_RSH is an unsigned shift.  If the value in dst_reg might
	 * be negative, then either:
	 * 1) src_reg might be zero, so the sign bit of the result is
	 *    unknown, so we lose our signed bounds
	 * 2) it's known negative, thus the unsigned bounds capture the
	 *    signed bounds
	 * 3) the signed bounds cross zero, so they tell us nothing
	 *    about the result
	 * If the value in dst_reg is known nonnegative, then again the
	 * unsigned bounds capture the signed bounds.
	 * Thus, in all cases it suffices to blow away our signed bounds
	 * and rely on inferring new ones from the unsigned bounds and
	 * var_off of the result.
	 */
	dst_reg->s32_min_value = S32_MIN;
	dst_reg->s32_max_value = S32_MAX;

	dst_reg->var_off = tnum_rshift(subreg, umin_val);
	dst_reg->u32_min_value >>= umax_val;
	dst_reg->u32_max_value >>= umin_val;

	__mark_reg64_unbounded(dst_reg);
	__update_reg32_bounds(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_sdiv(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	s32 *dst_smin = &dst_reg->s32_min_value;
	s32 *dst_smax = &dst_reg->s32_max_value;
	s32 src_val = src_reg->s32_min_value; /* non-zero, const divisor */
	s32 res1, res2;

	/* BPF div specification: S32_MIN / -1 = S32_MIN */
	if (*dst_smin == S32_MIN && src_val == -1) {
		/*
		 * If the dividend range contains more than just S32_MIN,
		 * we cannot precisely track the result, so it becomes unbounded.
		 * e.g., [S32_MIN, S32_MIN+10]/(-1),
		 *     = {S32_MIN} U [-(S32_MIN+10), -(S32_MIN+1)]
		 *     = {S32_MIN} U [S32_MAX-9, S32_MAX] = [S32_MIN, S32_MAX]
		 * Otherwise (if dividend is exactly S32_MIN), result remains S32_MIN.
		 */
		if (*dst_smax != S32_MIN) {
			*dst_smin = S32_MIN;
			*dst_smax = S32_MAX;
		}
		goto reset;
	}

	res1 = *dst_smin / src_val;
	res2 = *dst_smax / src_val;
	*dst_smin = min(res1, res2);
	*dst_smax = max(res1, res2);

reset:
	/* Reset other ranges/tnum to unbounded/unknown. */
	dst_reg->u32_min_value = 0;
	dst_reg->u32_max_value = U32_MAX;
	reset_reg64_and_tnum(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_smod(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	s32 *dst_smin = &dst_reg->s32_min_value;
	s32 *dst_smax = &dst_reg->s32_max_value;
	s32 src_val = src_reg->s32_min_value; /* non-zero, const divisor */

	/*
	 * Safe absolute value calculation:
	 * If src_val == S32_MIN (-2147483648), src_abs becomes 2147483648.
	 * Here use unsigned integer to avoid overflow.
	 */
	u32 src_abs = (src_val > 0) ? (u32)src_val : -(u32)src_val;

	/*
	 * Calculate the maximum possible absolute value of the result.
	 * Even if src_abs is 2147483648 (S32_MIN), subtracting 1 gives
	 * 2147483647 (S32_MAX), which fits perfectly in s32.
	 */
	s32 res_max_abs = src_abs - 1;

	/*
	 * If the dividend is already within the result range,
	 * the result remains unchanged. e.g., [-2, 5] % 10 = [-2, 5].
	 */
	if (*dst_smin >= -res_max_abs && *dst_smax <= res_max_abs)
		return;

	/* General case: result has the same sign as the dividend. */
	if (*dst_smin >= 0) {
		*dst_smin = 0;
		*dst_smax = min(*dst_smax, res_max_abs);
	} else if (*dst_smax <= 0) {
		*dst_smax = 0;
		*dst_smin = max(*dst_smin, -res_max_abs);
	} else {
		*dst_smin = -res_max_abs;
		*dst_smax = res_max_abs;
	}

	/* Reset other ranges/tnum to unbounded/unknown. */
	dst_reg->u32_min_value = 0;
	dst_reg->u32_max_value = U32_MAX;
	reset_reg64_and_tnum(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_sub(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	s32 *dst_smin = &dst_reg->s32_min_value;
	s32 *dst_smax = &dst_reg->s32_max_value;
	u32 *dst_umin = &dst_reg->u32_min_value;
	u32 *dst_umax = &dst_reg->u32_max_value;
	u32 umin_val = src_reg->u32_min_value;
	u32 umax_val = src_reg->u32_max_value;
	bool min_underflow, max_underflow;

	if (check_sub_overflow(*dst_smin, src_reg->s32_max_value, dst_smin) ||
	    check_sub_overflow(*dst_smax, src_reg->s32_min_value, dst_smax)) {
		/* Overflow possible, we know nothing */
		*dst_smin = S32_MIN;
		*dst_smax = S32_MAX;
	}

	/* If either all subtractions underflow or no subtractions
	 * underflow, it is okay to set: dst_umin = dst_umin - src_umax,
	 * dst_umax = dst_umax - src_umin. Otherwise (some subtractions
	 * underflow), set the output bounds to unbounded.
	 */
	min_underflow = check_sub_overflow(*dst_umin, umax_val, dst_umin);
	max_underflow = check_sub_overflow(*dst_umax, umin_val, dst_umax);

	if (min_underflow && !max_underflow) {
		*dst_umin = 0;
		*dst_umax = U32_MAX;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_udiv(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	u32 *dst_umin = &dst_reg->u32_min_value;
	u32 *dst_umax = &dst_reg->u32_max_value;
	u32 src_val = src_reg->u32_min_value; /* non-zero, const divisor */

	*dst_umin = *dst_umin / src_val;
	*dst_umax = *dst_umax / src_val;

	/* Reset other ranges/tnum to unbounded/unknown. */
	dst_reg->s32_min_value = S32_MIN;
	dst_reg->s32_max_value = S32_MAX;
	reset_reg64_and_tnum(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_umod(struct bpf_reg_state *dst_reg,
				  struct bpf_reg_state *src_reg)
{
	u32 *dst_umin = &dst_reg->u32_min_value;
	u32 *dst_umax = &dst_reg->u32_max_value;
	u32 src_val = src_reg->u32_min_value; /* non-zero, const divisor */
	u32 res_max = src_val - 1;

	/*
	 * If dst_umax <= res_max, the result remains unchanged.
	 * e.g., [2, 5] % 10 = [2, 5].
	 */
	if (*dst_umax <= res_max)
		return;

	*dst_umin = 0;
	*dst_umax = min(*dst_umax, res_max);

	/* Reset other ranges/tnum to unbounded/unknown. */
	dst_reg->s32_min_value = S32_MIN;
	dst_reg->s32_max_value = S32_MAX;
	reset_reg64_and_tnum(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar32_min_max_xor(struct bpf_reg_state *dst_reg,
				 struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_subreg_is_const(src_reg->var_off);
	bool dst_known = tnum_subreg_is_const(dst_reg->var_off);
	struct tnum var32_off = tnum_subreg(dst_reg->var_off);

	if (src_known && dst_known) {
		__mark_reg32_known(dst_reg, var32_off.value);
		return;
	}

	/* We get both minimum and maximum from the var32_off. */
	dst_reg->u32_min_value = var32_off.value;
	dst_reg->u32_max_value = var32_off.value | var32_off.mask;

	/* Safe to set s32 bounds by casting u32 result into s32 when u32
	 * doesn't cross sign boundary. Otherwise set s32 bounds to unbounded.
	 */
	if ((s32)dst_reg->u32_min_value <= (s32)dst_reg->u32_max_value) {
		dst_reg->s32_min_value = dst_reg->u32_min_value;
		dst_reg->s32_max_value = dst_reg->u32_max_value;
	} else {
		dst_reg->s32_min_value = S32_MIN;
		dst_reg->s32_max_value = S32_MAX;
	}
}


