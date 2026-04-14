// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_byte_swap(struct bpf_reg_state *dst_reg, struct bpf_insn *insn)
{
	/*
	 * Byte swap operation - update var_off using tnum_bswap.
	 * Three cases:
	 * 1. bswap(16|32|64): opcode=0xd7 (BPF_END | BPF_ALU64 | BPF_TO_LE)
	 *    unconditional swap
	 * 2. to_le(16|32|64): opcode=0xd4 (BPF_END | BPF_ALU | BPF_TO_LE)
	 *    swap on big-endian, truncation or no-op on little-endian
	 * 3. to_be(16|32|64): opcode=0xdc (BPF_END | BPF_ALU | BPF_TO_BE)
	 *    swap on little-endian, truncation or no-op on big-endian
	 */

	bool alu64 = BPF_CLASS(insn->code) == BPF_ALU64;
	bool to_le = BPF_SRC(insn->code) == BPF_TO_LE;
	bool is_big_endian;
#ifdef CONFIG_CPU_BIG_ENDIAN
	is_big_endian = true;
#else
	is_big_endian = false;
#endif
	/* Apply bswap if alu64 or switch between big-endian and little-endian machines */
	bool need_bswap = alu64 || (to_le == is_big_endian);

	/*
	 * If the register is mutated, manually reset its scalar ID to break
	 * any existing ties and avoid incorrect bounds propagation.
	 */
	if (need_bswap || insn->imm == 16 || insn->imm == 32)
		dst_reg->id = 0;

	if (need_bswap) {
		if (insn->imm == 16)
			dst_reg->var_off = tnum_bswap16(dst_reg->var_off);
		else if (insn->imm == 32)
			dst_reg->var_off = tnum_bswap32(dst_reg->var_off);
		else if (insn->imm == 64)
			dst_reg->var_off = tnum_bswap64(dst_reg->var_off);
		/*
		 * Byteswap scrambles the range, so we must reset bounds.
		 * Bounds will be re-derived from the new tnum later.
		 */
		__mark_reg_unbounded(dst_reg);
	}
	/* For bswap16/32, truncate dst register to match the swapped size */
	if (insn->imm == 16 || insn->imm == 32)
		coerce_reg_to_size(dst_reg, insn->imm / 8);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_add(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	s64 *dst_smin = &dst_reg->smin_value;
	s64 *dst_smax = &dst_reg->smax_value;
	u64 *dst_umin = &dst_reg->umin_value;
	u64 *dst_umax = &dst_reg->umax_value;
	u64 umin_val = src_reg->umin_value;
	u64 umax_val = src_reg->umax_value;
	bool min_overflow, max_overflow;

	if (check_add_overflow(*dst_smin, src_reg->smin_value, dst_smin) ||
	    check_add_overflow(*dst_smax, src_reg->smax_value, dst_smax)) {
		*dst_smin = S64_MIN;
		*dst_smax = S64_MAX;
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
		*dst_umax = U64_MAX;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_and(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_is_const(src_reg->var_off);
	bool dst_known = tnum_is_const(dst_reg->var_off);
	u64 umax_val = src_reg->umax_value;

	if (src_known && dst_known) {
		__mark_reg_known(dst_reg, dst_reg->var_off.value);
		return;
	}

	/* We get our minimum from the var_off, since that's inherently
	 * bitwise.  Our maximum is the minimum of the operands' maxima.
	 */
	dst_reg->umin_value = dst_reg->var_off.value;
	dst_reg->umax_value = min(dst_reg->umax_value, umax_val);

	/* Safe to set s64 bounds by casting u64 result into s64 when u64
	 * doesn't cross sign boundary. Otherwise set s64 bounds to unbounded.
	 */
	if ((s64)dst_reg->umin_value <= (s64)dst_reg->umax_value) {
		dst_reg->smin_value = dst_reg->umin_value;
		dst_reg->smax_value = dst_reg->umax_value;
	} else {
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
	}
	/* We may learn something more from the var_off */
	__update_reg_bounds(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_arsh(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	u64 umin_val = src_reg->umin_value;

	/* Upon reaching here, src_known is true and umax_val is equal
	 * to umin_val.
	 */
	dst_reg->smin_value >>= umin_val;
	dst_reg->smax_value >>= umin_val;

	dst_reg->var_off = tnum_arshift(dst_reg->var_off, umin_val, 64);

	/* blow away the dst_reg umin_value/umax_value and rely on
	 * dst_reg var_off to refine the result.
	 */
	dst_reg->umin_value = 0;
	dst_reg->umax_value = U64_MAX;

	/* Its not easy to operate on alu32 bounds here because it depends
	 * on bits being shifted in from upper 32-bits. Take easy way out
	 * and mark unbounded so we can recalculate later from tnum.
	 */
	__mark_reg32_unbounded(dst_reg);
	__update_reg_bounds(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_lsh(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	u64 umax_val = src_reg->umax_value;
	u64 umin_val = src_reg->umin_value;

	/* scalar64 calc uses 32bit unshifted bounds so must be called first */
	__scalar64_min_max_lsh(dst_reg, umin_val, umax_val);
	__scalar32_min_max_lsh(dst_reg, umin_val, umax_val);

	dst_reg->var_off = tnum_lshift(dst_reg->var_off, umin_val);
	/* We may learn something more from the var_off */
	__update_reg_bounds(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_mul(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	s64 *dst_smin = &dst_reg->smin_value;
	s64 *dst_smax = &dst_reg->smax_value;
	u64 *dst_umin = &dst_reg->umin_value;
	u64 *dst_umax = &dst_reg->umax_value;
	s64 tmp_prod[4];

	if (check_mul_overflow(*dst_umax, src_reg->umax_value, dst_umax) ||
	    check_mul_overflow(*dst_umin, src_reg->umin_value, dst_umin)) {
		/* Overflow possible, we know nothing */
		*dst_umin = 0;
		*dst_umax = U64_MAX;
	}
	if (check_mul_overflow(*dst_smin, src_reg->smin_value, &tmp_prod[0]) ||
	    check_mul_overflow(*dst_smin, src_reg->smax_value, &tmp_prod[1]) ||
	    check_mul_overflow(*dst_smax, src_reg->smin_value, &tmp_prod[2]) ||
	    check_mul_overflow(*dst_smax, src_reg->smax_value, &tmp_prod[3])) {
		/* Overflow possible, we know nothing */
		*dst_smin = S64_MIN;
		*dst_smax = S64_MAX;
	} else {
		*dst_smin = min_array(tmp_prod, 4);
		*dst_smax = max_array(tmp_prod, 4);
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_or(struct bpf_reg_state *dst_reg,
			      struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_is_const(src_reg->var_off);
	bool dst_known = tnum_is_const(dst_reg->var_off);
	u64 umin_val = src_reg->umin_value;

	if (src_known && dst_known) {
		__mark_reg_known(dst_reg, dst_reg->var_off.value);
		return;
	}

	/* We get our maximum from the var_off, and our minimum is the
	 * maximum of the operands' minima
	 */
	dst_reg->umin_value = max(dst_reg->umin_value, umin_val);
	dst_reg->umax_value = dst_reg->var_off.value | dst_reg->var_off.mask;

	/* Safe to set s64 bounds by casting u64 result into s64 when u64
	 * doesn't cross sign boundary. Otherwise set s64 bounds to unbounded.
	 */
	if ((s64)dst_reg->umin_value <= (s64)dst_reg->umax_value) {
		dst_reg->smin_value = dst_reg->umin_value;
		dst_reg->smax_value = dst_reg->umax_value;
	} else {
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
	}
	/* We may learn something more from the var_off */
	__update_reg_bounds(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_rsh(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	u64 umax_val = src_reg->umax_value;
	u64 umin_val = src_reg->umin_value;

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
	dst_reg->smin_value = S64_MIN;
	dst_reg->smax_value = S64_MAX;
	dst_reg->var_off = tnum_rshift(dst_reg->var_off, umin_val);
	dst_reg->umin_value >>= umax_val;
	dst_reg->umax_value >>= umin_val;

	/* Its not easy to operate on alu32 bounds here because it depends
	 * on bits being shifted in. Take easy way out and mark unbounded
	 * so we can recalculate later from tnum.
	 */
	__mark_reg32_unbounded(dst_reg);
	__update_reg_bounds(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_sdiv(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	s64 *dst_smin = &dst_reg->smin_value;
	s64 *dst_smax = &dst_reg->smax_value;
	s64 src_val = src_reg->smin_value; /* non-zero, const divisor */
	s64 res1, res2;

	/* BPF div specification: S64_MIN / -1 = S64_MIN */
	if (*dst_smin == S64_MIN && src_val == -1) {
		/*
		 * If the dividend range contains more than just S64_MIN,
		 * we cannot precisely track the result, so it becomes unbounded.
		 * e.g., [S64_MIN, S64_MIN+10]/(-1),
		 *     = {S64_MIN} U [-(S64_MIN+10), -(S64_MIN+1)]
		 *     = {S64_MIN} U [S64_MAX-9, S64_MAX] = [S64_MIN, S64_MAX]
		 * Otherwise (if dividend is exactly S64_MIN), result remains S64_MIN.
		 */
		if (*dst_smax != S64_MIN) {
			*dst_smin = S64_MIN;
			*dst_smax = S64_MAX;
		}
		goto reset;
	}

	res1 = div64_s64(*dst_smin, src_val);
	res2 = div64_s64(*dst_smax, src_val);
	*dst_smin = min(res1, res2);
	*dst_smax = max(res1, res2);

reset:
	/* Reset other ranges/tnum to unbounded/unknown. */
	dst_reg->umin_value = 0;
	dst_reg->umax_value = U64_MAX;
	reset_reg32_and_tnum(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_smod(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	s64 *dst_smin = &dst_reg->smin_value;
	s64 *dst_smax = &dst_reg->smax_value;
	s64 src_val = src_reg->smin_value; /* non-zero, const divisor */

	/*
	 * Safe absolute value calculation:
	 * If src_val == S64_MIN (-2^63), src_abs becomes 2^63.
	 * Here use unsigned integer to avoid overflow.
	 */
	u64 src_abs = (src_val > 0) ? (u64)src_val : -(u64)src_val;

	/*
	 * Calculate the maximum possible absolute value of the result.
	 * Even if src_abs is 2^63 (S64_MIN), subtracting 1 gives
	 * 2^63 - 1 (S64_MAX), which fits perfectly in s64.
	 */
	s64 res_max_abs = src_abs - 1;

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
	dst_reg->umin_value = 0;
	dst_reg->umax_value = U64_MAX;
	reset_reg32_and_tnum(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_sub(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	s64 *dst_smin = &dst_reg->smin_value;
	s64 *dst_smax = &dst_reg->smax_value;
	u64 *dst_umin = &dst_reg->umin_value;
	u64 *dst_umax = &dst_reg->umax_value;
	u64 umin_val = src_reg->umin_value;
	u64 umax_val = src_reg->umax_value;
	bool min_underflow, max_underflow;

	if (check_sub_overflow(*dst_smin, src_reg->smax_value, dst_smin) ||
	    check_sub_overflow(*dst_smax, src_reg->smin_value, dst_smax)) {
		/* Overflow possible, we know nothing */
		*dst_smin = S64_MIN;
		*dst_smax = S64_MAX;
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
		*dst_umax = U64_MAX;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_udiv(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	u64 *dst_umin = &dst_reg->umin_value;
	u64 *dst_umax = &dst_reg->umax_value;
	u64 src_val = src_reg->umin_value; /* non-zero, const divisor */

	*dst_umin = div64_u64(*dst_umin, src_val);
	*dst_umax = div64_u64(*dst_umax, src_val);

	/* Reset other ranges/tnum to unbounded/unknown. */
	dst_reg->smin_value = S64_MIN;
	dst_reg->smax_value = S64_MAX;
	reset_reg32_and_tnum(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_umod(struct bpf_reg_state *dst_reg,
				struct bpf_reg_state *src_reg)
{
	u64 *dst_umin = &dst_reg->umin_value;
	u64 *dst_umax = &dst_reg->umax_value;
	u64 src_val = src_reg->umin_value; /* non-zero, const divisor */
	u64 res_max = src_val - 1;

	/*
	 * If dst_umax <= res_max, the result remains unchanged.
	 * e.g., [2, 5] % 10 = [2, 5].
	 */
	if (*dst_umax <= res_max)
		return;

	*dst_umin = 0;
	*dst_umax = min(*dst_umax, res_max);

	/* Reset other ranges/tnum to unbounded/unknown. */
	dst_reg->smin_value = S64_MIN;
	dst_reg->smax_value = S64_MAX;
	reset_reg32_and_tnum(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scalar_min_max_xor(struct bpf_reg_state *dst_reg,
			       struct bpf_reg_state *src_reg)
{
	bool src_known = tnum_is_const(src_reg->var_off);
	bool dst_known = tnum_is_const(dst_reg->var_off);

	if (src_known && dst_known) {
		/* dst_reg->var_off.value has been updated earlier */
		__mark_reg_known(dst_reg, dst_reg->var_off.value);
		return;
	}

	/* We get both minimum and maximum from the var_off. */
	dst_reg->umin_value = dst_reg->var_off.value;
	dst_reg->umax_value = dst_reg->var_off.value | dst_reg->var_off.mask;

	/* Safe to set s64 bounds by casting u64 result into s64 when u64
	 * doesn't cross sign boundary. Otherwise set s64 bounds to unbounded.
	 */
	if ((s64)dst_reg->umin_value <= (s64)dst_reg->umax_value) {
		dst_reg->smin_value = dst_reg->umin_value;
		dst_reg->smax_value = dst_reg->umax_value;
	} else {
		dst_reg->smin_value = S64_MIN;
		dst_reg->smax_value = S64_MAX;
	}

	__update_reg_bounds(dst_reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_reg_state *scalar_reg_for_stack(struct bpf_verifier_env *env,
						  struct bpf_stack_state *stack)
{
	if (is_spilled_scalar_reg64(stack))
		return &stack->spilled_ptr;

	if (is_stack_all_misc(env, stack))
		return &unbound_reg;

	return NULL;
}


