// Extracted from /Users/nan/bs/aot/src/verifier.c
static int reg_bounds_sanity_check(struct bpf_verifier_env *env,
				   struct bpf_reg_state *reg, const char *ctx)
{
	const char *msg;

	if (reg->umin_value > reg->umax_value ||
	    reg->smin_value > reg->smax_value ||
	    reg->u32_min_value > reg->u32_max_value ||
	    reg->s32_min_value > reg->s32_max_value) {
		    msg = "range bounds violation";
		    goto out;
	}

	if (tnum_is_const(reg->var_off)) {
		u64 uval = reg->var_off.value;
		s64 sval = (s64)uval;

		if (reg->umin_value != uval || reg->umax_value != uval ||
		    reg->smin_value != sval || reg->smax_value != sval) {
			msg = "const tnum out of sync with range bounds";
			goto out;
		}
	}

	if (tnum_subreg_is_const(reg->var_off)) {
		u32 uval32 = tnum_subreg(reg->var_off).value;
		s32 sval32 = (s32)uval32;

		if (reg->u32_min_value != uval32 || reg->u32_max_value != uval32 ||
		    reg->s32_min_value != sval32 || reg->s32_max_value != sval32) {
			msg = "const subreg tnum out of sync with range bounds";
			goto out;
		}
	}

	return 0;
out:
	verifier_bug(env, "REG INVARIANTS VIOLATION (%s): %s u64=[%#llx, %#llx] "
		     "s64=[%#llx, %#llx] u32=[%#x, %#x] s32=[%#x, %#x] var_off=(%#llx, %#llx)",
		     ctx, msg, reg->umin_value, reg->umax_value,
		     reg->smin_value, reg->smax_value,
		     reg->u32_min_value, reg->u32_max_value,
		     reg->s32_min_value, reg->s32_max_value,
		     reg->var_off.value, reg->var_off.mask);
	if (env->test_reg_invariants)
		return -EFAULT;
	inner_mark_reg_unbounded(reg);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void reg_bounds_sync(struct bpf_reg_state *reg)
{
	/* We might have learned new bounds from the var_off. */
	inner_update_reg_bounds(reg);
	/* We might have learned something about the sign bit. */
	inner_reg_deduce_bounds(reg);
	inner_reg_deduce_bounds(reg);
	inner_reg_deduce_bounds(reg);
	/* We might have learned some bits from the bounds. */
	inner_reg_bound_offset(reg);
	/* Intersecting with the old var_off might have improved our bounds
	 * slightly, e.g. if umax was 0x7f...f and var_off was (0; 0xf...fc),
	 * then new var_off is (0; 0x7f...fc) which improves our umax.
	 */
	inner_update_reg_bounds(reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct btf_record *reg_btf_record(const struct bpf_reg_state *reg)
{
	struct btf_record *rec = NULL;
	struct btf_struct_meta *meta;

	if (reg->type == PTR_TO_MAP_VALUE) {
		rec = reg->map_ptr->record;
	} else if (type_is_ptr_alloc_obj(reg->type)) {
		meta = btf_find_struct_meta(reg->btf, reg->btf_id);
		if (meta)
			rec = meta->record;
	}
	return rec;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static u64 reg_const_value(struct bpf_reg_state *reg, bool subreg32)
{
	return subreg32 ? tnum_subreg(reg->var_off).value : reg->var_off.value;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
reg_find_field_offset(const struct bpf_reg_state *reg, s32 off, u32 fields)
{
	struct btf_field *field;
	struct btf_record *rec;

	rec = reg_btf_record(reg);
	if (!rec)
		return NULL;

	field = btf_record_find(rec, off, fields);
	if (!field)
		return NULL;

	return field;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool reg_is_dynptr_slice_pkt(const struct bpf_reg_state *reg)
{
	return base_type(reg->type) == PTR_TO_MEM &&
	       (reg->type &
		(DYNPTR_TYPE_SKB | DYNPTR_TYPE_XDP | DYNPTR_TYPE_SKB_META));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool reg_is_init_pkt_pointer(const struct bpf_reg_state *reg,
				    enum bpf_reg_type which)
{
	/* The register can already have a range from prior markings.
	 * This is fine as long as it hasn't been advanced from its
	 * origin.
	 */
	return reg->type == which &&
	       reg->id == 0 &&
	       reg->off == 0 &&
	       tnum_equals_const(reg->var_off, 0);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool reg_is_pkt_pointer(const struct bpf_reg_state *reg)
{
	return type_is_pkt_pointer(reg->type);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool reg_is_pkt_pointer_any(const struct bpf_reg_state *reg)
{
	return reg_is_pkt_pointer(reg) ||
	       reg->type == PTR_TO_PACKET_END;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool reg_may_point_to_spin_lock(const struct bpf_reg_state *reg)
{
	return btf_record_has_field(reg_btf_record(reg), BPF_SPIN_LOCK | BPF_RES_SPIN_LOCK);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool reg_not_null(const struct bpf_reg_state *reg)
{
	enum bpf_reg_type type;

	type = reg->type;
	if (type_may_be_null(type))
		return false;

	type = base_type(type);
	return type == PTR_TO_SOCKET ||
		type == PTR_TO_TCP_SOCK ||
		type == PTR_TO_MAP_VALUE ||
		type == PTR_TO_MAP_KEY ||
		type == PTR_TO_SOCK_COMMON ||
		(type == PTR_TO_BTF_ID && is_trusted_reg(reg)) ||
		(type == PTR_TO_MEM && !(reg->type & PTR_UNTRUSTED)) ||
		type == CONST_PTR_TO_MAP;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int reg_set_min_max(struct bpf_verifier_env *env,
			   struct bpf_reg_state *true_reg1,
			   struct bpf_reg_state *true_reg2,
			   struct bpf_reg_state *false_reg1,
			   struct bpf_reg_state *false_reg2,
			   u8 opcode, bool is_jmp32)
{
	int err;

	/* If either register is a pointer, we can't learn anything about its
	 * variable offset from the compare (unless they were a pointer into
	 * the same object, but we don't bother with that).
	 */
	if (false_reg1->type != SCALAR_VALUE || false_reg2->type != SCALAR_VALUE)
		return 0;

	/* We compute branch direction for same SCALAR_VALUE registers in
	 * is_scalar_branch_taken(). For unknown branch directions (e.g., BPF_JSET)
	 * on the same registers, we don't need to adjust the min/max values.
	 */
	if (false_reg1 == false_reg2)
		return 0;

	/* fallthrough (FALSE) branch */
	regs_refine_cond_op(false_reg1, false_reg2, rev_opcode(opcode), is_jmp32);
	reg_bounds_sync(false_reg1);
	reg_bounds_sync(false_reg2);

	/* jump (TRUE) branch */
	regs_refine_cond_op(true_reg1, true_reg2, opcode, is_jmp32);
	reg_bounds_sync(true_reg1);
	reg_bounds_sync(true_reg2);

	err = reg_bounds_sanity_check(env, true_reg1, "true_reg1");
	err = err ?: reg_bounds_sanity_check(env, true_reg2, "true_reg2");
	err = err ?: reg_bounds_sanity_check(env, false_reg1, "false_reg1");
	err = err ?: reg_bounds_sanity_check(env, false_reg2, "false_reg2");
	return err;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_reg_state *reg_state(struct bpf_verifier_env *env, int regno)
{
	return cur_regs(env) + regno;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool reg_type_mismatch(enum bpf_reg_type src, enum bpf_reg_type prev)
{
	return src != prev && (!reg_type_mismatch_ok(src) ||
			       !reg_type_mismatch_ok(prev));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool reg_type_mismatch_ok(enum bpf_reg_type type)
{
	switch (base_type(type)) {
	case PTR_TO_CTX:
	case PTR_TO_SOCKET:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_TCP_SOCK:
	case PTR_TO_XDP_SOCK:
	case PTR_TO_BTF_ID:
	case PTR_TO_ARENA:
		return false;
	default:
		return true;
	}
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_reg_assign_32_into_64(struct bpf_reg_state *reg)
{
	reg->umin_value = reg->u32_min_value;
	reg->umax_value = reg->u32_max_value;

	/* Attempt to pull 32-bit signed bounds into 64-bit bounds but must
	 * be positive otherwise set to worse case bounds and refine later
	 * from tnum.
	 */
	if (inner_reg32_bound_s64(reg->s32_min_value) &&
	    inner_reg32_bound_s64(reg->s32_max_value)) {
		reg->smin_value = reg->s32_min_value;
		reg->smax_value = reg->s32_max_value;
	} else {
		reg->smin_value = 0;
		reg->smax_value = U32_MAX;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_reg_deduce_mixed_bounds(struct bpf_reg_state *reg)
{
	/* Try to tighten 64-bit bounds from 32-bit knowledge, using 32-bit
	 * values on both sides of 64-bit range in hope to have tighter range.
	 * E.g., if r1 is [0x1'00000000, 0x3'80000000], and we learn from
	 * 32-bit signed > 0 operation that s32 bounds are now [1; 0x7fffffff].
	 * With this, we can substitute 1 as low 32-bits of _low_ 64-bit bound
	 * (0x100000000 -> 0x100000001) and 0x7fffffff as low 32-bits of
	 * _high_ 64-bit bound (0x380000000 -> 0x37fffffff) and arrive at a
	 * better overall bounds for r1 as [0x1'000000001; 0x3'7fffffff].
	 * We just need to make sure that derived bounds we are intersecting
	 * with are well-formed ranges in respective s64 or u64 domain, just
	 * like we do with similar kinds of 32-to-64 or 64-to-32 adjustments.
	 */
	inner_u64 new_umin, new_umax;
	inner_s64 new_smin, new_smax;

	/* u32 -> u64 tightening, it's always well-formed */
	new_umin = (reg->umin_value & ~0xffffffffULL) | reg->u32_min_value;
	new_umax = (reg->umax_value & ~0xffffffffULL) | reg->u32_max_value;
	reg->umin_value = max_t(u64, reg->umin_value, new_umin);
	reg->umax_value = min_t(u64, reg->umax_value, new_umax);
	/* u32 -> s64 tightening, u32 range embedded into s64 preserves range validity */
	new_smin = (reg->smin_value & ~0xffffffffULL) | reg->u32_min_value;
	new_smax = (reg->smax_value & ~0xffffffffULL) | reg->u32_max_value;
	reg->smin_value = max_t(s64, reg->smin_value, new_smin);
	reg->smax_value = min_t(s64, reg->smax_value, new_smax);

	/* Here we would like to handle a special case after sign extending load,
	 * when upper bits for a 64-bit range are all 1s or all 0s.
	 *
	 * Upper bits are all 1s when register is in a range:
	 *   [0xffff_ffff_0000_0000, 0xffff_ffff_ffff_ffff]
	 * Upper bits are all 0s when register is in a range:
	 *   [0x0000_0000_0000_0000, 0x0000_0000_ffff_ffff]
	 * Together this forms are continuous range:
	 *   [0xffff_ffff_0000_0000, 0x0000_0000_ffff_ffff]
	 *
	 * Now, suppose that register range is in fact tighter:
	 *   [0xffff_ffff_8000_0000, 0x0000_0000_ffff_ffff] (R)
	 * Also suppose that it's 32-bit range is positive,
	 * meaning that lower 32-bits of the full 64-bit register
	 * are in the range:
	 *   [0x0000_0000, 0x7fff_ffff] (W)
	 *
	 * If this happens, then any value in a range:
	 *   [0xffff_ffff_0000_0000, 0xffff_ffff_7fff_ffff]
	 * is smaller than a lowest bound of the range (R):
	 *   0xffff_ffff_8000_0000
	 * which means that upper bits of the full 64-bit register
	 * can't be all 1s, when lower bits are in range (W).
	 *
	 * Note that:
	 *  - 0xffff_ffff_8000_0000 == (s64)S32_MIN
	 *  - 0x0000_0000_7fff_ffff == (s64)S32_MAX
	 * These relations are used in the conditions below.
	 */
	if (reg->s32_min_value >= 0 && reg->smin_value >= S32_MIN && reg->smax_value <= S32_MAX) {
		reg->smin_value = reg->s32_min_value;
		reg->smax_value = reg->s32_max_value;
		reg->umin_value = reg->s32_min_value;
		reg->umax_value = reg->s32_max_value;
		reg->var_off = tnum_intersect(reg->var_off,
					      tnum_range(reg->smin_value, reg->smax_value));
	}
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool inner_reg32_bound_s64(s32 a)
{
	return a >= 0 && a <= S32_MAX;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_reg32_deduce_bounds(struct bpf_reg_state *reg)
{
	/* If upper 32 bits of u64/s64 range don't change, we can use lower 32
	 * bits to improve our u32/s32 boundaries.
	 *
	 * E.g., the case where we have upper 32 bits as zero ([10, 20] in
	 * u64) is pretty trivial, it's obvious that in u32 we'll also have
	 * [10, 20] range. But this property holds for any 64-bit range as
	 * long as upper 32 bits in that entire range of values stay the same.
	 *
	 * E.g., u64 range [0x10000000A, 0x10000000F] ([4294967306, 4294967311]
	 * in decimal) has the same upper 32 bits throughout all the values in
	 * that range. As such, lower 32 bits form a valid [0xA, 0xF] ([10, 15])
	 * range.
	 *
	 * Note also, that [0xA, 0xF] is a valid range both in u32 and in s32,
	 * following the rules outlined below about u64/s64 correspondence
	 * (which equally applies to u32 vs s32 correspondence). In general it
	 * depends on actual hexadecimal values of 32-bit range. They can form
	 * only valid u32, or only valid s32 ranges in some cases.
	 *
	 * So we use all these insights to derive bounds for subregisters here.
	 */
	if ((reg->umin_value >> 32) == (reg->umax_value >> 32)) {
		/* u64 to u32 casting preserves validity of low 32 bits as
		 * a range, if upper 32 bits are the same
		 */
		reg->u32_min_value = max_t(u32, reg->u32_min_value, (u32)reg->umin_value);
		reg->u32_max_value = min_t(u32, reg->u32_max_value, (u32)reg->umax_value);

		if ((s32)reg->umin_value <= (s32)reg->umax_value) {
			reg->s32_min_value = max_t(s32, reg->s32_min_value, (s32)reg->umin_value);
			reg->s32_max_value = min_t(s32, reg->s32_max_value, (s32)reg->umax_value);
		}
	}
	if ((reg->smin_value >> 32) == (reg->smax_value >> 32)) {
		/* low 32 bits should form a proper u32 range */
		if ((u32)reg->smin_value <= (u32)reg->smax_value) {
			reg->u32_min_value = max_t(u32, reg->u32_min_value, (u32)reg->smin_value);
			reg->u32_max_value = min_t(u32, reg->u32_max_value, (u32)reg->smax_value);
		}
		/* low 32 bits should form a proper s32 range */
		if ((s32)reg->smin_value <= (s32)reg->smax_value) {
			reg->s32_min_value = max_t(s32, reg->s32_min_value, (s32)reg->smin_value);
			reg->s32_max_value = min_t(s32, reg->s32_max_value, (s32)reg->smax_value);
		}
	}
	/* Special case where upper bits form a small sequence of two
	 * sequential numbers (in 32-bit unsigned space, so 0xffffffff to
	 * 0x00000000 is also valid), while lower bits form a proper s32 range
	 * going from negative numbers to positive numbers. E.g., let's say we
	 * have s64 range [-1, 1] ([0xffffffffffffffff, 0x0000000000000001]).
	 * Possible s64 values are {-1, 0, 1} ({0xffffffffffffffff,
	 * 0x0000000000000000, 0x00000000000001}). Ignoring upper 32 bits,
	 * we still get a valid s32 range [-1, 1] ([0xffffffff, 0x00000001]).
	 * Note that it doesn't have to be 0xffffffff going to 0x00000000 in
	 * upper 32 bits. As a random example, s64 range
	 * [0xfffffff0fffffff0; 0xfffffff100000010], forms a valid s32 range
	 * [-16, 16] ([0xfffffff0; 0x00000010]) in its 32 bit subregister.
	 */
	if ((u32)(reg->umin_value >> 32) + 1 == (u32)(reg->umax_value >> 32) &&
	    (s32)reg->umin_value < 0 && (s32)reg->umax_value >= 0) {
		reg->s32_min_value = max_t(s32, reg->s32_min_value, (s32)reg->umin_value);
		reg->s32_max_value = min_t(s32, reg->s32_max_value, (s32)reg->umax_value);
	}
	if ((u32)(reg->smin_value >> 32) + 1 == (u32)(reg->smax_value >> 32) &&
	    (s32)reg->smin_value < 0 && (s32)reg->smax_value >= 0) {
		reg->s32_min_value = max_t(s32, reg->s32_min_value, (s32)reg->smin_value);
		reg->s32_max_value = min_t(s32, reg->s32_max_value, (s32)reg->smax_value);
	}
	/* if u32 range forms a valid s32 range (due to matching sign bit),
	 * try to learn from that
	 */
	if ((s32)reg->u32_min_value <= (s32)reg->u32_max_value) {
		reg->s32_min_value = max_t(s32, reg->s32_min_value, reg->u32_min_value);
		reg->s32_max_value = min_t(s32, reg->s32_max_value, reg->u32_max_value);
	}
	/* If we cannot cross the sign boundary, then signed and unsigned bounds
	 * are the same, so combine.  This works even in the negative case, e.g.
	 * -3 s<= x s<= -1 implies 0xf...fd u<= x u<= 0xf...ff.
	 */
	if ((u32)reg->s32_min_value <= (u32)reg->s32_max_value) {
		reg->u32_min_value = max_t(u32, reg->s32_min_value, reg->u32_min_value);
		reg->u32_max_value = min_t(u32, reg->s32_max_value, reg->u32_max_value);
	} else {
		if (reg->u32_max_value < (u32)reg->s32_min_value) {
			/* See inner_reg64_deduce_bounds() for detailed explanation.
			 * Refine ranges in the following situation:
			 *
			 * 0                                                   U32_MAX
			 * |  [xxxxxxxxxxxxxx u32 range xxxxxxxxxxxxxx]              |
			 * |----------------------------|----------------------------|
			 * |xxxxx s32 range xxxxxxxxx]                       [xxxxxxx|
			 * 0                     S32_MAX S32_MIN                    -1
			 */
			reg->s32_min_value = (s32)reg->u32_min_value;
			reg->u32_max_value = min_t(u32, reg->u32_max_value, reg->s32_max_value);
		} else if ((u32)reg->s32_max_value < reg->u32_min_value) {
			/*
			 * 0                                                   U32_MAX
			 * |              [xxxxxxxxxxxxxx u32 range xxxxxxxxxxxxxx]  |
			 * |----------------------------|----------------------------|
			 * |xxxxxxxxx]                       [xxxxxxxxxxxx s32 range |
			 * 0                     S32_MAX S32_MIN                    -1
			 */
			reg->s32_max_value = (s32)reg->u32_max_value;
			reg->u32_min_value = max_t(u32, reg->u32_min_value, reg->s32_min_value);
		}
	}
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_reg64_deduce_bounds(struct bpf_reg_state *reg)
{
	/* If u64 range forms a valid s64 range (due to matching sign bit),
	 * try to learn from that. Let's do a bit of ASCII art to see when
	 * this is happening. Let's take u64 range first:
	 *
	 * 0             0x7fffffffffffffff 0x8000000000000000        U64_MAX
	 * |-------------------------------|--------------------------------|
	 *
	 * Valid u64 range is formed when umin and umax are anywhere in the
	 * range [0, U64_MAX], and umin <= umax. u64 case is simple and
	 * straightforward. Let's see how s64 range maps onto the same range
	 * of values, annotated below the line for comparison:
	 *
	 * 0             0x7fffffffffffffff 0x8000000000000000        U64_MAX
	 * |-------------------------------|--------------------------------|
	 * 0                        S64_MAX S64_MIN                        -1
	 *
	 * So s64 values basically start in the middle and they are logically
	 * contiguous to the right of it, wrapping around from -1 to 0, and
	 * then finishing as S64_MAX (0x7fffffffffffffff) right before
	 * S64_MIN. We can try drawing the continuity of u64 vs s64 values
	 * more visually as mapped to sign-agnostic range of hex values.
	 *
	 *  u64 start                                               u64 end
	 *  iinner_____________________________________________________________
	 * /                                                               \
	 * 0             0x7fffffffffffffff 0x8000000000000000        U64_MAX
	 * |-------------------------------|--------------------------------|
	 * 0                        S64_MAX S64_MIN                        -1
	 *                                / \
	 * >------------------------------   ------------------------------->
	 * s64 continues...        s64 end   s64 start          s64 "midpoint"
	 *
	 * What this means is that, in general, we can't always derive
	 * something new about u64 from any random s64 range, and vice versa.
	 *
	 * But we can do that in two particular cases. One is when entire
	 * u64/s64 range is *entirely* contained within left half of the above
	 * diagram or when it is *entirely* contained in the right half. I.e.:
	 *
	 * |-------------------------------|--------------------------------|
	 *     ^                   ^            ^                 ^
	 *     A                   B            C                 D
	 *
	 * [A, B] and [C, D] are contained entirely in their respective halves
	 * and form valid contiguous ranges as both u64 and s64 values. [A, B]
	 * will be non-negative both as u64 and s64 (and in fact it will be
	 * identical ranges no matter the signedness). [C, D] treated as s64
	 * will be a range of negative values, while in u64 it will be
	 * non-negative range of values larger than 0x8000000000000000.
	 *
	 * Now, any other range here can't be represented in both u64 and s64
	 * simultaneously. E.g., [A, C], [A, D], [B, C], [B, D] are valid
	 * contiguous u64 ranges, but they are discontinuous in s64. [B, C]
	 * in s64 would be properly presented as [S64_MIN, C] and [B, S64_MAX],
	 * for example. Similarly, valid s64 range [D, A] (going from negative
	 * to positive values), would be two separate [D, U64_MAX] and [0, A]
	 * ranges as u64. Currently reg_state can't represent two segments per
	 * numeric domain, so in such situations we can only derive maximal
	 * possible range ([0, U64_MAX] for u64, and [S64_MIN, S64_MAX] for s64).
	 *
	 * So we use these facts to derive umin/umax from smin/smax and vice
	 * versa only if they stay within the same "half". This is equivalent
	 * to checking sign bit: lower half will have sign bit as zero, upper
	 * half have sign bit 1. Below in code we simplify this by just
	 * casting umin/umax as smin/smax and checking if they form valid
	 * range, and vice versa. Those are equivalent checks.
	 */
	if ((s64)reg->umin_value <= (s64)reg->umax_value) {
		reg->smin_value = max_t(s64, reg->smin_value, reg->umin_value);
		reg->smax_value = min_t(s64, reg->smax_value, reg->umax_value);
	}
	/* If we cannot cross the sign boundary, then signed and unsigned bounds
	 * are the same, so combine.  This works even in the negative case, e.g.
	 * -3 s<= x s<= -1 implies 0xf...fd u<= x u<= 0xf...ff.
	 */
	if ((u64)reg->smin_value <= (u64)reg->smax_value) {
		reg->umin_value = max_t(u64, reg->smin_value, reg->umin_value);
		reg->umax_value = min_t(u64, reg->smax_value, reg->umax_value);
	} else {
		/* If the s64 range crosses the sign boundary, then it's split
		 * between the beginning and end of the U64 domain. In that
		 * case, we can derive new bounds if the u64 range overlaps
		 * with only one end of the s64 range.
		 *
		 * In the following example, the u64 range overlaps only with
		 * positive portion of the s64 range.
		 *
		 * 0                                                   U64_MAX
		 * |  [xxxxxxxxxxxxxx u64 range xxxxxxxxxxxxxx]              |
		 * |----------------------------|----------------------------|
		 * |xxxxx s64 range xxxxxxxxx]                       [xxxxxxx|
		 * 0                     S64_MAX S64_MIN                    -1
		 *
		 * We can thus derive the following new s64 and u64 ranges.
		 *
		 * 0                                                   U64_MAX
		 * |  [xxxxxx u64 range xxxxx]                               |
		 * |----------------------------|----------------------------|
		 * |  [xxxxxx s64 range xxxxx]                               |
		 * 0                     S64_MAX S64_MIN                    -1
		 *
		 * If they overlap in two places, we can't derive anything
		 * because reg_state can't represent two ranges per numeric
		 * domain.
		 *
		 * 0                                                   U64_MAX
		 * |  [xxxxxxxxxxxxxxxxx u64 range xxxxxxxxxxxxxxxxx]        |
		 * |----------------------------|----------------------------|
		 * |xxxxx s64 range xxxxxxxxx]                    [xxxxxxxxxx|
		 * 0                     S64_MAX S64_MIN                    -1
		 *
		 * The first condition below corresponds to the first diagram
		 * above.
		 */
		if (reg->umax_value < (u64)reg->smin_value) {
			reg->smin_value = (s64)reg->umin_value;
			reg->umax_value = min_t(u64, reg->umax_value, reg->smax_value);
		} else if ((u64)reg->smax_value < reg->umin_value) {
			/* This second condition considers the case where the u64 range
			 * overlaps with the negative portion of the s64 range:
			 *
			 * 0                                                   U64_MAX
			 * |              [xxxxxxxxxxxxxx u64 range xxxxxxxxxxxxxx]  |
			 * |----------------------------|----------------------------|
			 * |xxxxxxxxx]                       [xxxxxxxxxxxx s64 range |
			 * 0                     S64_MAX S64_MIN                    -1
			 */
			reg->smax_value = (s64)reg->umax_value;
			reg->umin_value = max_t(u64, reg->umin_value, reg->smin_value);
		}
	}
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_reg_bound_offset(struct bpf_reg_state *reg)
{
	struct tnum var64_off = tnum_intersect(reg->var_off,
					       tnum_range(reg->umin_value,
							  reg->umax_value));
	struct tnum var32_off = tnum_intersect(tnum_subreg(var64_off),
					       tnum_range(reg->u32_min_value,
							  reg->u32_max_value));

	reg->var_off = tnum_or(tnum_clear_subreg(var64_off), var32_off);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_reg_deduce_bounds(struct bpf_reg_state *reg)
{
	inner_reg32_deduce_bounds(reg);
	inner_reg64_deduce_bounds(reg);
	inner_reg_deduce_mixed_bounds(reg);
}
