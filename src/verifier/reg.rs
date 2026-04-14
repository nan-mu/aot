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
	__mark_reg_unbounded(reg);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void reg_bounds_sync(struct bpf_reg_state *reg)
{
	/* We might have learned new bounds from the var_off. */
	__update_reg_bounds(reg);
	/* We might have learned something about the sign bit. */
	__reg_deduce_bounds(reg);
	__reg_deduce_bounds(reg);
	__reg_deduce_bounds(reg);
	/* We might have learned some bits from the bounds. */
	__reg_bound_offset(reg);
	/* Intersecting with the old var_off might have improved our bounds
	 * slightly, e.g. if umax was 0x7f...f and var_off was (0; 0xf...fc),
	 * then new var_off is (0; 0x7f...fc) which improves our umax.
	 */
	__update_reg_bounds(reg);
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


