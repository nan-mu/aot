// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool regsafe(struct bpf_verifier_env *env, struct bpf_reg_state *rold,
		    struct bpf_reg_state *rcur, struct bpf_idmap *idmap,
		    enum exact_level exact)
{
	if (exact == EXACT)
		return regs_exact(rold, rcur, idmap);

	if (rold->type == NOT_INIT)
		/* explored state can't have used this */
		return true;

	/* Enforce that register types have to match exactly, including their
	 * modifiers (like PTR_MAYBE_NULL, MEM_RDONLY, etc), as a general
	 * rule.
	 *
	 * One can make a point that using a pointer register as unbounded
	 * SCALAR would be technically acceptable, but this could lead to
	 * pointer leaks because scalars are allowed to leak while pointers
	 * are not. We could make this safe in special cases if root is
	 * calling us, but it's probably not worth the hassle.
	 *
	 * Also, register types that are *not* MAYBE_NULL could technically be
	 * safe to use as their MAYBE_NULL variants (e.g., PTR_TO_MAP_VALUE
	 * is safe to be used as PTR_TO_MAP_VALUE_OR_NULL, provided both point
	 * to the same map).
	 * However, if the old MAYBE_NULL register then got NULL checked,
	 * doing so could have affected others with the same id, and we can't
	 * check for that because we lost the id when we converted to
	 * a non-MAYBE_NULL variant.
	 * So, as a general rule we don't allow mixing MAYBE_NULL and
	 * non-MAYBE_NULL registers as well.
	 */
	if (rold->type != rcur->type)
		return false;

	switch (base_type(rold->type)) {
	case SCALAR_VALUE:
		if (env->explore_alu_limits) {
			/* explore_alu_limits disables tnum_in() and range_within()
			 * logic and requires everything to be strict
			 */
			return memcmp(rold, rcur, offsetof(struct bpf_reg_state, id)) == 0 &&
			       check_scalar_ids(rold->id, rcur->id, idmap);
		}
		if (!rold->precise && exact == NOT_EXACT)
			return true;
		/*
		 * Linked register tracking uses rold->id to detect relationships.
		 * When rold->id == 0, the register is independent and any linking
		 * in rcur only adds constraints. When rold->id != 0, we must verify
		 * id mapping and (for BPF_ADD_CONST) offset consistency.
		 *
		 * +------------------+-----------+------------------+---------------+
		 * |                  | rold->id  | rold + ADD_CONST | rold->id == 0 |
		 * |------------------+-----------+------------------+---------------|
		 * | rcur->id         | range,ids | false            | range         |
		 * | rcur + ADD_CONST | false     | range,ids,off    | range         |
		 * | rcur->id == 0    | range,ids | false            | range         |
		 * +------------------+-----------+------------------+---------------+
		 *
		 * Why check_ids() for scalar registers?
		 *
		 * Consider the following BPF code:
		 *   1: r6 = ... unbound scalar, ID=a ...
		 *   2: r7 = ... unbound scalar, ID=b ...
		 *   3: if (r6 > r7) goto +1
		 *   4: r6 = r7
		 *   5: if (r6 > X) goto ...
		 *   6: ... memory operation using r7 ...
		 *
		 * First verification path is [1-6]:
		 * - at (4) same bpf_reg_state::id (b) would be assigned to r6 and r7;
		 * - at (5) r6 would be marked <= X, sync_linked_regs() would also mark
		 *   r7 <= X, because r6 and r7 share same id.
		 * Next verification path is [1-4, 6].
		 *
		 * Instruction (6) would be reached in two states:
		 *   I.  r6{.id=b}, r7{.id=b} via path 1-6;
		 *   II. r6{.id=a}, r7{.id=b} via path 1-4, 6.
		 *
		 * Use check_ids() to distinguish these states.
		 * ---
		 * Also verify that new value satisfies old value range knowledge.
		 */

		/*
		 * ADD_CONST flags must match exactly: BPF_ADD_CONST32 and
		 * BPF_ADD_CONST64 have different linking semantics in
		 * sync_linked_regs() (alu32 zero-extends, alu64 does not),
		 * so pruning across different flag types is unsafe.
		 */
		if (rold->id &&
		    (rold->id & BPF_ADD_CONST) != (rcur->id & BPF_ADD_CONST))
			return false;

		/* Both have offset linkage: offsets must match */
		if ((rold->id & BPF_ADD_CONST) && rold->off != rcur->off)
			return false;

		if (!check_scalar_ids(rold->id, rcur->id, idmap))
			return false;

		return range_within(rold, rcur) && tnum_in(rold->var_off, rcur->var_off);
	case PTR_TO_MAP_KEY:
	case PTR_TO_MAP_VALUE:
	case PTR_TO_MEM:
	case PTR_TO_BUF:
	case PTR_TO_TP_BUFFER:
		/* If the new min/max/var_off satisfy the old ones and
		 * everything else matches, we are OK.
		 */
		return memcmp(rold, rcur, offsetof(struct bpf_reg_state, var_off)) == 0 &&
		       range_within(rold, rcur) &&
		       tnum_in(rold->var_off, rcur->var_off) &&
		       check_ids(rold->id, rcur->id, idmap) &&
		       check_ids(rold->ref_obj_id, rcur->ref_obj_id, idmap);
	case PTR_TO_PACKET_META:
	case PTR_TO_PACKET:
		/* We must have at least as much range as the old ptr
		 * did, so that any accesses which were safe before are
		 * still safe.  This is true even if old range < old off,
		 * since someone could have accessed through (ptr - k), or
		 * even done ptr -= k in a register, to get a safe access.
		 */
		if (rold->range < 0 || rcur->range < 0) {
			/* special case for [BEYOND|AT]_PKT_END */
			if (rold->range != rcur->range)
				return false;
		} else if (rold->range > rcur->range) {
			return false;
		}
		/* If the offsets don't match, we can't trust our alignment;
		 * nor can we be sure that we won't fall out of range.
		 */
		if (rold->off != rcur->off)
			return false;
		/* id relations must be preserved */
		if (!check_ids(rold->id, rcur->id, idmap))
			return false;
		/* new val must satisfy old val knowledge */
		return range_within(rold, rcur) &&
		       tnum_in(rold->var_off, rcur->var_off);
	case PTR_TO_STACK:
		/* two stack pointers are equal only if they're pointing to
		 * the same stack frame, since fp-8 in foo != fp-8 in bar
		 */
		return regs_exact(rold, rcur, idmap) && rold->frameno == rcur->frameno;
	case PTR_TO_ARENA:
		return true;
	case PTR_TO_INSN:
		return memcmp(rold, rcur, offsetof(struct bpf_reg_state, var_off)) == 0 &&
			rold->off == rcur->off && range_within(rold, rcur) &&
			tnum_in(rold->var_off, rcur->var_off);
	default:
		return regs_exact(rold, rcur, idmap);
	}
}


