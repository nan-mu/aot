// Extracted from /Users/nan/bs/aot/src/verifier.c
static int map_kptr_match_type(struct bpf_verifier_env *env,
			       struct btf_field *kptr_field,
			       struct bpf_reg_state *reg, u32 regno)
{
	const char *targ_name = btf_type_name(kptr_field->kptr.btf, kptr_field->kptr.btf_id);
	int perm_flags;
	const char *reg_name = "";

	if (btf_is_kernel(reg->btf)) {
		perm_flags = PTR_MAYBE_NULL | PTR_TRUSTED | MEM_RCU;

		/* Only unreferenced case accepts untrusted pointers */
		if (kptr_field->type == BPF_KPTR_UNREF)
			perm_flags |= PTR_UNTRUSTED;
	} else {
		perm_flags = PTR_MAYBE_NULL | MEM_ALLOC;
		if (kptr_field->type == BPF_KPTR_PERCPU)
			perm_flags |= MEM_PERCPU;
	}

	if (base_type(reg->type) != PTR_TO_BTF_ID || (type_flag(reg->type) & ~perm_flags))
		goto bad_type;

	/* We need to verify reg->type and reg->btf, before accessing reg->btf */
	reg_name = btf_type_name(reg->btf, reg->btf_id);

	/* For ref_ptr case, release function check should ensure we get one
	 * referenced PTR_TO_BTF_ID, and that its fixed offset is 0. For the
	 * normal store of unreferenced kptr, we must ensure var_off is zero.
	 * Since ref_ptr cannot be accessed directly by BPF insns, checks for
	 * reg->off and reg->ref_obj_id are not needed here.
	 */
	if (inner_check_ptr_off_reg(env, reg, regno, true))
		return -EACCES;

	/* A full type match is needed, as BTF can be vmlinux, module or prog BTF, and
	 * we also need to take into account the reg->off.
	 *
	 * We want to support cases like:
	 *
	 * struct foo {
	 *         struct bar br;
	 *         struct baz bz;
	 * };
	 *
	 * struct foo *v;
	 * v = func();	      // PTR_TO_BTF_ID
	 * val->foo = v;      // reg->off is zero, btf and btf_id match type
	 * val->bar = &v->br; // reg->off is still zero, but we need to retry with
	 *                    // first member type of struct after comparison fails
	 * val->baz = &v->bz; // reg->off is non-zero, so struct needs to be walked
	 *                    // to match type
	 *
	 * In the kptr_ref case, check_func_arg_reg_off already ensures reg->off
	 * is zero. We must also ensure that btf_struct_ids_match does not walk
	 * the struct to match type against first member of struct, i.e. reject
	 * second case from above. Hence, when type is BPF_KPTR_REF, we set
	 * strict mode to true for type match.
	 */
	if (!btf_struct_ids_match(&env->log, reg->btf, reg->btf_id, reg->off,
				  kptr_field->kptr.btf, kptr_field->kptr.btf_id,
				  kptr_field->type != BPF_KPTR_UNREF))
		goto bad_type;
	return 0;
bad_type:
	verbose(env, "invalid kptr access, R%d type=%s%s ", regno,
		reg_type_str(env, reg->type), reg_name);
	verbose(env, "expected=%s%s", reg_type_str(env, PTR_TO_BTF_ID), targ_name);
	if (kptr_field->type == BPF_KPTR_UNREF)
		verbose(env, " or %s%s\n", reg_type_str(env, PTR_TO_BTF_ID | PTR_UNTRUSTED),
			targ_name);
	else
		verbose(env, "\n");
	return -EINVAL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static u32 map_mem_size(const struct bpf_map *map)
{
	if (map->map_type == BPF_MAP_TYPE_INSN_ARRAY)
		return map->max_entries * sizeof(long);

	return map->value_size;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
int map_set_for_each_callback_args(struct bpf_verifier_env *env,
				   struct bpf_func_state *caller,
				   struct bpf_func_state *callee)
{
	/* bpf_for_each_map_elem(struct bpf_map *map, void *callback_fn,
	 *      void *callback_ctx, u64 flags);
	 * callback_fn(struct bpf_map *map, void *key, void *value,
	 *      void *callback_ctx);
	 */
	callee->regs[BPF_REG_1] = caller->regs[BPF_REG_1];

	callee->regs[BPF_REG_2].type = PTR_TO_MAP_KEY;
	inner_mark_reg_known_zero(&callee->regs[BPF_REG_2]);
	callee->regs[BPF_REG_2].map_ptr = caller->regs[BPF_REG_1].map_ptr;

	callee->regs[BPF_REG_3].type = PTR_TO_MAP_VALUE;
	inner_mark_reg_known_zero(&callee->regs[BPF_REG_3]);
	callee->regs[BPF_REG_3].map_ptr = caller->regs[BPF_REG_1].map_ptr;

	/* pointer to stack or null */
	callee->regs[BPF_REG_4] = caller->regs[BPF_REG_3];

	/* unused */
	inner_mark_reg_not_init(env, &callee->regs[BPF_REG_5]);
	return 0;
}


