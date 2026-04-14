// Extracted from /Users/nan/bs/aot/src/verifier.c
static int fetch_kfunc_arg_meta(struct bpf_verifier_env *env,
				s32 func_id,
				s16 offset,
				struct bpf_kfunc_call_arg_meta *meta)
{
	struct bpf_kfunc_meta kfunc;
	int err;

	err = fetch_kfunc_meta(env, func_id, offset, &kfunc);
	if (err)
		return err;

	memset(meta, 0, sizeof(*meta));
	meta->btf = kfunc.btf;
	meta->func_id = kfunc.id;
	meta->func_proto = kfunc.proto;
	meta->func_name = kfunc.name;

	if (!kfunc.flags || !btf_kfunc_is_allowed(kfunc.btf, kfunc.id, env->prog))
		return -EACCES;

	meta->kfunc_flags = *kfunc.flags;

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int fetch_kfunc_meta(struct bpf_verifier_env *env,
			    s32 func_id,
			    s16 offset,
			    struct bpf_kfunc_meta *kfunc)
{
	const struct btf_type *func, *func_proto;
	const char *func_name;
	u32 *kfunc_flags;
	struct btf *btf;

	if (func_id <= 0) {
		verbose(env, "invalid kernel function btf_id %d\n", func_id);
		return -EINVAL;
	}

	btf = find_kfunc_desc_btf(env, offset);
	if (IS_ERR(btf)) {
		verbose(env, "failed to find BTF for kernel function\n");
		return PTR_ERR(btf);
	}

	/*
	 * Note that kfunc_flags may be NULL at this point, which
	 * means that we couldn't find func_id in any relevant
	 * kfunc_id_set. This most likely indicates an invalid kfunc
	 * call.  However we don't fail with an error here,
	 * and let the caller decide what to do with NULL kfunc->flags.
	 */
	kfunc_flags = btf_kfunc_flags(btf, func_id, env->prog);

	func = btf_type_by_id(btf, func_id);
	if (!func || !btf_type_is_func(func)) {
		verbose(env, "kernel btf_id %d is not a function\n", func_id);
		return -EINVAL;
	}

	func_name = btf_name_by_offset(btf, func->name_off);

	/*
	 * An actual prototype of a kfunc with KF_IMPLICIT_ARGS flag
	 * can be found through the counterpart _impl kfunc.
	 */
	if (kfunc_flags && (*kfunc_flags & KF_IMPLICIT_ARGS))
		func_proto = find_kfunc_impl_proto(env, btf, func_name);
	else
		func_proto = btf_type_by_id(btf, func->type);

	if (!func_proto || !btf_type_is_func_proto(func_proto)) {
		verbose(env, "kernel function btf_id %d does not have a valid func_proto\n",
			func_id);
		return -EINVAL;
	}

	memset(kfunc, 0, sizeof(*kfunc));
	kfunc->btf = btf;
	kfunc->id = func_id;
	kfunc->name = func_name;
	kfunc->proto = func_proto;
	kfunc->flags = kfunc_flags;

	return 0;
}


