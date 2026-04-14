// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool subprog_is_exc_cb(struct bpf_verifier_env *env, int subprog)
{
	return subprog_info(env, subprog)->is_exception_cb;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool subprog_is_global(const struct bpf_verifier_env *env, int subprog)
{
	struct bpf_func_info_aux *aux = env->prog->aux->func_info_aux;

	return aux && aux[subprog].linkage == BTF_FUNC_GLOBAL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static const char *subprog_name(const struct bpf_verifier_env *env, int subprog)
{
	struct bpf_func_info *info;

	if (!env->prog->aux->func_info)
		return "";

	info = &env->prog->aux->func_info[subprog];
	return btf_type_name(env->prog->aux->btf, info->type_id);
}


