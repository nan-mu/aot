// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool type_is_rcu(struct bpf_verifier_env *env,
			struct bpf_reg_state *reg,
			const char *field_name, u32 btf_id)
{
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_RCU(struct task_struct));
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_RCU(struct cgroup));
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_RCU(struct css_set));
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_RCU(struct cgroup_subsys_state));

	return btf_nested_type_is_trusted(&env->log, reg, field_name, btf_id, "__safe_rcu");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool type_is_rcu_or_null(struct bpf_verifier_env *env,
				struct bpf_reg_state *reg,
				const char *field_name, u32 btf_id)
{
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_RCU_OR_NULL(struct mm_struct));
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_RCU_OR_NULL(struct sk_buff));
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_RCU_OR_NULL(struct request_sock));

	return btf_nested_type_is_trusted(&env->log, reg, field_name, btf_id, "__safe_rcu_or_null");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool type_is_rdonly_mem(u32 type)
{
	return type & MEM_RDONLY;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool type_is_trusted(struct bpf_verifier_env *env,
			    struct bpf_reg_state *reg,
			    const char *field_name, u32 btf_id)
{
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED(struct bpf_iter_meta));
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED(struct bpf_iter__task));
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED(struct linux_binprm));
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED(struct file));

	return btf_nested_type_is_trusted(&env->log, reg, field_name, btf_id, "__safe_trusted");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool type_is_trusted_or_null(struct bpf_verifier_env *env,
				    struct bpf_reg_state *reg,
				    const char *field_name, u32 btf_id)
{
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED_OR_NULL(struct socket));
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED_OR_NULL(struct dentry));
	BTF_TYPE_EMIT(BTF_TYPE_SAFE_TRUSTED_OR_NULL(struct vm_area_struct));

	return btf_nested_type_is_trusted(&env->log, reg, field_name, btf_id,
					  "__safe_trusted_or_null");
}


