// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c
BTF_SET_START(btf_id_deny)
BTF_ID_UNUSED
#ifdef CONFIG_SMP
BTF_ID(func, ___migrate_enable)
BTF_ID(func, migrate_disable)
BTF_ID(func, migrate_enable)
#endif
#if !defined CONFIG_PREEMPT_RCU && !defined CONFIG_TINY_RCU
BTF_ID(func, rcu_read_unlock_strict)
#endif
#if defined(CONFIG_DEBUG_PREEMPT) || defined(CONFIG_TRACE_PREEMPT_TOGGLE)
BTF_ID(func, preempt_count_add)
BTF_ID(func, preempt_count_sub)
#endif
#ifdef CONFIG_PREEMPT_RCU
BTF_ID(func, __rcu_read_lock)
BTF_ID(func, __rcu_read_unlock)
#endif
BTF_SET_END(btf_id_deny)

/* fexit and fmod_ret can't be used to attach to __noreturn functions.
 * Currently, we must manually list all __noreturn functions here. Once a more
 * robust solution is implemented, this workaround can be removed.
 */
BTF_SET_START(noreturn_deny)
#ifdef CONFIG_IA32_EMULATION
BTF_ID(func, __ia32_sys_exit)
BTF_ID(func, __ia32_sys_exit_group)
#endif
#ifdef CONFIG_KUNIT
BTF_ID(func, __kunit_abort)
BTF_ID(func, kunit_try_catch_throw)
#endif
#ifdef CONFIG_MODULES
BTF_ID(func, __module_put_and_kthread_exit)
#endif
#ifdef CONFIG_X86_64
BTF_ID(func, __x64_sys_exit)
BTF_ID(func, __x64_sys_exit_group)
#endif
BTF_ID(func, do_exit)
BTF_ID(func, do_group_exit)
BTF_ID(func, kthread_complete_and_exit)
BTF_ID(func, make_task_dead)
BTF_SET_END(noreturn_deny)

static bool can_be_sleepable(struct bpf_prog *prog)
{
	if (prog->type == BPF_PROG_TYPE_TRACING) {
		switch (prog->expected_attach_type) {
		case BPF_TRACE_FENTRY:
		case BPF_TRACE_FEXIT:
		case BPF_MODIFY_RETURN:
		case BPF_TRACE_ITER:
		case BPF_TRACE_FSESSION:
			return true;
		default:
			return false;
		}
	}
	return prog->type == BPF_PROG_TYPE_LSM ||
	       prog->type == BPF_PROG_TYPE_KPROBE /* only for uprobes */ ||
	       prog->type == BPF_PROG_TYPE_STRUCT_OPS;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int btf_check_func_arg_match(struct bpf_verifier_env *env, int subprog,
				    const struct btf *btf,
				    struct bpf_reg_state *regs)
{
	struct bpf_subprog_info *sub = subprog_info(env, subprog);
	struct bpf_verifier_log *log = &env->log;
	u32 i;
	int ret;

	ret = btf_prepare_func_args(env, subprog);
	if (ret)
		return ret;

	/* check that BTF function arguments match actual types that the
	 * verifier sees.
	 */
	for (i = 0; i < sub->arg_cnt; i++) {
		u32 regno = i + 1;
		struct bpf_reg_state *reg = &regs[regno];
		struct bpf_subprog_arg_info *arg = &sub->args[i];

		if (arg->arg_type == ARG_ANYTHING) {
			if (reg->type != SCALAR_VALUE) {
				bpf_log(log, "R%d is not a scalar\n", regno);
				return -EINVAL;
			}
		} else if (arg->arg_type & PTR_UNTRUSTED) {
			/*
			 * Anything is allowed for untrusted arguments, as these are
			 * read-only and probe read instructions would protect against
			 * invalid memory access.
			 */
		} else if (arg->arg_type == ARG_PTR_TO_CTX) {
			ret = check_func_arg_reg_off(env, reg, regno, ARG_DONTCARE);
			if (ret < 0)
				return ret;
			/* If function expects ctx type in BTF check that caller
			 * is passing PTR_TO_CTX.
			 */
			if (reg->type != PTR_TO_CTX) {
				bpf_log(log, "arg#%d expects pointer to ctx\n", i);
				return -EINVAL;
			}
		} else if (base_type(arg->arg_type) == ARG_PTR_TO_MEM) {
			ret = check_func_arg_reg_off(env, reg, regno, ARG_DONTCARE);
			if (ret < 0)
				return ret;
			if (check_mem_reg(env, reg, regno, arg->mem_size))
				return -EINVAL;
			if (!(arg->arg_type & PTR_MAYBE_NULL) && (reg->type & PTR_MAYBE_NULL)) {
				bpf_log(log, "arg#%d is expected to be non-NULL\n", i);
				return -EINVAL;
			}
		} else if (base_type(arg->arg_type) == ARG_PTR_TO_ARENA) {
			/*
			 * Can pass any value and the kernel won't crash, but
			 * only PTR_TO_ARENA or SCALAR make sense. Everything
			 * else is a bug in the bpf program. Point it out to
			 * the user at the verification time instead of
			 * run-time debug nightmare.
			 */
			if (reg->type != PTR_TO_ARENA && reg->type != SCALAR_VALUE) {
				bpf_log(log, "R%d is not a pointer to arena or scalar.\n", regno);
				return -EINVAL;
			}
		} else if (arg->arg_type == (ARG_PTR_TO_DYNPTR | MEM_RDONLY)) {
			ret = check_func_arg_reg_off(env, reg, regno, ARG_PTR_TO_DYNPTR);
			if (ret)
				return ret;

			ret = process_dynptr_func(env, regno, -1, arg->arg_type, 0);
			if (ret)
				return ret;
		} else if (base_type(arg->arg_type) == ARG_PTR_TO_BTF_ID) {
			struct bpf_call_arg_meta meta;
			int err;

			if (register_is_null(reg) && type_may_be_null(arg->arg_type))
				continue;

			memset(&meta, 0, sizeof(meta)); /* leave func_id as zero */
			err = check_reg_type(env, regno, arg->arg_type, &arg->btf_id, &meta);
			err = err ?: check_func_arg_reg_off(env, reg, regno, arg->arg_type);
			if (err)
				return err;
		} else {
			verifier_bug(env, "unrecognized arg#%d type %d", i, arg->arg_type);
			return -EFAULT;
		}
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int btf_check_subprog_call(struct bpf_verifier_env *env, int subprog,
				  struct bpf_reg_state *regs)
{
	struct bpf_prog *prog = env->prog;
	struct btf *btf = prog->aux->btf;
	u32 btf_id;
	int err;

	if (!prog->aux->func_info)
		return -EINVAL;

	btf_id = prog->aux->func_info[subprog].type_id;
	if (!btf_id)
		return -EFAULT;

	if (prog->aux->func_info_aux[subprog].unreliable)
		return -EINVAL;

	err = btf_check_func_arg_match(env, subprog, btf, regs);
	/* Compiler optimizations can remove arguments from static functions
	 * or mismatched type can be passed into a global function.
	 * In such cases mark the function as unreliable from BTF point of view.
	 */
	if (err)
		prog->aux->func_info_aux[subprog].unreliable = true;
	return err;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static u32 btf_ld_kptr_type(struct bpf_verifier_env *env, struct btf_field *kptr_field)
{
	struct btf_record *rec;
	u32 ret;

	ret = PTR_MAYBE_NULL;
	if (rcu_safe_kptr(kptr_field) && in_rcu_cs(env)) {
		ret |= MEM_RCU;
		if (kptr_field->type == BPF_KPTR_PERCPU)
			ret |= MEM_PERCPU;
		else if (!btf_is_kernel(kptr_field->kptr.btf))
			ret |= MEM_ALLOC;

		rec = kptr_pointee_btf_record(kptr_field);
		if (rec && btf_record_has_field(rec, BPF_GRAPH_NODE))
			ret |= NON_OWN_REF;
	} else {
		ret |= PTR_UNTRUSTED;
	}

	return ret;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static const char *btf_type_name(const struct btf *btf, u32 id)
{
	return btf_name_by_offset(btf, btf_type_by_id(btf, id)->name_off);
}

static bool inner_btf_type_is_scalar_struct(struct bpf_verifier_env *env,
					const struct btf *btf,
					const struct btf_type *t, int rec)
{
	const struct btf_type *member_type;
	const struct btf_member *member;
	u32 i;

	if (!btf_type_is_struct(t))
		return false;

	for_each_member(i, t, member) {
		const struct btf_array *array;

		member_type = btf_type_skip_modifiers(btf, member->type, NULL);
		if (btf_type_is_struct(member_type)) {
			if (rec >= 3) {
				verbose(env, "max struct nesting depth exceeded\n");
				return false;
			}
			if (!inner_btf_type_is_scalar_struct(env, btf, member_type, rec + 1))
				return false;
			continue;
		}
		if (btf_type_is_array(member_type)) {
			array = btf_array(member_type);
			if (!array->nelems)
				return false;
			member_type = btf_type_skip_modifiers(btf, array->type, NULL);
			if (!btf_type_is_scalar(member_type))
				return false;
			continue;
		}
		if (!btf_type_is_scalar(member_type))
			return false;
	}
	return true;
}
