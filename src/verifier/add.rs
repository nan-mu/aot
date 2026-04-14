// Extracted from /Users/nan/bs/aot/src/verifier.c
static int add_fd_from_fd_array(struct bpf_verifier_env *env, int fd)
{
	struct bpf_map *map;
	struct btf *btf;
	CLASS(fd, f)(fd);
	int err;

	map = __bpf_map_get(f);
	if (!IS_ERR(map)) {
		err = __add_used_map(env, map);
		if (err < 0)
			return err;
		return 0;
	}

	btf = __btf_get_by_fd(f);
	if (!IS_ERR(btf)) {
		btf_get(btf);
		return __add_used_btf(env, btf);
	}

	verbose(env, "fd %d is not pointing to valid bpf_map or btf\n", fd);
	return PTR_ERR(map);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int add_hidden_subprog(struct bpf_verifier_env *env, struct bpf_insn *patch, int len)
{
	struct bpf_subprog_info *info = env->subprog_info;
	int cnt = env->subprog_cnt;
	struct bpf_prog *prog;

	/* We only reserve one slot for hidden subprogs in subprog_info. */
	if (env->hidden_subprog_cnt) {
		verifier_bug(env, "only one hidden subprog supported");
		return -EFAULT;
	}
	/* We're not patching any existing instruction, just appending the new
	 * ones for the hidden subprog. Hence all of the adjustment operations
	 * in bpf_patch_insn_data are no-ops.
	 */
	prog = bpf_patch_insn_data(env, env->prog->len - 1, patch, len);
	if (!prog)
		return -ENOMEM;
	env->prog = prog;
	info[cnt + 1].start = info[cnt].start;
	info[cnt].start = prog->len - len + 1;
	env->subprog_cnt++;
	env->hidden_subprog_cnt++;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int add_kfunc_call(struct bpf_verifier_env *env, u32 func_id, s16 offset)
{
	struct bpf_kfunc_btf_tab *btf_tab;
	struct btf_func_model func_model;
	struct bpf_kfunc_desc_tab *tab;
	struct bpf_prog_aux *prog_aux;
	struct bpf_kfunc_meta kfunc;
	struct bpf_kfunc_desc *desc;
	unsigned long addr;
	int err;

	prog_aux = env->prog->aux;
	tab = prog_aux->kfunc_tab;
	btf_tab = prog_aux->kfunc_btf_tab;
	if (!tab) {
		if (!btf_vmlinux) {
			verbose(env, "calling kernel function is not supported without CONFIG_DEBUG_INFO_BTF\n");
			return -ENOTSUPP;
		}

		if (!env->prog->jit_requested) {
			verbose(env, "JIT is required for calling kernel function\n");
			return -ENOTSUPP;
		}

		if (!bpf_jit_supports_kfunc_call()) {
			verbose(env, "JIT does not support calling kernel function\n");
			return -ENOTSUPP;
		}

		if (!env->prog->gpl_compatible) {
			verbose(env, "cannot call kernel function from non-GPL compatible program\n");
			return -EINVAL;
		}

		tab = kzalloc_obj(*tab, GFP_KERNEL_ACCOUNT);
		if (!tab)
			return -ENOMEM;
		prog_aux->kfunc_tab = tab;
	}

	/* func_id == 0 is always invalid, but instead of returning an error, be
	 * conservative and wait until the code elimination pass before returning
	 * error, so that invalid calls that get pruned out can be in BPF programs
	 * loaded from userspace.  It is also required that offset be untouched
	 * for such calls.
	 */
	if (!func_id && !offset)
		return 0;

	if (!btf_tab && offset) {
		btf_tab = kzalloc_obj(*btf_tab, GFP_KERNEL_ACCOUNT);
		if (!btf_tab)
			return -ENOMEM;
		prog_aux->kfunc_btf_tab = btf_tab;
	}

	if (find_kfunc_desc(env->prog, func_id, offset))
		return 0;

	if (tab->nr_descs == MAX_KFUNC_DESCS) {
		verbose(env, "too many different kernel function calls\n");
		return -E2BIG;
	}

	err = fetch_kfunc_meta(env, func_id, offset, &kfunc);
	if (err)
		return err;

	addr = kallsyms_lookup_name(kfunc.name);
	if (!addr) {
		verbose(env, "cannot find address for kernel function %s\n", kfunc.name);
		return -EINVAL;
	}

	if (bpf_dev_bound_kfunc_id(func_id)) {
		err = bpf_dev_bound_kfunc_check(&env->log, prog_aux);
		if (err)
			return err;
	}

	err = btf_distill_func_proto(&env->log, kfunc.btf, kfunc.proto, kfunc.name, &func_model);
	if (err)
		return err;

	desc = &tab->descs[tab->nr_descs++];
	desc->func_id = func_id;
	desc->offset = offset;
	desc->addr = addr;
	desc->func_model = func_model;
	sort(tab->descs, tab->nr_descs, sizeof(tab->descs[0]),
	     kfunc_desc_cmp_by_id_off, NULL);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int add_kfunc_in_insns(struct bpf_verifier_env *env,
			      struct bpf_insn *insn, int cnt)
{
	int i, ret;

	for (i = 0; i < cnt; i++, insn++) {
		if (bpf_pseudo_kfunc_call(insn)) {
			ret = add_kfunc_call(env, insn->imm, insn->off);
			if (ret < 0)
				return ret;
		}
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int add_scc_backedge(struct bpf_verifier_env *env,
			    struct bpf_verifier_state *st,
			    struct bpf_scc_backedge *backedge)
{
	struct bpf_scc_callchain *callchain = &env->callchain_buf;
	struct bpf_scc_visit *visit;

	if (!compute_scc_callchain(env, st, callchain)) {
		verifier_bug(env, "add backedge: no SCC in verification path, insn_idx %d",
			     st->insn_idx);
		return -EFAULT;
	}
	visit = scc_visit_lookup(env, callchain);
	if (!visit) {
		verifier_bug(env, "add backedge: no visit info for call chain %s",
			     format_callchain(env, callchain));
		return -EFAULT;
	}
	if (env->log.level & BPF_LOG_LEVEL2)
		verbose(env, "SCC backedge %s\n", format_callchain(env, callchain));
	backedge->next = visit->backedges;
	visit->backedges = backedge;
	visit->num_backedges++;
	env->num_backedges++;
	update_peak_states(env);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int add_subprog(struct bpf_verifier_env *env, int off)
{
	int insn_cnt = env->prog->len;
	int ret;

	if (off >= insn_cnt || off < 0) {
		verbose(env, "call to invalid destination\n");
		return -EINVAL;
	}
	ret = find_subprog(env, off);
	if (ret >= 0)
		return ret;
	if (env->subprog_cnt >= BPF_MAX_SUBPROGS) {
		verbose(env, "too many subprograms\n");
		return -E2BIG;
	}
	/* determine subprog starts. The end is one before the next starts */
	env->subprog_info[env->subprog_cnt++].start = off;
	sort(env->subprog_info, env->subprog_cnt,
	     sizeof(env->subprog_info[0]), cmp_subprogs, NULL);
	return env->subprog_cnt - 1;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int add_subprog_and_kfunc(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprog = env->subprog_info;
	int i, ret, insn_cnt = env->prog->len, ex_cb_insn;
	struct bpf_insn *insn = env->prog->insnsi;

	/* Add entry function. */
	ret = add_subprog(env, 0);
	if (ret)
		return ret;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (!bpf_pseudo_func(insn) && !bpf_pseudo_call(insn) &&
		    !bpf_pseudo_kfunc_call(insn))
			continue;

		if (!env->bpf_capable) {
			verbose(env, "loading/calling other bpf or kernel functions are allowed for CAP_BPF and CAP_SYS_ADMIN\n");
			return -EPERM;
		}

		if (bpf_pseudo_func(insn) || bpf_pseudo_call(insn))
			ret = add_subprog(env, i + insn->imm + 1);
		else
			ret = add_kfunc_call(env, insn->imm, insn->off);

		if (ret < 0)
			return ret;
	}

	ret = bpf_find_exception_callback_insn_off(env);
	if (ret < 0)
		return ret;
	ex_cb_insn = ret;

	/* If ex_cb_insn > 0, this means that the main program has a subprog
	 * marked using BTF decl tag to serve as the exception callback.
	 */
	if (ex_cb_insn) {
		ret = add_subprog(env, ex_cb_insn);
		if (ret < 0)
			return ret;
		for (i = 1; i < env->subprog_cnt; i++) {
			if (env->subprog_info[i].start != ex_cb_insn)
				continue;
			env->exception_callback_subprog = i;
			mark_subprog_exc_cb(env, i);
			break;
		}
	}

	/* Add a fake 'exit' subprog which could simplify subprog iteration
	 * logic. 'subprog_cnt' should not be increased.
	 */
	subprog[env->subprog_cnt].start = insn_cnt;

	if (env->log.level & BPF_LOG_LEVEL2)
		for (i = 0; i < env->subprog_cnt; i++)
			verbose(env, "func#%d @%d\n", i, subprog[i].start);

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int add_used_map(struct bpf_verifier_env *env, int fd)
{
	struct bpf_map *map;
	CLASS(fd, f)(fd);

	map = __bpf_map_get(f);
	if (IS_ERR(map)) {
		verbose(env, "fd %d is not pointing to valid bpf_map\n", fd);
		return PTR_ERR(map);
	}

	return __add_used_map(env, map);
}


