// Extracted from /Users/nan/bs/aot/src/verifier.c
static int jit_subprogs(struct bpf_verifier_env *env)
{
	struct bpf_prog *prog = env->prog, **func, *tmp;
	int i, j, subprog_start, subprog_end = 0, len, subprog;
	struct bpf_map *map_ptr;
	struct bpf_insn *insn;
	void *old_bpf_func;
	int err, num_exentries;
	int old_len, subprog_start_adjustment = 0;

	if (env->subprog_cnt <= 1)
		return 0;

	for (i = 0, insn = prog->insnsi; i < prog->len; i++, insn++) {
		if (!bpf_pseudo_func(insn) && !bpf_pseudo_call(insn))
			continue;

		/* Upon error here we cannot fall back to interpreter but
		 * need a hard reject of the program. Thus -EFAULT is
		 * propagated in any case.
		 */
		subprog = find_subprog(env, i + insn->imm + 1);
		if (verifier_bug_if(subprog < 0, env, "No program to jit at insn %d",
				    i + insn->imm + 1))
			return -EFAULT;
		/* temporarily remember subprog id inside insn instead of
		 * aux_data, since next loop will split up all insns into funcs
		 */
		insn->off = subprog;
		/* remember original imm in case JIT fails and fallback
		 * to interpreter will be needed
		 */
		env->insn_aux_data[i].call_imm = insn->imm;
		/* point imm to __bpf_call_base+1 from JITs point of view */
		insn->imm = 1;
		if (bpf_pseudo_func(insn)) {
#if defined(MODULES_VADDR)
			u64 addr = MODULES_VADDR;
#else
			u64 addr = VMALLOC_START;
#endif
			/* jit (e.g. x86_64) may emit fewer instructions
			 * if it learns a u32 imm is the same as a u64 imm.
			 * Set close enough to possible prog address.
			 */
			insn[0].imm = (u32)addr;
			insn[1].imm = addr >> 32;
		}
	}

	err = bpf_prog_alloc_jited_linfo(prog);
	if (err)
		goto out_undo_insn;

	err = -ENOMEM;
	func = kzalloc_objs(prog, env->subprog_cnt);
	if (!func)
		goto out_undo_insn;

	for (i = 0; i < env->subprog_cnt; i++) {
		subprog_start = subprog_end;
		subprog_end = env->subprog_info[i + 1].start;

		len = subprog_end - subprog_start;
		/* bpf_prog_run() doesn't call subprogs directly,
		 * hence main prog stats include the runtime of subprogs.
		 * subprogs don't have IDs and not reachable via prog_get_next_id
		 * func[i]->stats will never be accessed and stays NULL
		 */
		func[i] = bpf_prog_alloc_no_stats(bpf_prog_size(len), GFP_USER);
		if (!func[i])
			goto out_free;
		memcpy(func[i]->insnsi, &prog->insnsi[subprog_start],
		       len * sizeof(struct bpf_insn));
		func[i]->type = prog->type;
		func[i]->len = len;
		if (bpf_prog_calc_tag(func[i]))
			goto out_free;
		func[i]->is_func = 1;
		func[i]->sleepable = prog->sleepable;
		func[i]->aux->func_idx = i;
		/* Below members will be freed only at prog->aux */
		func[i]->aux->btf = prog->aux->btf;
		func[i]->aux->subprog_start = subprog_start + subprog_start_adjustment;
		func[i]->aux->func_info = prog->aux->func_info;
		func[i]->aux->func_info_cnt = prog->aux->func_info_cnt;
		func[i]->aux->poke_tab = prog->aux->poke_tab;
		func[i]->aux->size_poke_tab = prog->aux->size_poke_tab;
		func[i]->aux->main_prog_aux = prog->aux;

		for (j = 0; j < prog->aux->size_poke_tab; j++) {
			struct bpf_jit_poke_descriptor *poke;

			poke = &prog->aux->poke_tab[j];
			if (poke->insn_idx < subprog_end &&
			    poke->insn_idx >= subprog_start)
				poke->aux = func[i]->aux;
		}

		func[i]->aux->name[0] = 'F';
		func[i]->aux->stack_depth = env->subprog_info[i].stack_depth;
		if (env->subprog_info[i].priv_stack_mode == PRIV_STACK_ADAPTIVE)
			func[i]->aux->jits_use_priv_stack = true;

		func[i]->jit_requested = 1;
		func[i]->blinding_requested = prog->blinding_requested;
		func[i]->aux->kfunc_tab = prog->aux->kfunc_tab;
		func[i]->aux->kfunc_btf_tab = prog->aux->kfunc_btf_tab;
		func[i]->aux->linfo = prog->aux->linfo;
		func[i]->aux->nr_linfo = prog->aux->nr_linfo;
		func[i]->aux->jited_linfo = prog->aux->jited_linfo;
		func[i]->aux->linfo_idx = env->subprog_info[i].linfo_idx;
		func[i]->aux->arena = prog->aux->arena;
		func[i]->aux->used_maps = env->used_maps;
		func[i]->aux->used_map_cnt = env->used_map_cnt;
		num_exentries = 0;
		insn = func[i]->insnsi;
		for (j = 0; j < func[i]->len; j++, insn++) {
			if (BPF_CLASS(insn->code) == BPF_LDX &&
			    (BPF_MODE(insn->code) == BPF_PROBE_MEM ||
			     BPF_MODE(insn->code) == BPF_PROBE_MEM32 ||
			     BPF_MODE(insn->code) == BPF_PROBE_MEM32SX ||
			     BPF_MODE(insn->code) == BPF_PROBE_MEMSX))
				num_exentries++;
			if ((BPF_CLASS(insn->code) == BPF_STX ||
			     BPF_CLASS(insn->code) == BPF_ST) &&
			     BPF_MODE(insn->code) == BPF_PROBE_MEM32)
				num_exentries++;
			if (BPF_CLASS(insn->code) == BPF_STX &&
			     BPF_MODE(insn->code) == BPF_PROBE_ATOMIC)
				num_exentries++;
		}
		func[i]->aux->num_exentries = num_exentries;
		func[i]->aux->tail_call_reachable = env->subprog_info[i].tail_call_reachable;
		func[i]->aux->exception_cb = env->subprog_info[i].is_exception_cb;
		func[i]->aux->changes_pkt_data = env->subprog_info[i].changes_pkt_data;
		func[i]->aux->might_sleep = env->subprog_info[i].might_sleep;
		if (!i)
			func[i]->aux->exception_boundary = env->seen_exception;

		/*
		 * To properly pass the absolute subprog start to jit
		 * all instruction adjustments should be accumulated
		 */
		old_len = func[i]->len;
		func[i] = bpf_int_jit_compile(func[i]);
		subprog_start_adjustment += func[i]->len - old_len;

		if (!func[i]->jited) {
			err = -ENOTSUPP;
			goto out_free;
		}
		cond_resched();
	}

	/* at this point all bpf functions were successfully JITed
	 * now populate all bpf_calls with correct addresses and
	 * run last pass of JIT
	 */
	for (i = 0; i < env->subprog_cnt; i++) {
		insn = func[i]->insnsi;
		for (j = 0; j < func[i]->len; j++, insn++) {
			if (bpf_pseudo_func(insn)) {
				subprog = insn->off;
				insn[0].imm = (u32)(long)func[subprog]->bpf_func;
				insn[1].imm = ((u64)(long)func[subprog]->bpf_func) >> 32;
				continue;
			}
			if (!bpf_pseudo_call(insn))
				continue;
			subprog = insn->off;
			insn->imm = BPF_CALL_IMM(func[subprog]->bpf_func);
		}

		/* we use the aux data to keep a list of the start addresses
		 * of the JITed images for each function in the program
		 *
		 * for some architectures, such as powerpc64, the imm field
		 * might not be large enough to hold the offset of the start
		 * address of the callee's JITed image from __bpf_call_base
		 *
		 * in such cases, we can lookup the start address of a callee
		 * by using its subprog id, available from the off field of
		 * the call instruction, as an index for this list
		 */
		func[i]->aux->func = func;
		func[i]->aux->func_cnt = env->subprog_cnt - env->hidden_subprog_cnt;
		func[i]->aux->real_func_cnt = env->subprog_cnt;
	}
	for (i = 0; i < env->subprog_cnt; i++) {
		old_bpf_func = func[i]->bpf_func;
		tmp = bpf_int_jit_compile(func[i]);
		if (tmp != func[i] || func[i]->bpf_func != old_bpf_func) {
			verbose(env, "JIT doesn't support bpf-to-bpf calls\n");
			err = -ENOTSUPP;
			goto out_free;
		}
		cond_resched();
	}

	/*
	 * Cleanup func[i]->aux fields which aren't required
	 * or can become invalid in future
	 */
	for (i = 0; i < env->subprog_cnt; i++) {
		func[i]->aux->used_maps = NULL;
		func[i]->aux->used_map_cnt = 0;
	}

	/* finally lock prog and jit images for all functions and
	 * populate kallsysm. Begin at the first subprogram, since
	 * bpf_prog_load will add the kallsyms for the main program.
	 */
	for (i = 1; i < env->subprog_cnt; i++) {
		err = bpf_prog_lock_ro(func[i]);
		if (err)
			goto out_free;
	}

	for (i = 1; i < env->subprog_cnt; i++)
		bpf_prog_kallsyms_add(func[i]);

	/* Last step: make now unused interpreter insns from main
	 * prog consistent for later dump requests, so they can
	 * later look the same as if they were interpreted only.
	 */
	for (i = 0, insn = prog->insnsi; i < prog->len; i++, insn++) {
		if (bpf_pseudo_func(insn)) {
			insn[0].imm = env->insn_aux_data[i].call_imm;
			insn[1].imm = insn->off;
			insn->off = 0;
			continue;
		}
		if (!bpf_pseudo_call(insn))
			continue;
		insn->off = env->insn_aux_data[i].call_imm;
		subprog = find_subprog(env, i + insn->off + 1);
		insn->imm = subprog;
	}

	prog->jited = 1;
	prog->bpf_func = func[0]->bpf_func;
	prog->jited_len = func[0]->jited_len;
	prog->aux->extable = func[0]->aux->extable;
	prog->aux->num_exentries = func[0]->aux->num_exentries;
	prog->aux->func = func;
	prog->aux->func_cnt = env->subprog_cnt - env->hidden_subprog_cnt;
	prog->aux->real_func_cnt = env->subprog_cnt;
	prog->aux->bpf_exception_cb = (void *)func[env->exception_callback_subprog]->bpf_func;
	prog->aux->exception_boundary = func[0]->aux->exception_boundary;
	bpf_prog_jit_attempt_done(prog);
	return 0;
out_free:
	/* We failed JIT'ing, so at this point we need to unregister poke
	 * descriptors from subprogs, so that kernel is not attempting to
	 * patch it anymore as we're freeing the subprog JIT memory.
	 */
	for (i = 0; i < prog->aux->size_poke_tab; i++) {
		map_ptr = prog->aux->poke_tab[i].tail_call.map;
		map_ptr->ops->map_poke_untrack(map_ptr, prog->aux);
	}
	/* At this point we're guaranteed that poke descriptors are not
	 * live anymore. We can just unlink its descriptor table as it's
	 * released with the main prog.
	 */
	for (i = 0; i < env->subprog_cnt; i++) {
		if (!func[i])
			continue;
		func[i]->aux->poke_tab = NULL;
		bpf_jit_free(func[i]);
	}
	kfree(func);
out_undo_insn:
	/* cleanup main prog to be interpreted */
	prog->jit_requested = 0;
	prog->blinding_requested = 0;
	for (i = 0, insn = prog->insnsi; i < prog->len; i++, insn++) {
		if (!bpf_pseudo_call(insn))
			continue;
		insn->off = 0;
		insn->imm = env->insn_aux_data[i].call_imm;
	}
	bpf_prog_jit_attempt_done(prog);
	return err;
}


