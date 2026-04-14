// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_bpf_exit_full(struct bpf_verifier_env *env,
				 bool *do_print_state,
				 bool exception_exit)
{
	/* We must do check_reference_leak here before
	 * prepare_func_exit to handle the case when
	 * state->curframe > 0, it may be a callback function,
	 * for which reference_state must match caller reference
	 * state when it exits.
	 */
	int err = check_resource_leak(env, exception_exit,
				      exception_exit || !env->cur_state->curframe,
				      exception_exit ? "bpf_throw" :
				      "BPF_EXIT instruction in main prog");
	if (err)
		return err;

	/* The side effect of the prepare_func_exit which is
	 * being skipped is that it frees bpf_func_state.
	 * Typically, process_bpf_exit will only be hit with
	 * outermost exit. copy_verifier_state in pop_stack will
	 * handle freeing of any extra bpf_func_state left over
	 * from not processing all nested function exits. We
	 * also skip return code checks as they are not needed
	 * for exceptional exits.
	 */
	if (exception_exit)
		return PROCESS_BPF_EXIT;

	if (env->cur_state->curframe) {
		/* exit from nested function */
		err = prepare_func_exit(env, &env->insn_idx);
		if (err)
			return err;
		*do_print_state = true;
		return 0;
	}

	err = check_return_code(env, BPF_REG_0, "R0");
	if (err)
		return err;
	return PROCESS_BPF_EXIT;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_dynptr_func(struct bpf_verifier_env *env, int regno, int insn_idx,
			       enum bpf_arg_type arg_type, int clone_ref_obj_id)
{
	struct bpf_reg_state *reg = reg_state(env, regno);
	int err;

	if (reg->type != PTR_TO_STACK && reg->type != CONST_PTR_TO_DYNPTR) {
		verbose(env,
			"arg#%d expected pointer to stack or const struct bpf_dynptr\n",
			regno - 1);
		return -EINVAL;
	}

	/* MEM_UNINIT and MEM_RDONLY are exclusive, when applied to an
	 * ARG_PTR_TO_DYNPTR (or ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_*):
	 */
	if ((arg_type & (MEM_UNINIT | MEM_RDONLY)) == (MEM_UNINIT | MEM_RDONLY)) {
		verifier_bug(env, "misconfigured dynptr helper type flags");
		return -EFAULT;
	}

	/*  MEM_UNINIT - Points to memory that is an appropriate candidate for
	 *		 constructing a mutable bpf_dynptr object.
	 *
	 *		 Currently, this is only possible with PTR_TO_STACK
	 *		 pointing to a region of at least 16 bytes which doesn't
	 *		 contain an existing bpf_dynptr.
	 *
	 *  MEM_RDONLY - Points to a initialized bpf_dynptr that will not be
	 *		 mutated or destroyed. However, the memory it points to
	 *		 may be mutated.
	 *
	 *  None       - Points to a initialized dynptr that can be mutated and
	 *		 destroyed, including mutation of the memory it points
	 *		 to.
	 */
	if (arg_type & MEM_UNINIT) {
		int i;

		if (!is_dynptr_reg_valid_uninit(env, reg)) {
			verbose(env, "Dynptr has to be an uninitialized dynptr\n");
			return -EINVAL;
		}

		/* we write BPF_DW bits (8 bytes) at a time */
		for (i = 0; i < BPF_DYNPTR_SIZE; i += 8) {
			err = check_mem_access(env, insn_idx, regno,
					       i, BPF_DW, BPF_WRITE, -1, false, false);
			if (err)
				return err;
		}

		err = mark_stack_slots_dynptr(env, reg, arg_type, insn_idx, clone_ref_obj_id);
	} else /* MEM_RDONLY and None case from above */ {
		/* For the reg->type == PTR_TO_STACK case, bpf_dynptr is never const */
		if (reg->type == CONST_PTR_TO_DYNPTR && !(arg_type & MEM_RDONLY)) {
			verbose(env, "cannot pass pointer to const bpf_dynptr, the helper mutates it\n");
			return -EINVAL;
		}

		if (!is_dynptr_reg_valid_init(env, reg)) {
			verbose(env,
				"Expected an initialized dynptr as arg #%d\n",
				regno - 1);
			return -EINVAL;
		}

		/* Fold modifiers (in this case, MEM_RDONLY) when checking expected type */
		if (!is_dynptr_type_expected(env, reg, arg_type & ~MEM_RDONLY)) {
			verbose(env,
				"Expected a dynptr of type %s as arg #%d\n",
				dynptr_type_str(arg_to_dynptr_type(arg_type)), regno - 1);
			return -EINVAL;
		}

		err = mark_dynptr_read(env, reg);
	}
	return err;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_fd_array(struct bpf_verifier_env *env, union bpf_attr *attr, bpfptr_t uattr)
{
	size_t size = sizeof(int);
	int ret;
	int fd;
	u32 i;

	env->fd_array = make_bpfptr(attr->fd_array, uattr.is_kernel);

	/*
	 * The only difference between old (no fd_array_cnt is given) and new
	 * APIs is that in the latter case the fd_array is expected to be
	 * continuous and is scanned for map fds right away
	 */
	if (!attr->fd_array_cnt)
		return 0;

	/* Check for integer overflow */
	if (attr->fd_array_cnt >= (U32_MAX / size)) {
		verbose(env, "fd_array_cnt is too big (%u)\n", attr->fd_array_cnt);
		return -EINVAL;
	}

	for (i = 0; i < attr->fd_array_cnt; i++) {
		if (copy_from_bpfptr_offset(&fd, env->fd_array, i * size, size))
			return -EFAULT;

		ret = add_fd_from_fd_array(env, fd);
		if (ret)
			return ret;
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_irq_flag(struct bpf_verifier_env *env, int regno,
			     struct bpf_kfunc_call_arg_meta *meta)
{
	struct bpf_reg_state *reg = reg_state(env, regno);
	int err, kfunc_class = IRQ_NATIVE_KFUNC;
	bool irq_save;

	if (meta->func_id == special_kfunc_list[KF_bpf_local_irq_save] ||
	    meta->func_id == special_kfunc_list[KF_bpf_res_spin_lock_irqsave]) {
		irq_save = true;
		if (meta->func_id == special_kfunc_list[KF_bpf_res_spin_lock_irqsave])
			kfunc_class = IRQ_LOCK_KFUNC;
	} else if (meta->func_id == special_kfunc_list[KF_bpf_local_irq_restore] ||
		   meta->func_id == special_kfunc_list[KF_bpf_res_spin_unlock_irqrestore]) {
		irq_save = false;
		if (meta->func_id == special_kfunc_list[KF_bpf_res_spin_unlock_irqrestore])
			kfunc_class = IRQ_LOCK_KFUNC;
	} else {
		verifier_bug(env, "unknown irq flags kfunc");
		return -EFAULT;
	}

	if (irq_save) {
		if (!is_irq_flag_reg_valid_uninit(env, reg)) {
			verbose(env, "expected uninitialized irq flag as arg#%d\n", regno - 1);
			return -EINVAL;
		}

		err = check_mem_access(env, env->insn_idx, regno, 0, BPF_DW, BPF_WRITE, -1, false, false);
		if (err)
			return err;

		err = mark_stack_slot_irq_flag(env, meta, reg, env->insn_idx, kfunc_class);
		if (err)
			return err;
	} else {
		err = is_irq_flag_reg_valid_init(env, reg);
		if (err) {
			verbose(env, "expected an initialized irq flag as arg#%d\n", regno - 1);
			return err;
		}

		err = mark_irq_flag_read(env, reg);
		if (err)
			return err;

		err = unmark_stack_slot_irq_flag(env, reg, kfunc_class);
		if (err)
			return err;
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_iter_arg(struct bpf_verifier_env *env, int regno, int insn_idx,
			    struct bpf_kfunc_call_arg_meta *meta)
{
	struct bpf_reg_state *reg = reg_state(env, regno);
	const struct btf_type *t;
	int spi, err, i, nr_slots, btf_id;

	if (reg->type != PTR_TO_STACK) {
		verbose(env, "arg#%d expected pointer to an iterator on stack\n", regno - 1);
		return -EINVAL;
	}

	/* For iter_{new,next,destroy} functions, btf_check_iter_kfuncs()
	 * ensures struct convention, so we wouldn't need to do any BTF
	 * validation here. But given iter state can be passed as a parameter
	 * to any kfunc, if arg has "__iter" suffix, we need to be a bit more
	 * conservative here.
	 */
	btf_id = btf_check_iter_arg(meta->btf, meta->func_proto, regno - 1);
	if (btf_id < 0) {
		verbose(env, "expected valid iter pointer as arg #%d\n", regno - 1);
		return -EINVAL;
	}
	t = btf_type_by_id(meta->btf, btf_id);
	nr_slots = t->size / BPF_REG_SIZE;

	if (is_iter_new_kfunc(meta)) {
		/* bpf_iter_<type>_new() expects pointer to uninit iter state */
		if (!is_iter_reg_valid_uninit(env, reg, nr_slots)) {
			verbose(env, "expected uninitialized iter_%s as arg #%d\n",
				iter_type_str(meta->btf, btf_id), regno - 1);
			return -EINVAL;
		}

		for (i = 0; i < nr_slots * 8; i += BPF_REG_SIZE) {
			err = check_mem_access(env, insn_idx, regno,
					       i, BPF_DW, BPF_WRITE, -1, false, false);
			if (err)
				return err;
		}

		err = mark_stack_slots_iter(env, meta, reg, insn_idx, meta->btf, btf_id, nr_slots);
		if (err)
			return err;
	} else {
		/* iter_next() or iter_destroy(), as well as any kfunc
		 * accepting iter argument, expect initialized iter state
		 */
		err = is_iter_reg_valid_init(env, reg, meta->btf, btf_id, nr_slots);
		switch (err) {
		case 0:
			break;
		case -EINVAL:
			verbose(env, "expected an initialized iter_%s as arg #%d\n",
				iter_type_str(meta->btf, btf_id), regno - 1);
			return err;
		case -EPROTO:
			verbose(env, "expected an RCU CS when using %s\n", meta->func_name);
			return err;
		default:
			return err;
		}

		spi = iter_get_spi(env, reg, nr_slots);
		if (spi < 0)
			return spi;

		err = mark_iter_read(env, reg, spi, nr_slots);
		if (err)
			return err;

		/* remember meta->iter info for process_iter_next_call() */
		meta->iter.spi = spi;
		meta->iter.frameno = reg->frameno;
		meta->ref_obj_id = iter_ref_obj_id(env, reg, spi);

		if (is_iter_destroy_kfunc(meta)) {
			err = unmark_stack_slots_iter(env, reg, nr_slots);
			if (err)
				return err;
		}
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_iter_next_call(struct bpf_verifier_env *env, int insn_idx,
				  struct bpf_kfunc_call_arg_meta *meta)
{
	struct bpf_verifier_state *cur_st = env->cur_state, *queued_st, *prev_st;
	struct bpf_func_state *cur_fr = cur_st->frame[cur_st->curframe], *queued_fr;
	struct bpf_reg_state *cur_iter, *queued_iter;

	BTF_TYPE_EMIT(struct bpf_iter);

	cur_iter = get_iter_from_state(cur_st, meta);

	if (cur_iter->iter.state != BPF_ITER_STATE_ACTIVE &&
	    cur_iter->iter.state != BPF_ITER_STATE_DRAINED) {
		verifier_bug(env, "unexpected iterator state %d (%s)",
			     cur_iter->iter.state, iter_state_str(cur_iter->iter.state));
		return -EFAULT;
	}

	if (cur_iter->iter.state == BPF_ITER_STATE_ACTIVE) {
		/* Because iter_next() call is a checkpoint is_state_visitied()
		 * should guarantee parent state with same call sites and insn_idx.
		 */
		if (!cur_st->parent || cur_st->parent->insn_idx != insn_idx ||
		    !same_callsites(cur_st->parent, cur_st)) {
			verifier_bug(env, "bad parent state for iter next call");
			return -EFAULT;
		}
		/* Note cur_st->parent in the call below, it is necessary to skip
		 * checkpoint created for cur_st by is_state_visited()
		 * right at this instruction.
		 */
		prev_st = find_prev_entry(env, cur_st->parent, insn_idx);
		/* branch out active iter state */
		queued_st = push_stack(env, insn_idx + 1, insn_idx, false);
		if (IS_ERR(queued_st))
			return PTR_ERR(queued_st);

		queued_iter = get_iter_from_state(queued_st, meta);
		queued_iter->iter.state = BPF_ITER_STATE_ACTIVE;
		queued_iter->iter.depth++;
		if (prev_st)
			widen_imprecise_scalars(env, prev_st, queued_st);

		queued_fr = queued_st->frame[queued_st->curframe];
		mark_ptr_not_null_reg(&queued_fr->regs[BPF_REG_0]);
	}

	/* switch to DRAINED state, but keep the depth unchanged */
	/* mark current iter state as drained and assume returned NULL */
	cur_iter->iter.state = BPF_ITER_STATE_DRAINED;
	inner_mark_reg_const_zero(env, &cur_fr->regs[BPF_REG_0]);

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_kf_arg_ptr_to_btf_id(struct bpf_verifier_env *env,
					struct bpf_reg_state *reg,
					const struct btf_type *ref_t,
					const char *ref_tname, u32 ref_id,
					struct bpf_kfunc_call_arg_meta *meta,
					int argno)
{
	const struct btf_type *reg_ref_t;
	bool strict_type_match = false;
	const struct btf *reg_btf;
	const char *reg_ref_tname;
	bool taking_projection;
	bool struct_same;
	u32 reg_ref_id;

	if (base_type(reg->type) == PTR_TO_BTF_ID) {
		reg_btf = reg->btf;
		reg_ref_id = reg->btf_id;
	} else {
		reg_btf = btf_vmlinux;
		reg_ref_id = *reg2btf_ids[base_type(reg->type)];
	}

	/* Enforce strict type matching for calls to kfuncs that are acquiring
	 * or releasing a reference, or are no-cast aliases. We do _not_
	 * enforce strict matching for kfuncs by default,
	 * as we want to enable BPF programs to pass types that are bitwise
	 * equivalent without forcing them to explicitly cast with something
	 * like bpf_cast_to_kern_ctx().
	 *
	 * For example, say we had a type like the following:
	 *
	 * struct bpf_cpumask {
	 *	cpumask_t cpumask;
	 *	refcount_t usage;
	 * };
	 *
	 * Note that as specified in <linux/cpumask.h>, cpumask_t is typedef'ed
	 * to a struct cpumask, so it would be safe to pass a struct
	 * bpf_cpumask * to a kfunc expecting a struct cpumask *.
	 *
	 * The philosophy here is similar to how we allow scalars of different
	 * types to be passed to kfuncs as long as the size is the same. The
	 * only difference here is that we're simply allowing
	 * btf_struct_ids_match() to walk the struct at the 0th offset, and
	 * resolve types.
	 */
	if ((is_kfunc_release(meta) && reg->ref_obj_id) ||
	    btf_type_ids_nocast_alias(&env->log, reg_btf, reg_ref_id, meta->btf, ref_id))
		strict_type_match = true;

	WARN_ON_ONCE(is_kfunc_release(meta) &&
		     (reg->off || !tnum_is_const(reg->var_off) ||
		      reg->var_off.value));

	reg_ref_t = btf_type_skip_modifiers(reg_btf, reg_ref_id, &reg_ref_id);
	reg_ref_tname = btf_name_by_offset(reg_btf, reg_ref_t->name_off);
	struct_same = btf_struct_ids_match(&env->log, reg_btf, reg_ref_id, reg->off, meta->btf, ref_id, strict_type_match);
	/* If kfunc is accepting a projection type (ie. __sk_buff), it cannot
	 * actually use it -- it must cast to the underlying type. So we allow
	 * caller to pass in the underlying type.
	 */
	taking_projection = btf_is_projection_of(ref_tname, reg_ref_tname);
	if (!taking_projection && !struct_same) {
		verbose(env, "kernel function %s args#%d expected pointer to %s %s but R%d has a pointer to %s %s\n",
			meta->func_name, argno, btf_type_str(ref_t), ref_tname, argno + 1,
			btf_type_str(reg_ref_t), reg_ref_tname);
		return -EINVAL;
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_kf_arg_ptr_to_list_head(struct bpf_verifier_env *env,
					   struct bpf_reg_state *reg, u32 regno,
					   struct bpf_kfunc_call_arg_meta *meta)
{
	return inner_process_kf_arg_ptr_to_graph_root(env, reg, regno, meta, BPF_LIST_HEAD,
							  &meta->arg_list_head.field);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_kf_arg_ptr_to_list_node(struct bpf_verifier_env *env,
					   struct bpf_reg_state *reg, u32 regno,
					   struct bpf_kfunc_call_arg_meta *meta)
{
	return inner_process_kf_arg_ptr_to_graph_node(env, reg, regno, meta,
						  BPF_LIST_HEAD, BPF_LIST_NODE,
						  &meta->arg_list_head.field);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_kf_arg_ptr_to_rbtree_node(struct bpf_verifier_env *env,
					     struct bpf_reg_state *reg, u32 regno,
					     struct bpf_kfunc_call_arg_meta *meta)
{
	return inner_process_kf_arg_ptr_to_graph_node(env, reg, regno, meta,
						  BPF_RB_ROOT, BPF_RB_NODE,
						  &meta->arg_rbtree_root.field);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_kf_arg_ptr_to_rbtree_root(struct bpf_verifier_env *env,
					     struct bpf_reg_state *reg, u32 regno,
					     struct bpf_kfunc_call_arg_meta *meta)
{
	return inner_process_kf_arg_ptr_to_graph_root(env, reg, regno, meta, BPF_RB_ROOT,
							  &meta->arg_rbtree_root.field);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_kptr_func(struct bpf_verifier_env *env, int regno,
			     struct bpf_call_arg_meta *meta)
{
	struct bpf_reg_state *reg = reg_state(env, regno);
	struct btf_field *kptr_field;
	struct bpf_map *map_ptr;
	struct btf_record *rec;
	u32 kptr_off;

	if (type_is_ptr_alloc_obj(reg->type)) {
		rec = reg_btf_record(reg);
	} else { /* PTR_TO_MAP_VALUE */
		map_ptr = reg->map_ptr;
		if (!map_ptr->btf) {
			verbose(env, "map '%s' has to have BTF in order to use bpf_kptr_xchg\n",
				map_ptr->name);
			return -EINVAL;
		}
		rec = map_ptr->record;
		meta->map.ptr = map_ptr;
	}

	if (!tnum_is_const(reg->var_off)) {
		verbose(env,
			"R%d doesn't have constant offset. kptr has to be at the constant offset\n",
			regno);
		return -EINVAL;
	}

	if (!btf_record_has_field(rec, BPF_KPTR)) {
		verbose(env, "R%d has no valid kptr\n", regno);
		return -EINVAL;
	}

	kptr_off = reg->off + reg->var_off.value;
	kptr_field = btf_record_find(rec, kptr_off, BPF_KPTR);
	if (!kptr_field) {
		verbose(env, "off=%d doesn't point to kptr\n", kptr_off);
		return -EACCES;
	}
	if (kptr_field->type != BPF_KPTR_REF && kptr_field->type != BPF_KPTR_PERCPU) {
		verbose(env, "off=%d kptr isn't referenced kptr\n", kptr_off);
		return -EACCES;
	}
	meta->kptr_field = kptr_field;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_spin_lock(struct bpf_verifier_env *env, int regno, int flags)
{
	bool is_lock = flags & PROCESS_SPIN_LOCK, is_res_lock = flags & PROCESS_RES_LOCK;
	const char *lock_str = is_res_lock ? "bpf_res_spin" : "bpf_spin";
	struct bpf_reg_state *reg = reg_state(env, regno);
	struct bpf_verifier_state *cur = env->cur_state;
	bool is_const = tnum_is_const(reg->var_off);
	bool is_irq = flags & PROCESS_LOCK_IRQ;
	u64 val = reg->var_off.value;
	struct bpf_map *map = NULL;
	struct btf *btf = NULL;
	struct btf_record *rec;
	u32 spin_lock_off;
	int err;

	if (!is_const) {
		verbose(env,
			"R%d doesn't have constant offset. %s_lock has to be at the constant offset\n",
			regno, lock_str);
		return -EINVAL;
	}
	if (reg->type == PTR_TO_MAP_VALUE) {
		map = reg->map_ptr;
		if (!map->btf) {
			verbose(env,
				"map '%s' has to have BTF in order to use %s_lock\n",
				map->name, lock_str);
			return -EINVAL;
		}
	} else {
		btf = reg->btf;
	}

	rec = reg_btf_record(reg);
	if (!btf_record_has_field(rec, is_res_lock ? BPF_RES_SPIN_LOCK : BPF_SPIN_LOCK)) {
		verbose(env, "%s '%s' has no valid %s_lock\n", map ? "map" : "local",
			map ? map->name : "kptr", lock_str);
		return -EINVAL;
	}
	spin_lock_off = is_res_lock ? rec->res_spin_lock_off : rec->spin_lock_off;
	if (spin_lock_off != val + reg->off) {
		verbose(env, "off %lld doesn't point to 'struct %s_lock' that is at %d\n",
			val + reg->off, lock_str, spin_lock_off);
		return -EINVAL;
	}
	if (is_lock) {
		void *ptr;
		int type;

		if (map)
			ptr = map;
		else
			ptr = btf;

		if (!is_res_lock && cur->active_locks) {
			if (find_lock_state(env->cur_state, REF_TYPE_LOCK, 0, NULL)) {
				verbose(env,
					"Locking two bpf_spin_locks are not allowed\n");
				return -EINVAL;
			}
		} else if (is_res_lock && cur->active_locks) {
			if (find_lock_state(env->cur_state, REF_TYPE_RES_LOCK | REF_TYPE_RES_LOCK_IRQ, reg->id, ptr)) {
				verbose(env, "Acquiring the same lock again, AA deadlock detected\n");
				return -EINVAL;
			}
		}

		if (is_res_lock && is_irq)
			type = REF_TYPE_RES_LOCK_IRQ;
		else if (is_res_lock)
			type = REF_TYPE_RES_LOCK;
		else
			type = REF_TYPE_LOCK;
		err = acquire_lock_state(env, env->insn_idx, type, reg->id, ptr);
		if (err < 0) {
			verbose(env, "Failed to acquire lock state\n");
			return err;
		}
	} else {
		void *ptr;
		int type;

		if (map)
			ptr = map;
		else
			ptr = btf;

		if (!cur->active_locks) {
			verbose(env, "%s_unlock without taking a lock\n", lock_str);
			return -EINVAL;
		}

		if (is_res_lock && is_irq)
			type = REF_TYPE_RES_LOCK_IRQ;
		else if (is_res_lock)
			type = REF_TYPE_RES_LOCK;
		else
			type = REF_TYPE_LOCK;
		if (!find_lock_state(cur, type, reg->id, ptr)) {
			verbose(env, "%s_unlock of different lock\n", lock_str);
			return -EINVAL;
		}
		if (reg->id != cur->active_lock_id || ptr != cur->active_lock_ptr) {
			verbose(env, "%s_unlock cannot be out of order\n", lock_str);
			return -EINVAL;
		}
		if (release_lock_state(cur, type, reg->id, ptr)) {
			verbose(env, "%s_unlock of different lock\n", lock_str);
			return -EINVAL;
		}

		invalidate_non_owning_refs(env);
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_timer_func(struct bpf_verifier_env *env, int regno,
			      struct bpf_map_desc *map)
{
	if (IS_ENABLED(CONFIG_PREEMPT_RT)) {
		verbose(env, "bpf_timer cannot be used for PREEMPT_RT.\n");
		return -EOPNOTSUPP;
	}
	return check_map_field_pointer(env, regno, BPF_TIMER, map);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_timer_helper(struct bpf_verifier_env *env, int regno,
				struct bpf_call_arg_meta *meta)
{
	return process_timer_func(env, regno, &meta->map);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int process_timer_kfunc(struct bpf_verifier_env *env, int regno,
			       struct bpf_kfunc_call_arg_meta *meta)
{
	return process_timer_func(env, regno, &meta->map);
}

static int inner_process_kf_arg_ptr_to_graph_node(struct bpf_verifier_env *env,
				   struct bpf_reg_state *reg, u32 regno,
				   struct bpf_kfunc_call_arg_meta *meta,
				   enum btf_field_type head_field_type,
				   enum btf_field_type node_field_type,
				   struct btf_field **node_field)
{
	const char *node_type_name;
	const struct btf_type *et, *t;
	struct btf_field *field;
	u32 node_off;

	if (meta->btf != btf_vmlinux) {
		verifier_bug(env, "unexpected btf mismatch in kfunc call");
		return -EFAULT;
	}

	if (!check_kfunc_is_graph_node_api(env, node_field_type, meta->func_id))
		return -EFAULT;

	node_type_name = btf_field_type_name(node_field_type);
	if (!tnum_is_const(reg->var_off)) {
		verbose(env,
			"R%d doesn't have constant offset. %s has to be at the constant offset\n",
			regno, node_type_name);
		return -EINVAL;
	}

	node_off = reg->off + reg->var_off.value;
	field = reg_find_field_offset(reg, node_off, node_field_type);
	if (!field) {
		verbose(env, "%s not found at offset=%u\n", node_type_name, node_off);
		return -EINVAL;
	}

	field = *node_field;

	et = btf_type_by_id(field->graph_root.btf, field->graph_root.value_btf_id);
	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (!btf_struct_ids_match(&env->log, reg->btf, reg->btf_id, 0, field->graph_root.btf,
				  field->graph_root.value_btf_id, true)) {
		verbose(env, "operation on %s expects arg#1 %s at offset=%d "
			"in struct %s, but arg is at offset=%d in struct %s\n",
			btf_field_type_name(head_field_type),
			btf_field_type_name(node_field_type),
			field->graph_root.node_offset,
			btf_name_by_offset(field->graph_root.btf, et->name_off),
			node_off, btf_name_by_offset(reg->btf, t->name_off));
		return -EINVAL;
	}
	meta->arg_btf = reg->btf;
	meta->arg_btf_id = reg->btf_id;

	if (node_off != field->graph_root.node_offset) {
		verbose(env, "arg#1 offset=%d, but expected %s at offset=%d in struct %s\n",
			node_off, btf_field_type_name(node_field_type),
			field->graph_root.node_offset,
			btf_name_by_offset(field->graph_root.btf, et->name_off));
		return -EINVAL;
	}

	return 0;
}

//  from /Users/nan/bs/aot/src/verifier.c
static int inner_process_kf_arg_ptr_to_graph_root(struct bpf_veriExtractedfier_env *env,
				   struct bpf_reg_state *reg, u32 regno,
				   struct bpf_kfunc_call_arg_meta *meta,
				   enum btf_field_type head_field_type,
				   struct btf_field **head_field)
{
	const char *head_type_name;
	struct btf_field *field;
	struct btf_record *rec;
	u32 head_off;

	if (meta->btf != btf_vmlinux) {
		verifier_bug(env, "unexpected btf mismatch in kfunc call");
		return -EFAULT;
	}

	if (!check_kfunc_is_graph_root_api(env, head_field_type, meta->func_id))
		return -EFAULT;

	head_type_name = btf_field_type_name(head_field_type);
	if (!tnum_is_const(reg->var_off)) {
		verbose(env,
			"R%d doesn't have constant offset. %s has to be at the constant offset\n",
			regno, head_type_name);
		return -EINVAL;
	}

	rec = reg_btf_record(reg);
	head_off = reg->off + reg->var_off.value;
	field = btf_record_find(rec, head_off, head_field_type);
	if (!field) {
		verbose(env, "%s not found at offset=%u\n", head_type_name, head_off);
		return -EINVAL;
	}

	/* All functions require bpf_list_head to be protected using a bpf_spin_lock */
	if (check_reg_allocation_locked(env, reg)) {
		verbose(env, "bpf_spin_lock at off=%d must be held for %s\n",
			rec->spin_lock_off, head_type_name);
		return -EINVAL;
	}

	if (*head_field) {
		verifier_bug(env, "repeating %s arg", head_type_name);
		return -EFAULT;
	}
	*head_field = field;
	return 0;
}
