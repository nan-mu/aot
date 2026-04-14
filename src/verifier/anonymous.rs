// Extracted from /Users/nan/bs/aot/src/verifier.c
static void ___mark_reg_known(struct bpf_reg_state *reg, u64 imm)
{
	reg->var_off = tnum_const(imm);
	reg->smin_value = (s64)imm;
	reg->smax_value = (s64)imm;
	reg->umin_value = imm;
	reg->umax_value = imm;

	reg->s32_min_value = (s32)imm;
	reg->s32_max_value = (s32)imm;
	reg->u32_min_value = (u32)imm;
	reg->u32_max_value = (u32)imm;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int __add_used_btf(struct bpf_verifier_env *env, struct btf *btf)
{
	struct btf_mod_pair *btf_mod;
	int ret = 0;
	int i;

	/* check whether we recorded this BTF (and maybe module) already */
	for (i = 0; i < env->used_btf_cnt; i++)
		if (env->used_btfs[i].btf == btf)
			goto ret_put;

	if (env->used_btf_cnt >= MAX_USED_BTFS) {
		verbose(env, "The total number of btfs per program has reached the limit of %u\n",
			MAX_USED_BTFS);
		ret = -E2BIG;
		goto ret_put;
	}

	btf_mod = &env->used_btfs[env->used_btf_cnt];
	btf_mod->btf = btf;
	btf_mod->module = NULL;

	/* if we reference variables from kernel module, bump its refcount */
	if (btf_is_module(btf)) {
		btf_mod->module = btf_try_get_module(btf);
		if (!btf_mod->module) {
			ret = -ENXIO;
			goto ret_put;
		}
	}

	env->used_btf_cnt++;
	return 0;

ret_put:
	/* Either error or this BTF was already added */
	btf_put(btf);
	return ret;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int __add_used_map(struct bpf_verifier_env *env, struct bpf_map *map)
{
	int i, err;

	/* check whether we recorded this map already */
	for (i = 0; i < env->used_map_cnt; i++)
		if (env->used_maps[i] == map)
			return i;

	if (env->used_map_cnt >= MAX_USED_MAPS) {
		verbose(env, "The total number of maps per program has reached the limit of %u\n",
			MAX_USED_MAPS);
		return -E2BIG;
	}

	err = check_map_prog_compatibility(env, map, env->prog);
	if (err)
		return err;

	if (env->prog->sleepable)
		atomic64_inc(&map->sleepable_refcnt);

	/* hold the map. If the program is rejected by verifier,
	 * the map will be released by release_maps() or it
	 * will be used by the valid program until it's unloaded
	 * and all maps are released in bpf_free_used_maps()
	 */
	bpf_map_inc(map);

	env->used_maps[env->used_map_cnt++] = map;

	if (map->map_type == BPF_MAP_TYPE_INSN_ARRAY) {
		err = bpf_insn_array_init(map, env->prog);
		if (err) {
			verbose(env, "Failed to properly initialize insn array\n");
			return err;
		}
		env->insn_array_maps[env->insn_array_map_cnt++] = map;
	}

	return env->used_map_cnt - 1;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool __btf_type_is_scalar_struct(struct bpf_verifier_env *env,
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
			if (!__btf_type_is_scalar_struct(env, btf, member_type, rec + 1))
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


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int __check_buffer_access(struct bpf_verifier_env *env,
				 const char *buf_info,
				 const struct bpf_reg_state *reg,
				 int regno, int off, int size)
{
	if (off < 0) {
		verbose(env,
			"R%d invalid %s buffer access: off=%d, size=%d\n",
			regno, buf_info, off, size);
		return -EACCES;
	}
	if (!tnum_is_const(reg->var_off) || reg->var_off.value) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
		verbose(env,
			"R%d invalid variable buffer offset: off=%d, var_off=%s\n",
			regno, off, tn_buf);
		return -EACCES;
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int __check_mem_access(struct bpf_verifier_env *env, int regno,
			      int off, int size, u32 mem_size,
			      bool zero_size_allowed)
{
	bool size_ok = size > 0 || (size == 0 && zero_size_allowed);
	struct bpf_reg_state *reg;

	if (off >= 0 && size_ok && (u64)off + size <= mem_size)
		return 0;

	reg = &cur_regs(env)[regno];
	switch (reg->type) {
	case PTR_TO_MAP_KEY:
		verbose(env, "invalid access to map key, key_size=%d off=%d size=%d\n",
			mem_size, off, size);
		break;
	case PTR_TO_MAP_VALUE:
		verbose(env, "invalid access to map value, value_size=%d off=%d size=%d\n",
			mem_size, off, size);
		break;
	case PTR_TO_PACKET:
	case PTR_TO_PACKET_META:
	case PTR_TO_PACKET_END:
		verbose(env, "invalid access to packet, off=%d size=%d, R%d(id=%d,off=%d,r=%d)\n",
			off, size, regno, reg->id, off, mem_size);
		break;
	case PTR_TO_MEM:
	default:
		verbose(env, "invalid access to memory, mem_size=%u off=%d size=%d\n",
			mem_size, off, size);
	}

	return -EACCES;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int __check_pseudo_btf_id(struct bpf_verifier_env *env,
				 struct bpf_insn *insn,
				 struct bpf_insn_aux_data *aux,
				 struct btf *btf)
{
	const struct btf_var_secinfo *vsi;
	const struct btf_type *datasec;
	const struct btf_type *t;
	const char *sym_name;
	bool percpu = false;
	u32 type, id = insn->imm;
	s32 datasec_id;
	u64 addr;
	int i;

	t = btf_type_by_id(btf, id);
	if (!t) {
		verbose(env, "ldimm64 insn specifies invalid btf_id %d.\n", id);
		return -ENOENT;
	}

	if (!btf_type_is_var(t) && !btf_type_is_func(t)) {
		verbose(env, "pseudo btf_id %d in ldimm64 isn't KIND_VAR or KIND_FUNC\n", id);
		return -EINVAL;
	}

	sym_name = btf_name_by_offset(btf, t->name_off);
	addr = kallsyms_lookup_name(sym_name);
	if (!addr) {
		verbose(env, "ldimm64 failed to find the address for kernel symbol '%s'.\n",
			sym_name);
		return -ENOENT;
	}
	insn[0].imm = (u32)addr;
	insn[1].imm = addr >> 32;

	if (btf_type_is_func(t)) {
		aux->btf_var.reg_type = PTR_TO_MEM | MEM_RDONLY;
		aux->btf_var.mem_size = 0;
		return 0;
	}

	datasec_id = find_btf_percpu_datasec(btf);
	if (datasec_id > 0) {
		datasec = btf_type_by_id(btf, datasec_id);
		for_each_vsi(i, datasec, vsi) {
			if (vsi->type == id) {
				percpu = true;
				break;
			}
		}
	}

	type = t->type;
	t = btf_type_skip_modifiers(btf, type, NULL);
	if (percpu) {
		aux->btf_var.reg_type = PTR_TO_BTF_ID | MEM_PERCPU;
		aux->btf_var.btf = btf;
		aux->btf_var.btf_id = type;
	} else if (!btf_type_is_struct(t)) {
		const struct btf_type *ret;
		const char *tname;
		u32 tsize;

		/* resolve the type size of ksym. */
		ret = btf_resolve_size(btf, t, &tsize);
		if (IS_ERR(ret)) {
			tname = btf_name_by_offset(btf, t->name_off);
			verbose(env, "ldimm64 unable to resolve the size of type '%s': %ld\n",
				tname, PTR_ERR(ret));
			return -EINVAL;
		}
		aux->btf_var.reg_type = PTR_TO_MEM | MEM_RDONLY;
		aux->btf_var.mem_size = tsize;
	} else {
		aux->btf_var.reg_type = PTR_TO_BTF_ID;
		aux->btf_var.btf = btf;
		aux->btf_var.btf_id = type;
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int __check_ptr_off_reg(struct bpf_verifier_env *env,
			       const struct bpf_reg_state *reg, int regno,
			       bool fixed_off_ok)
{
	/* Access to this pointer-typed register or passing it to a helper
	 * is only allowed in its original, unmodified form.
	 */

	if (reg->off < 0) {
		verbose(env, "negative offset %s ptr R%d off=%d disallowed\n",
			reg_type_str(env, reg->type), regno, reg->off);
		return -EACCES;
	}

	if (!fixed_off_ok && reg->off) {
		verbose(env, "dereference of modified %s ptr R%d off=%d disallowed\n",
			reg_type_str(env, reg->type), regno, reg->off);
		return -EACCES;
	}

	if (!tnum_is_const(reg->var_off) || reg->var_off.value) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
		verbose(env, "variable %s access var_off=%s disallowed\n",
			reg_type_str(env, reg->type), tn_buf);
		return -EACCES;
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int __check_reg_arg(struct bpf_verifier_env *env, struct bpf_reg_state *regs, u32 regno,
			   enum reg_arg_type t)
{
	struct bpf_insn *insn = env->prog->insnsi + env->insn_idx;
	struct bpf_reg_state *reg;
	bool rw64;

	if (regno >= MAX_BPF_REG) {
		verbose(env, "R%d is invalid\n", regno);
		return -EINVAL;
	}

	mark_reg_scratched(env, regno);

	reg = &regs[regno];
	rw64 = is_reg64(insn, regno, reg, t);
	if (t == SRC_OP) {
		/* check whether register used as source operand can be read */
		if (reg->type == NOT_INIT) {
			verbose(env, "R%d !read_ok\n", regno);
			return -EACCES;
		}
		/* We don't need to worry about FP liveness because it's read-only */
		if (regno == BPF_REG_FP)
			return 0;

		if (rw64)
			mark_insn_zext(env, reg);

		return 0;
	} else {
		/* check whether register used as dest operand can be written to */
		if (regno == BPF_REG_FP) {
			verbose(env, "frame pointer is read only\n");
			return -EACCES;
		}
		reg->subreg_def = rw64 ? DEF_NOT_SUBREG : env->insn_idx + 1;
		if (t == DST_OP)
			mark_reg_unknown(env, regs, regno);
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __collect_linked_regs(struct linked_regs *reg_set, struct bpf_reg_state *reg,
				  u32 id, u32 frameno, u32 spi_or_reg, bool is_reg)
{
	struct linked_reg *e;

	if (reg->type != SCALAR_VALUE || (reg->id & ~BPF_ADD_CONST) != id)
		return;

	e = linked_regs_push(reg_set);
	if (e) {
		e->frameno = frameno;
		e->is_reg = is_reg;
		e->regno = spi_or_reg;
	} else {
		reg->id = 0;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct btf *__find_kfunc_desc_btf(struct bpf_verifier_env *env,
					 s16 offset)
{
	struct bpf_kfunc_btf kf_btf = { .offset = offset };
	struct bpf_kfunc_btf_tab *tab;
	struct bpf_kfunc_btf *b;
	struct module *mod;
	struct btf *btf;
	int btf_fd;

	tab = env->prog->aux->kfunc_btf_tab;
	b = bsearch(&kf_btf, tab->descs, tab->nr_descs,
		    sizeof(tab->descs[0]), kfunc_btf_cmp_by_off);
	if (!b) {
		if (tab->nr_descs == MAX_KFUNC_BTFS) {
			verbose(env, "too many different module BTFs\n");
			return ERR_PTR(-E2BIG);
		}

		if (bpfptr_is_null(env->fd_array)) {
			verbose(env, "kfunc offset > 0 without fd_array is invalid\n");
			return ERR_PTR(-EPROTO);
		}

		if (copy_from_bpfptr_offset(&btf_fd, env->fd_array,
					    offset * sizeof(btf_fd),
					    sizeof(btf_fd)))
			return ERR_PTR(-EFAULT);

		btf = btf_get_by_fd(btf_fd);
		if (IS_ERR(btf)) {
			verbose(env, "invalid module BTF fd specified\n");
			return btf;
		}

		if (!btf_is_module(btf)) {
			verbose(env, "BTF fd for kfunc is not a module BTF\n");
			btf_put(btf);
			return ERR_PTR(-EINVAL);
		}

		mod = btf_try_get_module(btf);
		if (!mod) {
			btf_put(btf);
			return ERR_PTR(-ENXIO);
		}

		b = &tab->descs[tab->nr_descs++];
		b->btf = btf;
		b->module = mod;
		b->offset = offset;

		/* sort() reorders entries by value, so b may no longer point
		 * to the right entry after this
		 */
		sort(tab->descs, tab->nr_descs, sizeof(tab->descs[0]),
		     kfunc_btf_cmp_by_off, NULL);
	} else {
		btf = b->btf;
	}

	return btf;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __fixup_collection_insert_kfunc(struct bpf_insn_aux_data *insn_aux,
					    u16 struct_meta_reg,
					    u16 node_offset_reg,
					    struct bpf_insn *insn,
					    struct bpf_insn *insn_buf,
					    int *cnt)
{
	struct btf_struct_meta *kptr_struct_meta = insn_aux->kptr_struct_meta;
	struct bpf_insn addr[2] = { BPF_LD_IMM64(struct_meta_reg, (long)kptr_struct_meta) };

	insn_buf[0] = addr[0];
	insn_buf[1] = addr[1];
	insn_buf[2] = BPF_MOV64_IMM(node_offset_reg, insn_aux->insert_off);
	insn_buf[3] = *insn;
	*cnt = 4;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int __get_spi(s32 off)
{
	return (-off - 1) / BPF_REG_SIZE;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool __is_pointer_value(bool allow_ptr_leaks,
			       const struct bpf_reg_state *reg)
{
	if (allow_ptr_leaks)
		return false;

	return reg->type != SCALAR_VALUE;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_btf_func_reg_size(struct bpf_verifier_env *env, struct bpf_reg_state *regs,
				     u32 regno, size_t reg_size)
{
	struct bpf_reg_state *reg = &regs[regno];

	if (regno == BPF_REG_0) {
		/* Function return value */
		reg->subreg_def = reg_size == sizeof(u64) ?
			DEF_NOT_SUBREG : env->insn_idx + 1;
	} else if (reg_size == sizeof(u64)) {
		/* Function argument */
		mark_insn_zext(env, reg);
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int __mark_chain_precision(struct bpf_verifier_env *env,
				  struct bpf_verifier_state *starting_state,
				  int regno,
				  bool *changed)
{
	struct bpf_verifier_state *st = starting_state;
	struct backtrack_state *bt = &env->bt;
	int first_idx = st->first_insn_idx;
	int last_idx = starting_state->insn_idx;
	int subseq_idx = -1;
	struct bpf_func_state *func;
	bool tmp, skip_first = true;
	struct bpf_reg_state *reg;
	int i, fr, err;

	if (!env->bpf_capable)
		return 0;

	changed = changed ?: &tmp;
	/* set frame number from which we are starting to backtrack */
	bt_init(bt, starting_state->curframe);

	/* Do sanity checks against current state of register and/or stack
	 * slot, but don't set precise flag in current state, as precision
	 * tracking in the current state is unnecessary.
	 */
	func = st->frame[bt->frame];
	if (regno >= 0) {
		reg = &func->regs[regno];
		if (reg->type != SCALAR_VALUE) {
			verifier_bug(env, "backtracking misuse");
			return -EFAULT;
		}
		bt_set_reg(bt, regno);
	}

	if (bt_empty(bt))
		return 0;

	for (;;) {
		DECLARE_BITMAP(mask, 64);
		u32 history = st->jmp_history_cnt;
		struct bpf_jmp_history_entry *hist;

		if (env->log.level & BPF_LOG_LEVEL2) {
			verbose(env, "mark_precise: frame%d: last_idx %d first_idx %d subseq_idx %d \n",
				bt->frame, last_idx, first_idx, subseq_idx);
		}

		if (last_idx < 0) {
			/* we are at the entry into subprog, which
			 * is expected for global funcs, but only if
			 * requested precise registers are R1-R5
			 * (which are global func's input arguments)
			 */
			if (st->curframe == 0 &&
			    st->frame[0]->subprogno > 0 &&
			    st->frame[0]->callsite == BPF_MAIN_FUNC &&
			    bt_stack_mask(bt) == 0 &&
			    (bt_reg_mask(bt) & ~BPF_REGMASK_ARGS) == 0) {
				bitmap_from_u64(mask, bt_reg_mask(bt));
				for_each_set_bit(i, mask, 32) {
					reg = &st->frame[0]->regs[i];
					bt_clear_reg(bt, i);
					if (reg->type == SCALAR_VALUE) {
						reg->precise = true;
						*changed = true;
					}
				}
				return 0;
			}

			verifier_bug(env, "backtracking func entry subprog %d reg_mask %x stack_mask %llx",
				     st->frame[0]->subprogno, bt_reg_mask(bt), bt_stack_mask(bt));
			return -EFAULT;
		}

		for (i = last_idx;;) {
			if (skip_first) {
				err = 0;
				skip_first = false;
			} else {
				hist = get_jmp_hist_entry(st, history, i);
				err = backtrack_insn(env, i, subseq_idx, hist, bt);
			}
			if (err == -ENOTSUPP) {
				mark_all_scalars_precise(env, starting_state);
				bt_reset(bt);
				return 0;
			} else if (err) {
				return err;
			}
			if (bt_empty(bt))
				/* Found assignment(s) into tracked register in this state.
				 * Since this state is already marked, just return.
				 * Nothing to be tracked further in the parent state.
				 */
				return 0;
			subseq_idx = i;
			i = get_prev_insn_idx(st, i, &history);
			if (i == -ENOENT)
				break;
			if (i >= env->prog->len) {
				/* This can happen if backtracking reached insn 0
				 * and there are still reg_mask or stack_mask
				 * to backtrack.
				 * It means the backtracking missed the spot where
				 * particular register was initialized with a constant.
				 */
				verifier_bug(env, "backtracking idx %d", i);
				return -EFAULT;
			}
		}
		st = st->parent;
		if (!st)
			break;

		for (fr = bt->frame; fr >= 0; fr--) {
			func = st->frame[fr];
			bitmap_from_u64(mask, bt_frame_reg_mask(bt, fr));
			for_each_set_bit(i, mask, 32) {
				reg = &func->regs[i];
				if (reg->type != SCALAR_VALUE) {
					bt_clear_frame_reg(bt, fr, i);
					continue;
				}
				if (reg->precise) {
					bt_clear_frame_reg(bt, fr, i);
				} else {
					reg->precise = true;
					*changed = true;
				}
			}

			bitmap_from_u64(mask, bt_frame_stack_mask(bt, fr));
			for_each_set_bit(i, mask, 64) {
				if (verifier_bug_if(i >= func->allocated_stack / BPF_REG_SIZE,
						    env, "stack slot %d, total slots %d",
						    i, func->allocated_stack / BPF_REG_SIZE))
					return -EFAULT;

				if (!is_spilled_scalar_reg(&func->stack[i])) {
					bt_clear_frame_slot(bt, fr, i);
					continue;
				}
				reg = &func->stack[i].spilled_ptr;
				if (reg->precise) {
					bt_clear_frame_slot(bt, fr, i);
				} else {
					reg->precise = true;
					*changed = true;
				}
			}
			if (env->log.level & BPF_LOG_LEVEL2) {
				fmt_reg_mask(env->tmp_str_buf, TMP_STR_BUF_LEN,
					     bt_frame_reg_mask(bt, fr));
				verbose(env, "mark_precise: frame%d: parent state regs=%s ",
					fr, env->tmp_str_buf);
				bpf_fmt_stack_mask(env->tmp_str_buf, TMP_STR_BUF_LEN,
					       bt_frame_stack_mask(bt, fr));
				verbose(env, "stack=%s: ", env->tmp_str_buf);
				print_verifier_state(env, st, fr, true);
			}
		}

		if (bt_empty(bt))
			return 0;

		subseq_idx = first_idx;
		last_idx = st->last_insn_idx;
		first_idx = st->first_insn_idx;
	}

	/* if we still have requested precise regs or slots, we missed
	 * something (e.g., stack access through non-r10 register), so
	 * fallback to marking all precise
	 */
	if (!bt_empty(bt)) {
		mark_all_scalars_precise(env, starting_state);
		bt_reset(bt);
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_dynptr_reg(struct bpf_reg_state *reg, enum bpf_dynptr_type type,
			      bool first_slot, int dynptr_id)
{
	/* reg->type has no meaning for STACK_DYNPTR, but when we set reg for
	 * callback arguments, it does need to be CONST_PTR_TO_DYNPTR, so simply
	 * set it unconditionally as it is ignored for STACK_DYNPTR anyway.
	 */
	__mark_reg_known_zero(reg);
	reg->type = CONST_PTR_TO_DYNPTR;
	/* Give each dynptr a unique id to uniquely associate slices to it. */
	reg->id = dynptr_id;
	reg->dynptr.type = type;
	reg->dynptr.first_slot = first_slot;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_reg32_known(struct bpf_reg_state *reg, u64 imm)
{
	reg->var_off = tnum_const_subreg(reg->var_off, imm);
	reg->s32_min_value = (s32)imm;
	reg->s32_max_value = (s32)imm;
	reg->u32_min_value = (u32)imm;
	reg->u32_max_value = (u32)imm;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_reg32_unbounded(struct bpf_reg_state *reg)
{
	reg->s32_min_value = S32_MIN;
	reg->s32_max_value = S32_MAX;
	reg->u32_min_value = 0;
	reg->u32_max_value = U32_MAX;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_reg64_unbounded(struct bpf_reg_state *reg)
{
	reg->smin_value = S64_MIN;
	reg->smax_value = S64_MAX;
	reg->umin_value = 0;
	reg->umax_value = U64_MAX;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_reg_const_zero(const struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	__mark_reg_known(reg, 0);
	reg->type = SCALAR_VALUE;
	/* all scalars are assumed imprecise initially (unless unprivileged,
	 * in which case everything is forced to be precise)
	 */
	reg->precise = !env->bpf_capable;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_reg_known(struct bpf_reg_state *reg, u64 imm)
{
	/* Clear off and union(map_ptr, range) */
	memset(((u8 *)reg) + sizeof(reg->type), 0,
	       offsetof(struct bpf_reg_state, var_off) - sizeof(reg->type));
	reg->id = 0;
	reg->ref_obj_id = 0;
	___mark_reg_known(reg, imm);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_reg_known_zero(struct bpf_reg_state *reg)
{
	__mark_reg_known(reg, 0);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_reg_not_init(const struct bpf_verifier_env *env,
				struct bpf_reg_state *reg)
{
	__mark_reg_unknown(env, reg);
	reg->type = NOT_INIT;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int __mark_reg_s32_range(struct bpf_verifier_env *env,
				struct bpf_reg_state *regs,
				u32 regno,
				s32 s32_min,
				s32 s32_max)
{
	struct bpf_reg_state *reg = regs + regno;

	reg->s32_min_value = max_t(s32, reg->s32_min_value, s32_min);
	reg->s32_max_value = min_t(s32, reg->s32_max_value, s32_max);

	reg->smin_value = max_t(s64, reg->smin_value, s32_min);
	reg->smax_value = min_t(s64, reg->smax_value, s32_max);

	reg_bounds_sync(reg);

	return reg_bounds_sanity_check(env, reg, "s32_range");
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_reg_unbounded(struct bpf_reg_state *reg)
{
	reg->smin_value = S64_MIN;
	reg->smax_value = S64_MAX;
	reg->umin_value = 0;
	reg->umax_value = U64_MAX;

	reg->s32_min_value = S32_MIN;
	reg->s32_max_value = S32_MAX;
	reg->u32_min_value = 0;
	reg->u32_max_value = U32_MAX;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_reg_unknown(const struct bpf_verifier_env *env,
			       struct bpf_reg_state *reg)
{
	__mark_reg_unknown_imprecise(reg);
	reg->precise = !env->bpf_capable;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __mark_reg_unknown_imprecise(struct bpf_reg_state *reg)
{
	/*
	 * Clear type, off, and union(map_ptr, range) and
	 * padding between 'type' and union
	 */
	memset(reg, 0, offsetof(struct bpf_reg_state, var_off));
	reg->type = SCALAR_VALUE;
	reg->id = 0;
	reg->ref_obj_id = 0;
	reg->var_off = tnum_unknown;
	reg->frameno = 0;
	reg->precise = false;
	__mark_reg_unbounded(reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
__process_kf_arg_ptr_to_graph_node(struct bpf_verifier_env *env,
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


// Extracted from /Users/nan/bs/aot/src/verifier.c
__process_kf_arg_ptr_to_graph_root(struct bpf_verifier_env *env,
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


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool __reg32_bound_s64(s32 a)
{
	return a >= 0 && a <= S32_MAX;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __reg32_deduce_bounds(struct bpf_reg_state *reg)
{
	/* If upper 32 bits of u64/s64 range don't change, we can use lower 32
	 * bits to improve our u32/s32 boundaries.
	 *
	 * E.g., the case where we have upper 32 bits as zero ([10, 20] in
	 * u64) is pretty trivial, it's obvious that in u32 we'll also have
	 * [10, 20] range. But this property holds for any 64-bit range as
	 * long as upper 32 bits in that entire range of values stay the same.
	 *
	 * E.g., u64 range [0x10000000A, 0x10000000F] ([4294967306, 4294967311]
	 * in decimal) has the same upper 32 bits throughout all the values in
	 * that range. As such, lower 32 bits form a valid [0xA, 0xF] ([10, 15])
	 * range.
	 *
	 * Note also, that [0xA, 0xF] is a valid range both in u32 and in s32,
	 * following the rules outlined below about u64/s64 correspondence
	 * (which equally applies to u32 vs s32 correspondence). In general it
	 * depends on actual hexadecimal values of 32-bit range. They can form
	 * only valid u32, or only valid s32 ranges in some cases.
	 *
	 * So we use all these insights to derive bounds for subregisters here.
	 */
	if ((reg->umin_value >> 32) == (reg->umax_value >> 32)) {
		/* u64 to u32 casting preserves validity of low 32 bits as
		 * a range, if upper 32 bits are the same
		 */
		reg->u32_min_value = max_t(u32, reg->u32_min_value, (u32)reg->umin_value);
		reg->u32_max_value = min_t(u32, reg->u32_max_value, (u32)reg->umax_value);

		if ((s32)reg->umin_value <= (s32)reg->umax_value) {
			reg->s32_min_value = max_t(s32, reg->s32_min_value, (s32)reg->umin_value);
			reg->s32_max_value = min_t(s32, reg->s32_max_value, (s32)reg->umax_value);
		}
	}
	if ((reg->smin_value >> 32) == (reg->smax_value >> 32)) {
		/* low 32 bits should form a proper u32 range */
		if ((u32)reg->smin_value <= (u32)reg->smax_value) {
			reg->u32_min_value = max_t(u32, reg->u32_min_value, (u32)reg->smin_value);
			reg->u32_max_value = min_t(u32, reg->u32_max_value, (u32)reg->smax_value);
		}
		/* low 32 bits should form a proper s32 range */
		if ((s32)reg->smin_value <= (s32)reg->smax_value) {
			reg->s32_min_value = max_t(s32, reg->s32_min_value, (s32)reg->smin_value);
			reg->s32_max_value = min_t(s32, reg->s32_max_value, (s32)reg->smax_value);
		}
	}
	/* Special case where upper bits form a small sequence of two
	 * sequential numbers (in 32-bit unsigned space, so 0xffffffff to
	 * 0x00000000 is also valid), while lower bits form a proper s32 range
	 * going from negative numbers to positive numbers. E.g., let's say we
	 * have s64 range [-1, 1] ([0xffffffffffffffff, 0x0000000000000001]).
	 * Possible s64 values are {-1, 0, 1} ({0xffffffffffffffff,
	 * 0x0000000000000000, 0x00000000000001}). Ignoring upper 32 bits,
	 * we still get a valid s32 range [-1, 1] ([0xffffffff, 0x00000001]).
	 * Note that it doesn't have to be 0xffffffff going to 0x00000000 in
	 * upper 32 bits. As a random example, s64 range
	 * [0xfffffff0fffffff0; 0xfffffff100000010], forms a valid s32 range
	 * [-16, 16] ([0xfffffff0; 0x00000010]) in its 32 bit subregister.
	 */
	if ((u32)(reg->umin_value >> 32) + 1 == (u32)(reg->umax_value >> 32) &&
	    (s32)reg->umin_value < 0 && (s32)reg->umax_value >= 0) {
		reg->s32_min_value = max_t(s32, reg->s32_min_value, (s32)reg->umin_value);
		reg->s32_max_value = min_t(s32, reg->s32_max_value, (s32)reg->umax_value);
	}
	if ((u32)(reg->smin_value >> 32) + 1 == (u32)(reg->smax_value >> 32) &&
	    (s32)reg->smin_value < 0 && (s32)reg->smax_value >= 0) {
		reg->s32_min_value = max_t(s32, reg->s32_min_value, (s32)reg->smin_value);
		reg->s32_max_value = min_t(s32, reg->s32_max_value, (s32)reg->smax_value);
	}
	/* if u32 range forms a valid s32 range (due to matching sign bit),
	 * try to learn from that
	 */
	if ((s32)reg->u32_min_value <= (s32)reg->u32_max_value) {
		reg->s32_min_value = max_t(s32, reg->s32_min_value, reg->u32_min_value);
		reg->s32_max_value = min_t(s32, reg->s32_max_value, reg->u32_max_value);
	}
	/* If we cannot cross the sign boundary, then signed and unsigned bounds
	 * are the same, so combine.  This works even in the negative case, e.g.
	 * -3 s<= x s<= -1 implies 0xf...fd u<= x u<= 0xf...ff.
	 */
	if ((u32)reg->s32_min_value <= (u32)reg->s32_max_value) {
		reg->u32_min_value = max_t(u32, reg->s32_min_value, reg->u32_min_value);
		reg->u32_max_value = min_t(u32, reg->s32_max_value, reg->u32_max_value);
	} else {
		if (reg->u32_max_value < (u32)reg->s32_min_value) {
			/* See __reg64_deduce_bounds() for detailed explanation.
			 * Refine ranges in the following situation:
			 *
			 * 0                                                   U32_MAX
			 * |  [xxxxxxxxxxxxxx u32 range xxxxxxxxxxxxxx]              |
			 * |----------------------------|----------------------------|
			 * |xxxxx s32 range xxxxxxxxx]                       [xxxxxxx|
			 * 0                     S32_MAX S32_MIN                    -1
			 */
			reg->s32_min_value = (s32)reg->u32_min_value;
			reg->u32_max_value = min_t(u32, reg->u32_max_value, reg->s32_max_value);
		} else if ((u32)reg->s32_max_value < reg->u32_min_value) {
			/*
			 * 0                                                   U32_MAX
			 * |              [xxxxxxxxxxxxxx u32 range xxxxxxxxxxxxxx]  |
			 * |----------------------------|----------------------------|
			 * |xxxxxxxxx]                       [xxxxxxxxxxxx s32 range |
			 * 0                     S32_MAX S32_MIN                    -1
			 */
			reg->s32_max_value = (s32)reg->u32_max_value;
			reg->u32_min_value = max_t(u32, reg->u32_min_value, reg->s32_min_value);
		}
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __reg64_deduce_bounds(struct bpf_reg_state *reg)
{
	/* If u64 range forms a valid s64 range (due to matching sign bit),
	 * try to learn from that. Let's do a bit of ASCII art to see when
	 * this is happening. Let's take u64 range first:
	 *
	 * 0             0x7fffffffffffffff 0x8000000000000000        U64_MAX
	 * |-------------------------------|--------------------------------|
	 *
	 * Valid u64 range is formed when umin and umax are anywhere in the
	 * range [0, U64_MAX], and umin <= umax. u64 case is simple and
	 * straightforward. Let's see how s64 range maps onto the same range
	 * of values, annotated below the line for comparison:
	 *
	 * 0             0x7fffffffffffffff 0x8000000000000000        U64_MAX
	 * |-------------------------------|--------------------------------|
	 * 0                        S64_MAX S64_MIN                        -1
	 *
	 * So s64 values basically start in the middle and they are logically
	 * contiguous to the right of it, wrapping around from -1 to 0, and
	 * then finishing as S64_MAX (0x7fffffffffffffff) right before
	 * S64_MIN. We can try drawing the continuity of u64 vs s64 values
	 * more visually as mapped to sign-agnostic range of hex values.
	 *
	 *  u64 start                                               u64 end
	 *  _______________________________________________________________
	 * /                                                               \
	 * 0             0x7fffffffffffffff 0x8000000000000000        U64_MAX
	 * |-------------------------------|--------------------------------|
	 * 0                        S64_MAX S64_MIN                        -1
	 *                                / \
	 * >------------------------------   ------------------------------->
	 * s64 continues...        s64 end   s64 start          s64 "midpoint"
	 *
	 * What this means is that, in general, we can't always derive
	 * something new about u64 from any random s64 range, and vice versa.
	 *
	 * But we can do that in two particular cases. One is when entire
	 * u64/s64 range is *entirely* contained within left half of the above
	 * diagram or when it is *entirely* contained in the right half. I.e.:
	 *
	 * |-------------------------------|--------------------------------|
	 *     ^                   ^            ^                 ^
	 *     A                   B            C                 D
	 *
	 * [A, B] and [C, D] are contained entirely in their respective halves
	 * and form valid contiguous ranges as both u64 and s64 values. [A, B]
	 * will be non-negative both as u64 and s64 (and in fact it will be
	 * identical ranges no matter the signedness). [C, D] treated as s64
	 * will be a range of negative values, while in u64 it will be
	 * non-negative range of values larger than 0x8000000000000000.
	 *
	 * Now, any other range here can't be represented in both u64 and s64
	 * simultaneously. E.g., [A, C], [A, D], [B, C], [B, D] are valid
	 * contiguous u64 ranges, but they are discontinuous in s64. [B, C]
	 * in s64 would be properly presented as [S64_MIN, C] and [B, S64_MAX],
	 * for example. Similarly, valid s64 range [D, A] (going from negative
	 * to positive values), would be two separate [D, U64_MAX] and [0, A]
	 * ranges as u64. Currently reg_state can't represent two segments per
	 * numeric domain, so in such situations we can only derive maximal
	 * possible range ([0, U64_MAX] for u64, and [S64_MIN, S64_MAX] for s64).
	 *
	 * So we use these facts to derive umin/umax from smin/smax and vice
	 * versa only if they stay within the same "half". This is equivalent
	 * to checking sign bit: lower half will have sign bit as zero, upper
	 * half have sign bit 1. Below in code we simplify this by just
	 * casting umin/umax as smin/smax and checking if they form valid
	 * range, and vice versa. Those are equivalent checks.
	 */
	if ((s64)reg->umin_value <= (s64)reg->umax_value) {
		reg->smin_value = max_t(s64, reg->smin_value, reg->umin_value);
		reg->smax_value = min_t(s64, reg->smax_value, reg->umax_value);
	}
	/* If we cannot cross the sign boundary, then signed and unsigned bounds
	 * are the same, so combine.  This works even in the negative case, e.g.
	 * -3 s<= x s<= -1 implies 0xf...fd u<= x u<= 0xf...ff.
	 */
	if ((u64)reg->smin_value <= (u64)reg->smax_value) {
		reg->umin_value = max_t(u64, reg->smin_value, reg->umin_value);
		reg->umax_value = min_t(u64, reg->smax_value, reg->umax_value);
	} else {
		/* If the s64 range crosses the sign boundary, then it's split
		 * between the beginning and end of the U64 domain. In that
		 * case, we can derive new bounds if the u64 range overlaps
		 * with only one end of the s64 range.
		 *
		 * In the following example, the u64 range overlaps only with
		 * positive portion of the s64 range.
		 *
		 * 0                                                   U64_MAX
		 * |  [xxxxxxxxxxxxxx u64 range xxxxxxxxxxxxxx]              |
		 * |----------------------------|----------------------------|
		 * |xxxxx s64 range xxxxxxxxx]                       [xxxxxxx|
		 * 0                     S64_MAX S64_MIN                    -1
		 *
		 * We can thus derive the following new s64 and u64 ranges.
		 *
		 * 0                                                   U64_MAX
		 * |  [xxxxxx u64 range xxxxx]                               |
		 * |----------------------------|----------------------------|
		 * |  [xxxxxx s64 range xxxxx]                               |
		 * 0                     S64_MAX S64_MIN                    -1
		 *
		 * If they overlap in two places, we can't derive anything
		 * because reg_state can't represent two ranges per numeric
		 * domain.
		 *
		 * 0                                                   U64_MAX
		 * |  [xxxxxxxxxxxxxxxxx u64 range xxxxxxxxxxxxxxxxx]        |
		 * |----------------------------|----------------------------|
		 * |xxxxx s64 range xxxxxxxxx]                    [xxxxxxxxxx|
		 * 0                     S64_MAX S64_MIN                    -1
		 *
		 * The first condition below corresponds to the first diagram
		 * above.
		 */
		if (reg->umax_value < (u64)reg->smin_value) {
			reg->smin_value = (s64)reg->umin_value;
			reg->umax_value = min_t(u64, reg->umax_value, reg->smax_value);
		} else if ((u64)reg->smax_value < reg->umin_value) {
			/* This second condition considers the case where the u64 range
			 * overlaps with the negative portion of the s64 range:
			 *
			 * 0                                                   U64_MAX
			 * |              [xxxxxxxxxxxxxx u64 range xxxxxxxxxxxxxx]  |
			 * |----------------------------|----------------------------|
			 * |xxxxxxxxx]                       [xxxxxxxxxxxx s64 range |
			 * 0                     S64_MAX S64_MIN                    -1
			 */
			reg->smax_value = (s64)reg->umax_value;
			reg->umin_value = max_t(u64, reg->umin_value, reg->smin_value);
		}
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __reg_assign_32_into_64(struct bpf_reg_state *reg)
{
	reg->umin_value = reg->u32_min_value;
	reg->umax_value = reg->u32_max_value;

	/* Attempt to pull 32-bit signed bounds into 64-bit bounds but must
	 * be positive otherwise set to worse case bounds and refine later
	 * from tnum.
	 */
	if (__reg32_bound_s64(reg->s32_min_value) &&
	    __reg32_bound_s64(reg->s32_max_value)) {
		reg->smin_value = reg->s32_min_value;
		reg->smax_value = reg->s32_max_value;
	} else {
		reg->smin_value = 0;
		reg->smax_value = U32_MAX;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __reg_bound_offset(struct bpf_reg_state *reg)
{
	struct tnum var64_off = tnum_intersect(reg->var_off,
					       tnum_range(reg->umin_value,
							  reg->umax_value));
	struct tnum var32_off = tnum_intersect(tnum_subreg(var64_off),
					       tnum_range(reg->u32_min_value,
							  reg->u32_max_value));

	reg->var_off = tnum_or(tnum_clear_subreg(var64_off), var32_off);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __reg_deduce_bounds(struct bpf_reg_state *reg)
{
	__reg32_deduce_bounds(reg);
	__reg64_deduce_bounds(reg);
	__reg_deduce_mixed_bounds(reg);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __reg_deduce_mixed_bounds(struct bpf_reg_state *reg)
{
	/* Try to tighten 64-bit bounds from 32-bit knowledge, using 32-bit
	 * values on both sides of 64-bit range in hope to have tighter range.
	 * E.g., if r1 is [0x1'00000000, 0x3'80000000], and we learn from
	 * 32-bit signed > 0 operation that s32 bounds are now [1; 0x7fffffff].
	 * With this, we can substitute 1 as low 32-bits of _low_ 64-bit bound
	 * (0x100000000 -> 0x100000001) and 0x7fffffff as low 32-bits of
	 * _high_ 64-bit bound (0x380000000 -> 0x37fffffff) and arrive at a
	 * better overall bounds for r1 as [0x1'000000001; 0x3'7fffffff].
	 * We just need to make sure that derived bounds we are intersecting
	 * with are well-formed ranges in respective s64 or u64 domain, just
	 * like we do with similar kinds of 32-to-64 or 64-to-32 adjustments.
	 */
	__u64 new_umin, new_umax;
	__s64 new_smin, new_smax;

	/* u32 -> u64 tightening, it's always well-formed */
	new_umin = (reg->umin_value & ~0xffffffffULL) | reg->u32_min_value;
	new_umax = (reg->umax_value & ~0xffffffffULL) | reg->u32_max_value;
	reg->umin_value = max_t(u64, reg->umin_value, new_umin);
	reg->umax_value = min_t(u64, reg->umax_value, new_umax);
	/* u32 -> s64 tightening, u32 range embedded into s64 preserves range validity */
	new_smin = (reg->smin_value & ~0xffffffffULL) | reg->u32_min_value;
	new_smax = (reg->smax_value & ~0xffffffffULL) | reg->u32_max_value;
	reg->smin_value = max_t(s64, reg->smin_value, new_smin);
	reg->smax_value = min_t(s64, reg->smax_value, new_smax);

	/* Here we would like to handle a special case after sign extending load,
	 * when upper bits for a 64-bit range are all 1s or all 0s.
	 *
	 * Upper bits are all 1s when register is in a range:
	 *   [0xffff_ffff_0000_0000, 0xffff_ffff_ffff_ffff]
	 * Upper bits are all 0s when register is in a range:
	 *   [0x0000_0000_0000_0000, 0x0000_0000_ffff_ffff]
	 * Together this forms are continuous range:
	 *   [0xffff_ffff_0000_0000, 0x0000_0000_ffff_ffff]
	 *
	 * Now, suppose that register range is in fact tighter:
	 *   [0xffff_ffff_8000_0000, 0x0000_0000_ffff_ffff] (R)
	 * Also suppose that it's 32-bit range is positive,
	 * meaning that lower 32-bits of the full 64-bit register
	 * are in the range:
	 *   [0x0000_0000, 0x7fff_ffff] (W)
	 *
	 * If this happens, then any value in a range:
	 *   [0xffff_ffff_0000_0000, 0xffff_ffff_7fff_ffff]
	 * is smaller than a lowest bound of the range (R):
	 *   0xffff_ffff_8000_0000
	 * which means that upper bits of the full 64-bit register
	 * can't be all 1s, when lower bits are in range (W).
	 *
	 * Note that:
	 *  - 0xffff_ffff_8000_0000 == (s64)S32_MIN
	 *  - 0x0000_0000_7fff_ffff == (s64)S32_MAX
	 * These relations are used in the conditions below.
	 */
	if (reg->s32_min_value >= 0 && reg->smin_value >= S32_MIN && reg->smax_value <= S32_MAX) {
		reg->smin_value = reg->s32_min_value;
		reg->smax_value = reg->s32_max_value;
		reg->umin_value = reg->s32_min_value;
		reg->umax_value = reg->s32_max_value;
		reg->var_off = tnum_intersect(reg->var_off,
					      tnum_range(reg->smin_value, reg->smax_value));
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __scalar32_min_max_lsh(struct bpf_reg_state *dst_reg,
				   u64 umin_val, u64 umax_val)
{
	/* We lose all sign bit information (except what we can pick
	 * up from var_off)
	 */
	dst_reg->s32_min_value = S32_MIN;
	dst_reg->s32_max_value = S32_MAX;
	/* If we might shift our top bit out, then we know nothing */
	if (umax_val > 31 || dst_reg->u32_max_value > 1ULL << (31 - umax_val)) {
		dst_reg->u32_min_value = 0;
		dst_reg->u32_max_value = U32_MAX;
	} else {
		dst_reg->u32_min_value <<= umin_val;
		dst_reg->u32_max_value <<= umax_val;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __scalar64_min_max_lsh(struct bpf_reg_state *dst_reg,
				   u64 umin_val, u64 umax_val)
{
	/* Special case <<32 because it is a common compiler pattern to sign
	 * extend subreg by doing <<32 s>>32. smin/smax assignments are correct
	 * because s32 bounds don't flip sign when shifting to the left by
	 * 32bits.
	 */
	if (umin_val == 32 && umax_val == 32) {
		dst_reg->smax_value = (s64)dst_reg->s32_max_value << 32;
		dst_reg->smin_value = (s64)dst_reg->s32_min_value << 32;
	} else {
		dst_reg->smax_value = S64_MAX;
		dst_reg->smin_value = S64_MIN;
	}

	/* If we might shift our top bit out, then we know nothing */
	if (dst_reg->umax_value > 1ULL << (63 - umax_val)) {
		dst_reg->umin_value = 0;
		dst_reg->umax_value = U64_MAX;
	} else {
		dst_reg->umin_value <<= umin_val;
		dst_reg->umax_value <<= umax_val;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __update_reg32_bounds(struct bpf_reg_state *reg)
{
	struct tnum var32_off = tnum_subreg(reg->var_off);

	/* min signed is max(sign bit) | min(other bits) */
	reg->s32_min_value = max_t(s32, reg->s32_min_value,
			var32_off.value | (var32_off.mask & S32_MIN));
	/* max signed is min(sign bit) | max(other bits) */
	reg->s32_max_value = min_t(s32, reg->s32_max_value,
			var32_off.value | (var32_off.mask & S32_MAX));
	reg->u32_min_value = max_t(u32, reg->u32_min_value, (u32)var32_off.value);
	reg->u32_max_value = min(reg->u32_max_value,
				 (u32)(var32_off.value | var32_off.mask));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __update_reg64_bounds(struct bpf_reg_state *reg)
{
	u64 tnum_next, tmax;
	bool umin_in_tnum;

	/* min signed is max(sign bit) | min(other bits) */
	reg->smin_value = max_t(s64, reg->smin_value,
				reg->var_off.value | (reg->var_off.mask & S64_MIN));
	/* max signed is min(sign bit) | max(other bits) */
	reg->smax_value = min_t(s64, reg->smax_value,
				reg->var_off.value | (reg->var_off.mask & S64_MAX));
	reg->umin_value = max(reg->umin_value, reg->var_off.value);
	reg->umax_value = min(reg->umax_value,
			      reg->var_off.value | reg->var_off.mask);

	/* Check if u64 and tnum overlap in a single value */
	tnum_next = tnum_step(reg->var_off, reg->umin_value);
	umin_in_tnum = (reg->umin_value & ~reg->var_off.mask) == reg->var_off.value;
	tmax = reg->var_off.value | reg->var_off.mask;
	if (umin_in_tnum && tnum_next > reg->umax_value) {
		/* The u64 range and the tnum only overlap in umin.
		 * u64:  ---[xxxxxx]-----
		 * tnum: --xx----------x-
		 */
		___mark_reg_known(reg, reg->umin_value);
	} else if (!umin_in_tnum && tnum_next == tmax) {
		/* The u64 range and the tnum only overlap in the maximum value
		 * represented by the tnum, called tmax.
		 * u64:  ---[xxxxxx]-----
		 * tnum: xx-----x--------
		 */
		___mark_reg_known(reg, tmax);
	} else if (!umin_in_tnum && tnum_next <= reg->umax_value &&
		   tnum_step(reg->var_off, tnum_next) > reg->umax_value) {
		/* The u64 range and the tnum only overlap in between umin
		 * (excluded) and umax.
		 * u64:  ---[xxxxxx]-----
		 * tnum: xx----x-------x-
		 */
		___mark_reg_known(reg, tnum_next);
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void __update_reg_bounds(struct bpf_reg_state *reg)
{
	__update_reg32_bounds(reg);
	__update_reg64_bounds(reg);
}


