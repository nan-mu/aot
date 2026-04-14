// Extracted from /Users/nan/bs/aot/src/verifier.c
static int find_btf_percpu_datasec(struct btf *btf)
{
	const struct btf_type *t;
	const char *tname;
	int i, n;

	/*
	 * Both vmlinux and module each have their own ".data..percpu"
	 * DATASECs in BTF. So for module's case, we need to skip vmlinux BTF
	 * types to look at only module's own BTF types.
	 */
	n = btf_nr_types(btf);
	for (i = btf_named_start_id(btf, true); i < n; i++) {
		t = btf_type_by_id(btf, i);
		if (BTF_INFO_KIND(t->info) != BTF_KIND_DATASEC)
			continue;

		tname = btf_name_by_offset(btf, t->name_off);
		if (!strcmp(tname, ".data..percpu"))
			return i;
	}

	return -ENOENT;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void find_good_pkt_pointers(struct bpf_verifier_state *vstate,
				   struct bpf_reg_state *dst_reg,
				   enum bpf_reg_type type,
				   bool range_right_open)
{
	struct bpf_func_state *state;
	struct bpf_reg_state *reg;
	int new_range;

	if (dst_reg->off < 0 ||
	    (dst_reg->off == 0 && range_right_open))
		/* This doesn't give us any range */
		return;

	if (dst_reg->umax_value > MAX_PACKET_OFF ||
	    dst_reg->umax_value + dst_reg->off > MAX_PACKET_OFF)
		/* Risk of overflow.  For instance, ptr + (1<<63) may be less
		 * than pkt_end, but that's because it's also less than pkt.
		 */
		return;

	new_range = dst_reg->off;
	if (range_right_open)
		new_range++;

	/* Examples for register markings:
	 *
	 * pkt_data in dst register:
	 *
	 *   r2 = r3;
	 *   r2 += 8;
	 *   if (r2 > pkt_end) goto <handle exception>
	 *   <access okay>
	 *
	 *   r2 = r3;
	 *   r2 += 8;
	 *   if (r2 < pkt_end) goto <access okay>
	 *   <handle exception>
	 *
	 *   Where:
	 *     r2 == dst_reg, pkt_end == src_reg
	 *     r2=pkt(id=n,off=8,r=0)
	 *     r3=pkt(id=n,off=0,r=0)
	 *
	 * pkt_data in src register:
	 *
	 *   r2 = r3;
	 *   r2 += 8;
	 *   if (pkt_end >= r2) goto <access okay>
	 *   <handle exception>
	 *
	 *   r2 = r3;
	 *   r2 += 8;
	 *   if (pkt_end <= r2) goto <handle exception>
	 *   <access okay>
	 *
	 *   Where:
	 *     pkt_end == dst_reg, r2 == src_reg
	 *     r2=pkt(id=n,off=8,r=0)
	 *     r3=pkt(id=n,off=0,r=0)
	 *
	 * Find register r3 and mark its range as r3=pkt(id=n,off=0,r=8)
	 * or r3=pkt(id=n,off=0,r=8-1), so that range of bytes [r3, r3 + 8)
	 * and [r3, r3 + 8-1) respectively is safe to access depending on
	 * the check.
	 */

	/* If our ids match, then we must have the same max_value.  And we
	 * don't care about the other reg's fixed offset, since if it's too big
	 * the range won't allow anything.
	 * dst_reg->off is known < MAX_PACKET_OFF, therefore it fits in a u16.
	 */
	bpf_for_each_reg_in_vstate(vstate, state, reg, ({
		if (reg->type == type && reg->id == dst_reg->id)
			/* keep the maximum range already checked */
			reg->range = max(reg->range, new_range);
	}));
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
find_kfunc_desc(const struct bpf_prog *prog, u32 func_id, u16 offset)
{
	struct bpf_kfunc_desc desc = {
		.func_id = func_id,
		.offset = offset,
	};
	struct bpf_kfunc_desc_tab *tab;

	tab = prog->aux->kfunc_tab;
	return bsearch(&desc, tab->descs, tab->nr_descs,
		       sizeof(tab->descs[0]), kfunc_desc_cmp_by_id_off);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct btf *find_kfunc_desc_btf(struct bpf_verifier_env *env, s16 offset)
{
	if (offset) {
		if (offset < 0) {
			/* In the future, this can be allowed to increase limit
			 * of fd index into fd_array, interpreted as u16.
			 */
			verbose(env, "negative offset disallowed for kernel module function call\n");
			return ERR_PTR(-EINVAL);
		}

		return inner_find_kfunc_desc_btf(env, offset);
	}
	return btf_vmlinux ?: ERR_PTR(-ENOENT);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static const struct btf_type *find_kfunc_impl_proto(struct bpf_verifier_env *env,
						    struct btf *btf,
						    const char *func_name)
{
	char *buf = env->tmp_str_buf;
	const struct btf_type *func;
	s32 impl_id;
	int len;

	len = snprintf(buf, TMP_STR_BUF_LEN, "%s%s", func_name, KF_IMPL_SUFFIX);
	if (len < 0 || len >= TMP_STR_BUF_LEN) {
		verbose(env, "function name %s%s is too long\n", func_name, KF_IMPL_SUFFIX);
		return NULL;
	}

	impl_id = btf_find_by_name_kind(btf, buf, BTF_KIND_FUNC);
	if (impl_id <= 0) {
		verbose(env, "cannot find function %s in BTF\n", buf);
		return NULL;
	}

	func = btf_type_by_id(btf, impl_id);

	return btf_type_by_id(btf, func->type);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_reference_state *find_lock_state(struct bpf_verifier_state *state, enum ref_state_type type,
						   int id, void *ptr)
{
	int i;

	for (i = 0; i < state->acquired_refs; i++) {
		struct bpf_reference_state *s = &state->refs[i];

		if (!(s->type & type))
			continue;

		if (s->id == id && s->ptr == ptr)
			return s;
	}
	return NULL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_verifier_state *find_prev_entry(struct bpf_verifier_env *env,
						  struct bpf_verifier_state *cur,
						  int insn_idx)
{
	struct bpf_verifier_state_list *sl;
	struct bpf_verifier_state *st;
	struct list_head *pos, *head;

	/* Explored states are pushed in stack order, most recent states come first */
	head = explored_state(env, insn_idx);
	list_for_each(pos, head) {
		sl = container_of(pos, struct bpf_verifier_state_list, node);
		/* If st->branches != 0 state is a part of current DFS verification path,
		 * hence cur & st for a loop.
		 */
		st = &sl->state;
		if (st->insn_idx == insn_idx && st->branches && same_callsites(st, cur) &&
		    st->dfs_depth < cur->dfs_depth)
			return st;
	}

	return NULL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool find_reference_state(struct bpf_verifier_state *state, int ptr_id)
{
	int i;

	for (i = 0; i < state->acquired_refs; i++)
		if (state->refs[i].id == ptr_id)
			return true;

	return false;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int find_subprog(struct bpf_verifier_env *env, int off)
{
	struct bpf_subprog_info *p;

	p = bpf_find_containing_subprog(env, off);
	if (!p || p->start != off)
		return -ENOENT;
	return p - env->subprog_info;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct btf *inner_find_kfunc_desc_btf(struct bpf_verifier_env *env,
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

