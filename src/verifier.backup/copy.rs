// Extracted from /Users/nan/bs/aot/src/verifier.c
static void *copy_array(void *dst, const void *src, size_t n, size_t size, gfp_t flags)
{
	size_t alloc_bytes;
	void *orig = dst;
	size_t bytes;

	if (ZERO_OR_NULL_PTR(src))
		goto out;

	if (unlikely(check_mul_overflow(n, size, &bytes)))
		return NULL;

	alloc_bytes = max(ksize(orig), kmalloc_size_roundup(bytes));
	dst = krealloc(orig, alloc_bytes, flags);
	if (!dst) {
		kfree(orig);
		return NULL;
	}

	memcpy(dst, src, bytes);
out:
	return dst ? dst : ZERO_SIZE_PTR;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int copy_func_state(struct bpf_func_state *dst,
			   const struct bpf_func_state *src)
{
	memcpy(dst, src, offsetof(struct bpf_func_state, stack));
	return copy_stack_state(dst, src);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int copy_insn_array(struct bpf_map *map, u32 start, u32 end, u32 *items)
{
	struct bpf_insn_array_value *value;
	u32 i;

	for (i = start; i <= end; i++) {
		value = map->ops->map_lookup_elem(map, &i);
		/*
		 * map_lookup_elem of an array map will never return an error,
		 * but not checking it makes some static analysers to worry
		 */
		if (IS_ERR(value))
			return PTR_ERR(value);
		else if (!value)
			return -EINVAL;
		items[i - start] = value->xlated_off;
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int copy_insn_array_uniq(struct bpf_map *map, u32 start, u32 end, u32 *off)
{
	u32 n = end - start + 1;
	int err;

	err = copy_insn_array(map, start, end, off);
	if (err)
		return err;

	return sort_insn_array_uniq(off, n);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int copy_reference_state(struct bpf_verifier_state *dst, const struct bpf_verifier_state *src)
{
	dst->refs = copy_array(dst->refs, src->refs, src->acquired_refs,
			       sizeof(struct bpf_reference_state), GFP_KERNEL_ACCOUNT);
	if (!dst->refs)
		return -ENOMEM;

	dst->acquired_refs = src->acquired_refs;
	dst->active_locks = src->active_locks;
	dst->active_preempt_locks = src->active_preempt_locks;
	dst->active_rcu_locks = src->active_rcu_locks;
	dst->active_irq_id = src->active_irq_id;
	dst->active_lock_id = src->active_lock_id;
	dst->active_lock_ptr = src->active_lock_ptr;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void copy_register_state(struct bpf_reg_state *dst, const struct bpf_reg_state *src)
{
	*dst = *src;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int copy_stack_state(struct bpf_func_state *dst, const struct bpf_func_state *src)
{
	size_t n = src->allocated_stack / BPF_REG_SIZE;

	dst->stack = copy_array(dst->stack, src->stack, n, sizeof(struct bpf_stack_state),
				GFP_KERNEL_ACCOUNT);
	if (!dst->stack)
		return -ENOMEM;

	dst->allocated_stack = src->allocated_stack;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int copy_verifier_state(struct bpf_verifier_state *dst_state,
			       const struct bpf_verifier_state *src)
{
	struct bpf_func_state *dst;
	int i, err;

	dst_state->jmp_history = copy_array(dst_state->jmp_history, src->jmp_history,
					  src->jmp_history_cnt, sizeof(*dst_state->jmp_history),
					  GFP_KERNEL_ACCOUNT);
	if (!dst_state->jmp_history)
		return -ENOMEM;
	dst_state->jmp_history_cnt = src->jmp_history_cnt;

	/* if dst has more stack frames then src frame, free them, this is also
	 * necessary in case of exceptional exits using bpf_throw.
	 */
	for (i = src->curframe + 1; i <= dst_state->curframe; i++) {
		free_func_state(dst_state->frame[i]);
		dst_state->frame[i] = NULL;
	}
	err = copy_reference_state(dst_state, src);
	if (err)
		return err;
	dst_state->speculative = src->speculative;
	dst_state->in_sleepable = src->in_sleepable;
	dst_state->cleaned = src->cleaned;
	dst_state->curframe = src->curframe;
	dst_state->branches = src->branches;
	dst_state->parent = src->parent;
	dst_state->first_insn_idx = src->first_insn_idx;
	dst_state->last_insn_idx = src->last_insn_idx;
	dst_state->dfs_depth = src->dfs_depth;
	dst_state->callback_unroll_depth = src->callback_unroll_depth;
	dst_state->may_goto_depth = src->may_goto_depth;
	dst_state->equal_state = src->equal_state;
	for (i = 0; i <= src->curframe; i++) {
		dst = dst_state->frame[i];
		if (!dst) {
			dst = kzalloc_obj(*dst, GFP_KERNEL_ACCOUNT);
			if (!dst)
				return -ENOMEM;
			dst_state->frame[i] = dst;
		}
		err = copy_func_state(dst, src->frame[i]);
		if (err)
			return err;
	}
	return 0;
}


