// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_iarray *iarray_realloc(struct bpf_iarray *old, size_t n_elem)
{
	size_t new_size = sizeof(struct bpf_iarray) + n_elem * sizeof(old->items[0]);
	struct bpf_iarray *new;

	new = kvrealloc(old, new_size, GFP_KERNEL_ACCOUNT);
	if (!new) {
		/* this is what callers always want, so simplify the call site */
		kvfree(old);
		return NULL;
	}

	new->cnt = n_elem;
	return new;
}


