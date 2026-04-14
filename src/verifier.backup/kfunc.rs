// Extracted from /Users/nan/bs/aot/src/verifier.c
static int kfunc_btf_cmp_by_off(const void *a, const void *b)
{
	const struct bpf_kfunc_btf *d0 = a;
	const struct bpf_kfunc_btf *d1 = b;

	return d0->offset - d1->offset;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int kfunc_desc_cmp_by_id_off(const void *a, const void *b)
{
	const struct bpf_kfunc_desc *d0 = a;
	const struct bpf_kfunc_desc *d1 = b;

	/* func_id is not greater than BTF_MAX_TYPE */
	return d0->func_id - d1->func_id ?: d0->offset - d1->offset;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int kfunc_desc_cmp_by_imm_off(const void *a, const void *b)
{
	const struct bpf_kfunc_desc *d0 = a;
	const struct bpf_kfunc_desc *d1 = b;

	if (d0->imm != d1->imm)
		return d0->imm < d1->imm ? -1 : 1;
	if (d0->offset != d1->offset)
		return d0->offset < d1->offset ? -1 : 1;
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool kfunc_spin_allowed(u32 btf_id)
{
	return is_bpf_graph_api_kfunc(btf_id) || is_bpf_iter_num_api_kfunc(btf_id) ||
	       is_bpf_res_spin_lock_kfunc(btf_id) || is_bpf_arena_kfunc(btf_id) ||
	       is_bpf_stream_kfunc(btf_id);
}


