// Extracted from /Users/nan/bs/aot/src/verifier.c
static int cmp_ptr_to_u32(const void *a, const void *b)
{
	return *(u32 *)a - *(u32 *)b;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int cmp_subprogs(const void *a, const void *b)
{
	return ((struct bpf_subprog_info *)a)->start -
	       ((struct bpf_subprog_info *)b)->start;
}


