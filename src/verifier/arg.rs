// Extracted from /Users/nan/bs/aot/src/verifier.c
static enum bpf_dynptr_type arg_to_dynptr_type(enum bpf_arg_type arg_type)
{
	switch (arg_type & DYNPTR_TYPE_FLAG_MASK) {
	case DYNPTR_TYPE_LOCAL:
		return BPF_DYNPTR_TYPE_LOCAL;
	case DYNPTR_TYPE_RINGBUF:
		return BPF_DYNPTR_TYPE_RINGBUF;
	case DYNPTR_TYPE_SKB:
		return BPF_DYNPTR_TYPE_SKB;
	case DYNPTR_TYPE_XDP:
		return BPF_DYNPTR_TYPE_XDP;
	case DYNPTR_TYPE_SKB_META:
		return BPF_DYNPTR_TYPE_SKB_META;
	case DYNPTR_TYPE_FILE:
		return BPF_DYNPTR_TYPE_FILE;
	default:
		return BPF_DYNPTR_TYPE_INVALID;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool arg_type_is_dynptr(enum bpf_arg_type type)
{
	return base_type(type) == ARG_PTR_TO_DYNPTR;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool arg_type_is_mem_size(enum bpf_arg_type type)
{
	return type == ARG_CONST_SIZE ||
	       type == ARG_CONST_SIZE_OR_ZERO;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool arg_type_is_raw_mem(enum bpf_arg_type type)
{
	return base_type(type) == ARG_PTR_TO_MEM &&
	       type & MEM_UNINIT;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool arg_type_is_release(enum bpf_arg_type type)
{
	return type & OBJ_RELEASE;
}


