// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool helper_multiple_ref_obj_use(enum bpf_func_id func_id,
					const struct bpf_map *map)
{
	int ref_obj_uses = 0;

	if (is_ptr_cast_function(func_id))
		ref_obj_uses++;
	if (is_acquire_function(func_id, map))
		ref_obj_uses++;
	if (is_dynptr_ref_function(func_id))
		ref_obj_uses++;

	return ref_obj_uses > 1;
}


