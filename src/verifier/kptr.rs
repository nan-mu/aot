// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct btf_record *kptr_pointee_btf_record(struct btf_field *kptr_field)
{
	struct btf_struct_meta *meta;

	if (btf_is_kernel(kptr_field->kptr.btf))
		return NULL;

	meta = btf_find_struct_meta(kptr_field->kptr.btf,
				    kptr_field->kptr.btf_id);

	return meta ? meta->record : NULL;
}


