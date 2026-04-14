// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool rcu_safe_kptr(const struct btf_field *field)
{
	const struct btf_field_kptr *kptr = &field->kptr;

	return field->type == BPF_KPTR_PERCPU ||
	       (field->type == BPF_KPTR_REF && rcu_protected_object(kptr->btf, kptr->btf_id));
}


