// Extracted from /Users/nan/bs/aot/src/verifier.c
static const char *disasm_kfunc_name(void *data, const struct bpf_insn *insn)
{
	const struct btf_type *func;
	struct btf *desc_btf;

	if (insn->src_reg != BPF_PSEUDO_KFUNC_CALL)
		return NULL;

	desc_btf = find_kfunc_desc_btf(data, insn->off);
	if (IS_ERR(desc_btf))
		return "<error>";

	func = btf_type_by_id(desc_btf, insn->imm);
	return btf_name_by_offset(desc_btf, func->name_off);
}


