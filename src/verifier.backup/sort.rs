// Extracted from /Users/nan/bs/aot/src/verifier.c
static int sort_insn_array_uniq(u32 *items, int cnt)
{
	int unique = 1;
	int i;

	sort(items, cnt, sizeof(items[0]), cmp_ptr_to_u32, NULL);

	for (i = 1; i < cnt; i++)
		if (items[i] != items[unique - 1])
			items[unique++] = items[i];

	return unique;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int sort_kfunc_descs_by_imm_off(struct bpf_verifier_env *env)
{
	struct bpf_kfunc_desc_tab *tab;
	int i, err;

	tab = env->prog->aux->kfunc_tab;
	if (!tab)
		return 0;

	for (i = 0; i < tab->nr_descs; i++) {
		err = set_kfunc_desc_imm(env, &tab->descs[i]);
		if (err)
			return err;
	}

	sort(tab->descs, tab->nr_descs, sizeof(tab->descs[0]),
	     kfunc_desc_cmp_by_imm_off, NULL);
	return 0;
}


