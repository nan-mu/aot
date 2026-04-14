// Extracted from /Users/nan/bs/aot/src/verifier.c
create_jt(int t, struct bpf_verifier_env *env)
{
	static struct bpf_subprog_info *subprog;
	int subprog_start, subprog_end;
	struct bpf_iarray *jt;
	int i;

	subprog = bpf_find_containing_subprog(env, t);
	subprog_start = subprog->start;
	subprog_end = (subprog + 1)->start;
	jt = jt_from_subprog(env, subprog_start, subprog_end);
	if (IS_ERR(jt))
		return jt;

	/* Check that the every element of the jump table fits within the given subprogram */
	for (i = 0; i < jt->cnt; i++) {
		if (jt->items[i] < subprog_start || jt->items[i] >= subprog_end) {
			verbose(env, "jump table for insn %d points outside of the subprog [%u,%u]\n",
					t, subprog_start, subprog_end);
			kvfree(jt);
			return ERR_PTR(-EINVAL);
		}
	}

	return jt;
}


