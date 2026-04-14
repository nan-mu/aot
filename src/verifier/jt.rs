// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_iarray *jt_from_map(struct bpf_map *map)
{
	struct bpf_iarray *jt;
	int err;
	int n;

	jt = iarray_realloc(NULL, map->max_entries);
	if (!jt)
		return ERR_PTR(-ENOMEM);

	n = copy_insn_array_uniq(map, 0, map->max_entries - 1, jt->items);
	if (n < 0) {
		err = n;
		goto err_free;
	}
	if (n == 0) {
		err = -EINVAL;
		goto err_free;
	}
	jt->cnt = n;
	return jt;

err_free:
	kvfree(jt);
	return ERR_PTR(err);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_iarray *jt_from_subprog(struct bpf_verifier_env *env,
					  int subprog_start, int subprog_end)
{
	struct bpf_iarray *jt = NULL;
	struct bpf_map *map;
	struct bpf_iarray *jt_cur;
	int i;

	for (i = 0; i < env->insn_array_map_cnt; i++) {
		/*
		 * TODO (when needed): collect only jump tables, not static keys
		 * or maps for indirect calls
		 */
		map = env->insn_array_maps[i];

		jt_cur = jt_from_map(map);
		if (IS_ERR(jt_cur)) {
			kvfree(jt);
			return jt_cur;
		}

		/*
		 * This is enough to check one element. The full table is
		 * checked to fit inside the subprog later in create_jt()
		 */
		if (jt_cur->items[0] >= subprog_start && jt_cur->items[0] < subprog_end) {
			u32 old_cnt = jt ? jt->cnt : 0;
			jt = iarray_realloc(jt, old_cnt + jt_cur->cnt);
			if (!jt) {
				kvfree(jt_cur);
				return ERR_PTR(-ENOMEM);
			}
			memcpy(jt->items + old_cnt, jt_cur->items, jt_cur->cnt << 2);
		}

		kvfree(jt_cur);
	}

	if (!jt) {
		verbose(env, "no jump tables found for subprog starting at %u\n", subprog_start);
		return ERR_PTR(-EINVAL);
	}

	jt->cnt = sort_insn_array_uniq(jt->items, jt->cnt);
	return jt;
}


