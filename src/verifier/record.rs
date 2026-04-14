// Extracted from /Users/nan/bs/aot/src/verifier.c
record_func_key(struct bpf_verifier_env *env, struct bpf_call_arg_meta *meta,
		int func_id, int insn_idx)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	struct bpf_reg_state *reg;
	struct bpf_map *map = meta->map.ptr;
	u64 val, max;
	int err;

	if (func_id != BPF_FUNC_tail_call)
		return 0;
	if (!map || map->map_type != BPF_MAP_TYPE_PROG_ARRAY) {
		verbose(env, "expected prog array map for tail call");
		return -EINVAL;
	}

	reg = reg_state(env, BPF_REG_3);
	val = reg->var_off.value;
	max = map->max_entries;

	if (!(is_reg_const(reg, false) && val < max)) {
		bpf_map_key_store(aux, BPF_MAP_KEY_POISON);
		return 0;
	}

	err = mark_chain_precision(env, BPF_REG_3);
	if (err)
		return err;
	if (bpf_map_key_unseen(aux))
		bpf_map_key_store(aux, val);
	else if (!bpf_map_key_poisoned(aux) &&
		  bpf_map_key_immediate(aux) != val)
		bpf_map_key_store(aux, BPF_MAP_KEY_POISON);
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
record_func_map(struct bpf_verifier_env *env, struct bpf_call_arg_meta *meta,
		int func_id, int insn_idx)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];
	struct bpf_map *map = meta->map.ptr;

	if (func_id != BPF_FUNC_tail_call &&
	    func_id != BPF_FUNC_map_lookup_elem &&
	    func_id != BPF_FUNC_map_update_elem &&
	    func_id != BPF_FUNC_map_delete_elem &&
	    func_id != BPF_FUNC_map_push_elem &&
	    func_id != BPF_FUNC_map_pop_elem &&
	    func_id != BPF_FUNC_map_peek_elem &&
	    func_id != BPF_FUNC_for_each_map_elem &&
	    func_id != BPF_FUNC_redirect_map &&
	    func_id != BPF_FUNC_map_lookup_percpu_elem)
		return 0;

	if (map == NULL) {
		verifier_bug(env, "expected map for helper call");
		return -EFAULT;
	}

	/* In case of read-only, some additional restrictions
	 * need to be applied in order to prevent altering the
	 * state of the map from program side.
	 */
	if ((map->map_flags & BPF_F_RDONLY_PROG) &&
	    (func_id == BPF_FUNC_map_delete_elem ||
	     func_id == BPF_FUNC_map_update_elem ||
	     func_id == BPF_FUNC_map_push_elem ||
	     func_id == BPF_FUNC_map_pop_elem)) {
		verbose(env, "write into map forbidden\n");
		return -EACCES;
	}

	if (!aux->map_ptr_state.map_ptr)
		bpf_map_ptr_store(aux, meta->map.ptr,
				  !meta->map.ptr->bypass_spec_v1, false);
	else if (aux->map_ptr_state.map_ptr != meta->map.ptr)
		bpf_map_ptr_store(aux, meta->map.ptr,
				  !meta->map.ptr->bypass_spec_v1, true);
	return 0;
}


