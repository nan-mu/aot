// Extracted from /Users/nan/bs/aot/src/verifier.c
static int indirect_jump_min_max_index(struct bpf_verifier_env *env,
				       int regno,
				       struct bpf_map *map,
				       u32 *pmin_index, u32 *pmax_index)
{
	struct bpf_reg_state *reg = reg_state(env, regno);
	u64 min_index, max_index;
	const u32 size = 8;

	if (check_add_overflow(reg->umin_value, reg->off, &min_index) ||
		(min_index > (u64) U32_MAX * size)) {
		verbose(env, "the sum of R%u umin_value %llu and off %u is too big\n",
			     regno, reg->umin_value, reg->off);
		return -ERANGE;
	}
	if (check_add_overflow(reg->umax_value, reg->off, &max_index) ||
		(max_index > (u64) U32_MAX * size)) {
		verbose(env, "the sum of R%u umax_value %llu and off %u is too big\n",
			     regno, reg->umax_value, reg->off);
		return -ERANGE;
	}

	min_index /= size;
	max_index /= size;

	if (max_index >= map->max_entries) {
		verbose(env, "R%u points to outside of jump table: [%llu,%llu] max_entries %u\n",
			     regno, min_index, max_index, map->max_entries);
		return -EINVAL;
	}

	*pmin_index = min_index;
	*pmax_index = max_index;
	return 0;
}


