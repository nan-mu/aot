// Extracted from /Users/nan/bs/aot/src/verifier.c
static int stack_slot_obj_get_spi(struct bpf_verifier_env *env, struct bpf_reg_state *reg,
			          const char *obj_kind, int nr_slots)
{
	int off, spi;

	if (!tnum_is_const(reg->var_off)) {
		verbose(env, "%s has to be at a constant offset\n", obj_kind);
		return -EINVAL;
	}

	off = reg->off + reg->var_off.value;
	if (off % BPF_REG_SIZE) {
		verbose(env, "cannot pass in %s at an offset=%d\n", obj_kind, off);
		return -EINVAL;
	}

	spi = __get_spi(off);
	if (spi + 1 < nr_slots) {
		verbose(env, "cannot pass in %s at an offset=%d\n", obj_kind, off);
		return -EINVAL;
	}

	if (!is_spi_bounds_valid(func(env, reg), spi, nr_slots))
		return -ERANGE;
	return spi;
}


