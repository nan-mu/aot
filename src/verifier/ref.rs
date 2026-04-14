// Extracted from /Users/nan/bs/aot/src/verifier.c
static int ref_convert_owning_non_owning(struct bpf_verifier_env *env, u32 ref_obj_id)
{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_func_state *unused;
	struct bpf_reg_state *reg;
	int i;

	if (!ref_obj_id) {
		verifier_bug(env, "ref_obj_id is zero for owning -> non-owning conversion");
		return -EFAULT;
	}

	for (i = 0; i < state->acquired_refs; i++) {
		if (state->refs[i].id != ref_obj_id)
			continue;

		/* Clear ref_obj_id here so release_reference doesn't clobber
		 * the whole reg
		 */
		bpf_for_each_reg_in_vstate(env->cur_state, unused, reg, ({
			if (reg->ref_obj_id == ref_obj_id) {
				reg->ref_obj_id = 0;
				ref_set_non_owning(env, reg);
			}
		}));
		return 0;
	}

	verifier_bug(env, "ref state missing for ref_obj_id");
	return -EFAULT;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int ref_set_non_owning(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	struct btf_record *rec = reg_btf_record(reg);

	if (!env->cur_state->active_locks) {
		verifier_bug(env, "%s w/o active lock", __func__);
		return -EFAULT;
	}

	if (type_flag(reg->type) & NON_OWN_REF) {
		verifier_bug(env, "NON_OWN_REF already set");
		return -EFAULT;
	}

	reg->type |= NON_OWN_REF;
	if (rec->refcount_off >= 0)
		reg->type |= MEM_RCU;

	return 0;
}


