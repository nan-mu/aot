// Extracted from /Users/nan/bs/aot/src/verifier.c
static void sync_linked_regs(struct bpf_verifier_env *env, struct bpf_verifier_state *vstate,
			     struct bpf_reg_state *known_reg, struct linked_regs *linked_regs)
{
	struct bpf_reg_state fake_reg;
	struct bpf_reg_state *reg;
	struct linked_reg *e;
	int i;

	for (i = 0; i < linked_regs->cnt; ++i) {
		e = &linked_regs->entries[i];
		reg = e->is_reg ? &vstate->frame[e->frameno]->regs[e->regno]
				: &vstate->frame[e->frameno]->stack[e->spi].spilled_ptr;
		if (reg->type != SCALAR_VALUE || reg == known_reg)
			continue;
		if ((reg->id & ~BPF_ADD_CONST) != (known_reg->id & ~BPF_ADD_CONST))
			continue;
		/*
		 * Skip mixed 32/64-bit links: the delta relationship doesn't
		 * hold across different ALU widths.
		 */
		if (((reg->id ^ known_reg->id) & BPF_ADD_CONST) == BPF_ADD_CONST)
			continue;
		if ((!(reg->id & BPF_ADD_CONST) && !(known_reg->id & BPF_ADD_CONST)) ||
		    reg->off == known_reg->off) {
			s32 saved_subreg_def = reg->subreg_def;

			copy_register_state(reg, known_reg);
			reg->subreg_def = saved_subreg_def;
		} else {
			s32 saved_subreg_def = reg->subreg_def;
			s32 saved_off = reg->off;
			u32 saved_id = reg->id;

			fake_reg.type = SCALAR_VALUE;
			inner_mark_reg_known(&fake_reg, (s64)reg->off - (s64)known_reg->off);

			/* reg = known_reg; reg += delta */
			copy_register_state(reg, known_reg);
			/*
			 * Must preserve off, id and subreg_def flag,
			 * otherwise another sync_linked_regs() will be incorrect.
			 */
			reg->off = saved_off;
			reg->id = saved_id;
			reg->subreg_def = saved_subreg_def;

			scalar32_min_max_add(reg, &fake_reg);
			scalar_min_max_add(reg, &fake_reg);
			reg->var_off = tnum_add(reg->var_off, fake_reg.var_off);
			if ((reg->id | known_reg->id) & BPF_ADD_CONST32)
				zext_32_to_64(reg);
			reg_bounds_sync(reg);
		}
		if (e->is_reg)
			mark_reg_scratched(env, e->regno);
		else
			mark_stack_slot_scratched(env, e->spi);
	}
}


