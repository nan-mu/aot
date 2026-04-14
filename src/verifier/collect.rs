// Extracted from /Users/nan/bs/aot/src/verifier.c
static void collect_linked_regs(struct bpf_verifier_env *env,
				struct bpf_verifier_state *vstate,
				u32 id,
				struct linked_regs *linked_regs)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_func_state *func;
	struct bpf_reg_state *reg;
	u16 live_regs;
	int i, j;

	id = id & ~BPF_ADD_CONST;
	for (i = vstate->curframe; i >= 0; i--) {
		live_regs = aux[frame_insn_idx(vstate, i)].live_regs_before;
		func = vstate->frame[i];
		for (j = 0; j < BPF_REG_FP; j++) {
			if (!(live_regs & BIT(j)))
				continue;
			reg = &func->regs[j];
			inner_collect_linked_regs(linked_regs, reg, id, i, j, true);
		}
		for (j = 0; j < func->allocated_stack / BPF_REG_SIZE; j++) {
			if (!is_spilled_reg(&func->stack[j]))
				continue;
			reg = &func->stack[j].spilled_ptr;
			inner_collect_linked_regs(linked_regs, reg, id, i, j, false);
		}
	}
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void inner_collect_linked_regs(struct linked_regs *reg_set, struct bpf_reg_state *reg,
				  u32 id, u32 frameno, u32 spi_or_reg, bool is_reg)
{
	struct linked_reg *e;

	if (reg->type != SCALAR_VALUE || (reg->id & ~BPF_ADD_CONST) != id)
		return;

	e = linked_regs_push(reg_set);
	if (e) {
		e->frameno = frameno;
		e->is_reg = is_reg;
		e->regno = spi_or_reg;
	} else {
		reg->id = 0;
	}
}
