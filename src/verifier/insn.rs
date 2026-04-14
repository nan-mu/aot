// Extracted from /Users/nan/bs/aot/src/verifier.c
static int insn_def_regno(const struct bpf_insn *insn)
{
	switch (BPF_CLASS(insn->code)) {
	case BPF_JMP:
	case BPF_JMP32:
	case BPF_ST:
		return -1;
	case BPF_STX:
		if (BPF_MODE(insn->code) == BPF_ATOMIC ||
		    BPF_MODE(insn->code) == BPF_PROBE_ATOMIC) {
			if (insn->imm == BPF_CMPXCHG)
				return BPF_REG_0;
			else if (insn->imm == BPF_LOAD_ACQ)
				return insn->dst_reg;
			else if (insn->imm & BPF_FETCH)
				return insn->src_reg;
		}
		return -1;
	default:
		return insn->dst_reg;
	}
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool insn_has_def32(struct bpf_insn *insn)
{
	int dst_reg = insn_def_regno(insn);

	if (dst_reg == -1)
		return false;

	return !is_reg64(insn, dst_reg, NULL, DST_OP);
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool insn_is_cond_jump(u8 code)
{
	u8 op;

	op = BPF_OP(code);
	if (BPF_CLASS(code) == BPF_JMP32)
		return op != BPF_JA;

	if (BPF_CLASS(code) != BPF_JMP)
		return false;

	return op != BPF_JA && op != BPF_EXIT && op != BPF_CALL;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int insn_stack_access_flags(int frameno, int spi)
{
	return INSN_F_STACK_ACCESS | (spi << INSN_F_SPI_SHIFT) | frameno;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int insn_stack_access_frameno(int insn_flags)
{
	return insn_flags & INSN_F_FRAMENO_MASK;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int insn_stack_access_spi(int insn_flags)
{
	return (insn_flags >> INSN_F_SPI_SHIFT) & INSN_F_SPI_MASK;
}


