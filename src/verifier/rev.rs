// Extracted from /Users/nan/bs/aot/src/verifier.c
static u8 rev_opcode(u8 opcode)
{
	switch (opcode) {
	case BPF_JEQ:		return BPF_JNE;
	case BPF_JNE:		return BPF_JEQ;
	/* JSET doesn't have it's reverse opcode in BPF, so add
	 * BPF_X flag to denote the reverse of that operation
	 */
	case BPF_JSET:		return BPF_JSET | BPF_X;
	case BPF_JSET | BPF_X:	return BPF_JSET;
	case BPF_JGE:		return BPF_JLT;
	case BPF_JGT:		return BPF_JLE;
	case BPF_JLE:		return BPF_JGT;
	case BPF_JLT:		return BPF_JGE;
	case BPF_JSGE:		return BPF_JSLT;
	case BPF_JSGT:		return BPF_JSLE;
	case BPF_JSLE:		return BPF_JSGT;
	case BPF_JSLT:		return BPF_JSGE;
	default:		return 0;
	}
}


