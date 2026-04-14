// Extracted from /Users/nan/bs/aot/src/verifier.c
static u32 frame_insn_idx(struct bpf_verifier_state *st, u32 frame)
{
	return frame == st->curframe
	       ? st->insn_idx
	       : st->frame[frame + 1]->callsite;
}


