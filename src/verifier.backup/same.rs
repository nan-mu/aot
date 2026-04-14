// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool same_callsites(struct bpf_verifier_state *a, struct bpf_verifier_state *b)
{
	int fr;

	if (a->curframe != b->curframe)
		return false;

	for (fr = a->curframe; fr >= 0; fr--)
		if (a->frame[fr]->callsite != b->frame[fr]->callsite)
			return false;

	return true;
}


