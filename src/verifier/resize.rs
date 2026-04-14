// Extracted from /Users/nan/bs/aot/src/verifier.c
static int resize_reference_state(struct bpf_verifier_state *state, size_t n)
{
	state->refs = realloc_array(state->refs, state->acquired_refs, n,
				    sizeof(struct bpf_reference_state));
	if (!state->refs)
		return -ENOMEM;

	state->acquired_refs = n;
	return 0;
}


