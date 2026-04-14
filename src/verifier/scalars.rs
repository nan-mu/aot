// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool scalars_exact_for_widen(const struct bpf_reg_state *rold,
				    const struct bpf_reg_state *rcur)
{
	return !memcmp(rold, rcur, offsetof(struct bpf_reg_state, id));
}


