// Extracted from /Users/nan/bs/aot/src/verifier.c
static __init int unbound_reg_init(void)
{
	inner_mark_reg_unknown_imprecise(&unbound_reg);
	return 0;
}


