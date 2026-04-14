// Extracted from /Users/nan/bs/aot/src/verifier.c
static __init int unbound_reg_init(void)
{
	__mark_reg_unknown_imprecise(&unbound_reg);
	return 0;
}


