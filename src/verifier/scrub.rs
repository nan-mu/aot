// Extracted from /Users/nan/bs/aot/src/verifier.c
static void scrub_spilled_slot(u8 *stype)
{
	if (*stype != STACK_INVALID)
		*stype = STACK_MISC;
}


