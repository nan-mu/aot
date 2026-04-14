// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool error_recoverable_with_nospec(int err)
{
	/* Should only return true for non-fatal errors that are allowed to
	 * occur during speculative verification. For these we can insert a
	 * nospec and the program might still be accepted. Do not include
	 * something like ENOMEM because it is likely to re-occur for the next
	 * architectural path once it has been recovered-from in all speculative
	 * paths.
	 */
	return err == -EPERM || err == -EACCES || err == -EINVAL;
}


