// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool allow_tail_call_in_subprogs(struct bpf_verifier_env *env)
{
	return env->prog->jit_requested &&
	       bpf_jit_supports_subprog_tailcalls();
}
