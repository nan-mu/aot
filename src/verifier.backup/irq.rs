// Extracted from /Users/nan/bs/aot/src/verifier.c
static int irq_flag_get_spi(struct bpf_verifier_env *env, struct bpf_reg_state *reg)
{
	return stack_slot_obj_get_spi(env, reg, "irq_flag", 1);
}


