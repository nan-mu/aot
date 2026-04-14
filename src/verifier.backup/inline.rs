// Extracted from /Users/nan/bs/aot/src/verifier.c
static struct bpf_prog *inline_bpf_loop(struct bpf_verifier_env *env,
					int position,
					s32 stack_base,
					u32 callback_subprogno,
					u32 *total_cnt)
{
	s32 r6_offset = stack_base + 0 * BPF_REG_SIZE;
	s32 r7_offset = stack_base + 1 * BPF_REG_SIZE;
	s32 r8_offset = stack_base + 2 * BPF_REG_SIZE;
	int reg_loop_max = BPF_REG_6;
	int reg_loop_cnt = BPF_REG_7;
	int reg_loop_ctx = BPF_REG_8;

	struct bpf_insn *insn_buf = env->insn_buf;
	struct bpf_prog *new_prog;
	u32 callback_start;
	u32 call_insn_offset;
	s32 callback_offset;
	u32 cnt = 0;

	/* This represents an inlined version of bpf_iter.c:bpf_loop,
	 * be careful to modify this code in sync.
	 */

	/* Return error and jump to the end of the patch if
	 * expected number of iterations is too big.
	 */
	insn_buf[cnt++] = BPF_JMP_IMM(BPF_JLE, BPF_REG_1, BPF_MAX_LOOPS, 2);
	insn_buf[cnt++] = BPF_MOV32_IMM(BPF_REG_0, -E2BIG);
	insn_buf[cnt++] = BPF_JMP_IMM(BPF_JA, 0, 0, 16);
	/* spill R6, R7, R8 to use these as loop vars */
	insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, r6_offset);
	insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, r7_offset);
	insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_8, r8_offset);
	/* initialize loop vars */
	insn_buf[cnt++] = BPF_MOV64_REG(reg_loop_max, BPF_REG_1);
	insn_buf[cnt++] = BPF_MOV32_IMM(reg_loop_cnt, 0);
	insn_buf[cnt++] = BPF_MOV64_REG(reg_loop_ctx, BPF_REG_3);
	/* loop header,
	 * if reg_loop_cnt >= reg_loop_max skip the loop body
	 */
	insn_buf[cnt++] = BPF_JMP_REG(BPF_JGE, reg_loop_cnt, reg_loop_max, 5);
	/* callback call,
	 * correct callback offset would be set after patching
	 */
	insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_1, reg_loop_cnt);
	insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_2, reg_loop_ctx);
	insn_buf[cnt++] = BPF_CALL_REL(0);
	/* increment loop counter */
	insn_buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, reg_loop_cnt, 1);
	/* jump to loop header if callback returned 0 */
	insn_buf[cnt++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, -6);
	/* return value of bpf_loop,
	 * set R0 to the number of iterations
	 */
	insn_buf[cnt++] = BPF_MOV64_REG(BPF_REG_0, reg_loop_cnt);
	/* restore original values of R6, R7, R8 */
	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, r6_offset);
	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_10, r7_offset);
	insn_buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_10, r8_offset);

	*total_cnt = cnt;
	new_prog = bpf_patch_insn_data(env, position, insn_buf, cnt);
	if (!new_prog)
		return new_prog;

	/* callback start is known only after patching */
	callback_start = env->subprog_info[callback_subprogno].start;
	/* Note: insn_buf[12] is an offset of BPF_CALL_REL instruction */
	call_insn_offset = position + 12;
	callback_offset = callback_start - call_insn_offset - 1;
	new_prog->insnsi[call_insn_offset].imm = callback_offset;

	return new_prog;
}


