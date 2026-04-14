// Extracted from /Users/nan/bs/aot/src/verifier.c
static int backtrack_insn(struct bpf_verifier_env *env, int idx, int subseq_idx,
			  struct bpf_jmp_history_entry *hist, struct backtrack_state *bt)
{
	struct bpf_insn *insn = env->prog->insnsi + idx;
	u8 class = BPF_CLASS(insn->code);
	u8 opcode = BPF_OP(insn->code);
	u8 mode = BPF_MODE(insn->code);
	u32 dreg = insn->dst_reg;
	u32 sreg = insn->src_reg;
	u32 spi, i, fr;

	if (insn->code == 0)
		return 0;
	if (env->log.level & BPF_LOG_LEVEL2) {
		fmt_reg_mask(env->tmp_str_buf, TMP_STR_BUF_LEN, bt_reg_mask(bt));
		verbose(env, "mark_precise: frame%d: regs=%s ",
			bt->frame, env->tmp_str_buf);
		bpf_fmt_stack_mask(env->tmp_str_buf, TMP_STR_BUF_LEN, bt_stack_mask(bt));
		verbose(env, "stack=%s before ", env->tmp_str_buf);
		verbose(env, "%d: ", idx);
		verbose_insn(env, insn);
	}

	/* If there is a history record that some registers gained range at this insn,
	 * propagate precision marks to those registers, so that bt_is_reg_set()
	 * accounts for these registers.
	 */
	bt_sync_linked_regs(bt, hist);

	if (class == BPF_ALU || class == BPF_ALU64) {
		if (!bt_is_reg_set(bt, dreg))
			return 0;
		if (opcode == BPF_END || opcode == BPF_NEG) {
			/* sreg is reserved and unused
			 * dreg still need precision before this insn
			 */
			return 0;
		} else if (opcode == BPF_MOV) {
			if (BPF_SRC(insn->code) == BPF_X) {
				/* dreg = sreg or dreg = (s8, s16, s32)sreg
				 * dreg needs precision after this insn
				 * sreg needs precision before this insn
				 */
				bt_clear_reg(bt, dreg);
				if (sreg != BPF_REG_FP)
					bt_set_reg(bt, sreg);
			} else {
				/* dreg = K
				 * dreg needs precision after this insn.
				 * Corresponding register is already marked
				 * as precise=true in this verifier state.
				 * No further markings in parent are necessary
				 */
				bt_clear_reg(bt, dreg);
			}
		} else {
			if (BPF_SRC(insn->code) == BPF_X) {
				/* dreg += sreg
				 * both dreg and sreg need precision
				 * before this insn
				 */
				if (sreg != BPF_REG_FP)
					bt_set_reg(bt, sreg);
			} /* else dreg += K
			   * dreg still needs precision before this insn
			   */
		}
	} else if (class == BPF_LDX ||
		   is_atomic_load_insn(insn) ||
		   is_atomic_fetch_insn(insn)) {
		u32 load_reg = dreg;

		/*
		 * Atomic fetch operation writes the old value into
		 * a register (sreg or r0) and if it was tracked for
		 * precision, propagate to the stack slot like we do
		 * in regular ldx.
		 */
		if (is_atomic_fetch_insn(insn))
			load_reg = insn->imm == BPF_CMPXCHG ?
				   BPF_REG_0 : sreg;

		if (!bt_is_reg_set(bt, load_reg))
			return 0;
		bt_clear_reg(bt, load_reg);

		/* scalars can only be spilled into stack w/o losing precision.
		 * Load from any other memory can be zero extended.
		 * The desire to keep that precision is already indicated
		 * by 'precise' mark in corresponding register of this state.
		 * No further tracking necessary.
		 */
		if (!hist || !(hist->flags & INSN_F_STACK_ACCESS))
			return 0;
		/* dreg = *(u64 *)[fp - off] was a fill from the stack.
		 * that [fp - off] slot contains scalar that needs to be
		 * tracked with precision
		 */
		spi = insn_stack_access_spi(hist->flags);
		fr = insn_stack_access_frameno(hist->flags);
		bt_set_frame_slot(bt, fr, spi);
	} else if (class == BPF_STX || class == BPF_ST) {
		if (bt_is_reg_set(bt, dreg))
			/* stx & st shouldn't be using _scalar_ dst_reg
			 * to access memory. It means backtracking
			 * encountered a case of pointer subtraction.
			 */
			return -ENOTSUPP;
		/* scalars can only be spilled into stack */
		if (!hist || !(hist->flags & INSN_F_STACK_ACCESS))
			return 0;
		spi = insn_stack_access_spi(hist->flags);
		fr = insn_stack_access_frameno(hist->flags);
		if (!bt_is_frame_slot_set(bt, fr, spi))
			return 0;
		bt_clear_frame_slot(bt, fr, spi);
		if (class == BPF_STX)
			bt_set_reg(bt, sreg);
	} else if (class == BPF_JMP || class == BPF_JMP32) {
		if (bpf_pseudo_call(insn)) {
			int subprog_insn_idx, subprog;

			subprog_insn_idx = idx + insn->imm + 1;
			subprog = find_subprog(env, subprog_insn_idx);
			if (subprog < 0)
				return -EFAULT;

			if (subprog_is_global(env, subprog)) {
				/* check that jump history doesn't have any
				 * extra instructions from subprog; the next
				 * instruction after call to global subprog
				 * should be literally next instruction in
				 * caller program
				 */
				verifier_bug_if(idx + 1 != subseq_idx, env,
						"extra insn from subprog");
				/* r1-r5 are invalidated after subprog call,
				 * so for global func call it shouldn't be set
				 * anymore
				 */
				if (bt_reg_mask(bt) & BPF_REGMASK_ARGS) {
					verifier_bug(env, "global subprog unexpected regs %x",
						     bt_reg_mask(bt));
					return -EFAULT;
				}
				/* global subprog always sets R0 */
				bt_clear_reg(bt, BPF_REG_0);
				return 0;
			} else {
				/* static subprog call instruction, which
				 * means that we are exiting current subprog,
				 * so only r1-r5 could be still requested as
				 * precise, r0 and r6-r10 or any stack slot in
				 * the current frame should be zero by now
				 */
				if (bt_reg_mask(bt) & ~BPF_REGMASK_ARGS) {
					verifier_bug(env, "static subprog unexpected regs %x",
						     bt_reg_mask(bt));
					return -EFAULT;
				}
				/* we are now tracking register spills correctly,
				 * so any instance of leftover slots is a bug
				 */
				if (bt_stack_mask(bt) != 0) {
					verifier_bug(env,
						     "static subprog leftover stack slots %llx",
						     bt_stack_mask(bt));
					return -EFAULT;
				}
				/* propagate r1-r5 to the caller */
				for (i = BPF_REG_1; i <= BPF_REG_5; i++) {
					if (bt_is_reg_set(bt, i)) {
						bt_clear_reg(bt, i);
						bt_set_frame_reg(bt, bt->frame - 1, i);
					}
				}
				if (bt_subprog_exit(bt))
					return -EFAULT;
				return 0;
			}
		} else if (is_sync_callback_calling_insn(insn) && idx != subseq_idx - 1) {
			/* exit from callback subprog to callback-calling helper or
			 * kfunc call. Use idx/subseq_idx check to discern it from
			 * straight line code backtracking.
			 * Unlike the subprog call handling above, we shouldn't
			 * propagate precision of r1-r5 (if any requested), as they are
			 * not actually arguments passed directly to callback subprogs
			 */
			if (bt_reg_mask(bt) & ~BPF_REGMASK_ARGS) {
				verifier_bug(env, "callback unexpected regs %x",
					     bt_reg_mask(bt));
				return -EFAULT;
			}
			if (bt_stack_mask(bt) != 0) {
				verifier_bug(env, "callback leftover stack slots %llx",
					     bt_stack_mask(bt));
				return -EFAULT;
			}
			/* clear r1-r5 in callback subprog's mask */
			for (i = BPF_REG_1; i <= BPF_REG_5; i++)
				bt_clear_reg(bt, i);
			if (bt_subprog_exit(bt))
				return -EFAULT;
			return 0;
		} else if (opcode == BPF_CALL) {
			/* kfunc with imm==0 is invalid and fixup_kfunc_call will
			 * catch this error later. Make backtracking conservative
			 * with ENOTSUPP.
			 */
			if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL && insn->imm == 0)
				return -ENOTSUPP;
			/* regular helper call sets R0 */
			bt_clear_reg(bt, BPF_REG_0);
			if (bt_reg_mask(bt) & BPF_REGMASK_ARGS) {
				/* if backtracking was looking for registers R1-R5
				 * they should have been found already.
				 */
				verifier_bug(env, "backtracking call unexpected regs %x",
					     bt_reg_mask(bt));
				return -EFAULT;
			}
			if (insn->src_reg == BPF_REG_0 && insn->imm == BPF_FUNC_tail_call
			    && subseq_idx - idx != 1) {
				if (bt_subprog_enter(bt))
					return -EFAULT;
			}
		} else if (opcode == BPF_EXIT) {
			bool r0_precise;

			/* Backtracking to a nested function call, 'idx' is a part of
			 * the inner frame 'subseq_idx' is a part of the outer frame.
			 * In case of a regular function call, instructions giving
			 * precision to registers R1-R5 should have been found already.
			 * In case of a callback, it is ok to have R1-R5 marked for
			 * backtracking, as these registers are set by the function
			 * invoking callback.
			 */
			if (subseq_idx >= 0 && bpf_calls_callback(env, subseq_idx))
				for (i = BPF_REG_1; i <= BPF_REG_5; i++)
					bt_clear_reg(bt, i);
			if (bt_reg_mask(bt) & BPF_REGMASK_ARGS) {
				verifier_bug(env, "backtracking exit unexpected regs %x",
					     bt_reg_mask(bt));
				return -EFAULT;
			}

			/* BPF_EXIT in subprog or callback always returns
			 * right after the call instruction, so by checking
			 * whether the instruction at subseq_idx-1 is subprog
			 * call or not we can distinguish actual exit from
			 * *subprog* from exit from *callback*. In the former
			 * case, we need to propagate r0 precision, if
			 * necessary. In the former we never do that.
			 */
			r0_precise = subseq_idx - 1 >= 0 &&
				     bpf_pseudo_call(&env->prog->insnsi[subseq_idx - 1]) &&
				     bt_is_reg_set(bt, BPF_REG_0);

			bt_clear_reg(bt, BPF_REG_0);
			if (bt_subprog_enter(bt))
				return -EFAULT;

			if (r0_precise)
				bt_set_reg(bt, BPF_REG_0);
			/* r6-r9 and stack slots will stay set in caller frame
			 * bitmasks until we return back from callee(s)
			 */
			return 0;
		} else if (BPF_SRC(insn->code) == BPF_X) {
			if (!bt_is_reg_set(bt, dreg) && !bt_is_reg_set(bt, sreg))
				return 0;
			/* dreg <cond> sreg
			 * Both dreg and sreg need precision before
			 * this insn. If only sreg was marked precise
			 * before it would be equally necessary to
			 * propagate it to dreg.
			 */
			if (!hist || !(hist->flags & INSN_F_SRC_REG_STACK))
				bt_set_reg(bt, sreg);
			if (!hist || !(hist->flags & INSN_F_DST_REG_STACK))
				bt_set_reg(bt, dreg);
		} else if (BPF_SRC(insn->code) == BPF_K) {
			 /* dreg <cond> K
			  * Only dreg still needs precision before
			  * this insn, so for the K-based conditional
			  * there is nothing new to be marked.
			  */
		}
	} else if (class == BPF_LD) {
		if (!bt_is_reg_set(bt, dreg))
			return 0;
		bt_clear_reg(bt, dreg);
		/* It's ld_imm64 or ld_abs or ld_ind.
		 * For ld_imm64 no further tracking of precision
		 * into parent is necessary
		 */
		if (mode == BPF_IND || mode == BPF_ABS)
			/* to be analyzed */
			return -ENOTSUPP;
	}
	/* Propagate precision marks to linked registers, to account for
	 * registers marked as precise in this function.
	 */
	bt_sync_linked_regs(bt, hist);
	return 0;
}


