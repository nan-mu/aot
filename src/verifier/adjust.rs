//! Missing types: BpfVerifierEnv, BpfProgAux, BpfProg, BpfInsn, BpfInsnAuxData, BpfJitPokeDescriptor, BpfVerifierState, BpfFuncState, BpfRegState, BpfSanitizeInfo, Tnum, BpfSubprogInfo。·
//! 此文件，不应该使用任何unwrap，应该将错误向上抛，携带一个上下文标注出错位置。上层去理解错误和封装Err类型。
//! 应当将所有数组修改为VecQueue来优化插入工作的速度与逻辑。之后应该用工具统计数组使用频率，来决定使用何种结构。

use anyhow::{anyhow, Result};
use tracing::instrument;

/// 此处，aux.func_info.as_mut().unwrap，不应该使用unwrap，应该将错误向上抛
#[instrument(skip(env))]
pub fn adjust_btf_func(env: &mut BpfVerifierEnv) {
    let aux: &mut BpfProgAux = env.prog.aux;
    if aux.func_info.is_none() {
        return;
    }

    for i in 0..(env.subprog_cnt - env.hidden_subprog_cnt) as usize {
        aux.func_info.as_mut().unwrap()[i].insn_off = env.subprog_info[i].start;
    }
}

#[instrument(skip(env))]
pub fn adjust_insn_arrays(env: &mut BpfVerifierEnv, off: u32, len: u32) {
    if len == 1 {
        return;
    }
    for i in 0..env.insn_array_map_cnt as usize {
        bpf_insn_array_adjust(env.insn_array_maps[i], off, len);
    }
}

#[instrument(skip(env))]
pub fn adjust_insn_arrays_after_remove(env: &mut BpfVerifierEnv, off: u32, len: u32) {
    for i in 0..env.insn_array_map_cnt as usize {
        bpf_insn_array_adjust_after_remove(env.insn_array_maps[i], off, len);
    }
}

/// 此处，出现了数组的搬运。后续需要修改结构体为VecQueue来优化插入工作的速度与逻辑。
#[instrument(skip(env, new_prog))]
pub fn adjust_insn_aux_data(env: &mut BpfVerifierEnv, new_prog: &BpfProg, off: u32, cnt: u32) {
    let data: &mut [BpfInsnAuxData] = env.insn_aux_data;
    let insn: &[BpfInsn] = new_prog.insnsi;
    let old_seen = data[off as usize].seen;

    /* aux info at OFF always needs adjustment, no matter fast path
	 * (cnt == 1) is taken or not. There is no guarantee INSN at OFF is the
	 * original insn at old prog.
	 */
    data[off as usize].zext_dst = insn_has_def32(&insn[(off + cnt - 1) as usize]);
    if cnt == 1 {
        return;
    }

    // 也就是此处
    let prog_len = new_prog.len;

    let src_start = off as usize;
    let dst_start = (off + cnt - 1) as usize;
    let move_len = (prog_len - off - cnt + 1) as usize;
    for i in (0..move_len).rev() {
        data[dst_start + i] = data[src_start + i].clone();
    }

    for i in off as usize..(off + cnt - 1) as usize {
        data[i] = BpfInsnAuxData::default();
        data[i].seen = old_seen;
        data[i].zext_dst = insn_has_def32(&insn[i]);
    }
}

#[instrument(skip(prog))]
pub fn adjust_jmp_off(prog: &mut BpfProg, tgt_idx: u32, delta: u32) -> Result<i32> {
    let insn_cnt = prog.len;

    for i in 0..insn_cnt {
        if tgt_idx <= i && i < tgt_idx + delta {
            continue;
        }

        let insn = &mut prog.insnsi[i as usize];
        let code = insn.code;

        if (bpf_class(code) != BPF_JMP && bpf_class(code) != BPF_JMP32)
            || bpf_op(code) == BPF_CALL
            || bpf_op(code) == BPF_EXIT
        {
            continue;
        }

        if insn.code == (BPF_JMP32 | BPF_JA) {
            if (i as i32 + 1 + insn.imm) as u32 != tgt_idx {
                continue;
            }
            insn.imm = check_add_overflow_i32(insn.imm, delta as i32)
                .ok_or_else(|| anyhow!("-ERANGE: jmp32 imm overflow"))?;
        } else {
            if (i as i32 + 1 + insn.off as i32) as u32 != tgt_idx {
                continue;
            }
            insn.off = check_add_overflow_i16(insn.off, delta as i16)
                .ok_or_else(|| anyhow!("-ERANGE: jmp off overflow"))?;
        }
    }

    Ok(0)
}

#[instrument(skip(prog))]
pub fn adjust_poke_descs(prog: &mut BpfProg, off: u32, len: u32) {
    let tab: &mut [BpfJitPokeDescriptor] = prog.aux.poke_tab;
    let sz = prog.aux.size_poke_tab;

    for i in 0..sz as usize {
        let desc = &mut tab[i];
        if desc.insn_idx <= off {
            continue;
        }
        desc.insn_idx += len - 1;
    }
}

/// 重写该函数
// Extracted from /Users/nan/bs/aot/src/verifier.c
static int adjust_ptr_min_max_vals(struct bpf_verifier_env *env,
				   struct bpf_insn *insn,
				   const struct bpf_reg_state *ptr_reg,
				   const struct bpf_reg_state *off_reg)
{
	struct bpf_verifier_state *vstate = env->cur_state;
	struct bpf_func_state *state = vstate->frame[vstate->curframe];
	struct bpf_reg_state *regs = state->regs, *dst_reg;
	bool known = tnum_is_const(off_reg->var_off);
	s64 smin_val = off_reg->smin_value, smax_val = off_reg->smax_value,
	    smin_ptr = ptr_reg->smin_value, smax_ptr = ptr_reg->smax_value;
	u64 umin_val = off_reg->umin_value, umax_val = off_reg->umax_value,
	    umin_ptr = ptr_reg->umin_value, umax_ptr = ptr_reg->umax_value;
	struct bpf_sanitize_info info = {};
	u8 opcode = BPF_OP(insn->code);
	u32 dst = insn->dst_reg;
	int ret, bounds_ret;

	dst_reg = &regs[dst];

	if ((known && (smin_val != smax_val || umin_val != umax_val)) ||
	    smin_val > smax_val || umin_val > umax_val) {
		/* Taint dst register if offset had invalid bounds derived from
		 * e.g. dead branches.
		 */
		__mark_reg_unknown(env, dst_reg);
		return 0;
	}

	if (BPF_CLASS(insn->code) != BPF_ALU64) {
		/* 32-bit ALU ops on pointers produce (meaningless) scalars */
		if (opcode == BPF_SUB && env->allow_ptr_leaks) {
			__mark_reg_unknown(env, dst_reg);
			return 0;
		}

		verbose(env,
			"R%d 32-bit pointer arithmetic prohibited\n",
			dst);
		return -EACCES;
	}

	if (ptr_reg->type & PTR_MAYBE_NULL) {
		verbose(env, "R%d pointer arithmetic on %s prohibited, null-check it first\n",
			dst, reg_type_str(env, ptr_reg->type));
		return -EACCES;
	}

	/*
	 * Accesses to untrusted PTR_TO_MEM are done through probe
	 * instructions, hence no need to track offsets.
	 */
	if (base_type(ptr_reg->type) == PTR_TO_MEM && (ptr_reg->type & PTR_UNTRUSTED))
		return 0;

	switch (base_type(ptr_reg->type)) {
	case PTR_TO_CTX:
	case PTR_TO_MAP_VALUE:
	case PTR_TO_MAP_KEY:
	case PTR_TO_STACK:
	case PTR_TO_PACKET_META:
	case PTR_TO_PACKET:
	case PTR_TO_TP_BUFFER:
	case PTR_TO_BTF_ID:
	case PTR_TO_MEM:
	case PTR_TO_BUF:
	case PTR_TO_FUNC:
	case CONST_PTR_TO_DYNPTR:
		break;
	case PTR_TO_FLOW_KEYS:
		if (known)
			break;
		fallthrough;
	case CONST_PTR_TO_MAP:
		/* smin_val represents the known value */
		if (known && smin_val == 0 && opcode == BPF_ADD)
			break;
		fallthrough;
	default:
		verbose(env, "R%d pointer arithmetic on %s prohibited\n",
			dst, reg_type_str(env, ptr_reg->type));
		return -EACCES;
	}

	/* In case of 'scalar += pointer', dst_reg inherits pointer type and id.
	 * The id may be overwritten later if we create a new variable offset.
	 */
	dst_reg->type = ptr_reg->type;
	dst_reg->id = ptr_reg->id;

	if (!check_reg_sane_offset(env, off_reg, ptr_reg->type) ||
	    !check_reg_sane_offset(env, ptr_reg, ptr_reg->type))
		return -EINVAL;

	/* pointer types do not carry 32-bit bounds at the moment. */
	__mark_reg32_unbounded(dst_reg);

	if (sanitize_needed(opcode)) {
		ret = sanitize_ptr_alu(env, insn, ptr_reg, off_reg, dst_reg,
				       &info, false);
		if (ret < 0)
			return sanitize_err(env, insn, ret, off_reg, dst_reg);
	}

	switch (opcode) {
	case BPF_ADD:
		/* We can take a fixed offset as long as it doesn't overflow
		 * the s32 'off' field
		 */
		if (known && (ptr_reg->off + smin_val ==
			      (s64)(s32)(ptr_reg->off + smin_val))) {
			/* pointer += K.  Accumulate it into fixed offset */
			dst_reg->smin_value = smin_ptr;
			dst_reg->smax_value = smax_ptr;
			dst_reg->umin_value = umin_ptr;
			dst_reg->umax_value = umax_ptr;
			dst_reg->var_off = ptr_reg->var_off;
			dst_reg->off = ptr_reg->off + smin_val;
			dst_reg->raw = ptr_reg->raw;
			break;
		}
		/* A new variable offset is created.  Note that off_reg->off
		 * == 0, since it's a scalar.
		 * dst_reg gets the pointer type and since some positive
		 * integer value was added to the pointer, give it a new 'id'
		 * if it's a PTR_TO_PACKET.
		 * this creates a new 'base' pointer, off_reg (variable) gets
		 * added into the variable offset, and we copy the fixed offset
		 * from ptr_reg.
		 */
		if (check_add_overflow(smin_ptr, smin_val, &dst_reg->smin_value) ||
		    check_add_overflow(smax_ptr, smax_val, &dst_reg->smax_value)) {
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		}
		if (check_add_overflow(umin_ptr, umin_val, &dst_reg->umin_value) ||
		    check_add_overflow(umax_ptr, umax_val, &dst_reg->umax_value)) {
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		}
		dst_reg->var_off = tnum_add(ptr_reg->var_off, off_reg->var_off);
		dst_reg->off = ptr_reg->off;
		dst_reg->raw = ptr_reg->raw;
		if (reg_is_pkt_pointer(ptr_reg)) {
			dst_reg->id = ++env->id_gen;
			/* something was added to pkt_ptr, set range to zero */
			memset(&dst_reg->raw, 0, sizeof(dst_reg->raw));
		}
		break;
	case BPF_SUB:
		if (dst_reg == off_reg) {
			/* scalar -= pointer.  Creates an unknown scalar */
			verbose(env, "R%d tried to subtract pointer from scalar\n",
				dst);
			return -EACCES;
		}
		/* We don't allow subtraction from FP, because (according to
		 * test_verifier.c test "invalid fp arithmetic", JITs might not
		 * be able to deal with it.
		 */
		if (ptr_reg->type == PTR_TO_STACK) {
			verbose(env, "R%d subtraction from stack pointer prohibited\n",
				dst);
			return -EACCES;
		}
		if (known && (ptr_reg->off - smin_val ==
			      (s64)(s32)(ptr_reg->off - smin_val))) {
			/* pointer -= K.  Subtract it from fixed offset */
			dst_reg->smin_value = smin_ptr;
			dst_reg->smax_value = smax_ptr;
			dst_reg->umin_value = umin_ptr;
			dst_reg->umax_value = umax_ptr;
			dst_reg->var_off = ptr_reg->var_off;
			dst_reg->id = ptr_reg->id;
			dst_reg->off = ptr_reg->off - smin_val;
			dst_reg->raw = ptr_reg->raw;
			break;
		}
		/* A new variable offset is created.  If the subtrahend is known
		 * nonnegative, then any reg->range we had before is still good.
		 */
		if (check_sub_overflow(smin_ptr, smax_val, &dst_reg->smin_value) ||
		    check_sub_overflow(smax_ptr, smin_val, &dst_reg->smax_value)) {
			/* Overflow possible, we know nothing */
			dst_reg->smin_value = S64_MIN;
			dst_reg->smax_value = S64_MAX;
		}
		if (umin_ptr < umax_val) {
			/* Overflow possible, we know nothing */
			dst_reg->umin_value = 0;
			dst_reg->umax_value = U64_MAX;
		} else {
			/* Cannot overflow (as long as bounds are consistent) */
			dst_reg->umin_value = umin_ptr - umax_val;
			dst_reg->umax_value = umax_ptr - umin_val;
		}
		dst_reg->var_off = tnum_sub(ptr_reg->var_off, off_reg->var_off);
		dst_reg->off = ptr_reg->off;
		dst_reg->raw = ptr_reg->raw;
		if (reg_is_pkt_pointer(ptr_reg)) {
			dst_reg->id = ++env->id_gen;
			/* something was added to pkt_ptr, set range to zero */
			if (smin_val < 0)
				memset(&dst_reg->raw, 0, sizeof(dst_reg->raw));
		}
		break;
	case BPF_AND:
	case BPF_OR:
	case BPF_XOR:
		/* bitwise ops on pointers are troublesome, prohibit. */
		verbose(env, "R%d bitwise operator %s on pointer prohibited\n",
			dst, bpf_alu_string[opcode >> 4]);
		return -EACCES;
	default:
		/* other operators (e.g. MUL,LSH) produce non-pointer results */
		verbose(env, "R%d pointer arithmetic with %s operator prohibited\n",
			dst, bpf_alu_string[opcode >> 4]);
		return -EACCES;
	}

	if (!check_reg_sane_offset(env, dst_reg, ptr_reg->type))
		return -EINVAL;
	reg_bounds_sync(dst_reg);
	bounds_ret = sanitize_check_bounds(env, insn, dst_reg);
	if (bounds_ret == -EACCES)
		return bounds_ret;
	if (sanitize_needed(opcode)) {
		ret = sanitize_ptr_alu(env, insn, dst_reg, off_reg, dst_reg,
				       &info, true);
		if (verifier_bug_if(!can_skip_alu_sanitation(env, insn)
				    && !env->cur_state->speculative
				    && bounds_ret
				    && !ret,
				    env, "Pointer type unsupported by sanitize_check_bounds() not rejected by retrieve_ptr_limit() as required")) {
			return -EFAULT;
		}
		if (ret < 0)
			return sanitize_err(env, insn, ret, off_reg, dst_reg);
	}

	return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int adjust_reg_min_max_vals(struct bpf_verifier_env *env,
				   struct bpf_insn *insn)
{
	struct bpf_verifier_state *vstate = env->cur_state;
	struct bpf_func_state *state = vstate->frame[vstate->curframe];
	struct bpf_reg_state *regs = state->regs, *dst_reg, *src_reg;
	struct bpf_reg_state *ptr_reg = NULL, off_reg = {0};
	bool alu32 = (BPF_CLASS(insn->code) != BPF_ALU64);
	u8 opcode = BPF_OP(insn->code);
	int err;

	dst_reg = &regs[insn->dst_reg];
	src_reg = NULL;

	if (dst_reg->type == PTR_TO_ARENA) {
		struct bpf_insn_aux_data *aux = cur_aux(env);

		if (BPF_CLASS(insn->code) == BPF_ALU64)
			/*
			 * 32-bit operations zero upper bits automatically.
			 * 64-bit operations need to be converted to 32.
			 */
			aux->needs_zext = true;

		/* Any arithmetic operations are allowed on arena pointers */
		return 0;
	}

	if (dst_reg->type != SCALAR_VALUE)
		ptr_reg = dst_reg;

	if (BPF_SRC(insn->code) == BPF_X) {
		src_reg = &regs[insn->src_reg];
		if (src_reg->type != SCALAR_VALUE) {
			if (dst_reg->type != SCALAR_VALUE) {
				/* Combining two pointers by any ALU op yields
				 * an arbitrary scalar. Disallow all math except
				 * pointer subtraction
				 */
				if (opcode == BPF_SUB && env->allow_ptr_leaks) {
					mark_reg_unknown(env, regs, insn->dst_reg);
					return 0;
				}
				verbose(env, "R%d pointer %s pointer prohibited\n",
					insn->dst_reg,
					bpf_alu_string[opcode >> 4]);
				return -EACCES;
			} else {
				/* scalar += pointer
				 * This is legal, but we have to reverse our
				 * src/dest handling in computing the range
				 */
				err = mark_chain_precision(env, insn->dst_reg);
				if (err)
					return err;
				return adjust_ptr_min_max_vals(env, insn,
							       src_reg, dst_reg);
			}
		} else if (ptr_reg) {
			/* pointer += scalar */
			err = mark_chain_precision(env, insn->src_reg);
			if (err)
				return err;
			return adjust_ptr_min_max_vals(env, insn,
						       dst_reg, src_reg);
		} else if (dst_reg->precise) {
			/* if dst_reg is precise, src_reg should be precise as well */
			err = mark_chain_precision(env, insn->src_reg);
			if (err)
				return err;
		}
	} else {
		/* Pretend the src is a reg with a known value, since we only
		 * need to be able to read from this state.
		 */
		off_reg.type = SCALAR_VALUE;
		__mark_reg_known(&off_reg, insn->imm);
		src_reg = &off_reg;
		if (ptr_reg) /* pointer += K */
			return adjust_ptr_min_max_vals(env, insn,
						       ptr_reg, src_reg);
	}

	/* Got here implies adding two SCALAR_VALUEs */
	if (WARN_ON_ONCE(ptr_reg)) {
		print_verifier_state(env, vstate, vstate->curframe, true);
		verbose(env, "verifier internal error: unexpected ptr_reg\n");
		return -EFAULT;
	}
	if (WARN_ON(!src_reg)) {
		print_verifier_state(env, vstate, vstate->curframe, true);
		verbose(env, "verifier internal error: no src_reg\n");
		return -EFAULT;
	}
	/*
	 * For alu32 linked register tracking, we need to check dst_reg's
	 * umax_value before the ALU operation. After adjust_scalar_min_max_vals(),
	 * alu32 ops will have zero-extended the result, making umax_value <= U32_MAX.
	 */
	u64 dst_umax = dst_reg->umax_value;

	err = adjust_scalar_min_max_vals(env, insn, dst_reg, *src_reg);
	if (err)
		return err;
	/*
	 * Compilers can generate the code
	 * r1 = r2
	 * r1 += 0x1
	 * if r2 < 1000 goto ...
	 * use r1 in memory access
	 * So remember constant delta between r2 and r1 and update r1 after
	 * 'if' condition.
	 */
	if (env->bpf_capable &&
	    (BPF_OP(insn->code) == BPF_ADD || BPF_OP(insn->code) == BPF_SUB) &&
	    dst_reg->id && is_reg_const(src_reg, alu32)) {
		u64 val = reg_const_value(src_reg, alu32);
		s32 off;

		if (!alu32 && ((s64)val < S32_MIN || (s64)val > S32_MAX))
			goto clear_id;

		if (alu32 && (dst_umax > U32_MAX))
			goto clear_id;

		off = (s32)val;

		if (BPF_OP(insn->code) == BPF_SUB) {
			/* Negating S32_MIN would overflow */
			if (off == S32_MIN)
				goto clear_id;
			off = -off;
		}

		if (dst_reg->id & BPF_ADD_CONST) {
			/*
			 * If the register already went through rX += val
			 * we cannot accumulate another val into rx->off.
			 */
clear_id:
			dst_reg->off = 0;
			dst_reg->id = 0;
		} else {
			if (alu32)
				dst_reg->id |= BPF_ADD_CONST32;
			else
				dst_reg->id |= BPF_ADD_CONST64;
			dst_reg->off = off;
		}
	} else {
		/*
		 * Make sure ID is cleared otherwise dst_reg min/max could be
		 * incorrectly propagated into other registers by sync_linked_regs()
		 */
		dst_reg->id = 0;
	}
	return 0;
}

#[instrument(skip(env, insn, dst_reg, src_reg))]
pub fn adjust_scalar_min_max_vals(
    env: &mut BpfVerifierEnv,
    insn: &BpfInsn,
    dst_reg: &mut BpfRegState,
    src_reg: BpfRegState,
) -> Result<i32> {
    let opcode = bpf_op(insn.code);
    let alu32 = bpf_class(insn.code) != BPF_ALU64;

    if !is_safe_to_compute_dst_reg_range(insn, &src_reg) {
        inner_mark_reg_unknown(env, dst_reg);
        return Ok(0);
    }

    if sanitize_needed(opcode) {
        let ret = sanitize_val_alu(env, insn);
        if ret < 0 {
            return Err(anyhow!("sanitize_val_alu failed: {ret}"));
        }
    }

	/* Calculate sign/unsigned bounds and tnum for alu32 and alu64 bit ops.
	 * There are two classes of instructions: The first class we track both
	 * alu32 and alu64 sign/unsigned bounds independently this provides the
	 * greatest amount of precision when alu operations are mixed with jmp32
	 * operations. These operations are BPF_ADD, BPF_SUB, BPF_MUL, BPF_ADD,
	 * and BPF_OR. This is possible because these ops have fairly easy to
	 * understand and calculate behavior in both 32-bit and 64-bit alu ops.
	 * See alu32 verifier tests for examples. The second class of
	 * operations, BPF_LSH, BPF_RSH, and BPF_ARSH, however are not so easy
	 * with regards to tracking sign/unsigned bounds because the bits may
	 * cross subreg boundaries in the alu64 case. When this happens we mark
	 * the reg unbounded in the subreg bound space and use the resulting
	 * tnum to calculate an approximation of the sign/unsigned bounds.
	 */
    // TODO: 该switch 缺少了分支，我已经替换为原来的c代码，重写将这个switch 重写为rust
	switch (opcode) {
	case BPF_ADD:
		scalar32_min_max_add(dst_reg, &src_reg);
		scalar_min_max_add(dst_reg, &src_reg);
		dst_reg->var_off = tnum_add(dst_reg->var_off, src_reg.var_off);
		break;
	case BPF_SUB:
		scalar32_min_max_sub(dst_reg, &src_reg);
		scalar_min_max_sub(dst_reg, &src_reg);
		dst_reg->var_off = tnum_sub(dst_reg->var_off, src_reg.var_off);
		break;
	case BPF_NEG:
		env->fake_reg[0] = *dst_reg;
		__mark_reg_known(dst_reg, 0);
		scalar32_min_max_sub(dst_reg, &env->fake_reg[0]);
		scalar_min_max_sub(dst_reg, &env->fake_reg[0]);
		dst_reg->var_off = tnum_neg(env->fake_reg[0].var_off);
		break;
	case BPF_MUL:
		dst_reg->var_off = tnum_mul(dst_reg->var_off, src_reg.var_off);
		scalar32_min_max_mul(dst_reg, &src_reg);
		scalar_min_max_mul(dst_reg, &src_reg);
		break;
	case BPF_DIV:
		/* BPF div specification: x / 0 = 0 */
		if ((alu32 && src_reg.u32_min_value == 0) || (!alu32 && src_reg.umin_value == 0)) {
			___mark_reg_known(dst_reg, 0);
			break;
		}
		if (alu32)
			if (off == 1)
				scalar32_min_max_sdiv(dst_reg, &src_reg);
			else
				scalar32_min_max_udiv(dst_reg, &src_reg);
		else
			if (off == 1)
				scalar_min_max_sdiv(dst_reg, &src_reg);
			else
				scalar_min_max_udiv(dst_reg, &src_reg);
		break;
	case BPF_MOD:
		/* BPF mod specification: x % 0 = x */
		if ((alu32 && src_reg.u32_min_value == 0) || (!alu32 && src_reg.umin_value == 0))
			break;
		if (alu32)
			if (off == 1)
				scalar32_min_max_smod(dst_reg, &src_reg);
			else
				scalar32_min_max_umod(dst_reg, &src_reg);
		else
			if (off == 1)
				scalar_min_max_smod(dst_reg, &src_reg);
			else
				scalar_min_max_umod(dst_reg, &src_reg);
		break;
	case BPF_AND:
		if (tnum_is_const(src_reg.var_off)) {
			ret = maybe_fork_scalars(env, insn, dst_reg);
			if (ret)
				return ret;
		}
		dst_reg->var_off = tnum_and(dst_reg->var_off, src_reg.var_off);
		scalar32_min_max_and(dst_reg, &src_reg);
		scalar_min_max_and(dst_reg, &src_reg);
		break;
	case BPF_OR:
		if (tnum_is_const(src_reg.var_off)) {
			ret = maybe_fork_scalars(env, insn, dst_reg);
			if (ret)
				return ret;
		}
		dst_reg->var_off = tnum_or(dst_reg->var_off, src_reg.var_off);
		scalar32_min_max_or(dst_reg, &src_reg);
		scalar_min_max_or(dst_reg, &src_reg);
		break;
	case BPF_XOR:
		dst_reg->var_off = tnum_xor(dst_reg->var_off, src_reg.var_off);
		scalar32_min_max_xor(dst_reg, &src_reg);
		scalar_min_max_xor(dst_reg, &src_reg);
		break;
	case BPF_LSH:
		if (alu32)
			scalar32_min_max_lsh(dst_reg, &src_reg);
		else
			scalar_min_max_lsh(dst_reg, &src_reg);
		break;
	case BPF_RSH:
		if (alu32)
			scalar32_min_max_rsh(dst_reg, &src_reg);
		else
			scalar_min_max_rsh(dst_reg, &src_reg);
		break;
	case BPF_ARSH:
		if (alu32)
			scalar32_min_max_arsh(dst_reg, &src_reg);
		else
			scalar_min_max_arsh(dst_reg, &src_reg);
		break;
	case BPF_END:
		scalar_byte_swap(dst_reg, insn);
		break;
	default:
		break;
	}

    /*
	 * ALU32 ops are zero extended into 64bit register.
	 *
	 * BPF_END is already handled inside the helper (truncation),
	 * so skip zext here to avoid unexpected zero extension.
	 * e.g., le64: opcode=(BPF_END|BPF_ALU|BPF_TO_LE), imm=0x40
	 * This is a 64bit byte swap operation with alu32==true,
	 * but we should not zero extend the result.
	 */
    if alu32 && opcode != BPF_END {
        zext_32_to_64(dst_reg);
    }
    reg_bounds_sync(dst_reg);
    Ok(0)
}

#[instrument(skip(env))]
pub fn adjust_subprog_starts(env: &mut BpfVerifierEnv, off: u32, len: u32) {
    if len == 1 {
        return;
    }
    /* NOTE: fake 'exit' subprog should be updated as well. */
    for i in 0..=env.subprog_cnt as usize {
        if env.subprog_info[i].start <= off as i32 {
            continue;
        }
        env.subprog_info[i].start += (len - 1) as i32;
    }
}

#[instrument(skip(env))]
pub fn adjust_subprog_starts_after_remove(
    env: &mut BpfVerifierEnv,
    off: u32,
    cnt: u32,
) -> Result<i32> {
    // TODO: 原实现中使用for，我需要你也写成for，rust可以把index提出来的，原实现和注释如下：
    // /* find first prog starting at or after off (first to remove) */
	// for (i = 0; i < env->subprog_cnt; i++)
	// 	if (env->subprog_info[i].start >= off)
	// 		break;
	// /* find first prog starting at or after off + cnt (first to stay) */
	// for (j = i; j < env->subprog_cnt; j++)
	// 	if (env->subprog_info[j].start >= off + cnt)
	// 		break;
    let mut i = 0usize;
    while i < env.subprog_cnt as usize && env.subprog_info[i].start < off as i32 {
        i += 1;
    }

    let mut j = i;
    while j < env.subprog_cnt as usize && env.subprog_info[j].start < (off + cnt) as i32 {
        j += 1;
    }

    // TODO: 原本的实现非常有问题，加入了不必要的判别条件，我已经重写了这个函数，检查是否正确
    // 我认为的错误实现：
    // if j < env.subprog_cnt as usize && env.subprog_info[j].start != (off + cnt) as i32 {
    //     j = j.saturating_sub(1);
    // }
    // C原实现
    // /* if j doesn't start exactly at off + cnt, we are just removing
	//  * the front of previous prog
	//  */
	// if (env->subprog_info[j].start != off + cnt)
	// 	j--;
    if (env.subprog_info[j].start != off + cnt)
		j = j.saturating_sub(1);

    // TODO: 这里同样是逻辑与原实现不同，根据以下C代码重写
    if (j > i) {
		struct bpf_prog_aux *aux = env->prog->aux;
		int move;

		/* move fake 'exit' subprog as well */
		move = env->subprog_cnt + 1 - j;

		memmove(env->subprog_info + i,
			env->subprog_info + j,
			sizeof(*env->subprog_info) * move);
		env->subprog_cnt -= j - i;

		/* remove func_info */
		if (aux->func_info) {
			move = aux->func_info_cnt - j;

			memmove(aux->func_info + i,
				aux->func_info + j,
				sizeof(*aux->func_info) * move);
			aux->func_info_cnt -= j - i;
			/* func_info->insn_off is set after all code rewrites,
			 * in adjust_btf_func() - no need to adjust
			 */
		}
	} else {
		/* convert i from "first prog to remove" to "first to adjust" */
		if (env->subprog_info[i].start == off)
			i++;
	}

	/* update fake 'exit' subprog as well */
	for (; i <= env->subprog_cnt; i++)
		env->subprog_info[i].start -= cnt;

    Ok(0)
}
