// Extracted from /Users/nan/bs/aot/src/verifier.c
static int convert_ctx_accesses(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprogs = env->subprog_info;
	const struct bpf_verifier_ops *ops = env->ops;
	int i, cnt, size, ctx_field_size, ret, delta = 0, epilogue_cnt = 0;
	const int insn_cnt = env->prog->len;
	struct bpf_insn *epilogue_buf = env->epilogue_buf;
	struct bpf_insn *insn_buf = env->insn_buf;
	struct bpf_insn *insn;
	u32 target_size, size_default, off;
	struct bpf_prog *new_prog;
	enum bpf_access_type type;
	bool is_narrower_load;
	int epilogue_idx = 0;

	if (ops->gen_epilogue) {
		epilogue_cnt = ops->gen_epilogue(epilogue_buf, env->prog,
						 -(subprogs[0].stack_depth + 8));
		if (epilogue_cnt >= INSN_BUF_SIZE) {
			verifier_bug(env, "epilogue is too long");
			return -EFAULT;
		} else if (epilogue_cnt) {
			/* Save the ARG_PTR_TO_CTX for the epilogue to use */
			cnt = 0;
			subprogs[0].stack_depth += 8;
			insn_buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_1,
						      -subprogs[0].stack_depth);
			insn_buf[cnt++] = env->prog->insnsi[0];
			new_prog = bpf_patch_insn_data(env, 0, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;
			env->prog = new_prog;
			delta += cnt - 1;

			ret = add_kfunc_in_insns(env, epilogue_buf, epilogue_cnt - 1);
			if (ret < 0)
				return ret;
		}
	}

	if (ops->gen_prologue || env->seen_direct_write) {
		if (!ops->gen_prologue) {
			verifier_bug(env, "gen_prologue is null");
			return -EFAULT;
		}
		cnt = ops->gen_prologue(insn_buf, env->seen_direct_write,
					env->prog);
		if (cnt >= INSN_BUF_SIZE) {
			verifier_bug(env, "prologue is too long");
			return -EFAULT;
		} else if (cnt) {
			new_prog = bpf_patch_insn_data(env, 0, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			env->prog = new_prog;
			delta += cnt - 1;

			ret = add_kfunc_in_insns(env, insn_buf, cnt - 1);
			if (ret < 0)
				return ret;
		}
	}

	if (delta)
		WARN_ON(adjust_jmp_off(env->prog, 0, delta));

	if (bpf_prog_is_offloaded(env->prog->aux))
		return 0;

	insn = env->prog->insnsi + delta;

	for (i = 0; i < insn_cnt; i++, insn++) {
		bpf_convert_ctx_access_t convert_ctx_access;
		u8 mode;

		if (env->insn_aux_data[i + delta].nospec) {
			WARN_ON_ONCE(env->insn_aux_data[i + delta].alu_state);
			struct bpf_insn *patch = insn_buf;

			*patch++ = BPF_ST_NOSPEC();
			*patch++ = *insn;
			cnt = patch - insn_buf;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			/* This can not be easily merged with the
			 * nospec_result-case, because an insn may require a
			 * nospec before and after itself. Therefore also do not
			 * 'continue' here but potentially apply further
			 * patching to insn. *insn should equal patch[1] now.
			 */
		}

		if (insn->code == (BPF_LDX | BPF_MEM | BPF_B) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_H) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_W) ||
		    insn->code == (BPF_LDX | BPF_MEM | BPF_DW) ||
		    insn->code == (BPF_LDX | BPF_MEMSX | BPF_B) ||
		    insn->code == (BPF_LDX | BPF_MEMSX | BPF_H) ||
		    insn->code == (BPF_LDX | BPF_MEMSX | BPF_W)) {
			type = BPF_READ;
		} else if (insn->code == (BPF_STX | BPF_MEM | BPF_B) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_H) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_W) ||
			   insn->code == (BPF_STX | BPF_MEM | BPF_DW) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_B) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_H) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_W) ||
			   insn->code == (BPF_ST | BPF_MEM | BPF_DW)) {
			type = BPF_WRITE;
		} else if ((insn->code == (BPF_STX | BPF_ATOMIC | BPF_B) ||
			    insn->code == (BPF_STX | BPF_ATOMIC | BPF_H) ||
			    insn->code == (BPF_STX | BPF_ATOMIC | BPF_W) ||
			    insn->code == (BPF_STX | BPF_ATOMIC | BPF_DW)) &&
			   env->insn_aux_data[i + delta].ptr_type == PTR_TO_ARENA) {
			insn->code = BPF_STX | BPF_PROBE_ATOMIC | BPF_SIZE(insn->code);
			env->prog->aux->num_exentries++;
			continue;
		} else if (insn->code == (BPF_JMP | BPF_EXIT) &&
			   epilogue_cnt &&
			   i + delta < subprogs[1].start) {
			/* Generate epilogue for the main prog */
			if (epilogue_idx) {
				/* jump back to the earlier generated epilogue */
				insn_buf[0] = BPF_JMP32_A(epilogue_idx - i - delta - 1);
				cnt = 1;
			} else {
				memcpy(insn_buf, epilogue_buf,
				       epilogue_cnt * sizeof(*epilogue_buf));
				cnt = epilogue_cnt;
				/* epilogue_idx cannot be 0. It must have at
				 * least one ctx ptr saving insn before the
				 * epilogue.
				 */
				epilogue_idx = i + delta;
			}
			goto patch_insn_buf;
		} else {
			continue;
		}

		if (type == BPF_WRITE &&
		    env->insn_aux_data[i + delta].nospec_result) {
			/* nospec_result is only used to mitigate Spectre v4 and
			 * to limit verification-time for Spectre v1.
			 */
			struct bpf_insn *patch = insn_buf;

			*patch++ = *insn;
			*patch++ = BPF_ST_NOSPEC();
			cnt = patch - insn_buf;
			new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
			if (!new_prog)
				return -ENOMEM;

			delta    += cnt - 1;
			env->prog = new_prog;
			insn      = new_prog->insnsi + i + delta;
			continue;
		}

		switch ((int)env->insn_aux_data[i + delta].ptr_type) {
		case PTR_TO_CTX:
			if (!ops->convert_ctx_access)
				continue;
			convert_ctx_access = ops->convert_ctx_access;
			break;
		case PTR_TO_SOCKET:
		case PTR_TO_SOCK_COMMON:
			convert_ctx_access = bpf_sock_convert_ctx_access;
			break;
		case PTR_TO_TCP_SOCK:
			convert_ctx_access = bpf_tcp_sock_convert_ctx_access;
			break;
		case PTR_TO_XDP_SOCK:
			convert_ctx_access = bpf_xdp_sock_convert_ctx_access;
			break;
		case PTR_TO_BTF_ID:
		case PTR_TO_BTF_ID | PTR_UNTRUSTED:
		/* PTR_TO_BTF_ID | MEM_ALLOC always has a valid lifetime, unlike
		 * PTR_TO_BTF_ID, and an active ref_obj_id, but the same cannot
		 * be said once it is marked PTR_UNTRUSTED, hence we must handle
		 * any faults for loads into such types. BPF_WRITE is disallowed
		 * for this case.
		 */
		case PTR_TO_BTF_ID | MEM_ALLOC | PTR_UNTRUSTED:
		case PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED:
			if (type == BPF_READ) {
				if (BPF_MODE(insn->code) == BPF_MEM)
					insn->code = BPF_LDX | BPF_PROBE_MEM |
						     BPF_SIZE((insn)->code);
				else
					insn->code = BPF_LDX | BPF_PROBE_MEMSX |
						     BPF_SIZE((insn)->code);
				env->prog->aux->num_exentries++;
			}
			continue;
		case PTR_TO_ARENA:
			if (BPF_MODE(insn->code) == BPF_MEMSX) {
				if (!bpf_jit_supports_insn(insn, true)) {
					verbose(env, "sign extending loads from arena are not supported yet\n");
					return -EOPNOTSUPP;
				}
				insn->code = BPF_CLASS(insn->code) | BPF_PROBE_MEM32SX | BPF_SIZE(insn->code);
			} else {
				insn->code = BPF_CLASS(insn->code) | BPF_PROBE_MEM32 | BPF_SIZE(insn->code);
			}
			env->prog->aux->num_exentries++;
			continue;
		default:
			continue;
		}

		ctx_field_size = env->insn_aux_data[i + delta].ctx_field_size;
		size = BPF_LDST_BYTES(insn);
		mode = BPF_MODE(insn->code);

		/* If the read access is a narrower load of the field,
		 * convert to a 4/8-byte load, to minimum program type specific
		 * convert_ctx_access changes. If conversion is successful,
		 * we will apply proper mask to the result.
		 */
		is_narrower_load = size < ctx_field_size;
		size_default = bpf_ctx_off_adjust_machine(ctx_field_size);
		off = insn->off;
		if (is_narrower_load) {
			u8 size_code;

			if (type == BPF_WRITE) {
				verifier_bug(env, "narrow ctx access misconfigured");
				return -EFAULT;
			}

			size_code = BPF_H;
			if (ctx_field_size == 4)
				size_code = BPF_W;
			else if (ctx_field_size == 8)
				size_code = BPF_DW;

			insn->off = off & ~(size_default - 1);
			insn->code = BPF_LDX | BPF_MEM | size_code;
		}

		target_size = 0;
		cnt = convert_ctx_access(type, insn, insn_buf, env->prog,
					 &target_size);
		if (cnt == 0 || cnt >= INSN_BUF_SIZE ||
		    (ctx_field_size && !target_size)) {
			verifier_bug(env, "error during ctx access conversion (%d)", cnt);
			return -EFAULT;
		}

		if (is_narrower_load && size < target_size) {
			u8 shift = bpf_ctx_narrow_access_offset(
				off, size, size_default) * 8;
			if (shift && cnt + 1 >= INSN_BUF_SIZE) {
				verifier_bug(env, "narrow ctx load misconfigured");
				return -EFAULT;
			}
			if (ctx_field_size <= 4) {
				if (shift)
					insn_buf[cnt++] = BPF_ALU32_IMM(BPF_RSH,
									insn->dst_reg,
									shift);
				insn_buf[cnt++] = BPF_ALU32_IMM(BPF_AND, insn->dst_reg,
								(1 << size * 8) - 1);
			} else {
				if (shift)
					insn_buf[cnt++] = BPF_ALU64_IMM(BPF_RSH,
									insn->dst_reg,
									shift);
				insn_buf[cnt++] = BPF_ALU32_IMM(BPF_AND, insn->dst_reg,
								(1ULL << size * 8) - 1);
			}
		}
		if (mode == BPF_MEMSX)
			insn_buf[cnt++] = BPF_RAW_INSN(BPF_ALU64 | BPF_MOV | BPF_X,
						       insn->dst_reg, insn->dst_reg,
						       size * 8, 0);

patch_insn_buf:
		new_prog = bpf_patch_insn_data(env, i + delta, insn_buf, cnt);
		if (!new_prog)
			return -ENOMEM;

		delta += cnt - 1;

		/* keep walking new program and skip insns we just inserted */
		env->prog = new_prog;
		insn      = new_prog->insnsi + i + delta;
	}

	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static void convert_pseudo_ld_imm64(struct bpf_verifier_env *env)
{
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int i;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (insn->code != (BPF_LD | BPF_IMM | BPF_DW))
			continue;
		if (insn->src_reg == BPF_PSEUDO_FUNC)
			continue;
		insn->src_reg = 0;
	}
}


