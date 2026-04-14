// Extracted from /Users/nan/bs/aot/src/verifier.c
static int resolve_map_arg_type(struct bpf_verifier_env *env,
				 const struct bpf_call_arg_meta *meta,
				 enum bpf_arg_type *arg_type)
{
	if (!meta->map.ptr) {
		/* kernel subsystem misconfigured verifier */
		verifier_bug(env, "invalid map_ptr to access map->type");
		return -EFAULT;
	}

	switch (meta->map.ptr->map_type) {
	case BPF_MAP_TYPE_SOCKMAP:
	case BPF_MAP_TYPE_SOCKHASH:
		if (*arg_type == ARG_PTR_TO_MAP_VALUE) {
			*arg_type = ARG_PTR_TO_BTF_ID_SOCK_COMMON;
		} else {
			verbose(env, "invalid arg_type for sockmap/sockhash\n");
			return -EINVAL;
		}
		break;
	case BPF_MAP_TYPE_BLOOM_FILTER:
		if (meta->func_id == BPF_FUNC_map_peek_elem)
			*arg_type = ARG_PTR_TO_MAP_VALUE;
		break;
	default:
		break;
	}
	return 0;
}


// Extracted from /Users/nan/bs/aot/src/verifier.c
static int resolve_pseudo_ldimm64(struct bpf_verifier_env *env)
{
	struct bpf_insn *insn = env->prog->insnsi;
	int insn_cnt = env->prog->len;
	int i, err;

	err = bpf_prog_calc_tag(env->prog);
	if (err)
		return err;

	for (i = 0; i < insn_cnt; i++, insn++) {
		if (BPF_CLASS(insn->code) == BPF_LDX &&
		    ((BPF_MODE(insn->code) != BPF_MEM && BPF_MODE(insn->code) != BPF_MEMSX) ||
		    insn->imm != 0)) {
			verbose(env, "BPF_LDX uses reserved fields\n");
			return -EINVAL;
		}

		if (insn[0].code == (BPF_LD | BPF_IMM | BPF_DW)) {
			struct bpf_insn_aux_data *aux;
			struct bpf_map *map;
			int map_idx;
			u64 addr;
			u32 fd;

			if (i == insn_cnt - 1 || insn[1].code != 0 ||
			    insn[1].dst_reg != 0 || insn[1].src_reg != 0 ||
			    insn[1].off != 0) {
				verbose(env, "invalid bpf_ld_imm64 insn\n");
				return -EINVAL;
			}

			if (insn[0].src_reg == 0)
				/* valid generic load 64-bit imm */
				goto next_insn;

			if (insn[0].src_reg == BPF_PSEUDO_BTF_ID) {
				aux = &env->insn_aux_data[i];
				err = check_pseudo_btf_id(env, insn, aux);
				if (err)
					return err;
				goto next_insn;
			}

			if (insn[0].src_reg == BPF_PSEUDO_FUNC) {
				aux = &env->insn_aux_data[i];
				aux->ptr_type = PTR_TO_FUNC;
				goto next_insn;
			}

			/* In final convert_pseudo_ld_imm64() step, this is
			 * converted into regular 64-bit imm load insn.
			 */
			switch (insn[0].src_reg) {
			case BPF_PSEUDO_MAP_VALUE:
			case BPF_PSEUDO_MAP_IDX_VALUE:
				break;
			case BPF_PSEUDO_MAP_FD:
			case BPF_PSEUDO_MAP_IDX:
				if (insn[1].imm == 0)
					break;
				fallthrough;
			default:
				verbose(env, "unrecognized bpf_ld_imm64 insn\n");
				return -EINVAL;
			}

			switch (insn[0].src_reg) {
			case BPF_PSEUDO_MAP_IDX_VALUE:
			case BPF_PSEUDO_MAP_IDX:
				if (bpfptr_is_null(env->fd_array)) {
					verbose(env, "fd_idx without fd_array is invalid\n");
					return -EPROTO;
				}
				if (copy_from_bpfptr_offset(&fd, env->fd_array,
							    insn[0].imm * sizeof(fd),
							    sizeof(fd)))
					return -EFAULT;
				break;
			default:
				fd = insn[0].imm;
				break;
			}

			map_idx = add_used_map(env, fd);
			if (map_idx < 0)
				return map_idx;
			map = env->used_maps[map_idx];

			aux = &env->insn_aux_data[i];
			aux->map_index = map_idx;

			if (insn[0].src_reg == BPF_PSEUDO_MAP_FD ||
			    insn[0].src_reg == BPF_PSEUDO_MAP_IDX) {
				addr = (unsigned long)map;
			} else {
				u32 off = insn[1].imm;

				if (!map->ops->map_direct_value_addr) {
					verbose(env, "no direct value access support for this map type\n");
					return -EINVAL;
				}

				err = map->ops->map_direct_value_addr(map, &addr, off);
				if (err) {
					verbose(env, "invalid access to map value pointer, value_size=%u off=%u\n",
						map->value_size, off);
					return err;
				}

				aux->map_off = off;
				addr += off;
			}

			insn[0].imm = (u32)addr;
			insn[1].imm = addr >> 32;

next_insn:
			insn++;
			i++;
			continue;
		}

		/* Basic sanity check before we invest more work here. */
		if (!bpf_opcode_in_insntable(insn->code)) {
			verbose(env, "unknown opcode %02x\n", insn->code);
			return -EINVAL;
		}
	}

	/* now all pseudo BPF_LD_IMM64 instructions load valid
	 * 'struct bpf_map *' into a register instead of user map_fd.
	 * These pointers will be used later by verifier to validate map access.
	 */
	return 0;
}


