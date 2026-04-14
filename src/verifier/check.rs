// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_abnormal_return(struct bpf_verifier_env *env) {
  int i;

  for (i = 1; i < env->subprog_cnt; i++) {
    if (env->subprog_info[i].has_ld_abs) {
      verbose(env, "LD_ABS is not allowed in subprogs without BTF\n");
      return -EINVAL;
    }
    if (env->subprog_info[i].has_tail_call) {
      verbose(env, "tail_call is not allowed in subprogs without BTF\n");
      return -EINVAL;
    }
  }
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_alu_op(struct bpf_verifier_env *env, struct bpf_insn *insn) {
  struct bpf_reg_state *regs = cur_regs(env);
  u8 opcode = BPF_OP(insn->code);
  int err;

  if (opcode == BPF_END || opcode == BPF_NEG) {
    if (opcode == BPF_NEG) {
      if (BPF_SRC(insn->code) != BPF_K || insn->src_reg != BPF_REG_0 ||
          insn->off != 0 || insn->imm != 0) {
        verbose(env, "BPF_NEG uses reserved fields\n");
        return -EINVAL;
      }
    } else {
      if (insn->src_reg != BPF_REG_0 || insn->off != 0 ||
          (insn->imm != 16 && insn->imm != 32 && insn->imm != 64) ||
          (BPF_CLASS(insn->code) == BPF_ALU64 &&
           BPF_SRC(insn->code) != BPF_TO_LE)) {
        verbose(env, "BPF_END uses reserved fields\n");
        return -EINVAL;
      }
    }

    /* check src operand */
    err = check_reg_arg(env, insn->dst_reg, SRC_OP);
    if (err)
      return err;

    if (is_pointer_value(env, insn->dst_reg)) {
      verbose(env, "R%d pointer arithmetic prohibited\n", insn->dst_reg);
      return -EACCES;
    }

    /* check dest operand */
    if ((opcode == BPF_NEG || opcode == BPF_END) &&
        regs[insn->dst_reg].type == SCALAR_VALUE) {
      err = check_reg_arg(env, insn->dst_reg, DST_OP_NO_MARK);
      err = err
                ?: adjust_scalar_min_max_vals(env, insn, &regs[insn->dst_reg],
                                              regs[insn->dst_reg]);
    } else {
      err = check_reg_arg(env, insn->dst_reg, DST_OP);
    }
    if (err)
      return err;

  } else if (opcode == BPF_MOV) {

    if (BPF_SRC(insn->code) == BPF_X) {
      if (BPF_CLASS(insn->code) == BPF_ALU) {
        if ((insn->off != 0 && insn->off != 8 && insn->off != 16) ||
            insn->imm) {
          verbose(env, "BPF_MOV uses reserved fields\n");
          return -EINVAL;
        }
      } else if (insn->off == BPF_ADDR_SPACE_CAST) {
        if (insn->imm != 1 && insn->imm != 1u << 16) {
          verbose(env, "addr_space_cast insn can only convert between address "
                       "space 1 and 0\n");
          return -EINVAL;
        }
        if (!env->prog->aux->arena) {
          verbose(env, "addr_space_cast insn can only be used in a program "
                       "that has an associated arena\n");
          return -EINVAL;
        }
      } else {
        if ((insn->off != 0 && insn->off != 8 && insn->off != 16 &&
             insn->off != 32) ||
            insn->imm) {
          verbose(env, "BPF_MOV uses reserved fields\n");
          return -EINVAL;
        }
      }

      /* check src operand */
      err = check_reg_arg(env, insn->src_reg, SRC_OP);
      if (err)
        return err;
    } else {
      if (insn->src_reg != BPF_REG_0 || insn->off != 0) {
        verbose(env, "BPF_MOV uses reserved fields\n");
        return -EINVAL;
      }
    }

    /* check dest operand, mark as required later */
    err = check_reg_arg(env, insn->dst_reg, DST_OP_NO_MARK);
    if (err)
      return err;

    if (BPF_SRC(insn->code) == BPF_X) {
      struct bpf_reg_state *src_reg = regs + insn->src_reg;
      struct bpf_reg_state *dst_reg = regs + insn->dst_reg;

      if (BPF_CLASS(insn->code) == BPF_ALU64) {
        if (insn->imm) {
          /* off == BPF_ADDR_SPACE_CAST */
          mark_reg_unknown(env, regs, insn->dst_reg);
          if (insn->imm == 1) { /* cast from as(1) to as(0) */
            dst_reg->type = PTR_TO_ARENA;
            /* PTR_TO_ARENA is 32-bit */
            dst_reg->subreg_def = env->insn_idx + 1;
          }
        } else if (insn->off == 0) {
          /* case: R1 = R2
           * copy register state to dest reg
           */
          assign_scalar_id_before_mov(env, src_reg);
          copy_register_state(dst_reg, src_reg);
          dst_reg->subreg_def = DEF_NOT_SUBREG;
        } else {
          /* case: R1 = (s8, s16 s32)R2 */
          if (is_pointer_value(env, insn->src_reg)) {
            verbose(env, "R%d sign-extension part of pointer\n", insn->src_reg);
            return -EACCES;
          } else if (src_reg->type == SCALAR_VALUE) {
            bool no_sext;

            no_sext = src_reg->umax_value < (1ULL << (insn->off - 1));
            if (no_sext)
              assign_scalar_id_before_mov(env, src_reg);
            copy_register_state(dst_reg, src_reg);
            if (!no_sext)
              dst_reg->id = 0;
            coerce_reg_to_size_sx(dst_reg, insn->off >> 3);
            dst_reg->subreg_def = DEF_NOT_SUBREG;
          } else {
            mark_reg_unknown(env, regs, insn->dst_reg);
          }
        }
      } else {
        /* R1 = (u32) R2 */
        if (is_pointer_value(env, insn->src_reg)) {
          verbose(env, "R%d partial copy of pointer\n", insn->src_reg);
          return -EACCES;
        } else if (src_reg->type == SCALAR_VALUE) {
          if (insn->off == 0) {
            bool is_src_reg_u32 = get_reg_width(src_reg) <= 32;

            if (is_src_reg_u32)
              assign_scalar_id_before_mov(env, src_reg);
            copy_register_state(dst_reg, src_reg);
            /* Make sure ID is cleared if src_reg is not in u32
             * range otherwise dst_reg min/max could be incorrectly
             * propagated into src_reg by sync_linked_regs()
             */
            if (!is_src_reg_u32)
              dst_reg->id = 0;
            dst_reg->subreg_def = env->insn_idx + 1;
          } else {
            /* case: W1 = (s8, s16)W2 */
            bool no_sext = src_reg->umax_value < (1ULL << (insn->off - 1));

            if (no_sext)
              assign_scalar_id_before_mov(env, src_reg);
            copy_register_state(dst_reg, src_reg);
            if (!no_sext)
              dst_reg->id = 0;
            dst_reg->subreg_def = env->insn_idx + 1;
            coerce_subreg_to_size_sx(dst_reg, insn->off >> 3);
          }
        } else {
          mark_reg_unknown(env, regs, insn->dst_reg);
        }
        zext_32_to_64(dst_reg);
        reg_bounds_sync(dst_reg);
      }
    } else {
      /* case: R = imm
       * remember the value we stored into this reg
       */
      /* clear any state inner_mark_reg_known doesn't set */
      mark_reg_unknown(env, regs, insn->dst_reg);
      regs[insn->dst_reg].type = SCALAR_VALUE;
      if (BPF_CLASS(insn->code) == BPF_ALU64) {
        inner_mark_reg_known(regs + insn->dst_reg, insn->imm);
      } else {
        inner_mark_reg_known(regs + insn->dst_reg, (u32)insn->imm);
      }
    }

  } else if (opcode > BPF_END) {
    verbose(env, "invalid BPF_ALU opcode %x\n", opcode);
    return -EINVAL;

  } else { /* all other ALU ops: and, sub, xor, add, ... */

    if (BPF_SRC(insn->code) == BPF_X) {
      if (insn->imm != 0 || (insn->off != 0 && insn->off != 1) ||
          (insn->off == 1 && opcode != BPF_MOD && opcode != BPF_DIV)) {
        verbose(env, "BPF_ALU uses reserved fields\n");
        return -EINVAL;
      }
      /* check src1 operand */
      err = check_reg_arg(env, insn->src_reg, SRC_OP);
      if (err)
        return err;
    } else {
      if (insn->src_reg != BPF_REG_0 || (insn->off != 0 && insn->off != 1) ||
          (insn->off == 1 && opcode != BPF_MOD && opcode != BPF_DIV)) {
        verbose(env, "BPF_ALU uses reserved fields\n");
        return -EINVAL;
      }
    }

    /* check src2 operand */
    err = check_reg_arg(env, insn->dst_reg, SRC_OP);
    if (err)
      return err;

    if ((opcode == BPF_MOD || opcode == BPF_DIV) &&
        BPF_SRC(insn->code) == BPF_K && insn->imm == 0) {
      verbose(env, "div by zero\n");
      return -EINVAL;
    }

    if ((opcode == BPF_LSH || opcode == BPF_RSH || opcode == BPF_ARSH) &&
        BPF_SRC(insn->code) == BPF_K) {
      int size = BPF_CLASS(insn->code) == BPF_ALU64 ? 64 : 32;

      if (insn->imm < 0 || insn->imm >= size) {
        verbose(env, "invalid shift %d\n", insn->imm);
        return -EINVAL;
      }
    }

    /* check dest operand */
    err = check_reg_arg(env, insn->dst_reg, DST_OP_NO_MARK);
    err = err ?: adjust_reg_min_max_vals(env, insn);
    if (err)
      return err;
  }

  return reg_bounds_sanity_check(env, &regs[insn->dst_reg], "alu");
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_arg_pair_ok(const struct bpf_func_proto *fn) {
  /* bpf_xxx(..., buf, len) call will access 'len'
   * bytes from memory 'buf'. Both arg types need
   * to be paired, so make sure there's no buggy
   * helper function specification.
   */
  if (arg_type_is_mem_size(fn->arg1_type) || check_args_pair_invalid(fn, 0) ||
      check_args_pair_invalid(fn, 1) || check_args_pair_invalid(fn, 2) ||
      check_args_pair_invalid(fn, 3) || check_args_pair_invalid(fn, 4))
    return false;

  return true;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_args_pair_invalid(const struct bpf_func_proto *fn, int arg) {
  bool is_fixed = fn->arg_type[arg] & MEM_FIXED_SIZE;
  bool has_size = fn->arg_size[arg] != 0;
  bool is_next_size = false;

  if (arg + 1 < ARRAY_SIZE(fn->arg_type))
    is_next_size = arg_type_is_mem_size(fn->arg_type[arg + 1]);

  if (base_type(fn->arg_type[arg]) != ARG_PTR_TO_MEM)
    return is_next_size;

  return has_size == is_next_size || is_next_size == is_fixed;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_atomic(struct bpf_verifier_env *env, struct bpf_insn *insn) {
  switch (insn->imm) {
  case BPF_ADD:
  case BPF_ADD | BPF_FETCH:
  case BPF_AND:
  case BPF_AND | BPF_FETCH:
  case BPF_OR:
  case BPF_OR | BPF_FETCH:
  case BPF_XOR:
  case BPF_XOR | BPF_FETCH:
  case BPF_XCHG:
  case BPF_CMPXCHG:
    return check_atomic_rmw(env, insn);
  case BPF_LOAD_ACQ:
    if (BPF_SIZE(insn->code) == BPF_DW && BITS_PER_LONG != 64) {
      verbose(env,
              "64-bit load-acquires are only supported on 64-bit arches\n");
      return -EOPNOTSUPP;
    }
    return check_atomic_load(env, insn);
  case BPF_STORE_REL:
    if (BPF_SIZE(insn->code) == BPF_DW && BITS_PER_LONG != 64) {
      verbose(env,
              "64-bit store-releases are only supported on 64-bit arches\n");
      return -EOPNOTSUPP;
    }
    return check_atomic_store(env, insn);
  default:
    verbose(env, "BPF_ATOMIC uses invalid atomic opcode %02x\n", insn->imm);
    return -EINVAL;
  }
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_atomic_load(struct bpf_verifier_env *env,
                             struct bpf_insn *insn) {
  int err;

  err = check_load_mem(env, insn, true, false, false, "atomic_load");
  if (err)
    return err;

  if (!atomic_ptr_type_ok(env, insn->src_reg, insn)) {
    verbose(env, "BPF_ATOMIC loads from R%d %s is not allowed\n", insn->src_reg,
            reg_type_str(env, reg_state(env, insn->src_reg)->type));
    return -EACCES;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_atomic_rmw(struct bpf_verifier_env *env,
                            struct bpf_insn *insn) {
  int load_reg;
  int err;

  if (BPF_SIZE(insn->code) != BPF_W && BPF_SIZE(insn->code) != BPF_DW) {
    verbose(env, "invalid atomic operand size\n");
    return -EINVAL;
  }

  /* check src1 operand */
  err = check_reg_arg(env, insn->src_reg, SRC_OP);
  if (err)
    return err;

  /* check src2 operand */
  err = check_reg_arg(env, insn->dst_reg, SRC_OP);
  if (err)
    return err;

  if (insn->imm == BPF_CMPXCHG) {
    /* Check comparison of R0 with memory location */
    const u32 aux_reg = BPF_REG_0;

    err = check_reg_arg(env, aux_reg, SRC_OP);
    if (err)
      return err;

    if (is_pointer_value(env, aux_reg)) {
      verbose(env, "R%d leaks addr into mem\n", aux_reg);
      return -EACCES;
    }
  }

  if (is_pointer_value(env, insn->src_reg)) {
    verbose(env, "R%d leaks addr into mem\n", insn->src_reg);
    return -EACCES;
  }

  if (!atomic_ptr_type_ok(env, insn->dst_reg, insn)) {
    verbose(env, "BPF_ATOMIC stores into R%d %s is not allowed\n",
            insn->dst_reg,
            reg_type_str(env, reg_state(env, insn->dst_reg)->type));
    return -EACCES;
  }

  if (insn->imm & BPF_FETCH) {
    if (insn->imm == BPF_CMPXCHG)
      load_reg = BPF_REG_0;
    else
      load_reg = insn->src_reg;

    /* check and record load of old value */
    err = check_reg_arg(env, load_reg, DST_OP);
    if (err)
      return err;
  } else {
    /* This instruction accesses a memory location but doesn't
     * actually load it into a register.
     */
    load_reg = -1;
  }

  /* Check whether we can read the memory, with second call for fetch
   * case to simulate the register fill.
   */
  err = check_mem_access(env, env->insn_idx, insn->dst_reg, insn->off,
                         BPF_SIZE(insn->code), BPF_READ, -1, true, false);
  if (!err && load_reg >= 0)
    err =
        check_mem_access(env, env->insn_idx, insn->dst_reg, insn->off,
                         BPF_SIZE(insn->code), BPF_READ, load_reg, true, false);
  if (err)
    return err;

  if (is_arena_reg(env, insn->dst_reg)) {
    err = save_aux_ptr_type(env, PTR_TO_ARENA, false);
    if (err)
      return err;
  }
  /* Check whether we can write into the same memory. */
  err = check_mem_access(env, env->insn_idx, insn->dst_reg, insn->off,
                         BPF_SIZE(insn->code), BPF_WRITE, -1, true, false);
  if (err)
    return err;
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_atomic_store(struct bpf_verifier_env *env,
                              struct bpf_insn *insn) {
  int err;

  err = check_store_reg(env, insn, true);
  if (err)
    return err;

  if (!atomic_ptr_type_ok(env, insn->dst_reg, insn)) {
    verbose(env, "BPF_ATOMIC stores into R%d %s is not allowed\n",
            insn->dst_reg,
            reg_type_str(env, reg_state(env, insn->dst_reg)->type));
    return -EACCES;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_attach_btf_id(struct bpf_verifier_env *env) {
  struct bpf_prog *prog = env->prog;
  struct bpf_prog *tgt_prog = prog->aux->dst_prog;
  struct bpf_attach_target_info tgt_info = {};
  u32 btf_id = prog->aux->attach_btf_id;
  struct bpf_trampoline *tr;
  int ret;
  u64 key;

  if (prog->type == BPF_PROG_TYPE_SYSCALL) {
    if (prog->sleepable)
      /* attach_btf_id checked to be zero already */
      return 0;
    verbose(env, "Syscall programs can only be sleepable\n");
    return -EINVAL;
  }

  if (prog->sleepable && !can_be_sleepable(prog)) {
    verbose(env, "Only fentry/fexit/fmod_ret, lsm, iter, uprobe, and "
                 "struct_ops programs can be sleepable\n");
    return -EINVAL;
  }

  if (prog->type == BPF_PROG_TYPE_STRUCT_OPS)
    return check_struct_ops_btf_id(env);

  if (prog->type != BPF_PROG_TYPE_TRACING && prog->type != BPF_PROG_TYPE_LSM &&
      prog->type != BPF_PROG_TYPE_EXT)
    return 0;

  ret = bpf_check_attach_target(&env->log, prog, tgt_prog, btf_id, &tgt_info);
  if (ret)
    return ret;

  if (tgt_prog && prog->type == BPF_PROG_TYPE_EXT) {
    /* to make freplace equivalent to their targets, they need to
     * inherit env->ops and expected_attach_type for the rest of the
     * verification
     */
    env->ops = bpf_verifier_ops[tgt_prog->type];
    prog->expected_attach_type = tgt_prog->expected_attach_type;
  }

  /* store info about the attachment target that will be used later */
  prog->aux->attach_func_proto = tgt_info.tgt_type;
  prog->aux->attach_func_name = tgt_info.tgt_name;
  prog->aux->mod = tgt_info.tgt_mod;

  if (tgt_prog) {
    prog->aux->saved_dst_prog_type = tgt_prog->type;
    prog->aux->saved_dst_attach_type = tgt_prog->expected_attach_type;
  }

  if (prog->expected_attach_type == BPF_TRACE_RAW_TP) {
    prog->aux->attach_btf_trace = true;
    return 0;
  } else if (prog->expected_attach_type == BPF_TRACE_ITER) {
    return bpf_iter_prog_supported(prog);
  }

  if (prog->type == BPF_PROG_TYPE_LSM) {
    ret = bpf_lsm_verify_prog(&env->log, prog);
    if (ret < 0)
      return ret;
  } else if (prog->type == BPF_PROG_TYPE_TRACING &&
             btf_id_set_contains(&btf_id_deny, btf_id)) {
    verbose(env, "Attaching tracing programs to function '%s' is rejected.\n",
            tgt_info.tgt_name);
    return -EINVAL;
  } else if ((prog->expected_attach_type == BPF_TRACE_FEXIT ||
              prog->expected_attach_type == BPF_TRACE_FSESSION ||
              prog->expected_attach_type == BPF_MODIFY_RETURN) &&
             btf_id_set_contains(&noreturn_deny, btf_id)) {
    verbose(env,
            "Attaching fexit/fsession/fmod_ret to __noreturn function '%s' is "
            "rejected.\n",
            tgt_info.tgt_name);
    return -EINVAL;
  }

  key = bpf_trampoline_compute_key(tgt_prog, prog->aux->attach_btf, btf_id);
  tr = bpf_trampoline_get(key, &tgt_info);
  if (!tr)
    return -ENOMEM;

  if (tgt_prog && tgt_prog->aux->tail_call_reachable)
    tr->flags = BPF_TRAMP_F_TAIL_CALL_CTX;

  prog->aux->dst_trampoline = tr;
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_attach_modify_return(unsigned long addr,
                                      const char *func_name) {
  if (within_error_injection_list(addr) ||
      !strncmp(SECURITY_PREFIX, func_name, sizeof(SECURITY_PREFIX) - 1))
    return 0;

  return -EINVAL;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_bpf_snprintf_call(struct bpf_verifier_env *env,
                                   struct bpf_reg_state *regs) {
  struct bpf_reg_state *fmt_reg = &regs[BPF_REG_3];
  struct bpf_reg_state *data_len_reg = &regs[BPF_REG_5];
  struct bpf_map *fmt_map = fmt_reg->map_ptr;
  struct bpf_bprintf_data data = {};
  int err, fmt_map_off, num_args;
  u64 fmt_addr;
  char *fmt;

  /* data must be an array of u64 */
  if (data_len_reg->var_off.value % 8)
    return -EINVAL;
  num_args = data_len_reg->var_off.value / 8;

  /* fmt being ARG_PTR_TO_CONST_STR guarantees that var_off is const
   * and map_direct_value_addr is set.
   */
  fmt_map_off = fmt_reg->off + fmt_reg->var_off.value;
  err = fmt_map->ops->map_direct_value_addr(fmt_map, &fmt_addr, fmt_map_off);
  if (err) {
    verbose(env, "failed to retrieve map value address\n");
    return -EFAULT;
  }
  fmt = (char *)(long)fmt_addr + fmt_map_off;

  /* We are also guaranteed that fmt+fmt_map_off is NULL terminated, we
   * can focus on validating the format specifiers.
   */
  err = bpf_bprintf_prepare(fmt, UINT_MAX, NULL, num_args, &data);
  if (err < 0)
    verbose(env, "Invalid format string\n");

  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_btf_func(struct bpf_verifier_env *env,
                          const union bpf_attr *attr, bpfptr_t uattr) {
  const struct btf_type *type, *func_proto, *ret_type;
  u32 i, nfuncs, urec_size;
  struct bpf_func_info *krecord;
  struct bpf_func_info_aux *info_aux = NULL;
  struct bpf_prog *prog;
  const struct btf *btf;
  bpfptr_t urecord;
  bool scalar_return;
  int ret = -ENOMEM;

  nfuncs = attr->func_info_cnt;
  if (!nfuncs) {
    if (check_abnormal_return(env))
      return -EINVAL;
    return 0;
  }
  if (nfuncs != env->subprog_cnt) {
    verbose(env,
            "number of funcs in func_info doesn't match number of subprogs\n");
    return -EINVAL;
  }

  urec_size = attr->func_info_rec_size;

  prog = env->prog;
  btf = prog->aux->btf;

  urecord = make_bpfptr(attr->func_info, uattr.is_kernel);

  krecord = prog->aux->func_info;
  info_aux = kzalloc_objs(*info_aux, nfuncs, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
  if (!info_aux)
    return -ENOMEM;

  for (i = 0; i < nfuncs; i++) {
    /* check insn_off */
    ret = -EINVAL;

    if (env->subprog_info[i].start != krecord[i].insn_off) {
      verbose(env, "func_info BTF section doesn't match subprog layout in BPF "
                   "program\n");
      goto err_free;
    }

    /* Already checked type_id */
    type = btf_type_by_id(btf, krecord[i].type_id);
    info_aux[i].linkage = BTF_INFO_VLEN(type->info);
    /* Already checked func_proto */
    func_proto = btf_type_by_id(btf, type->type);

    ret_type = btf_type_skip_modifiers(btf, func_proto->type, NULL);
    scalar_return =
        btf_type_is_small_int(ret_type) || btf_is_any_enum(ret_type);
    if (i && !scalar_return && env->subprog_info[i].has_ld_abs) {
      verbose(env, "LD_ABS is only allowed in functions that return 'int'.\n");
      goto err_free;
    }
    if (i && !scalar_return && env->subprog_info[i].has_tail_call) {
      verbose(env,
              "tail_call is only allowed in functions that return 'int'.\n");
      goto err_free;
    }

    bpfptr_add(&urecord, urec_size);
  }

  prog->aux->func_info_aux = info_aux;
  return 0;

err_free:
  kfree(info_aux);
  return ret;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_btf_func_early(struct bpf_verifier_env *env,
                                const union bpf_attr *attr, bpfptr_t uattr) {
  u32 krec_size = sizeof(struct bpf_func_info);
  const struct btf_type *type, *func_proto;
  u32 i, nfuncs, urec_size, min_size;
  struct bpf_func_info *krecord;
  struct bpf_prog *prog;
  const struct btf *btf;
  u32 prev_offset = 0;
  bpfptr_t urecord;
  int ret = -ENOMEM;

  nfuncs = attr->func_info_cnt;
  if (!nfuncs) {
    if (check_abnormal_return(env))
      return -EINVAL;
    return 0;
  }

  urec_size = attr->func_info_rec_size;
  if (urec_size < MIN_BPF_FUNCINFO_SIZE || urec_size > MAX_FUNCINFO_REC_SIZE ||
      urec_size % sizeof(u32)) {
    verbose(env, "invalid func info rec size %u\n", urec_size);
    return -EINVAL;
  }

  prog = env->prog;
  btf = prog->aux->btf;

  urecord = make_bpfptr(attr->func_info, uattr.is_kernel);
  min_size = min_t(u32, krec_size, urec_size);

  krecord = kvcalloc(nfuncs, krec_size, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
  if (!krecord)
    return -ENOMEM;

  for (i = 0; i < nfuncs; i++) {
    ret = bpf_check_uarg_tail_zero(urecord, krec_size, urec_size);
    if (ret) {
      if (ret == -E2BIG) {
        verbose(env, "nonzero tailing record in func info");
        /* set the size kernel expects so loader can zero
         * out the rest of the record.
         */
        if (copy_to_bpfptr_offset(uattr,
                                  offsetof(union bpf_attr, func_info_rec_size),
                                  &min_size, sizeof(min_size)))
          ret = -EFAULT;
      }
      goto err_free;
    }

    if (copy_from_bpfptr(&krecord[i], urecord, min_size)) {
      ret = -EFAULT;
      goto err_free;
    }

    /* check insn_off */
    ret = -EINVAL;
    if (i == 0) {
      if (krecord[i].insn_off) {
        verbose(env, "nonzero insn_off %u for the first func info record",
                krecord[i].insn_off);
        goto err_free;
      }
    } else if (krecord[i].insn_off <= prev_offset) {
      verbose(env,
              "same or smaller insn offset (%u) than previous func info record "
              "(%u)",
              krecord[i].insn_off, prev_offset);
      goto err_free;
    }

    /* check type_id */
    type = btf_type_by_id(btf, krecord[i].type_id);
    if (!type || !btf_type_is_func(type)) {
      verbose(env, "invalid type id %d in func info", krecord[i].type_id);
      goto err_free;
    }

    func_proto = btf_type_by_id(btf, type->type);
    if (unlikely(!func_proto || !btf_type_is_func_proto(func_proto)))
      /* btf_func_check() already verified it during BTF load */
      goto err_free;

    prev_offset = krecord[i].insn_off;
    bpfptr_add(&urecord, urec_size);
  }

  prog->aux->func_info = krecord;
  prog->aux->func_info_cnt = nfuncs;
  return 0;

err_free:
  kvfree(krecord);
  return ret;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_btf_id_ok(const struct bpf_func_proto *fn) {
  int i;

  for (i = 0; i < ARRAY_SIZE(fn->arg_type); i++) {
    if (base_type(fn->arg_type[i]) == ARG_PTR_TO_BTF_ID)
      return !!fn->arg_btf_id[i];
    if (base_type(fn->arg_type[i]) == ARG_PTR_TO_SPIN_LOCK)
      return fn->arg_btf_id[i] == BPF_PTR_POISON;
    if (base_type(fn->arg_type[i]) != ARG_PTR_TO_BTF_ID && fn->arg_btf_id[i] &&
        /* arg_btf_id and arg_size are in a union. */
        (base_type(fn->arg_type[i]) != ARG_PTR_TO_MEM ||
         !(fn->arg_type[i] & MEM_FIXED_SIZE)))
      return false;
  }

  return true;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_btf_info(struct bpf_verifier_env *env,
                          const union bpf_attr *attr, bpfptr_t uattr) {
  int err;

  if (!attr->func_info_cnt && !attr->line_info_cnt) {
    if (check_abnormal_return(env))
      return -EINVAL;
    return 0;
  }

  err = check_btf_func(env, attr, uattr);
  if (err)
    return err;

  err = check_btf_line(env, attr, uattr);
  if (err)
    return err;

  err = check_core_relo(env, attr, uattr);
  if (err)
    return err;

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_btf_info_early(struct bpf_verifier_env *env,
                                const union bpf_attr *attr, bpfptr_t uattr) {
  struct btf *btf;
  int err;

  if (!attr->func_info_cnt && !attr->line_info_cnt) {
    if (check_abnormal_return(env))
      return -EINVAL;
    return 0;
  }

  btf = btf_get_by_fd(attr->prog_btf_fd);
  if (IS_ERR(btf))
    return PTR_ERR(btf);
  if (btf_is_kernel(btf)) {
    btf_put(btf);
    return -EACCES;
  }
  env->prog->aux->btf = btf;

  err = check_btf_func_early(env, attr, uattr);
  if (err)
    return err;
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_btf_line(struct bpf_verifier_env *env,
                          const union bpf_attr *attr, bpfptr_t uattr) {
  u32 i, s, nr_linfo, ncopy, expected_size, rec_size, prev_offset = 0;
  struct bpf_subprog_info *sub;
  struct bpf_line_info *linfo;
  struct bpf_prog *prog;
  const struct btf *btf;
  bpfptr_t ulinfo;
  int err;

  nr_linfo = attr->line_info_cnt;
  if (!nr_linfo)
    return 0;
  if (nr_linfo > INT_MAX / sizeof(struct bpf_line_info))
    return -EINVAL;

  rec_size = attr->line_info_rec_size;
  if (rec_size < MIN_BPF_LINEINFO_SIZE || rec_size > MAX_LINEINFO_REC_SIZE ||
      rec_size & (sizeof(u32) - 1))
    return -EINVAL;

  /* Need to zero it in case the userspace may
   * pass in a smaller bpf_line_info object.
   */
  linfo = kvzalloc_objs(struct bpf_line_info, nr_linfo,
                        GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
  if (!linfo)
    return -ENOMEM;

  prog = env->prog;
  btf = prog->aux->btf;

  s = 0;
  sub = env->subprog_info;
  ulinfo = make_bpfptr(attr->line_info, uattr.is_kernel);
  expected_size = sizeof(struct bpf_line_info);
  ncopy = min_t(u32, expected_size, rec_size);
  for (i = 0; i < nr_linfo; i++) {
    err = bpf_check_uarg_tail_zero(ulinfo, expected_size, rec_size);
    if (err) {
      if (err == -E2BIG) {
        verbose(env, "nonzero tailing record in line_info");
        if (copy_to_bpfptr_offset(uattr,
                                  offsetof(union bpf_attr, line_info_rec_size),
                                  &expected_size, sizeof(expected_size)))
          err = -EFAULT;
      }
      goto err_free;
    }

    if (copy_from_bpfptr(&linfo[i], ulinfo, ncopy)) {
      err = -EFAULT;
      goto err_free;
    }

    /*
     * Check insn_off to ensure
     * 1) strictly increasing AND
     * 2) bounded by prog->len
     *
     * The linfo[0].insn_off == 0 check logically falls into
     * the later "missing bpf_line_info for func..." case
     * because the first linfo[0].insn_off must be the
     * first sub also and the first sub must have
     * subprog_info[0].start == 0.
     */
    if ((i && linfo[i].insn_off <= prev_offset) ||
        linfo[i].insn_off >= prog->len) {
      verbose(
          env,
          "Invalid line_info[%u].insn_off:%u (prev_offset:%u prog->len:%u)\n",
          i, linfo[i].insn_off, prev_offset, prog->len);
      err = -EINVAL;
      goto err_free;
    }

    if (!prog->insnsi[linfo[i].insn_off].code) {
      verbose(env, "Invalid insn code at line_info[%u].insn_off\n", i);
      err = -EINVAL;
      goto err_free;
    }

    if (!btf_name_by_offset(btf, linfo[i].line_off) ||
        !btf_name_by_offset(btf, linfo[i].file_name_off)) {
      verbose(env, "Invalid line_info[%u].line_off or .file_name_off\n", i);
      err = -EINVAL;
      goto err_free;
    }

    if (s != env->subprog_cnt) {
      if (linfo[i].insn_off == sub[s].start) {
        sub[s].linfo_idx = i;
        s++;
      } else if (sub[s].start < linfo[i].insn_off) {
        verbose(env, "missing bpf_line_info for func#%u\n", s);
        err = -EINVAL;
        goto err_free;
      }
    }

    prev_offset = linfo[i].insn_off;
    bpfptr_add(&ulinfo, rec_size);
  }

  if (s != env->subprog_cnt) {
    verbose(env, "missing bpf_line_info for %u funcs starting from func#%u\n",
            env->subprog_cnt - s, s);
    err = -EINVAL;
    goto err_free;
  }

  prog->aux->linfo = linfo;
  prog->aux->nr_linfo = nr_linfo;

  return 0;

err_free:
  kvfree(linfo);
  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_buffer_access(struct bpf_verifier_env *env,
                               const struct bpf_reg_state *reg, int regno,
                               int off, int size, bool zero_size_allowed,
                               u32 *max_access) {
  const char *buf_info = type_is_rdonly_mem(reg->type) ? "rdonly" : "rdwr";
  int err;

  err = inner_check_buffer_access(env, buf_info, reg, regno, off, size);
  if (err)
    return err;

  if (off + size > *max_access)
    *max_access = off + size;

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_cfg(struct bpf_verifier_env *env) {
  int insn_cnt = env->prog->len;
  int *insn_stack, *insn_state;
  int ex_insn_beg, i, ret = 0;

  insn_state = env->cfg.insn_state =
      kvzalloc_objs(int, insn_cnt, GFP_KERNEL_ACCOUNT);
  if (!insn_state)
    return -ENOMEM;

  insn_stack = env->cfg.insn_stack =
      kvzalloc_objs(int, insn_cnt, GFP_KERNEL_ACCOUNT);
  if (!insn_stack) {
    kvfree(insn_state);
    return -ENOMEM;
  }

  ex_insn_beg = env->exception_callback_subprog
                    ? env->subprog_info[env->exception_callback_subprog].start
                    : 0;

  insn_state[0] = DISCOVERED; /* mark 1st insn as discovered */
  insn_stack[0] = 0;          /* 0 is the first instruction */
  env->cfg.cur_stack = 1;

walk_cfg:
  while (env->cfg.cur_stack > 0) {
    int t = insn_stack[env->cfg.cur_stack - 1];

    ret = visit_insn(t, env);
    switch (ret) {
    case DONE_EXPLORING:
      insn_state[t] = EXPLORED;
      env->cfg.cur_stack--;
      break;
    case KEEP_EXPLORING:
      break;
    default:
      if (ret > 0) {
        verifier_bug(env, "visit_insn internal bug");
        ret = -EFAULT;
      }
      goto err_free;
    }
  }

  if (env->cfg.cur_stack < 0) {
    verifier_bug(env, "pop stack internal bug");
    ret = -EFAULT;
    goto err_free;
  }

  if (ex_insn_beg && insn_state[ex_insn_beg] != EXPLORED) {
    insn_state[ex_insn_beg] = DISCOVERED;
    insn_stack[0] = ex_insn_beg;
    env->cfg.cur_stack = 1;
    goto walk_cfg;
  }

  for (i = 0; i < insn_cnt; i++) {
    struct bpf_insn *insn = &env->prog->insnsi[i];

    if (insn_state[i] != EXPLORED) {
      verbose(env, "unreachable insn %d\n", i);
      ret = -EINVAL;
      goto err_free;
    }
    if (bpf_is_ldimm64(insn)) {
      if (insn_state[i + 1] != 0) {
        verbose(env, "jump into the middle of ldimm64 insn %d\n", i);
        ret = -EINVAL;
        goto err_free;
      }
      i++; /* skip second half of ldimm64 */
    }
  }
  ret = 0; /* cfg looks good */
  env->prog->aux->changes_pkt_data = env->subprog_info[0].changes_pkt_data;
  env->prog->aux->might_sleep = env->subprog_info[0].might_sleep;

err_free:
  kvfree(insn_state);
  kvfree(insn_stack);
  env->cfg.insn_state = env->cfg.insn_stack = NULL;
  return ret;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_cond_jmp_op(struct bpf_verifier_env *env,
                             struct bpf_insn *insn, int *insn_idx) {
  struct bpf_verifier_state *this_branch = env->cur_state;
  struct bpf_verifier_state *other_branch;
  struct bpf_reg_state *regs = this_branch->frame[this_branch->curframe]->regs;
  struct bpf_reg_state *dst_reg, *other_branch_regs, *src_reg = NULL;
  struct bpf_reg_state *eq_branch_regs;
  struct linked_regs linked_regs = {};
  u8 opcode = BPF_OP(insn->code);
  int insn_flags = 0;
  bool is_jmp32;
  int pred = -1;
  int err;

  /* Only conditional jumps are expected to reach here. */
  if (opcode == BPF_JA || opcode > BPF_JCOND) {
    verbose(env, "invalid BPF_JMP/JMP32 opcode %x\n", opcode);
    return -EINVAL;
  }

  if (opcode == BPF_JCOND) {
    struct bpf_verifier_state *cur_st = env->cur_state, *queued_st, *prev_st;
    int idx = *insn_idx;

    if (insn->code != (BPF_JMP | BPF_JCOND) || insn->src_reg != BPF_MAY_GOTO ||
        insn->dst_reg || insn->imm) {
      verbose(env, "invalid may_goto imm %d\n", insn->imm);
      return -EINVAL;
    }
    prev_st = find_prev_entry(env, cur_st->parent, idx);

    /* branch out 'fallthrough' insn as a new state to explore */
    queued_st = push_stack(env, idx + 1, idx, false);
    if (IS_ERR(queued_st))
      return PTR_ERR(queued_st);

    queued_st->may_goto_depth++;
    if (prev_st)
      widen_imprecise_scalars(env, prev_st, queued_st);
    *insn_idx += insn->off;
    return 0;
  }

  /* check src2 operand */
  err = check_reg_arg(env, insn->dst_reg, SRC_OP);
  if (err)
    return err;

  dst_reg = &regs[insn->dst_reg];
  if (BPF_SRC(insn->code) == BPF_X) {
    if (insn->imm != 0) {
      verbose(env, "BPF_JMP/JMP32 uses reserved fields\n");
      return -EINVAL;
    }

    /* check src1 operand */
    err = check_reg_arg(env, insn->src_reg, SRC_OP);
    if (err)
      return err;

    src_reg = &regs[insn->src_reg];
    if (!(reg_is_pkt_pointer_any(dst_reg) && reg_is_pkt_pointer_any(src_reg)) &&
        is_pointer_value(env, insn->src_reg)) {
      verbose(env, "R%d pointer comparison prohibited\n", insn->src_reg);
      return -EACCES;
    }

    if (src_reg->type == PTR_TO_STACK)
      insn_flags |= INSN_F_SRC_REG_STACK;
    if (dst_reg->type == PTR_TO_STACK)
      insn_flags |= INSN_F_DST_REG_STACK;
  } else {
    if (insn->src_reg != BPF_REG_0) {
      verbose(env, "BPF_JMP/JMP32 uses reserved fields\n");
      return -EINVAL;
    }
    src_reg = &env->fake_reg[0];
    memset(src_reg, 0, sizeof(*src_reg));
    src_reg->type = SCALAR_VALUE;
    inner_mark_reg_known(src_reg, insn->imm);

    if (dst_reg->type == PTR_TO_STACK)
      insn_flags |= INSN_F_DST_REG_STACK;
  }

  if (insn_flags) {
    err = push_jmp_history(env, this_branch, insn_flags, 0);
    if (err)
      return err;
  }

  is_jmp32 = BPF_CLASS(insn->code) == BPF_JMP32;
  pred = is_branch_taken(dst_reg, src_reg, opcode, is_jmp32);
  if (pred >= 0) {
    /* If we get here with a dst_reg pointer type it is because
     * above is_branch_taken() special cased the 0 comparison.
     */
    if (!inner_is_pointer_value(false, dst_reg))
      err = mark_chain_precision(env, insn->dst_reg);
    if (BPF_SRC(insn->code) == BPF_X && !err &&
        !inner_is_pointer_value(false, src_reg))
      err = mark_chain_precision(env, insn->src_reg);
    if (err)
      return err;
  }

  if (pred == 1) {
    /* Only follow the goto, ignore fall-through. If needed, push
     * the fall-through branch for simulation under speculative
     * execution.
     */
    if (!env->bypass_spec_v1) {
      err = sanitize_speculative_path(env, insn, *insn_idx + 1, *insn_idx);
      if (err < 0)
        return err;
    }
    if (env->log.level & BPF_LOG_LEVEL)
      print_insn_state(env, this_branch, this_branch->curframe);
    *insn_idx += insn->off;
    return 0;
  } else if (pred == 0) {
    /* Only follow the fall-through branch, since that's where the
     * program will go. If needed, push the goto branch for
     * simulation under speculative execution.
     */
    if (!env->bypass_spec_v1) {
      err = sanitize_speculative_path(env, insn, *insn_idx + insn->off + 1,
                                      *insn_idx);
      if (err < 0)
        return err;
    }
    if (env->log.level & BPF_LOG_LEVEL)
      print_insn_state(env, this_branch, this_branch->curframe);
    return 0;
  }

  /* Push scalar registers sharing same ID to jump history,
   * do this before creating 'other_branch', so that both
   * 'this_branch' and 'other_branch' share this history
   * if parent state is created.
   */
  if (BPF_SRC(insn->code) == BPF_X && src_reg->type == SCALAR_VALUE &&
      src_reg->id)
    collect_linked_regs(env, this_branch, src_reg->id, &linked_regs);
  if (dst_reg->type == SCALAR_VALUE && dst_reg->id)
    collect_linked_regs(env, this_branch, dst_reg->id, &linked_regs);
  if (linked_regs.cnt > 1) {
    err = push_jmp_history(env, this_branch, 0, linked_regs_pack(&linked_regs));
    if (err)
      return err;
  }

  other_branch = push_stack(env, *insn_idx + insn->off + 1, *insn_idx, false);
  if (IS_ERR(other_branch))
    return PTR_ERR(other_branch);
  other_branch_regs = other_branch->frame[other_branch->curframe]->regs;

  if (BPF_SRC(insn->code) == BPF_X) {
    err = reg_set_min_max(env, &other_branch_regs[insn->dst_reg],
                          &other_branch_regs[insn->src_reg], dst_reg, src_reg,
                          opcode, is_jmp32);
  } else /* BPF_SRC(insn->code) == BPF_K */ {
    /* reg_set_min_max() can mangle the fake_reg. Make a copy
     * so that these are two different memory locations. The
     * src_reg is not used beyond here in context of K.
     */
    memcpy(&env->fake_reg[1], &env->fake_reg[0], sizeof(env->fake_reg[0]));
    err = reg_set_min_max(env, &other_branch_regs[insn->dst_reg],
                          &env->fake_reg[0], dst_reg, &env->fake_reg[1], opcode,
                          is_jmp32);
  }
  if (err)
    return err;

  if (BPF_SRC(insn->code) == BPF_X && src_reg->type == SCALAR_VALUE &&
      src_reg->id &&
      !WARN_ON_ONCE(src_reg->id != other_branch_regs[insn->src_reg].id)) {
    sync_linked_regs(env, this_branch, src_reg, &linked_regs);
    sync_linked_regs(env, other_branch, &other_branch_regs[insn->src_reg],
                     &linked_regs);
  }
  if (dst_reg->type == SCALAR_VALUE && dst_reg->id &&
      !WARN_ON_ONCE(dst_reg->id != other_branch_regs[insn->dst_reg].id)) {
    sync_linked_regs(env, this_branch, dst_reg, &linked_regs);
    sync_linked_regs(env, other_branch, &other_branch_regs[insn->dst_reg],
                     &linked_regs);
  }

  /* if one pointer register is compared to another pointer
   * register check if PTR_MAYBE_NULL could be lifted.
   * E.g. register A - maybe null
   *      register B - not null
   * for JNE A, B, ... - A is not null in the false branch;
   * for JEQ A, B, ... - A is not null in the true branch.
   *
   * Since PTR_TO_BTF_ID points to a kernel struct that does
   * not need to be null checked by the BPF program, i.e.,
   * could be null even without PTR_MAYBE_NULL marking, so
   * only propagate nullness when neither reg is that type.
   */
  if (!is_jmp32 && BPF_SRC(insn->code) == BPF_X &&
      inner_is_pointer_value(false, src_reg) &&
      inner_is_pointer_value(false, dst_reg) &&
      type_may_be_null(src_reg->type) != type_may_be_null(dst_reg->type) &&
      base_type(src_reg->type) != PTR_TO_BTF_ID &&
      base_type(dst_reg->type) != PTR_TO_BTF_ID) {
    eq_branch_regs = NULL;
    switch (opcode) {
    case BPF_JEQ:
      eq_branch_regs = other_branch_regs;
      break;
    case BPF_JNE:
      eq_branch_regs = regs;
      break;
    default:
      /* do nothing */
      break;
    }
    if (eq_branch_regs) {
      if (type_may_be_null(src_reg->type))
        mark_ptr_not_null_reg(&eq_branch_regs[insn->src_reg]);
      else
        mark_ptr_not_null_reg(&eq_branch_regs[insn->dst_reg]);
    }
  }

  /* detect if R == 0 where R is returned from bpf_map_lookup_elem().
   * NOTE: these optimizations below are related with pointer comparison
   *       which will never be JMP32.
   */
  if (!is_jmp32 && BPF_SRC(insn->code) == BPF_K && insn->imm == 0 &&
      (opcode == BPF_JEQ || opcode == BPF_JNE) &&
      type_may_be_null(dst_reg->type)) {
    /* Mark all identical registers in each branch as either
     * safe or unknown depending R == 0 or R != 0 conditional.
     */
    mark_ptr_or_null_regs(this_branch, insn->dst_reg, opcode == BPF_JNE);
    mark_ptr_or_null_regs(other_branch, insn->dst_reg, opcode == BPF_JEQ);
  } else if (!try_match_pkt_pointers(insn, dst_reg, &regs[insn->src_reg],
                                     this_branch, other_branch) &&
             is_pointer_value(env, insn->dst_reg)) {
    verbose(env, "R%d pointer comparison prohibited\n", insn->dst_reg);
    return -EACCES;
  }
  if (env->log.level & BPF_LOG_LEVEL)
    print_insn_state(env, this_branch, this_branch->curframe);
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_core_relo(struct bpf_verifier_env *env,
                           const union bpf_attr *attr, bpfptr_t uattr) {
  u32 i, nr_core_relo, ncopy, expected_size, rec_size;
  struct bpf_core_relo core_relo = {};
  struct bpf_prog *prog = env->prog;
  const struct btf *btf = prog->aux->btf;
  struct bpf_core_ctx ctx = {
      .log = &env->log,
      .btf = btf,
  };
  bpfptr_t u_core_relo;
  int err;

  nr_core_relo = attr->core_relo_cnt;
  if (!nr_core_relo)
    return 0;
  if (nr_core_relo > INT_MAX / sizeof(struct bpf_core_relo))
    return -EINVAL;

  rec_size = attr->core_relo_rec_size;
  if (rec_size < MIN_CORE_RELO_SIZE || rec_size > MAX_CORE_RELO_SIZE ||
      rec_size % sizeof(u32))
    return -EINVAL;

  u_core_relo = make_bpfptr(attr->core_relos, uattr.is_kernel);
  expected_size = sizeof(struct bpf_core_relo);
  ncopy = min_t(u32, expected_size, rec_size);

  /* Unlike func_info and line_info, copy and apply each CO-RE
   * relocation record one at a time.
   */
  for (i = 0; i < nr_core_relo; i++) {
    /* future proofing when sizeof(bpf_core_relo) changes */
    err = bpf_check_uarg_tail_zero(u_core_relo, expected_size, rec_size);
    if (err) {
      if (err == -E2BIG) {
        verbose(env, "nonzero tailing record in core_relo");
        if (copy_to_bpfptr_offset(uattr,
                                  offsetof(union bpf_attr, core_relo_rec_size),
                                  &expected_size, sizeof(expected_size)))
          err = -EFAULT;
      }
      break;
    }

    if (copy_from_bpfptr(&core_relo, u_core_relo, ncopy)) {
      err = -EFAULT;
      break;
    }

    if (core_relo.insn_off % 8 || core_relo.insn_off / 8 >= prog->len) {
      verbose(env, "Invalid core_relo[%u].insn_off:%u prog->len:%u\n", i,
              core_relo.insn_off, prog->len);
      err = -EINVAL;
      break;
    }

    err = bpf_core_apply(&ctx, &core_relo, i,
                         &prog->insnsi[core_relo.insn_off / 8]);
    if (err)
      break;
    bpfptr_add(&u_core_relo, rec_size);
  }
  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_css_task_iter_allowlist(struct bpf_verifier_env *env) {
  enum bpf_prog_type prog_type = resolve_prog_type(env->prog);

  switch (prog_type) {
  case BPF_PROG_TYPE_LSM:
    return true;
  case BPF_PROG_TYPE_TRACING:
    if (env->prog->expected_attach_type == BPF_TRACE_ITER)
      return true;
    fallthrough;
  default:
    return in_sleepable(env);
  }
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_ctx_access(struct bpf_verifier_env *env, int insn_idx, int off,
                            int size, enum bpf_access_type t,
                            struct bpf_insn_access_aux *info) {
  if (env->ops->is_valid_access &&
      env->ops->is_valid_access(off, size, t, env->prog, info)) {
    /* A non zero info.ctx_field_size indicates that this field is a
     * candidate for later verifier transformation to load the whole
     * field and then apply a mask when accessed with a narrower
     * access than actual ctx access size. A zero info.ctx_field_size
     * will only allow for whole field access and rejects any other
     * type of narrower access.
     */
    if (base_type(info->reg_type) == PTR_TO_BTF_ID) {
      if (info->ref_obj_id &&
          !find_reference_state(env->cur_state, info->ref_obj_id)) {
        verbose(env,
                "invalid bpf_context access off=%d. Reference may already be "
                "released\n",
                off);
        return -EACCES;
      }
    } else {
      env->insn_aux_data[insn_idx].ctx_field_size = info->ctx_field_size;
    }
    /* remember the offset of last byte accessed in ctx */
    if (env->prog->aux->max_ctx_offset < off + size)
      env->prog->aux->max_ctx_offset = off + size;
    return 0;
  }

  verbose(env, "invalid bpf_context access off=%d size=%d\n", off, size);
  return -EACCES;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static void check_fastcall_stack_contract(struct bpf_verifier_env *env,
                                          struct bpf_func_state *state,
                                          int insn_idx, int off) {
  struct bpf_subprog_info *subprog = &env->subprog_info[state->subprogno];
  struct bpf_insn_aux_data *aux = env->insn_aux_data;
  int i;

  if (subprog->fastcall_stack_off <= off || aux[insn_idx].fastcall_pattern)
    return;
  /* access to the region [max_stack_depth .. fastcall_stack_off)
   * from something that is not a part of the fastcall pattern,
   * disable fastcall rewrites for current subprogram by setting
   * fastcall_stack_off to a value smaller than any possible offset.
   */
  subprog->fastcall_stack_off = S16_MIN;
  /* reset fastcall aux flags within subprogram,
   * happens at most once per subprogram
   */
  for (i = subprog->start; i < (subprog + 1)->start; ++i) {
    aux[i].fastcall_spills_num = 0;
    aux[i].fastcall_pattern = 0;
  }
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_flow_keys_access(struct bpf_verifier_env *env, int off,
                                  int size) {
  if (size < 0 || off < 0 || (u64)off + size > sizeof(struct bpf_flow_keys)) {
    verbose(env, "invalid access to flow keys off=%d size=%d\n", off, size);
    return -EACCES;
  }
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_func_arg(struct bpf_verifier_env *env, u32 arg,
                          struct bpf_call_arg_meta *meta,
                          const struct bpf_func_proto *fn, int insn_idx) {
  u32 regno = BPF_REG_1 + arg;
  struct bpf_reg_state *reg = reg_state(env, regno);
  enum bpf_arg_type arg_type = fn->arg_type[arg];
  enum bpf_reg_type type = reg->type;
  u32 *arg_btf_id = NULL;
  u32 key_size;
  int err = 0;

  if (arg_type == ARG_DONTCARE)
    return 0;

  err = check_reg_arg(env, regno, SRC_OP);
  if (err)
    return err;

  if (arg_type == ARG_ANYTHING) {
    if (is_pointer_value(env, regno)) {
      verbose(env, "R%d leaks addr into helper function\n", regno);
      return -EACCES;
    }
    return 0;
  }

  if (type_is_pkt_pointer(type) &&
      !may_access_direct_pkt_data(env, meta, BPF_READ)) {
    verbose(env, "helper access to the packet is not allowed\n");
    return -EACCES;
  }

  if (base_type(arg_type) == ARG_PTR_TO_MAP_VALUE) {
    err = resolve_map_arg_type(env, meta, &arg_type);
    if (err)
      return err;
  }

  if (register_is_null(reg) && type_may_be_null(arg_type))
    /* A NULL register has a SCALAR_VALUE type, so skip
     * type checking.
     */
    goto skip_type_check;

  /* arg_btf_id and arg_size are in a union. */
  if (base_type(arg_type) == ARG_PTR_TO_BTF_ID ||
      base_type(arg_type) == ARG_PTR_TO_SPIN_LOCK)
    arg_btf_id = fn->arg_btf_id[arg];

  err = check_reg_type(env, regno, arg_type, arg_btf_id, meta);
  if (err)
    return err;

  err = check_func_arg_reg_off(env, reg, regno, arg_type);
  if (err)
    return err;

skip_type_check:
  if (arg_type_is_release(arg_type)) {
    if (arg_type_is_dynptr(arg_type)) {
      struct bpf_func_state *state = func(env, reg);
      int spi;

      /* Only dynptr created on stack can be released, thus
       * the get_spi and stack state checks for spilled_ptr
       * should only be done before process_dynptr_func for
       * PTR_TO_STACK.
       */
      if (reg->type == PTR_TO_STACK) {
        spi = dynptr_get_spi(env, reg);
        if (spi < 0 || !state->stack[spi].spilled_ptr.ref_obj_id) {
          verbose(env, "arg %d is an unacquired reference\n", regno);
          return -EINVAL;
        }
      } else {
        verbose(env, "cannot release unowned const bpf_dynptr\n");
        return -EINVAL;
      }
    } else if (!reg->ref_obj_id && !register_is_null(reg)) {
      verbose(env, "R%d must be referenced when passed to release function\n",
              regno);
      return -EINVAL;
    }
    if (meta->release_regno) {
      verifier_bug(env, "more than one release argument");
      return -EFAULT;
    }
    meta->release_regno = regno;
  }

  if (reg->ref_obj_id && base_type(arg_type) != ARG_KPTR_XCHG_DEST) {
    if (meta->ref_obj_id) {
      verbose(env, "more than one arg with ref_obj_id R%d %u %u", regno,
              reg->ref_obj_id, meta->ref_obj_id);
      return -EACCES;
    }
    meta->ref_obj_id = reg->ref_obj_id;
  }

  switch (base_type(arg_type)) {
  case ARG_CONST_MAP_PTR:
    /* bpf_map_xxx(map_ptr) call: remember that map_ptr */
    if (meta->map.ptr) {
      /* Use map_uid (which is unique id of inner map) to reject:
       * inner_map1 = bpf_map_lookup_elem(outer_map, key1)
       * inner_map2 = bpf_map_lookup_elem(outer_map, key2)
       * if (inner_map1 && inner_map2) {
       *     timer = bpf_map_lookup_elem(inner_map1);
       *     if (timer)
       *         // mismatch would have been allowed
       *         bpf_timer_init(timer, inner_map2);
       * }
       *
       * Comparing map_ptr is enough to distinguish normal and outer maps.
       */
      if (meta->map.ptr != reg->map_ptr || meta->map.uid != reg->map_uid) {
        verbose(env,
                "timer pointer in R1 map_uid=%d doesn't match map pointer in "
                "R2 map_uid=%d\n",
                meta->map.uid, reg->map_uid);
        return -EINVAL;
      }
    }
    meta->map.ptr = reg->map_ptr;
    meta->map.uid = reg->map_uid;
    break;
  case ARG_PTR_TO_MAP_KEY:
    /* bpf_map_xxx(..., map_ptr, ..., key) call:
     * check that [key, key + map->key_size) are within
     * stack limits and initialized
     */
    if (!meta->map.ptr) {
      /* in function declaration map_ptr must come before
       * map_key, so that it's verified and known before
       * we have to check map_key here. Otherwise it means
       * that kernel subsystem misconfigured verifier
       */
      verifier_bug(env, "invalid map_ptr to access map->key");
      return -EFAULT;
    }
    key_size = meta->map.ptr->key_size;
    err = check_helper_mem_access(env, regno, key_size, BPF_READ, false, NULL);
    if (err)
      return err;
    if (can_elide_value_nullness(meta->map.ptr->map_type)) {
      err = get_constant_map_key(env, reg, key_size, &meta->const_map_key);
      if (err < 0) {
        meta->const_map_key = -1;
        if (err == -EOPNOTSUPP)
          err = 0;
        else
          return err;
      }
    }
    break;
  case ARG_PTR_TO_MAP_VALUE:
    if (type_may_be_null(arg_type) && register_is_null(reg))
      return 0;

    /* bpf_map_xxx(..., map_ptr, ..., value) call:
     * check [value, value + map->value_size) validity
     */
    if (!meta->map.ptr) {
      /* kernel subsystem misconfigured verifier */
      verifier_bug(env, "invalid map_ptr to access map->value");
      return -EFAULT;
    }
    meta->raw_mode = arg_type & MEM_UNINIT;
    err = check_helper_mem_access(env, regno, meta->map.ptr->value_size,
                                  arg_type & MEM_WRITE ? BPF_WRITE : BPF_READ,
                                  false, meta);
    break;
  case ARG_PTR_TO_PERCPU_BTF_ID:
    if (!reg->btf_id) {
      verbose(env, "Helper has invalid btf_id in R%d\n", regno);
      return -EACCES;
    }
    meta->ret_btf = reg->btf;
    meta->ret_btf_id = reg->btf_id;
    break;
  case ARG_PTR_TO_SPIN_LOCK:
    if (in_rbtree_lock_required_cb(env)) {
      verbose(env, "can't spin_{lock,unlock} in rbtree cb\n");
      return -EACCES;
    }
    if (meta->func_id == BPF_FUNC_spin_lock) {
      err = process_spin_lock(env, regno, PROCESS_SPIN_LOCK);
      if (err)
        return err;
    } else if (meta->func_id == BPF_FUNC_spin_unlock) {
      err = process_spin_lock(env, regno, 0);
      if (err)
        return err;
    } else {
      verifier_bug(env, "spin lock arg on unexpected helper");
      return -EFAULT;
    }
    break;
  case ARG_PTR_TO_TIMER:
    err = process_timer_helper(env, regno, meta);
    if (err)
      return err;
    break;
  case ARG_PTR_TO_FUNC:
    meta->subprogno = reg->subprogno;
    break;
  case ARG_PTR_TO_MEM:
    /* The access to this pointer is only checked when we hit the
     * next is_mem_size argument below.
     */
    meta->raw_mode = arg_type & MEM_UNINIT;
    if (arg_type & MEM_FIXED_SIZE) {
      err = check_helper_mem_access(env, regno, fn->arg_size[arg],
                                    arg_type & MEM_WRITE ? BPF_WRITE : BPF_READ,
                                    false, meta);
      if (err)
        return err;
      if (arg_type & MEM_ALIGNED)
        err = check_ptr_alignment(env, reg, 0, fn->arg_size[arg], true);
    }
    break;
  case ARG_CONST_SIZE:
    err = check_mem_size_reg(
        env, reg, regno,
        fn->arg_type[arg - 1] & MEM_WRITE ? BPF_WRITE : BPF_READ, false, meta);
    break;
  case ARG_CONST_SIZE_OR_ZERO:
    err = check_mem_size_reg(
        env, reg, regno,
        fn->arg_type[arg - 1] & MEM_WRITE ? BPF_WRITE : BPF_READ, true, meta);
    break;
  case ARG_PTR_TO_DYNPTR:
    err = process_dynptr_func(env, regno, insn_idx, arg_type, 0);
    if (err)
      return err;
    break;
  case ARG_CONST_ALLOC_SIZE_OR_ZERO:
    if (!tnum_is_const(reg->var_off)) {
      verbose(env, "R%d is not a known constant'\n", regno);
      return -EACCES;
    }
    meta->mem_size = reg->var_off.value;
    err = mark_chain_precision(env, regno);
    if (err)
      return err;
    break;
  case ARG_PTR_TO_CONST_STR: {
    err = check_reg_const_str(env, reg, regno);
    if (err)
      return err;
    break;
  }
  case ARG_KPTR_XCHG_DEST:
    err = process_kptr_func(env, regno, meta);
    if (err)
      return err;
    break;
  }

  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_func_arg_reg_off(struct bpf_verifier_env *env,
                                  const struct bpf_reg_state *reg, int regno,
                                  enum bpf_arg_type arg_type) {
  u32 type = reg->type;

  /* When referenced register is passed to release function, its fixed
   * offset must be 0.
   *
   * We will check arg_type_is_release reg has ref_obj_id when storing
   * meta->release_regno.
   */
  if (arg_type_is_release(arg_type)) {
    /* ARG_PTR_TO_DYNPTR with OBJ_RELEASE is a bit special, as it
     * may not directly point to the object being released, but to
     * dynptr pointing to such object, which might be at some offset
     * on the stack. In that case, we simply to fallback to the
     * default handling.
     */
    if (arg_type_is_dynptr(arg_type) && type == PTR_TO_STACK)
      return 0;

    /* Doing check_ptr_off_reg check for the offset will catch this
     * because fixed_off_ok is false, but checking here allows us
     * to give the user a better error message.
     */
    if (reg->off) {
      verbose(env,
              "R%d must have zero offset when passed to release func or "
              "trusted arg to kfunc\n",
              regno);
      return -EINVAL;
    }
    return inner_check_ptr_off_reg(env, reg, regno, false);
  }

  switch (type) {
  /* Pointer types where both fixed and variable offset is explicitly allowed:
   */
  case PTR_TO_STACK:
  case PTR_TO_PACKET:
  case PTR_TO_PACKET_META:
  case PTR_TO_MAP_KEY:
  case PTR_TO_MAP_VALUE:
  case PTR_TO_MEM:
  case PTR_TO_MEM | MEM_RDONLY:
  case PTR_TO_MEM | MEM_RINGBUF:
  case PTR_TO_BUF:
  case PTR_TO_BUF | MEM_RDONLY:
  case PTR_TO_ARENA:
  case SCALAR_VALUE:
    return 0;
  /* All the rest must be rejected, except PTR_TO_BTF_ID which allows
   * fixed offset.
   */
  case PTR_TO_BTF_ID:
  case PTR_TO_BTF_ID | MEM_ALLOC:
  case PTR_TO_BTF_ID | PTR_TRUSTED:
  case PTR_TO_BTF_ID | MEM_RCU:
  case PTR_TO_BTF_ID | MEM_ALLOC | NON_OWN_REF:
  case PTR_TO_BTF_ID | MEM_ALLOC | NON_OWN_REF | MEM_RCU:
    /* When referenced PTR_TO_BTF_ID is passed to release function,
     * its fixed offset must be 0. In the other cases, fixed offset
     * can be non-zero. This was already checked above. So pass
     * fixed_off_ok as true to allow fixed offset for all other
     * cases. var_off always must be 0 for PTR_TO_BTF_ID, hence we
     * still need to do checks instead of returning.
     */
    return inner_check_ptr_off_reg(env, reg, regno, true);
  default:
    return inner_check_ptr_off_reg(env, reg, regno, false);
  }
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_func_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
                           int *insn_idx) {
  struct bpf_verifier_state *state = env->cur_state;
  struct bpf_func_state *caller;
  int err, subprog, target_insn;

  target_insn = *insn_idx + insn->imm + 1;
  subprog = find_subprog(env, target_insn);
  if (verifier_bug_if(subprog < 0, env,
                      "target of func call at insn %d is not a program",
                      target_insn))
    return -EFAULT;

  caller = state->frame[state->curframe];
  err = btf_check_subprog_call(env, subprog, caller->regs);
  if (err == -EFAULT)
    return err;
  if (subprog_is_global(env, subprog)) {
    const char *sub_name = subprog_name(env, subprog);

    if (env->cur_state->active_locks) {
      verbose(env,
              "global function calls are not allowed while holding a lock,\n"
              "use static function instead\n");
      return -EINVAL;
    }

    if (env->subprog_info[subprog].might_sleep &&
        (env->cur_state->active_rcu_locks ||
         env->cur_state->active_preempt_locks ||
         env->cur_state->active_irq_id || !in_sleepable(env))) {
      verbose(env, "global functions that may sleep are not allowed in "
                   "non-sleepable context,\n"
                   "i.e., in a RCU/IRQ/preempt-disabled section, or in\n"
                   "a non-sleepable BPF program context\n");
      return -EINVAL;
    }

    if (err) {
      verbose(env, "Caller passes invalid args into func#%d ('%s')\n", subprog,
              sub_name);
      return err;
    }

    if (env->log.level & BPF_LOG_LEVEL)
      verbose(env, "Func#%d ('%s') is global and assumed valid.\n", subprog,
              sub_name);
    if (env->subprog_info[subprog].changes_pkt_data)
      clear_all_pkt_pointers(env);
    /* mark global subprog for verifying after main prog */
    subprog_aux(env, subprog)->called = true;
    clear_caller_saved_regs(env, caller->regs);

    /* All global functions return a 64-bit SCALAR_VALUE */
    mark_reg_unknown(env, caller->regs, BPF_REG_0);
    caller->regs[BPF_REG_0].subreg_def = DEF_NOT_SUBREG;

    /* continue with next insn after call */
    return 0;
  }

  /* for regular function entry setup new frame and continue
   * from that frame.
   */
  err = setup_func_entry(env, subprog, *insn_idx, set_callee_state, state);
  if (err)
    return err;

  clear_caller_saved_regs(env, caller->regs);

  /* and go analyze first insn of the callee */
  *insn_idx = env->subprog_info[subprog].start - 1;

  bpf_reset_live_stack_callchain(env);

  if (env->log.level & BPF_LOG_LEVEL) {
    verbose(env, "caller:\n");
    print_verifier_state(env, state, caller->frameno, true);
    verbose(env, "callee:\n");
    print_verifier_state(env, state, state->curframe, true);
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_func_proto(const struct bpf_func_proto *fn) {
  return check_raw_mode_ok(fn) && check_arg_pair_ok(fn) &&
                 check_mem_arg_rw_flag_ok(fn) && check_btf_id_ok(fn)
             ? 0
             : -EINVAL;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_generic_ptr_alignment(struct bpf_verifier_env *env,
                                       const struct bpf_reg_state *reg,
                                       const char *pointer_desc, int off,
                                       int size, bool strict) {
  struct tnum reg_off;

  /* Byte size accesses are always allowed. */
  if (!strict || size == 1)
    return 0;

  reg_off = tnum_add(reg->var_off, tnum_const(reg->off + off));
  if (!tnum_is_aligned(reg_off, size)) {
    char tn_buf[48];

    tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
    verbose(env, "misaligned %saccess off %s+%d+%d size %d\n", pointer_desc,
            tn_buf, reg->off, off, size);
    return -EACCES;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_get_func_ip(struct bpf_verifier_env *env) {
  enum bpf_prog_type type = resolve_prog_type(env->prog);
  int func_id = BPF_FUNC_get_func_ip;

  if (type == BPF_PROG_TYPE_TRACING) {
    if (!bpf_prog_has_trampoline(env->prog)) {
      verbose(env,
              "func %s#%d supported only for fentry/fexit/fmod_ret programs\n",
              func_id_name(func_id), func_id);
      return -ENOTSUPP;
    }
    return 0;
  } else if (type == BPF_PROG_TYPE_KPROBE) {
    return 0;
  }

  verbose(env, "func %s#%d not supported for program type %d\n",
          func_id_name(func_id), func_id, type);
  return -ENOTSUPP;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_helper_call(struct bpf_verifier_env *env,
                             struct bpf_insn *insn, int *insn_idx_p) {
  enum bpf_prog_type prog_type = resolve_prog_type(env->prog);
  bool returns_cpu_specific_alloc_ptr = false;
  const struct bpf_func_proto *fn = NULL;
  enum bpf_return_type ret_type;
  enum bpf_type_flag ret_flag;
  struct bpf_reg_state *regs;
  struct bpf_call_arg_meta meta;
  int insn_idx = *insn_idx_p;
  bool changes_data;
  int i, err, func_id;

  /* find function prototype */
  func_id = insn->imm;
  err = get_helper_proto(env, insn->imm, &fn);
  if (err == -ERANGE) {
    verbose(env, "invalid func %s#%d\n", func_id_name(func_id), func_id);
    return -EINVAL;
  }

  if (err) {
    verbose(env, "program of this type cannot use helper %s#%d\n",
            func_id_name(func_id), func_id);
    return err;
  }

  /* eBPF programs must be GPL compatible to use GPL-ed functions */
  if (!env->prog->gpl_compatible && fn->gpl_only) {
    verbose(env, "cannot call GPL-restricted function from non-GPL compatible "
                 "program\n");
    return -EINVAL;
  }

  if (fn->allowed && !fn->allowed(env->prog)) {
    verbose(env, "helper call is not allowed in probe\n");
    return -EINVAL;
  }

  if (!in_sleepable(env) && fn->might_sleep) {
    verbose(env, "helper call might sleep in a non-sleepable prog\n");
    return -EINVAL;
  }

  /* With LD_ABS/IND some JITs save/restore skb from r1. */
  changes_data = bpf_helper_changes_pkt_data(func_id);
  if (changes_data && fn->arg1_type != ARG_PTR_TO_CTX) {
    verifier_bug(env, "func %s#%d: r1 != ctx", func_id_name(func_id), func_id);
    return -EFAULT;
  }

  memset(&meta, 0, sizeof(meta));
  meta.pkt_access = fn->pkt_access;

  err = check_func_proto(fn);
  if (err) {
    verifier_bug(env, "incorrect func proto %s#%d", func_id_name(func_id),
                 func_id);
    return err;
  }

  if (env->cur_state->active_rcu_locks) {
    if (fn->might_sleep) {
      verbose(env, "sleepable helper %s#%d in rcu_read_lock region\n",
              func_id_name(func_id), func_id);
      return -EINVAL;
    }
  }

  if (env->cur_state->active_preempt_locks) {
    if (fn->might_sleep) {
      verbose(env, "sleepable helper %s#%d in non-preemptible region\n",
              func_id_name(func_id), func_id);
      return -EINVAL;
    }
  }

  if (env->cur_state->active_irq_id) {
    if (fn->might_sleep) {
      verbose(env, "sleepable helper %s#%d in IRQ-disabled region\n",
              func_id_name(func_id), func_id);
      return -EINVAL;
    }
  }

  /* Track non-sleepable context for helpers. */
  if (!in_sleepable_context(env))
    env->insn_aux_data[insn_idx].non_sleepable = true;

  meta.func_id = func_id;
  /* check args */
  for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++) {
    err = check_func_arg(env, i, &meta, fn, insn_idx);
    if (err)
      return err;
  }

  err = record_func_map(env, &meta, func_id, insn_idx);
  if (err)
    return err;

  err = record_func_key(env, &meta, func_id, insn_idx);
  if (err)
    return err;

  /* Mark slots with STACK_MISC in case of raw mode, stack offset
   * is inferred from register state.
   */
  for (i = 0; i < meta.access_size; i++) {
    err = check_mem_access(env, insn_idx, meta.regno, i, BPF_B, BPF_WRITE, -1,
                           false, false);
    if (err)
      return err;
  }

  regs = cur_regs(env);

  if (meta.release_regno) {
    err = -EINVAL;
    if (arg_type_is_dynptr(fn->arg_type[meta.release_regno - BPF_REG_1])) {
      err = unmark_stack_slots_dynptr(env, &regs[meta.release_regno]);
    } else if (func_id == BPF_FUNC_kptr_xchg && meta.ref_obj_id) {
      u32 ref_obj_id = meta.ref_obj_id;
      bool in_rcu = in_rcu_cs(env);
      struct bpf_func_state *state;
      struct bpf_reg_state *reg;

      err = release_reference_nomark(env->cur_state, ref_obj_id);
      if (!err) {
        bpf_for_each_reg_in_vstate(env->cur_state, state, reg, ({
                                     if (reg->ref_obj_id == ref_obj_id) {
                                       if (in_rcu && (reg->type & MEM_ALLOC) &&
                                           (reg->type & MEM_PERCPU)) {
                                         reg->ref_obj_id = 0;
                                         reg->type &= ~MEM_ALLOC;
                                         reg->type |= MEM_RCU;
                                       } else {
                                         mark_reg_invalid(env, reg);
                                       }
                                     }
                                   }));
      }
    } else if (meta.ref_obj_id) {
      err = release_reference(env, meta.ref_obj_id);
    } else if (register_is_null(&regs[meta.release_regno])) {
      /* meta.ref_obj_id can only be 0 if register that is meant to be
       * released is NULL, which must be > R0.
       */
      err = 0;
    }
    if (err) {
      verbose(env, "func %s#%d reference has not been acquired before\n",
              func_id_name(func_id), func_id);
      return err;
    }
  }

  switch (func_id) {
  case BPF_FUNC_tail_call:
    err = check_resource_leak(env, false, true, "tail_call");
    if (err)
      return err;
    break;
  case BPF_FUNC_get_local_storage:
    /* check that flags argument in get_local_storage(map, flags) is 0,
     * this is required because get_local_storage() can't return an error.
     */
    if (!register_is_null(&regs[BPF_REG_2])) {
      verbose(env, "get_local_storage() doesn't support non-zero flags\n");
      return -EINVAL;
    }
    break;
  case BPF_FUNC_for_each_map_elem:
    err = push_callback_call(env, insn, insn_idx, meta.subprogno,
                             set_map_elem_callback_state);
    break;
  case BPF_FUNC_timer_set_callback:
    err = push_callback_call(env, insn, insn_idx, meta.subprogno,
                             set_timer_callback_state);
    break;
  case BPF_FUNC_find_vma:
    err = push_callback_call(env, insn, insn_idx, meta.subprogno,
                             set_find_vma_callback_state);
    break;
  case BPF_FUNC_snprintf:
    err = check_bpf_snprintf_call(env, regs);
    break;
  case BPF_FUNC_loop:
    update_loop_inline_state(env, meta.subprogno);
    /* Verifier relies on R1 value to determine if bpf_loop() iteration
     * is finished, thus mark it precise.
     */
    err = mark_chain_precision(env, BPF_REG_1);
    if (err)
      return err;
    if (cur_func(env)->callback_depth < regs[BPF_REG_1].umax_value) {
      err = push_callback_call(env, insn, insn_idx, meta.subprogno,
                               set_loop_callback_state);
    } else {
      cur_func(env)->callback_depth = 0;
      if (env->log.level & BPF_LOG_LEVEL2)
        verbose(env, "frame%d bpf_loop iteration limit reached\n",
                env->cur_state->curframe);
    }
    break;
  case BPF_FUNC_dynptr_from_mem:
    if (regs[BPF_REG_1].type != PTR_TO_MAP_VALUE) {
      verbose(env, "Unsupported reg type %s for bpf_dynptr_from_mem data\n",
              reg_type_str(env, regs[BPF_REG_1].type));
      return -EACCES;
    }
    break;
  case BPF_FUNC_set_retval:
    if (prog_type == BPF_PROG_TYPE_LSM &&
        env->prog->expected_attach_type == BPF_LSM_CGROUP) {
      if (!env->prog->aux->attach_func_proto->type) {
        /* Make sure programs that attach to void
         * hooks don't try to modify return value.
         */
        verbose(env, "BPF_LSM_CGROUP that attach to void LSM hooks can't "
                     "modify return value!\n");
        return -EINVAL;
      }
    }
    break;
  case BPF_FUNC_dynptr_data: {
    struct bpf_reg_state *reg;
    int id, ref_obj_id;

    reg = get_dynptr_arg_reg(env, fn, regs);
    if (!reg)
      return -EFAULT;

    if (meta.dynptr_id) {
      verifier_bug(env, "meta.dynptr_id already set");
      return -EFAULT;
    }
    if (meta.ref_obj_id) {
      verifier_bug(env, "meta.ref_obj_id already set");
      return -EFAULT;
    }

    id = dynptr_id(env, reg);
    if (id < 0) {
      verifier_bug(env, "failed to obtain dynptr id");
      return id;
    }

    ref_obj_id = dynptr_ref_obj_id(env, reg);
    if (ref_obj_id < 0) {
      verifier_bug(env, "failed to obtain dynptr ref_obj_id");
      return ref_obj_id;
    }

    meta.dynptr_id = id;
    meta.ref_obj_id = ref_obj_id;

    break;
  }
  case BPF_FUNC_dynptr_write: {
    enum bpf_dynptr_type dynptr_type;
    struct bpf_reg_state *reg;

    reg = get_dynptr_arg_reg(env, fn, regs);
    if (!reg)
      return -EFAULT;

    dynptr_type = dynptr_get_type(env, reg);
    if (dynptr_type == BPF_DYNPTR_TYPE_INVALID)
      return -EFAULT;

    if (dynptr_type == BPF_DYNPTR_TYPE_SKB ||
        dynptr_type == BPF_DYNPTR_TYPE_SKB_META)
      /* this will trigger clear_all_pkt_pointers(), which will
       * invalidate all dynptr slices associated with the skb
       */
      changes_data = true;

    break;
  }
  case BPF_FUNC_per_cpu_ptr:
  case BPF_FUNC_this_cpu_ptr: {
    struct bpf_reg_state *reg = &regs[BPF_REG_1];
    const struct btf_type *type;

    if (reg->type & MEM_RCU) {
      type = btf_type_by_id(reg->btf, reg->btf_id);
      if (!type || !btf_type_is_struct(type)) {
        verbose(env, "Helper has invalid btf/btf_id in R1\n");
        return -EFAULT;
      }
      returns_cpu_specific_alloc_ptr = true;
      env->insn_aux_data[insn_idx].call_with_percpu_alloc_ptr = true;
    }
    break;
  }
  case BPF_FUNC_user_ringbuf_drain:
    err = push_callback_call(env, insn, insn_idx, meta.subprogno,
                             set_user_ringbuf_callback_state);
    break;
  }

  if (err)
    return err;

  /* reset caller saved regs */
  for (i = 0; i < CALLER_SAVED_REGS; i++) {
    mark_reg_not_init(env, regs, caller_saved[i]);
    check_reg_arg(env, caller_saved[i], DST_OP_NO_MARK);
  }

  /* helper call returns 64-bit value. */
  regs[BPF_REG_0].subreg_def = DEF_NOT_SUBREG;

  /* update return register (already marked as written above) */
  ret_type = fn->ret_type;
  ret_flag = type_flag(ret_type);

  switch (base_type(ret_type)) {
  case RET_INTEGER:
    /* sets type to SCALAR_VALUE */
    mark_reg_unknown(env, regs, BPF_REG_0);
    break;
  case RET_VOID:
    regs[BPF_REG_0].type = NOT_INIT;
    break;
  case RET_PTR_TO_MAP_VALUE:
    /* There is no offset yet applied, variable or fixed */
    mark_reg_known_zero(env, regs, BPF_REG_0);
    /* remember map_ptr, so that check_map_access()
     * can check 'value_size' boundary of memory access
     * to map element returned from bpf_map_lookup_elem()
     */
    if (meta.map.ptr == NULL) {
      verifier_bug(env, "unexpected null map_ptr");
      return -EFAULT;
    }

    if (func_id == BPF_FUNC_map_lookup_elem &&
        can_elide_value_nullness(meta.map.ptr->map_type) &&
        meta.const_map_key >= 0 &&
        meta.const_map_key < meta.map.ptr->max_entries)
      ret_flag &= ~PTR_MAYBE_NULL;

    regs[BPF_REG_0].map_ptr = meta.map.ptr;
    regs[BPF_REG_0].map_uid = meta.map.uid;
    regs[BPF_REG_0].type = PTR_TO_MAP_VALUE | ret_flag;
    if (!type_may_be_null(ret_flag) &&
        btf_record_has_field(meta.map.ptr->record,
                             BPF_SPIN_LOCK | BPF_RES_SPIN_LOCK)) {
      regs[BPF_REG_0].id = ++env->id_gen;
    }
    break;
  case RET_PTR_TO_SOCKET:
    mark_reg_known_zero(env, regs, BPF_REG_0);
    regs[BPF_REG_0].type = PTR_TO_SOCKET | ret_flag;
    break;
  case RET_PTR_TO_SOCK_COMMON:
    mark_reg_known_zero(env, regs, BPF_REG_0);
    regs[BPF_REG_0].type = PTR_TO_SOCK_COMMON | ret_flag;
    break;
  case RET_PTR_TO_TCP_SOCK:
    mark_reg_known_zero(env, regs, BPF_REG_0);
    regs[BPF_REG_0].type = PTR_TO_TCP_SOCK | ret_flag;
    break;
  case RET_PTR_TO_MEM:
    mark_reg_known_zero(env, regs, BPF_REG_0);
    regs[BPF_REG_0].type = PTR_TO_MEM | ret_flag;
    regs[BPF_REG_0].mem_size = meta.mem_size;
    break;
  case RET_PTR_TO_MEM_OR_BTF_ID: {
    const struct btf_type *t;

    mark_reg_known_zero(env, regs, BPF_REG_0);
    t = btf_type_skip_modifiers(meta.ret_btf, meta.ret_btf_id, NULL);
    if (!btf_type_is_struct(t)) {
      u32 tsize;
      const struct btf_type *ret;
      const char *tname;

      /* resolve the type size of ksym. */
      ret = btf_resolve_size(meta.ret_btf, t, &tsize);
      if (IS_ERR(ret)) {
        tname = btf_name_by_offset(meta.ret_btf, t->name_off);
        verbose(env, "unable to resolve the size of type '%s': %ld\n", tname,
                PTR_ERR(ret));
        return -EINVAL;
      }
      regs[BPF_REG_0].type = PTR_TO_MEM | ret_flag;
      regs[BPF_REG_0].mem_size = tsize;
    } else {
      if (returns_cpu_specific_alloc_ptr) {
        regs[BPF_REG_0].type = PTR_TO_BTF_ID | MEM_ALLOC | MEM_RCU;
      } else {
        /* MEM_RDONLY may be carried from ret_flag, but it
         * doesn't apply on PTR_TO_BTF_ID. Fold it, otherwise
         * it will confuse the check of PTR_TO_BTF_ID in
         * check_mem_access().
         */
        ret_flag &= ~MEM_RDONLY;
        regs[BPF_REG_0].type = PTR_TO_BTF_ID | ret_flag;
      }

      regs[BPF_REG_0].btf = meta.ret_btf;
      regs[BPF_REG_0].btf_id = meta.ret_btf_id;
    }
    break;
  }
  case RET_PTR_TO_BTF_ID: {
    struct btf *ret_btf;
    int ret_btf_id;

    mark_reg_known_zero(env, regs, BPF_REG_0);
    regs[BPF_REG_0].type = PTR_TO_BTF_ID | ret_flag;
    if (func_id == BPF_FUNC_kptr_xchg) {
      ret_btf = meta.kptr_field->kptr.btf;
      ret_btf_id = meta.kptr_field->kptr.btf_id;
      if (!btf_is_kernel(ret_btf)) {
        regs[BPF_REG_0].type |= MEM_ALLOC;
        if (meta.kptr_field->type == BPF_KPTR_PERCPU)
          regs[BPF_REG_0].type |= MEM_PERCPU;
      }
    } else {
      if (fn->ret_btf_id == BPF_PTR_POISON) {
        verifier_bug(env,
                     "func %s has non-overwritten BPF_PTR_POISON return type",
                     func_id_name(func_id));
        return -EFAULT;
      }
      ret_btf = btf_vmlinux;
      ret_btf_id = *fn->ret_btf_id;
    }
    if (ret_btf_id == 0) {
      verbose(env, "invalid return type %u of func %s#%d\n",
              base_type(ret_type), func_id_name(func_id), func_id);
      return -EINVAL;
    }
    regs[BPF_REG_0].btf = ret_btf;
    regs[BPF_REG_0].btf_id = ret_btf_id;
    break;
  }
  default:
    verbose(env, "unknown return type %u of func %s#%d\n", base_type(ret_type),
            func_id_name(func_id), func_id);
    return -EINVAL;
  }

  if (type_may_be_null(regs[BPF_REG_0].type))
    regs[BPF_REG_0].id = ++env->id_gen;

  if (helper_multiple_ref_obj_use(func_id, meta.map.ptr)) {
    verifier_bug(env, "func %s#%d sets ref_obj_id more than once",
                 func_id_name(func_id), func_id);
    return -EFAULT;
  }

  if (is_dynptr_ref_function(func_id))
    regs[BPF_REG_0].dynptr_id = meta.dynptr_id;

  if (is_ptr_cast_function(func_id) || is_dynptr_ref_function(func_id)) {
    /* For release_reference() */
    regs[BPF_REG_0].ref_obj_id = meta.ref_obj_id;
  } else if (is_acquire_function(func_id, meta.map.ptr)) {
    int id = acquire_reference(env, insn_idx);

    if (id < 0)
      return id;
    /* For mark_ptr_or_null_reg() */
    regs[BPF_REG_0].id = id;
    /* For release_reference() */
    regs[BPF_REG_0].ref_obj_id = id;
  }

  err = do_refine_retval_range(env, regs, fn->ret_type, func_id, &meta);
  if (err)
    return err;

  err = check_map_func_compatibility(env, meta.map.ptr, func_id);
  if (err)
    return err;

  if ((func_id == BPF_FUNC_get_stack || func_id == BPF_FUNC_get_task_stack) &&
      !env->prog->has_callchain_buf) {
    const char *err_str;

#ifdef CONFIG_PERF_EVENTS
    err = get_callchain_buffers(sysctl_perf_event_max_stack);
    err_str = "cannot get callchain buffer for func %s#%d\n";
#else
    err = -ENOTSUPP;
    err_str = "func %s#%d not supported without CONFIG_PERF_EVENTS\n";
#endif
    if (err) {
      verbose(env, err_str, func_id_name(func_id), func_id);
      return err;
    }

    env->prog->has_callchain_buf = true;
  }

  if (func_id == BPF_FUNC_get_stackid || func_id == BPF_FUNC_get_stack)
    env->prog->call_get_stack = true;

  if (func_id == BPF_FUNC_get_func_ip) {
    if (check_get_func_ip(env))
      return -ENOTSUPP;
    env->prog->call_get_func_ip = true;
  }

  if (func_id == BPF_FUNC_tail_call) {
    if (env->cur_state->curframe) {
      struct bpf_verifier_state *branch;

      mark_reg_scratched(env, BPF_REG_0);
      branch = push_stack(env, env->insn_idx + 1, env->insn_idx, false);
      if (IS_ERR(branch))
        return PTR_ERR(branch);
      clear_all_pkt_pointers(env);
      mark_reg_unknown(env, regs, BPF_REG_0);
      err = prepare_func_exit(env, &env->insn_idx);
      if (err)
        return err;
      env->insn_idx--;
    } else {
      changes_data = false;
    }
  }

  if (changes_data)
    clear_all_pkt_pointers(env);
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_helper_mem_access(struct bpf_verifier_env *env, int regno,
                                   int access_size,
                                   enum bpf_access_type access_type,
                                   bool zero_size_allowed,
                                   struct bpf_call_arg_meta *meta) {
  struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[regno];
  u32 *max_access;

  switch (base_type(reg->type)) {
  case PTR_TO_PACKET:
  case PTR_TO_PACKET_META:
    return check_packet_access(env, regno, reg->off, access_size,
                               zero_size_allowed);
  case PTR_TO_MAP_KEY:
    if (access_type == BPF_WRITE) {
      verbose(env, "R%d cannot write into %s\n", regno,
              reg_type_str(env, reg->type));
      return -EACCES;
    }
    return check_mem_region_access(env, regno, reg->off, access_size,
                                   reg->map_ptr->key_size, false);
  case PTR_TO_MAP_VALUE:
    if (check_map_access_type(env, regno, reg->off, access_size, access_type))
      return -EACCES;
    return check_map_access(env, regno, reg->off, access_size,
                            zero_size_allowed, ACCESS_HELPER);
  case PTR_TO_MEM:
    if (type_is_rdonly_mem(reg->type)) {
      if (access_type == BPF_WRITE) {
        verbose(env, "R%d cannot write into %s\n", regno,
                reg_type_str(env, reg->type));
        return -EACCES;
      }
    }
    return check_mem_region_access(env, regno, reg->off, access_size,
                                   reg->mem_size, zero_size_allowed);
  case PTR_TO_BUF:
    if (type_is_rdonly_mem(reg->type)) {
      if (access_type == BPF_WRITE) {
        verbose(env, "R%d cannot write into %s\n", regno,
                reg_type_str(env, reg->type));
        return -EACCES;
      }

      max_access = &env->prog->aux->max_rdonly_access;
    } else {
      max_access = &env->prog->aux->max_rdwr_access;
    }
    return check_buffer_access(env, reg, regno, reg->off, access_size,
                               zero_size_allowed, max_access);
  case PTR_TO_STACK:
    return check_stack_range_initialized(env, regno, reg->off, access_size,
                                         zero_size_allowed, access_type, meta);
  case PTR_TO_BTF_ID:
    return check_ptr_to_btf_access(env, regs, regno, reg->off, access_size,
                                   BPF_READ, -1);
  case PTR_TO_CTX:
    /* in case the function doesn't know how to access the context,
     * (because we are in a program of type SYSCALL for example), we
     * can not statically check its size.
     * Dynamically check it now.
     */
    if (!env->ops->convert_ctx_access) {
      int offset = access_size - 1;

      /* Allow zero-byte read from PTR_TO_CTX */
      if (access_size == 0)
        return zero_size_allowed ? 0 : -EACCES;

      return check_mem_access(env, env->insn_idx, regno, offset, BPF_B,
                              access_type, -1, false, false);
    }

    fallthrough;
  default: /* scalar_value or invalid ptr */
    /* Allow zero-byte read from NULL, regardless of pointer type */
    if (zero_size_allowed && access_size == 0 && register_is_null(reg))
      return 0;

    verbose(env, "R%d type=%s ", regno, reg_type_str(env, reg->type));
    verbose(env, "expected=%s\n", reg_type_str(env, PTR_TO_STACK));
    return -EACCES;
  }
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_ids(u32 old_id, u32 cur_id, struct bpf_idmap *idmap) {
  struct bpf_id_pair *map = idmap->map;
  unsigned int i;

  /* either both IDs should be set or both should be zero */
  if (!!old_id != !!cur_id)
    return false;

  if (old_id == 0) /* cur_id == 0 as well */
    return true;

  for (i = 0; i < idmap->cnt; i++) {
    if (map[i].old == old_id)
      return map[i].cur == cur_id;
    if (map[i].cur == cur_id)
      return false;
  }

  /* Reached the end of known mappings; haven't seen this id before */
  if (idmap->cnt < BPF_ID_MAP_SIZE) {
    map[idmap->cnt].old = old_id;
    map[idmap->cnt].cur = cur_id;
    idmap->cnt++;
    return true;
  }

  /* We ran out of idmap slots, which should be impossible */
  WARN_ON_ONCE(1);
  return false;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_indirect_jump(struct bpf_verifier_env *env,
                               struct bpf_insn *insn) {
  struct bpf_verifier_state *other_branch;
  struct bpf_reg_state *dst_reg;
  struct bpf_map *map;
  u32 min_index, max_index;
  int err = 0;
  int n;
  int i;

  dst_reg = reg_state(env, insn->dst_reg);
  if (dst_reg->type != PTR_TO_INSN) {
    verbose(env, "R%d has type %s, expected PTR_TO_INSN\n", insn->dst_reg,
            reg_type_str(env, dst_reg->type));
    return -EINVAL;
  }

  map = dst_reg->map_ptr;
  if (verifier_bug_if(!map, env, "R%d has an empty map pointer", insn->dst_reg))
    return -EFAULT;

  if (verifier_bug_if(map->map_type != BPF_MAP_TYPE_INSN_ARRAY, env,
                      "R%d has incorrect map type %d", insn->dst_reg,
                      map->map_type))
    return -EFAULT;

  err = indirect_jump_min_max_index(env, insn->dst_reg, map, &min_index,
                                    &max_index);
  if (err)
    return err;

  /* Ensure that the buffer is large enough */
  if (!env->gotox_tmp_buf ||
      env->gotox_tmp_buf->cnt < max_index - min_index + 1) {
    env->gotox_tmp_buf =
        iarray_realloc(env->gotox_tmp_buf, max_index - min_index + 1);
    if (!env->gotox_tmp_buf)
      return -ENOMEM;
  }

  n = copy_insn_array_uniq(map, min_index, max_index,
                           env->gotox_tmp_buf->items);
  if (n < 0)
    return n;
  if (n == 0) {
    verbose(env, "register R%d doesn't point to any offset in map id=%d\n",
            insn->dst_reg, map->id);
    return -EINVAL;
  }

  for (i = 0; i < n - 1; i++) {
    other_branch = push_stack(env, env->gotox_tmp_buf->items[i], env->insn_idx,
                              env->cur_state->speculative);
    if (IS_ERR(other_branch))
      return PTR_ERR(other_branch);
  }
  env->insn_idx = env->gotox_tmp_buf->items[n - 1];
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_kfunc_args(struct bpf_verifier_env *env,
                            struct bpf_kfunc_call_arg_meta *meta,
                            int insn_idx) {
  const char *func_name = meta->func_name, *ref_tname;
  const struct btf *btf = meta->btf;
  const struct btf_param *args;
  struct btf_record *rec;
  u32 i, nargs;
  int ret;

  args = (const struct btf_param *)(meta->func_proto + 1);
  nargs = btf_type_vlen(meta->func_proto);
  if (nargs > MAX_BPF_FUNC_REG_ARGS) {
    verbose(env, "Function %s has %d > %d args\n", func_name, nargs,
            MAX_BPF_FUNC_REG_ARGS);
    return -EINVAL;
  }

  /* Check that BTF function arguments match actual types that the
   * verifier sees.
   */
  for (i = 0; i < nargs; i++) {
    struct bpf_reg_state *regs = cur_regs(env), *reg = &regs[i + 1];
    const struct btf_type *t, *ref_t, *resolve_ret;
    enum bpf_arg_type arg_type = ARG_DONTCARE;
    u32 regno = i + 1, ref_id, type_size;
    bool is_ret_buf_sz = false;
    int kf_arg_type;

    t = btf_type_skip_modifiers(btf, args[i].type, NULL);

    if (is_kfunc_arg_ignore(btf, &args[i]))
      continue;

    if (is_kfunc_arg_prog_aux(btf, &args[i])) {
      /* Reject repeated use bpf_prog_aux */
      if (meta->arg_prog) {
        verifier_bug(env, "Only 1 prog->aux argument supported per-kfunc");
        return -EFAULT;
      }
      meta->arg_prog = true;
      cur_aux(env)->arg_prog = regno;
      continue;
    }

    if (btf_type_is_scalar(t)) {
      if (reg->type != SCALAR_VALUE) {
        verbose(env, "R%d is not a scalar\n", regno);
        return -EINVAL;
      }

      if (is_kfunc_arg_constant(meta->btf, &args[i])) {
        if (meta->arg_constant.found) {
          verifier_bug(env, "only one constant argument permitted");
          return -EFAULT;
        }
        if (!tnum_is_const(reg->var_off)) {
          verbose(env, "R%d must be a known constant\n", regno);
          return -EINVAL;
        }
        ret = mark_chain_precision(env, regno);
        if (ret < 0)
          return ret;
        meta->arg_constant.found = true;
        meta->arg_constant.value = reg->var_off.value;
      } else if (is_kfunc_arg_scalar_with_name(btf, &args[i],
                                               "rdonly_buf_size")) {
        meta->r0_rdonly = true;
        is_ret_buf_sz = true;
      } else if (is_kfunc_arg_scalar_with_name(btf, &args[i],
                                               "rdwr_buf_size")) {
        is_ret_buf_sz = true;
      }

      if (is_ret_buf_sz) {
        if (meta->r0_size) {
          verbose(env, "2 or more rdonly/rdwr_buf_size parameters for kfunc");
          return -EINVAL;
        }

        if (!tnum_is_const(reg->var_off)) {
          verbose(env, "R%d is not a const\n", regno);
          return -EINVAL;
        }

        meta->r0_size = reg->var_off.value;
        ret = mark_chain_precision(env, regno);
        if (ret)
          return ret;
      }
      continue;
    }

    if (!btf_type_is_ptr(t)) {
      verbose(env, "Unrecognized arg#%d type %s\n", i, btf_type_str(t));
      return -EINVAL;
    }

    if ((register_is_null(reg) || type_may_be_null(reg->type)) &&
        !is_kfunc_arg_nullable(meta->btf, &args[i])) {
      verbose(env, "Possibly NULL pointer passed to trusted arg%d\n", i);
      return -EACCES;
    }

    if (reg->ref_obj_id) {
      if (is_kfunc_release(meta) && meta->ref_obj_id) {
        verifier_bug(env, "more than one arg with ref_obj_id R%d %u %u", regno,
                     reg->ref_obj_id, meta->ref_obj_id);
        return -EFAULT;
      }
      meta->ref_obj_id = reg->ref_obj_id;
      if (is_kfunc_release(meta))
        meta->release_regno = regno;
    }

    ref_t = btf_type_skip_modifiers(btf, t->type, &ref_id);
    ref_tname = btf_name_by_offset(btf, ref_t->name_off);

    kf_arg_type =
        get_kfunc_ptr_arg_type(env, meta, t, ref_t, ref_tname, args, i, nargs);
    if (kf_arg_type < 0)
      return kf_arg_type;

    switch (kf_arg_type) {
    case KF_ARG_PTR_TO_NULL:
      continue;
    case KF_ARG_PTR_TO_MAP:
      if (!reg->map_ptr) {
        verbose(env, "pointer in R%d isn't map pointer\n", regno);
        return -EINVAL;
      }
      if (meta->map.ptr && (reg->map_ptr->record->wq_off >= 0 ||
                            reg->map_ptr->record->task_work_off >= 0)) {
        /* Use map_uid (which is unique id of inner map) to reject:
         * inner_map1 = bpf_map_lookup_elem(outer_map, key1)
         * inner_map2 = bpf_map_lookup_elem(outer_map, key2)
         * if (inner_map1 && inner_map2) {
         *     wq = bpf_map_lookup_elem(inner_map1);
         *     if (wq)
         *         // mismatch would have been allowed
         *         bpf_wq_init(wq, inner_map2);
         * }
         *
         * Comparing map_ptr is enough to distinguish normal and outer maps.
         */
        if (meta->map.ptr != reg->map_ptr || meta->map.uid != reg->map_uid) {
          if (reg->map_ptr->record->task_work_off >= 0) {
            verbose(env,
                    "bpf_task_work pointer in R2 map_uid=%d doesn't match map "
                    "pointer in R3 map_uid=%d\n",
                    meta->map.uid, reg->map_uid);
            return -EINVAL;
          }
          verbose(env,
                  "workqueue pointer in R1 map_uid=%d doesn't match map "
                  "pointer in R2 map_uid=%d\n",
                  meta->map.uid, reg->map_uid);
          return -EINVAL;
        }
      }
      meta->map.ptr = reg->map_ptr;
      meta->map.uid = reg->map_uid;
      fallthrough;
    case KF_ARG_PTR_TO_ALLOC_BTF_ID:
    case KF_ARG_PTR_TO_BTF_ID:
      if (!is_trusted_reg(reg)) {
        if (!is_kfunc_rcu(meta)) {
          verbose(env, "R%d must be referenced or trusted\n", regno);
          return -EINVAL;
        }
        if (!is_rcu_reg(reg)) {
          verbose(env, "R%d must be a rcu pointer\n", regno);
          return -EINVAL;
        }
      }
      fallthrough;
    case KF_ARG_PTR_TO_CTX:
    case KF_ARG_PTR_TO_DYNPTR:
    case KF_ARG_PTR_TO_ITER:
    case KF_ARG_PTR_TO_LIST_HEAD:
    case KF_ARG_PTR_TO_LIST_NODE:
    case KF_ARG_PTR_TO_RB_ROOT:
    case KF_ARG_PTR_TO_RB_NODE:
    case KF_ARG_PTR_TO_MEM:
    case KF_ARG_PTR_TO_MEM_SIZE:
    case KF_ARG_PTR_TO_CALLBACK:
    case KF_ARG_PTR_TO_REFCOUNTED_KPTR:
    case KF_ARG_PTR_TO_CONST_STR:
    case KF_ARG_PTR_TO_WORKQUEUE:
    case KF_ARG_PTR_TO_TIMER:
    case KF_ARG_PTR_TO_TASK_WORK:
    case KF_ARG_PTR_TO_IRQ_FLAG:
    case KF_ARG_PTR_TO_RES_SPIN_LOCK:
      break;
    default:
      verifier_bug(env, "unknown kfunc arg type %d", kf_arg_type);
      return -EFAULT;
    }

    if (is_kfunc_release(meta) && reg->ref_obj_id)
      arg_type |= OBJ_RELEASE;
    ret = check_func_arg_reg_off(env, reg, regno, arg_type);
    if (ret < 0)
      return ret;

    switch (kf_arg_type) {
    case KF_ARG_PTR_TO_CTX:
      if (reg->type != PTR_TO_CTX) {
        verbose(env, "arg#%d expected pointer to ctx, but got %s\n", i,
                reg_type_str(env, reg->type));
        return -EINVAL;
      }

      if (meta->func_id == special_kfunc_list[KF_bpf_cast_to_kern_ctx]) {
        ret = get_kern_ctx_btf_id(&env->log, resolve_prog_type(env->prog));
        if (ret < 0)
          return -EINVAL;
        meta->ret_btf_id = ret;
      }
      break;
    case KF_ARG_PTR_TO_ALLOC_BTF_ID:
      if (reg->type == (PTR_TO_BTF_ID | MEM_ALLOC)) {
        if (meta->func_id != special_kfunc_list[KF_bpf_obj_drop_impl]) {
          verbose(env, "arg#%d expected for bpf_obj_drop_impl()\n", i);
          return -EINVAL;
        }
      } else if (reg->type == (PTR_TO_BTF_ID | MEM_ALLOC | MEM_PERCPU)) {
        if (meta->func_id != special_kfunc_list[KF_bpf_percpu_obj_drop_impl]) {
          verbose(env, "arg#%d expected for bpf_percpu_obj_drop_impl()\n", i);
          return -EINVAL;
        }
      } else {
        verbose(env, "arg#%d expected pointer to allocated object\n", i);
        return -EINVAL;
      }
      if (!reg->ref_obj_id) {
        verbose(env, "allocated object must be referenced\n");
        return -EINVAL;
      }
      if (meta->btf == btf_vmlinux) {
        meta->arg_btf = reg->btf;
        meta->arg_btf_id = reg->btf_id;
      }
      break;
    case KF_ARG_PTR_TO_DYNPTR: {
      enum bpf_arg_type dynptr_arg_type = ARG_PTR_TO_DYNPTR;
      int clone_ref_obj_id = 0;

      if (reg->type == CONST_PTR_TO_DYNPTR)
        dynptr_arg_type |= MEM_RDONLY;

      if (is_kfunc_arg_uninit(btf, &args[i]))
        dynptr_arg_type |= MEM_UNINIT;

      if (meta->func_id == special_kfunc_list[KF_bpf_dynptr_from_skb]) {
        dynptr_arg_type |= DYNPTR_TYPE_SKB;
      } else if (meta->func_id == special_kfunc_list[KF_bpf_dynptr_from_xdp]) {
        dynptr_arg_type |= DYNPTR_TYPE_XDP;
      } else if (meta->func_id ==
                 special_kfunc_list[KF_bpf_dynptr_from_skb_meta]) {
        dynptr_arg_type |= DYNPTR_TYPE_SKB_META;
      } else if (meta->func_id == special_kfunc_list[KF_bpf_dynptr_from_file]) {
        dynptr_arg_type |= DYNPTR_TYPE_FILE;
      } else if (meta->func_id ==
                 special_kfunc_list[KF_bpf_dynptr_file_discard]) {
        dynptr_arg_type |= DYNPTR_TYPE_FILE;
        meta->release_regno = regno;
      } else if (meta->func_id == special_kfunc_list[KF_bpf_dynptr_clone] &&
                 (dynptr_arg_type & MEM_UNINIT)) {
        enum bpf_dynptr_type parent_type = meta->initialized_dynptr.type;

        if (parent_type == BPF_DYNPTR_TYPE_INVALID) {
          verifier_bug(env, "no dynptr type for parent of clone");
          return -EFAULT;
        }

        dynptr_arg_type |= (unsigned int)get_dynptr_type_flag(parent_type);
        clone_ref_obj_id = meta->initialized_dynptr.ref_obj_id;
        if (dynptr_type_refcounted(parent_type) && !clone_ref_obj_id) {
          verifier_bug(env, "missing ref obj id for parent of clone");
          return -EFAULT;
        }
      }

      ret = process_dynptr_func(env, regno, insn_idx, dynptr_arg_type,
                                clone_ref_obj_id);
      if (ret < 0)
        return ret;

      if (!(dynptr_arg_type & MEM_UNINIT)) {
        int id = dynptr_id(env, reg);

        if (id < 0) {
          verifier_bug(env, "failed to obtain dynptr id");
          return id;
        }
        meta->initialized_dynptr.id = id;
        meta->initialized_dynptr.type = dynptr_get_type(env, reg);
        meta->initialized_dynptr.ref_obj_id = dynptr_ref_obj_id(env, reg);
      }

      break;
    }
    case KF_ARG_PTR_TO_ITER:
      if (meta->func_id == special_kfunc_list[KF_bpf_iter_css_task_new]) {
        if (!check_css_task_iter_allowlist(env)) {
          verbose(env, "css_task_iter is only allowed in bpf_lsm, bpf_iter and "
                       "sleepable progs\n");
          return -EINVAL;
        }
      }
      ret = process_iter_arg(env, regno, insn_idx, meta);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_LIST_HEAD:
      if (reg->type != PTR_TO_MAP_VALUE &&
          reg->type != (PTR_TO_BTF_ID | MEM_ALLOC)) {
        verbose(env,
                "arg#%d expected pointer to map value or allocated object\n",
                i);
        return -EINVAL;
      }
      if (reg->type == (PTR_TO_BTF_ID | MEM_ALLOC) && !reg->ref_obj_id) {
        verbose(env, "allocated object must be referenced\n");
        return -EINVAL;
      }
      ret = process_kf_arg_ptr_to_list_head(env, reg, regno, meta);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_RB_ROOT:
      if (reg->type != PTR_TO_MAP_VALUE &&
          reg->type != (PTR_TO_BTF_ID | MEM_ALLOC)) {
        verbose(env,
                "arg#%d expected pointer to map value or allocated object\n",
                i);
        return -EINVAL;
      }
      if (reg->type == (PTR_TO_BTF_ID | MEM_ALLOC) && !reg->ref_obj_id) {
        verbose(env, "allocated object must be referenced\n");
        return -EINVAL;
      }
      ret = process_kf_arg_ptr_to_rbtree_root(env, reg, regno, meta);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_LIST_NODE:
      if (reg->type != (PTR_TO_BTF_ID | MEM_ALLOC)) {
        verbose(env, "arg#%d expected pointer to allocated object\n", i);
        return -EINVAL;
      }
      if (!reg->ref_obj_id) {
        verbose(env, "allocated object must be referenced\n");
        return -EINVAL;
      }
      ret = process_kf_arg_ptr_to_list_node(env, reg, regno, meta);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_RB_NODE:
      if (meta->func_id == special_kfunc_list[KF_bpf_rbtree_add_impl]) {
        if (reg->type != (PTR_TO_BTF_ID | MEM_ALLOC)) {
          verbose(env, "arg#%d expected pointer to allocated object\n", i);
          return -EINVAL;
        }
        if (!reg->ref_obj_id) {
          verbose(env, "allocated object must be referenced\n");
          return -EINVAL;
        }
      } else {
        if (!type_is_non_owning_ref(reg->type) && !reg->ref_obj_id) {
          verbose(
              env,
              "%s can only take non-owning or refcounted bpf_rb_node pointer\n",
              func_name);
          return -EINVAL;
        }
        if (in_rbtree_lock_required_cb(env)) {
          verbose(env, "%s not allowed in rbtree cb\n", func_name);
          return -EINVAL;
        }
      }

      ret = process_kf_arg_ptr_to_rbtree_node(env, reg, regno, meta);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_MAP:
      /* If argument has '__map' suffix expect 'struct bpf_map *' */
      ref_id = *reg2btf_ids[CONST_PTR_TO_MAP];
      ref_t = btf_type_by_id(btf_vmlinux, ref_id);
      ref_tname = btf_name_by_offset(btf, ref_t->name_off);
      fallthrough;
    case KF_ARG_PTR_TO_BTF_ID:
      /* Only base_type is checked, further checks are done here */
      if ((base_type(reg->type) != PTR_TO_BTF_ID ||
           (bpf_type_has_unsafe_modifiers(reg->type) && !is_rcu_reg(reg))) &&
          !reg2btf_ids[base_type(reg->type)]) {
        verbose(env, "arg#%d is %s ", i, reg_type_str(env, reg->type));
        verbose(env, "expected %s or socket\n",
                reg_type_str(env, base_type(reg->type) |
                                      (type_flag(reg->type) &
                                       BPF_REG_TRUSTED_MODIFIERS)));
        return -EINVAL;
      }
      ret = process_kf_arg_ptr_to_btf_id(env, reg, ref_t, ref_tname, ref_id,
                                         meta, i);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_MEM:
      resolve_ret = btf_resolve_size(btf, ref_t, &type_size);
      if (IS_ERR(resolve_ret)) {
        verbose(
            env,
            "arg#%d reference type('%s %s') size cannot be determined: %ld\n",
            i, btf_type_str(ref_t), ref_tname, PTR_ERR(resolve_ret));
        return -EINVAL;
      }
      ret = check_mem_reg(env, reg, regno, type_size);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_MEM_SIZE: {
      struct bpf_reg_state *buff_reg = &regs[regno];
      const struct btf_param *buff_arg = &args[i];
      struct bpf_reg_state *size_reg = &regs[regno + 1];
      const struct btf_param *size_arg = &args[i + 1];

      if (!register_is_null(buff_reg) ||
          !is_kfunc_arg_nullable(meta->btf, buff_arg)) {
        ret = check_kfunc_mem_size_reg(env, size_reg, regno + 1);
        if (ret < 0) {
          verbose(
              env,
              "arg#%d arg#%d memory, len pair leads to invalid memory access\n",
              i, i + 1);
          return ret;
        }
      }

      if (is_kfunc_arg_const_mem_size(meta->btf, size_arg, size_reg)) {
        if (meta->arg_constant.found) {
          verifier_bug(env, "only one constant argument permitted");
          return -EFAULT;
        }
        if (!tnum_is_const(size_reg->var_off)) {
          verbose(env, "R%d must be a known constant\n", regno + 1);
          return -EINVAL;
        }
        meta->arg_constant.found = true;
        meta->arg_constant.value = size_reg->var_off.value;
      }

      /* Skip next '__sz' or '__szk' argument */
      i++;
      break;
    }
    case KF_ARG_PTR_TO_CALLBACK:
      if (reg->type != PTR_TO_FUNC) {
        verbose(env, "arg%d expected pointer to func\n", i);
        return -EINVAL;
      }
      meta->subprogno = reg->subprogno;
      break;
    case KF_ARG_PTR_TO_REFCOUNTED_KPTR:
      if (!type_is_ptr_alloc_obj(reg->type)) {
        verbose(env, "arg#%d is neither owning or non-owning ref\n", i);
        return -EINVAL;
      }
      if (!type_is_non_owning_ref(reg->type))
        meta->arg_owning_ref = true;

      rec = reg_btf_record(reg);
      if (!rec) {
        verifier_bug(env, "Couldn't find btf_record");
        return -EFAULT;
      }

      if (rec->refcount_off < 0) {
        verbose(env, "arg#%d doesn't point to a type with bpf_refcount field\n",
                i);
        return -EINVAL;
      }

      meta->arg_btf = reg->btf;
      meta->arg_btf_id = reg->btf_id;
      break;
    case KF_ARG_PTR_TO_CONST_STR:
      if (reg->type != PTR_TO_MAP_VALUE) {
        verbose(env, "arg#%d doesn't point to a const string\n", i);
        return -EINVAL;
      }
      ret = check_reg_const_str(env, reg, regno);
      if (ret)
        return ret;
      break;
    case KF_ARG_PTR_TO_WORKQUEUE:
      if (reg->type != PTR_TO_MAP_VALUE) {
        verbose(env, "arg#%d doesn't point to a map value\n", i);
        return -EINVAL;
      }
      ret = check_map_field_pointer(env, regno, BPF_WORKQUEUE, &meta->map);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_TIMER:
      if (reg->type != PTR_TO_MAP_VALUE) {
        verbose(env, "arg#%d doesn't point to a map value\n", i);
        return -EINVAL;
      }
      ret = process_timer_kfunc(env, regno, meta);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_TASK_WORK:
      if (reg->type != PTR_TO_MAP_VALUE) {
        verbose(env, "arg#%d doesn't point to a map value\n", i);
        return -EINVAL;
      }
      ret = check_map_field_pointer(env, regno, BPF_TASK_WORK, &meta->map);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_IRQ_FLAG:
      if (reg->type != PTR_TO_STACK) {
        verbose(env, "arg#%d doesn't point to an irq flag on stack\n", i);
        return -EINVAL;
      }
      ret = process_irq_flag(env, regno, meta);
      if (ret < 0)
        return ret;
      break;
    case KF_ARG_PTR_TO_RES_SPIN_LOCK: {
      int flags = PROCESS_RES_LOCK;

      if (reg->type != PTR_TO_MAP_VALUE &&
          reg->type != (PTR_TO_BTF_ID | MEM_ALLOC)) {
        verbose(env, "arg#%d doesn't point to map value or allocated object\n",
                i);
        return -EINVAL;
      }

      if (!is_bpf_res_spin_lock_kfunc(meta->func_id))
        return -EFAULT;
      if (meta->func_id == special_kfunc_list[KF_bpf_res_spin_lock] ||
          meta->func_id == special_kfunc_list[KF_bpf_res_spin_lock_irqsave])
        flags |= PROCESS_SPIN_LOCK;
      if (meta->func_id == special_kfunc_list[KF_bpf_res_spin_lock_irqsave] ||
          meta->func_id ==
              special_kfunc_list[KF_bpf_res_spin_unlock_irqrestore])
        flags |= PROCESS_LOCK_IRQ;
      ret = process_spin_lock(env, regno, flags);
      if (ret < 0)
        return ret;
      break;
    }
    }
  }

  if (is_kfunc_release(meta) && !meta->release_regno) {
    verbose(env,
            "release kernel function %s expects refcounted PTR_TO_BTF_ID\n",
            func_name);
    return -EINVAL;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_kfunc_call(struct bpf_verifier_env *env, struct bpf_insn *insn,
                            int *insn_idx_p) {
  bool sleepable, rcu_lock, rcu_unlock, preempt_disable, preempt_enable;
  u32 i, nargs, ptr_type_id, release_ref_obj_id;
  struct bpf_reg_state *regs = cur_regs(env);
  const char *func_name, *ptr_type_name;
  const struct btf_type *t, *ptr_type;
  struct bpf_kfunc_call_arg_meta meta;
  struct bpf_insn_aux_data *insn_aux;
  int err, insn_idx = *insn_idx_p;
  const struct btf_param *args;
  struct btf *desc_btf;

  /* skip for now, but return error when we find this in fixup_kfunc_call */
  if (!insn->imm)
    return 0;

  err = fetch_kfunc_arg_meta(env, insn->imm, insn->off, &meta);
  if (err == -EACCES && meta.func_name)
    verbose(env, "calling kernel function %s is not allowed\n", meta.func_name);
  if (err)
    return err;
  desc_btf = meta.btf;
  func_name = meta.func_name;
  insn_aux = &env->insn_aux_data[insn_idx];

  insn_aux->is_iter_next = is_iter_next_kfunc(&meta);

  if (!insn->off &&
      (insn->imm == special_kfunc_list[KF_bpf_res_spin_lock] ||
       insn->imm == special_kfunc_list[KF_bpf_res_spin_lock_irqsave])) {
    struct bpf_verifier_state *branch;
    struct bpf_reg_state *regs;

    branch = push_stack(env, env->insn_idx + 1, env->insn_idx, false);
    if (IS_ERR(branch)) {
      verbose(env, "failed to push state for failed lock acquisition\n");
      return PTR_ERR(branch);
    }

    regs = branch->frame[branch->curframe]->regs;

    /* Clear r0-r5 registers in forked state */
    for (i = 0; i < CALLER_SAVED_REGS; i++)
      mark_reg_not_init(env, regs, caller_saved[i]);

    mark_reg_unknown(env, regs, BPF_REG_0);
    err = inner_mark_reg_s32_range(env, regs, BPF_REG_0, -MAX_ERRNO, -1);
    if (err) {
      verbose(env,
              "failed to mark s32 range for retval in forked state for lock\n");
      return err;
    }
    inner_mark_btf_func_reg_size(env, regs, BPF_REG_0, sizeof(u32));
  } else if (!insn->off && insn->imm == special_kfunc_list[KF___bpf_trap]) {
    verbose(env, "unexpected __bpf_trap() due to uninitialized variable?\n");
    return -EFAULT;
  }

  if (is_kfunc_destructive(&meta) && !capable(CAP_SYS_BOOT)) {
    verbose(env, "destructive kfunc calls require CAP_SYS_BOOT capability\n");
    return -EACCES;
  }

  sleepable = is_kfunc_sleepable(&meta);
  if (sleepable && !in_sleepable(env)) {
    verbose(env, "program must be sleepable to call sleepable kfunc %s\n",
            func_name);
    return -EACCES;
  }

  /* Track non-sleepable context for kfuncs, same as for helpers. */
  if (!in_sleepable_context(env))
    insn_aux->non_sleepable = true;

  /* Check the arguments */
  err = check_kfunc_args(env, &meta, insn_idx);
  if (err < 0)
    return err;

  if (meta.func_id == special_kfunc_list[KF_bpf_rbtree_add_impl]) {
    err = push_callback_call(env, insn, insn_idx, meta.subprogno,
                             set_rbtree_add_callback_state);
    if (err) {
      verbose(env, "kfunc %s#%d failed callback verification\n", func_name,
              meta.func_id);
      return err;
    }
  }

  if (meta.func_id == special_kfunc_list[KF_bpf_session_cookie]) {
    meta.r0_size = sizeof(u64);
    meta.r0_rdonly = false;
  }

  if (is_bpf_wq_set_callback_kfunc(meta.func_id)) {
    err = push_callback_call(env, insn, insn_idx, meta.subprogno,
                             set_timer_callback_state);
    if (err) {
      verbose(env, "kfunc %s#%d failed callback verification\n", func_name,
              meta.func_id);
      return err;
    }
  }

  if (is_task_work_add_kfunc(meta.func_id)) {
    err = push_callback_call(env, insn, insn_idx, meta.subprogno,
                             set_task_work_schedule_callback_state);
    if (err) {
      verbose(env, "kfunc %s#%d failed callback verification\n", func_name,
              meta.func_id);
      return err;
    }
  }

  rcu_lock = is_kfunc_bpf_rcu_read_lock(&meta);
  rcu_unlock = is_kfunc_bpf_rcu_read_unlock(&meta);

  preempt_disable = is_kfunc_bpf_preempt_disable(&meta);
  preempt_enable = is_kfunc_bpf_preempt_enable(&meta);

  if (rcu_lock) {
    env->cur_state->active_rcu_locks++;
  } else if (rcu_unlock) {
    struct bpf_func_state *state;
    struct bpf_reg_state *reg;
    u32 clear_mask = (1 << STACK_SPILL) | (1 << STACK_ITER);

    if (env->cur_state->active_rcu_locks == 0) {
      verbose(env, "unmatched rcu read unlock (kernel function %s)\n",
              func_name);
      return -EINVAL;
    }
    if (--env->cur_state->active_rcu_locks == 0) {
      bpf_for_each_reg_in_vstate_mask(env->cur_state, state, reg, clear_mask, ({
                                        if (reg->type & MEM_RCU) {
                                          reg->type &=
                                              ~(MEM_RCU | PTR_MAYBE_NULL);
                                          reg->type |= PTR_UNTRUSTED;
                                        }
                                      }));
    }
  } else if (sleepable && env->cur_state->active_rcu_locks) {
    verbose(env, "kernel func %s is sleepable within rcu_read_lock region\n",
            func_name);
    return -EACCES;
  }

  if (in_rbtree_lock_required_cb(env) && (rcu_lock || rcu_unlock)) {
    verbose(
        env,
        "Calling bpf_rcu_read_{lock,unlock} in unnecessary rbtree callback\n");
    return -EACCES;
  }

  if (env->cur_state->active_preempt_locks) {
    if (preempt_disable) {
      env->cur_state->active_preempt_locks++;
    } else if (preempt_enable) {
      env->cur_state->active_preempt_locks--;
    } else if (sleepable) {
      verbose(env,
              "kernel func %s is sleepable within non-preemptible region\n",
              func_name);
      return -EACCES;
    }
  } else if (preempt_disable) {
    env->cur_state->active_preempt_locks++;
  } else if (preempt_enable) {
    verbose(env,
            "unmatched attempt to enable preemption (kernel function %s)\n",
            func_name);
    return -EINVAL;
  }

  if (env->cur_state->active_irq_id && sleepable) {
    verbose(env, "kernel func %s is sleepable within IRQ-disabled region\n",
            func_name);
    return -EACCES;
  }

  if (is_kfunc_rcu_protected(&meta) && !in_rcu_cs(env)) {
    verbose(env, "kernel func %s requires RCU critical section protection\n",
            func_name);
    return -EACCES;
  }

  /* In case of release function, we get register number of refcounted
   * PTR_TO_BTF_ID in bpf_kfunc_arg_meta, do the release now.
   */
  if (meta.release_regno) {
    struct bpf_reg_state *reg = &regs[meta.release_regno];

    if (meta.initialized_dynptr.ref_obj_id) {
      err = unmark_stack_slots_dynptr(env, reg);
    } else {
      err = release_reference(env, reg->ref_obj_id);
      if (err)
        verbose(env, "kfunc %s#%d reference has not been acquired before\n",
                func_name, meta.func_id);
    }
    if (err)
      return err;
  }

  if (meta.func_id == special_kfunc_list[KF_bpf_list_push_front_impl] ||
      meta.func_id == special_kfunc_list[KF_bpf_list_push_back_impl] ||
      meta.func_id == special_kfunc_list[KF_bpf_rbtree_add_impl]) {
    release_ref_obj_id = regs[BPF_REG_2].ref_obj_id;
    insn_aux->insert_off = regs[BPF_REG_2].off;
    insn_aux->kptr_struct_meta =
        btf_find_struct_meta(meta.arg_btf, meta.arg_btf_id);
    err = ref_convert_owning_non_owning(env, release_ref_obj_id);
    if (err) {
      verbose(env,
              "kfunc %s#%d conversion of owning ref to non-owning failed\n",
              func_name, meta.func_id);
      return err;
    }

    err = release_reference(env, release_ref_obj_id);
    if (err) {
      verbose(env, "kfunc %s#%d reference has not been acquired before\n",
              func_name, meta.func_id);
      return err;
    }
  }

  if (meta.func_id == special_kfunc_list[KF_bpf_throw]) {
    if (!bpf_jit_supports_exceptions()) {
      verbose(env, "JIT does not support calling kfunc %s#%d\n", func_name,
              meta.func_id);
      return -ENOTSUPP;
    }
    env->seen_exception = true;

    /* In the case of the default callback, the cookie value passed
     * to bpf_throw becomes the return value of the program.
     */
    if (!env->exception_callback_subprog) {
      err = check_return_code(env, BPF_REG_1, "R1");
      if (err < 0)
        return err;
    }
  }

  for (i = 0; i < CALLER_SAVED_REGS; i++) {
    u32 regno = caller_saved[i];

    mark_reg_not_init(env, regs, regno);
    regs[regno].subreg_def = DEF_NOT_SUBREG;
  }

  /* Check return type */
  t = btf_type_skip_modifiers(desc_btf, meta.func_proto->type, NULL);

  if (is_kfunc_acquire(&meta) && !btf_type_is_struct_ptr(meta.btf, t)) {
    /* Only exception is bpf_obj_new_impl */
    if (meta.btf != btf_vmlinux ||
        (meta.func_id != special_kfunc_list[KF_bpf_obj_new_impl] &&
         meta.func_id != special_kfunc_list[KF_bpf_percpu_obj_new_impl] &&
         meta.func_id != special_kfunc_list[KF_bpf_refcount_acquire_impl])) {
      verbose(env, "acquire kernel function does not return PTR_TO_BTF_ID\n");
      return -EINVAL;
    }
  }

  if (btf_type_is_scalar(t)) {
    mark_reg_unknown(env, regs, BPF_REG_0);
    if (meta.btf == btf_vmlinux &&
        (meta.func_id == special_kfunc_list[KF_bpf_res_spin_lock] ||
         meta.func_id == special_kfunc_list[KF_bpf_res_spin_lock_irqsave]))
      inner_mark_reg_const_zero(env, &regs[BPF_REG_0]);
    mark_btf_func_reg_size(env, BPF_REG_0, t->size);
  } else if (btf_type_is_ptr(t)) {
    ptr_type = btf_type_skip_modifiers(desc_btf, t->type, &ptr_type_id);
    err = check_special_kfunc(env, &meta, regs, insn_aux, ptr_type, desc_btf);
    if (err) {
      if (err < 0)
        return err;
    } else if (btf_type_is_void(ptr_type)) {
      /* kfunc returning 'void *' is equivalent to returning scalar */
      mark_reg_unknown(env, regs, BPF_REG_0);
    } else if (!__btf_type_is_struct(ptr_type)) {
      if (!meta.r0_size) {
        __u32 sz;

        if (!IS_ERR(btf_resolve_size(desc_btf, ptr_type, &sz))) {
          meta.r0_size = sz;
          meta.r0_rdonly = true;
        }
      }
      if (!meta.r0_size) {
        ptr_type_name = btf_name_by_offset(desc_btf, ptr_type->name_off);
        verbose(
            env,
            "kernel function %s returns pointer type %s %s is not supported\n",
            func_name, btf_type_str(ptr_type), ptr_type_name);
        return -EINVAL;
      }

      mark_reg_known_zero(env, regs, BPF_REG_0);
      regs[BPF_REG_0].type = PTR_TO_MEM;
      regs[BPF_REG_0].mem_size = meta.r0_size;

      if (meta.r0_rdonly)
        regs[BPF_REG_0].type |= MEM_RDONLY;

      /* Ensures we don't access the memory after a release_reference() */
      if (meta.ref_obj_id)
        regs[BPF_REG_0].ref_obj_id = meta.ref_obj_id;

      if (is_kfunc_rcu_protected(&meta))
        regs[BPF_REG_0].type |= MEM_RCU;
    } else {
      enum bpf_reg_type type = PTR_TO_BTF_ID;

      if (meta.func_id == special_kfunc_list[KF_bpf_get_kmem_cache])
        type |= PTR_UNTRUSTED;
      else if (is_kfunc_rcu_protected(&meta) ||
               (is_iter_next_kfunc(&meta) &&
                (get_iter_from_state(env->cur_state, &meta)->type & MEM_RCU))) {
        /*
         * If the iterator's constructor (the _new
         * function e.g., bpf_iter_task_new) has been
         * annotated with BPF kfunc flag
         * KF_RCU_PROTECTED and was called within a RCU
         * read-side critical section, also propagate
         * the MEM_RCU flag to the pointer returned from
         * the iterator's next function (e.g.,
         * bpf_iter_task_next).
         */
        type |= MEM_RCU;
      } else {
        /*
         * Any PTR_TO_BTF_ID that is returned from a BPF
         * kfunc should by default be treated as
         * implicitly trusted.
         */
        type |= PTR_TRUSTED;
      }

      mark_reg_known_zero(env, regs, BPF_REG_0);
      regs[BPF_REG_0].btf = desc_btf;
      regs[BPF_REG_0].type = type;
      regs[BPF_REG_0].btf_id = ptr_type_id;
    }

    if (is_kfunc_ret_null(&meta)) {
      regs[BPF_REG_0].type |= PTR_MAYBE_NULL;
      /* For mark_ptr_or_null_reg, see 93c230e3f5bd6 */
      regs[BPF_REG_0].id = ++env->id_gen;
    }
    mark_btf_func_reg_size(env, BPF_REG_0, sizeof(void *));
    if (is_kfunc_acquire(&meta)) {
      int id = acquire_reference(env, insn_idx);

      if (id < 0)
        return id;
      if (is_kfunc_ret_null(&meta))
        regs[BPF_REG_0].id = id;
      regs[BPF_REG_0].ref_obj_id = id;
    } else if (is_rbtree_node_type(ptr_type) || is_list_node_type(ptr_type)) {
      ref_set_non_owning(env, &regs[BPF_REG_0]);
    }

    if (reg_may_point_to_spin_lock(&regs[BPF_REG_0]) && !regs[BPF_REG_0].id)
      regs[BPF_REG_0].id = ++env->id_gen;
  } else if (btf_type_is_void(t)) {
    if (meta.btf == btf_vmlinux) {
      if (meta.func_id == special_kfunc_list[KF_bpf_obj_drop_impl] ||
          meta.func_id == special_kfunc_list[KF_bpf_percpu_obj_drop_impl]) {
        insn_aux->kptr_struct_meta =
            btf_find_struct_meta(meta.arg_btf, meta.arg_btf_id);
      }
    }
  }

  if (is_kfunc_pkt_changing(&meta))
    clear_all_pkt_pointers(env);

  nargs = btf_type_vlen(meta.func_proto);
  args = (const struct btf_param *)(meta.func_proto + 1);
  for (i = 0; i < nargs; i++) {
    u32 regno = i + 1;

    t = btf_type_skip_modifiers(desc_btf, args[i].type, NULL);
    if (btf_type_is_ptr(t))
      mark_btf_func_reg_size(env, regno, sizeof(void *));
    else
      /* scalar. ensured by btf_check_kfunc_arg_match() */
      mark_btf_func_reg_size(env, regno, t->size);
  }

  if (is_iter_next_kfunc(&meta)) {
    err = process_iter_next_call(env, insn_idx, &meta);
    if (err)
      return err;
  }

  if (meta.func_id == special_kfunc_list[KF_bpf_session_cookie])
    env->prog->call_session_cookie = true;

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_kfunc_is_graph_node_api(struct bpf_verifier_env *env,
                                          enum btf_field_type node_field_type,
                                          u32 kfunc_btf_id) {
  bool ret;

  switch (node_field_type) {
  case BPF_LIST_NODE:
    ret = (kfunc_btf_id == special_kfunc_list[KF_bpf_list_push_front_impl] ||
           kfunc_btf_id == special_kfunc_list[KF_bpf_list_push_back_impl]);
    break;
  case BPF_RB_NODE:
    ret = (kfunc_btf_id == special_kfunc_list[KF_bpf_rbtree_remove] ||
           kfunc_btf_id == special_kfunc_list[KF_bpf_rbtree_add_impl] ||
           kfunc_btf_id == special_kfunc_list[KF_bpf_rbtree_left] ||
           kfunc_btf_id == special_kfunc_list[KF_bpf_rbtree_right]);
    break;
  default:
    verbose(env,
            "verifier internal error: unexpected graph node argument type %s\n",
            btf_field_type_name(node_field_type));
    return false;
  }

  if (!ret)
    verbose(env, "verifier internal error: %s node arg for unknown kfunc\n",
            btf_field_type_name(node_field_type));
  return ret;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_kfunc_is_graph_root_api(struct bpf_verifier_env *env,
                                          enum btf_field_type head_field_type,
                                          u32 kfunc_btf_id) {
  bool ret;

  switch (head_field_type) {
  case BPF_LIST_HEAD:
    ret = is_bpf_list_api_kfunc(kfunc_btf_id);
    break;
  case BPF_RB_ROOT:
    ret = is_bpf_rbtree_api_kfunc(kfunc_btf_id);
    break;
  default:
    verbose(env,
            "verifier internal error: unexpected graph root argument type %s\n",
            btf_field_type_name(head_field_type));
    return false;
  }

  if (!ret)
    verbose(env, "verifier internal error: %s head arg for unknown kfunc\n",
            btf_field_type_name(head_field_type));
  return ret;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_kfunc_mem_size_reg(struct bpf_verifier_env *env,
                                    struct bpf_reg_state *reg, u32 regno) {
  struct bpf_reg_state *mem_reg = &cur_regs(env)[regno - 1];
  bool may_be_null = type_may_be_null(mem_reg->type);
  struct bpf_reg_state saved_reg;
  struct bpf_call_arg_meta meta;
  int err;

  WARN_ON_ONCE(regno < BPF_REG_2 || regno > BPF_REG_5);

  memset(&meta, 0, sizeof(meta));

  if (may_be_null) {
    saved_reg = *mem_reg;
    mark_ptr_not_null_reg(mem_reg);
  }

  err = check_mem_size_reg(env, reg, regno, BPF_READ, true, &meta);
  err = err ?: check_mem_size_reg(env, reg, regno, BPF_WRITE, true, &meta);

  if (may_be_null)
    *mem_reg = saved_reg;

  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_ld_abs(struct bpf_verifier_env *env, struct bpf_insn *insn) {
  struct bpf_reg_state *regs = cur_regs(env);
  static const int ctx_reg = BPF_REG_6;
  u8 mode = BPF_MODE(insn->code);
  int i, err;

  if (!may_access_skb(resolve_prog_type(env->prog))) {
    verbose(
        env,
        "BPF_LD_[ABS|IND] instructions not allowed for this program type\n");
    return -EINVAL;
  }

  if (!env->ops->gen_ld_abs) {
    verifier_bug(env, "gen_ld_abs is null");
    return -EFAULT;
  }

  if (insn->dst_reg != BPF_REG_0 || insn->off != 0 ||
      BPF_SIZE(insn->code) == BPF_DW ||
      (mode == BPF_ABS && insn->src_reg != BPF_REG_0)) {
    verbose(env, "BPF_LD_[ABS|IND] uses reserved fields\n");
    return -EINVAL;
  }

  /* check whether implicit source operand (register R6) is readable */
  err = check_reg_arg(env, ctx_reg, SRC_OP);
  if (err)
    return err;

  /* Disallow usage of BPF_LD_[ABS|IND] with reference tracking, as
   * gen_ld_abs() may terminate the program at runtime, leading to
   * reference leak.
   */
  err = check_resource_leak(env, false, true, "BPF_LD_[ABS|IND]");
  if (err)
    return err;

  if (regs[ctx_reg].type != PTR_TO_CTX) {
    verbose(env, "at the time of BPF_LD_ABS|IND R6 != pointer to skb\n");
    return -EINVAL;
  }

  if (mode == BPF_IND) {
    /* check explicit source operand */
    err = check_reg_arg(env, insn->src_reg, SRC_OP);
    if (err)
      return err;
  }

  err = check_ptr_off_reg(env, &regs[ctx_reg], ctx_reg);
  if (err < 0)
    return err;

  /* reset caller saved regs to unreadable */
  for (i = 0; i < CALLER_SAVED_REGS; i++) {
    mark_reg_not_init(env, regs, caller_saved[i]);
    check_reg_arg(env, caller_saved[i], DST_OP_NO_MARK);
  }

  /* mark destination R0 register as readable, since it contains
   * the value fetched from the packet.
   * Already marked as written above.
   */
  mark_reg_unknown(env, regs, BPF_REG_0);
  /* ld_abs load up to 32-bit skb data. */
  regs[BPF_REG_0].subreg_def = env->insn_idx + 1;
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_ld_imm(struct bpf_verifier_env *env, struct bpf_insn *insn) {
  struct bpf_insn_aux_data *aux = cur_aux(env);
  struct bpf_reg_state *regs = cur_regs(env);
  struct bpf_reg_state *dst_reg;
  struct bpf_map *map;
  int err;

  if (BPF_SIZE(insn->code) != BPF_DW) {
    verbose(env, "invalid BPF_LD_IMM insn\n");
    return -EINVAL;
  }
  if (insn->off != 0) {
    verbose(env, "BPF_LD_IMM64 uses reserved fields\n");
    return -EINVAL;
  }

  err = check_reg_arg(env, insn->dst_reg, DST_OP);
  if (err)
    return err;

  dst_reg = &regs[insn->dst_reg];
  if (insn->src_reg == 0) {
    u64 imm = ((u64)(insn + 1)->imm << 32) | (u32)insn->imm;

    dst_reg->type = SCALAR_VALUE;
    inner_mark_reg_known(&regs[insn->dst_reg], imm);
    return 0;
  }

  /* All special src_reg cases are listed below. From this point onwards
   * we either succeed and assign a corresponding dst_reg->type after
   * zeroing the offset, or fail and reject the program.
   */
  mark_reg_known_zero(env, regs, insn->dst_reg);

  if (insn->src_reg == BPF_PSEUDO_BTF_ID) {
    dst_reg->type = aux->btf_var.reg_type;
    switch (base_type(dst_reg->type)) {
    case PTR_TO_MEM:
      dst_reg->mem_size = aux->btf_var.mem_size;
      break;
    case PTR_TO_BTF_ID:
      dst_reg->btf = aux->btf_var.btf;
      dst_reg->btf_id = aux->btf_var.btf_id;
      break;
    default:
      verifier_bug(env, "pseudo btf id: unexpected dst reg type");
      return -EFAULT;
    }
    return 0;
  }

  if (insn->src_reg == BPF_PSEUDO_FUNC) {
    struct bpf_prog_aux *aux = env->prog->aux;
    u32 subprogno = find_subprog(env, env->insn_idx + insn->imm + 1);

    if (!aux->func_info) {
      verbose(env, "missing btf func_info\n");
      return -EINVAL;
    }
    if (aux->func_info_aux[subprogno].linkage != BTF_FUNC_STATIC) {
      verbose(env, "callback function not static\n");
      return -EINVAL;
    }

    dst_reg->type = PTR_TO_FUNC;
    dst_reg->subprogno = subprogno;
    return 0;
  }

  map = env->used_maps[aux->map_index];
  dst_reg->map_ptr = map;

  if (insn->src_reg == BPF_PSEUDO_MAP_VALUE ||
      insn->src_reg == BPF_PSEUDO_MAP_IDX_VALUE) {
    if (map->map_type == BPF_MAP_TYPE_ARENA) {
      inner_mark_reg_unknown(env, dst_reg);
      return 0;
    }
    dst_reg->type = PTR_TO_MAP_VALUE;
    dst_reg->off = aux->map_off;
    WARN_ON_ONCE(map->map_type != BPF_MAP_TYPE_INSN_ARRAY &&
                 map->max_entries != 1);
    /* We want reg->id to be same (0) as map_value is not distinct */
  } else if (insn->src_reg == BPF_PSEUDO_MAP_FD ||
             insn->src_reg == BPF_PSEUDO_MAP_IDX) {
    dst_reg->type = CONST_PTR_TO_MAP;
  } else {
    verifier_bug(env, "unexpected src reg value for ldimm64");
    return -EFAULT;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_load_mem(struct bpf_verifier_env *env, struct bpf_insn *insn,
                          bool strict_alignment_once, bool is_ldsx,
                          bool allow_trust_mismatch, const char *ctx) {
  struct bpf_reg_state *regs = cur_regs(env);
  enum bpf_reg_type src_reg_type;
  int err;

  /* check src operand */
  err = check_reg_arg(env, insn->src_reg, SRC_OP);
  if (err)
    return err;

  /* check dst operand */
  err = check_reg_arg(env, insn->dst_reg, DST_OP_NO_MARK);
  if (err)
    return err;

  src_reg_type = regs[insn->src_reg].type;

  /* Check if (src_reg + off) is readable. The state of dst_reg will be
   * updated by this call.
   */
  err = check_mem_access(env, env->insn_idx, insn->src_reg, insn->off,
                         BPF_SIZE(insn->code), BPF_READ, insn->dst_reg,
                         strict_alignment_once, is_ldsx);
  err = err ?: save_aux_ptr_type(env, src_reg_type, allow_trust_mismatch);
  err = err ?: reg_bounds_sanity_check(env, &regs[insn->dst_reg], ctx);

  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_map_access(struct bpf_verifier_env *env, u32 regno, int off,
                            int size, bool zero_size_allowed,
                            enum bpf_access_src src) {
  struct bpf_verifier_state *vstate = env->cur_state;
  struct bpf_func_state *state = vstate->frame[vstate->curframe];
  struct bpf_reg_state *reg = &state->regs[regno];
  struct bpf_map *map = reg->map_ptr;
  u32 mem_size = map_mem_size(map);
  struct btf_record *rec;
  int err, i;

  err = check_mem_region_access(env, regno, off, size, mem_size,
                                zero_size_allowed);
  if (err)
    return err;

  if (IS_ERR_OR_NULL(map->record))
    return 0;
  rec = map->record;
  for (i = 0; i < rec->cnt; i++) {
    struct btf_field *field = &rec->fields[i];
    u32 p = field->offset;

    /* If any part of a field  can be touched by load/store, reject
     * this program. To check that [x1, x2) overlaps with [y1, y2),
     * it is sufficient to check x1 < y2 && y1 < x2.
     */
    if (reg->smin_value + off < p + field->size &&
        p < reg->umax_value + off + size) {
      switch (field->type) {
      case BPF_KPTR_UNREF:
      case BPF_KPTR_REF:
      case BPF_KPTR_PERCPU:
      case BPF_UPTR:
        if (src != ACCESS_DIRECT) {
          verbose(env, "%s cannot be accessed indirectly by helper\n",
                  btf_field_type_name(field->type));
          return -EACCES;
        }
        if (!tnum_is_const(reg->var_off)) {
          verbose(env, "%s access cannot have variable offset\n",
                  btf_field_type_name(field->type));
          return -EACCES;
        }
        if (p != off + reg->var_off.value) {
          verbose(env, "%s access misaligned expected=%u off=%llu\n",
                  btf_field_type_name(field->type), p,
                  off + reg->var_off.value);
          return -EACCES;
        }
        if (size != bpf_size_to_bytes(BPF_DW)) {
          verbose(env, "%s access size must be BPF_DW\n",
                  btf_field_type_name(field->type));
          return -EACCES;
        }
        break;
      default:
        verbose(env, "%s cannot be accessed directly by load/store\n",
                btf_field_type_name(field->type));
        return -EACCES;
      }
    }
  }
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_map_access_type(struct bpf_verifier_env *env, u32 regno,
                                 int off, int size, enum bpf_access_type type) {
  struct bpf_reg_state *reg = reg_state(env, regno);
  struct bpf_map *map = reg->map_ptr;
  u32 cap = bpf_map_flags_to_cap(map);

  if (type == BPF_WRITE && !(cap & BPF_MAP_CAN_WRITE)) {
    verbose(env, "write into map forbidden, value_size=%d off=%d size=%d\n",
            map->value_size, off, size);
    return -EACCES;
  }

  if (type == BPF_READ && !(cap & BPF_MAP_CAN_READ)) {
    verbose(env, "read from map forbidden, value_size=%d off=%d size=%d\n",
            map->value_size, off, size);
    return -EACCES;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_map_field_pointer(struct bpf_verifier_env *env, u32 regno,
                                   enum btf_field_type field_type,
                                   struct bpf_map_desc *map_desc) {
  struct bpf_reg_state *reg = reg_state(env, regno);
  bool is_const = tnum_is_const(reg->var_off);
  struct bpf_map *map = reg->map_ptr;
  u64 val = reg->var_off.value;
  const char *struct_name = btf_field_type_name(field_type);
  int field_off = -1;

  if (!is_const) {
    verbose(env,
            "R%d doesn't have constant offset. %s has to be at the constant "
            "offset\n",
            regno, struct_name);
    return -EINVAL;
  }
  if (!map->btf) {
    verbose(env, "map '%s' has to have BTF in order to use %s\n", map->name,
            struct_name);
    return -EINVAL;
  }
  if (!btf_record_has_field(map->record, field_type)) {
    verbose(env, "map '%s' has no valid %s\n", map->name, struct_name);
    return -EINVAL;
  }
  switch (field_type) {
  case BPF_TIMER:
    field_off = map->record->timer_off;
    break;
  case BPF_TASK_WORK:
    field_off = map->record->task_work_off;
    break;
  case BPF_WORKQUEUE:
    field_off = map->record->wq_off;
    break;
  default:
    verifier_bug(env, "unsupported BTF field type: %s\n", struct_name);
    return -EINVAL;
  }
  if (field_off != val + reg->off) {
    verbose(env, "off %lld doesn't point to 'struct %s' that is at %d\n",
            val + reg->off, struct_name, field_off);
    return -EINVAL;
  }
  if (map_desc->ptr) {
    verifier_bug(env, "Two map pointers in a %s helper", struct_name);
    return -EFAULT;
  }
  map_desc->uid = reg->map_uid;
  map_desc->ptr = map;
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_map_func_compatibility(struct bpf_verifier_env *env,
                                        struct bpf_map *map, int func_id) {
  if (!map)
    return 0;

  /* We need a two way check, first is from map perspective ... */
  switch (map->map_type) {
  case BPF_MAP_TYPE_PROG_ARRAY:
    if (func_id != BPF_FUNC_tail_call)
      goto error;
    break;
  case BPF_MAP_TYPE_PERF_EVENT_ARRAY:
    if (func_id != BPF_FUNC_perf_event_read &&
        func_id != BPF_FUNC_perf_event_output &&
        func_id != BPF_FUNC_skb_output &&
        func_id != BPF_FUNC_perf_event_read_value &&
        func_id != BPF_FUNC_xdp_output)
      goto error;
    break;
  case BPF_MAP_TYPE_RINGBUF:
    if (func_id != BPF_FUNC_ringbuf_output &&
        func_id != BPF_FUNC_ringbuf_reserve &&
        func_id != BPF_FUNC_ringbuf_query &&
        func_id != BPF_FUNC_ringbuf_reserve_dynptr &&
        func_id != BPF_FUNC_ringbuf_submit_dynptr &&
        func_id != BPF_FUNC_ringbuf_discard_dynptr)
      goto error;
    break;
  case BPF_MAP_TYPE_USER_RINGBUF:
    if (func_id != BPF_FUNC_user_ringbuf_drain)
      goto error;
    break;
  case BPF_MAP_TYPE_STACK_TRACE:
    if (func_id != BPF_FUNC_get_stackid)
      goto error;
    break;
  case BPF_MAP_TYPE_CGROUP_ARRAY:
    if (func_id != BPF_FUNC_skb_under_cgroup &&
        func_id != BPF_FUNC_current_task_under_cgroup)
      goto error;
    break;
  case BPF_MAP_TYPE_CGROUP_STORAGE:
  case BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
    if (func_id != BPF_FUNC_get_local_storage)
      goto error;
    break;
  case BPF_MAP_TYPE_DEVMAP:
  case BPF_MAP_TYPE_DEVMAP_HASH:
    if (func_id != BPF_FUNC_redirect_map && func_id != BPF_FUNC_map_lookup_elem)
      goto error;
    break;
  /* Restrict bpf side of cpumap and xskmap, open when use-cases
   * appear.
   */
  case BPF_MAP_TYPE_CPUMAP:
    if (func_id != BPF_FUNC_redirect_map)
      goto error;
    break;
  case BPF_MAP_TYPE_XSKMAP:
    if (func_id != BPF_FUNC_redirect_map && func_id != BPF_FUNC_map_lookup_elem)
      goto error;
    break;
  case BPF_MAP_TYPE_ARRAY_OF_MAPS:
  case BPF_MAP_TYPE_HASH_OF_MAPS:
    if (func_id != BPF_FUNC_map_lookup_elem)
      goto error;
    break;
  case BPF_MAP_TYPE_SOCKMAP:
    if (func_id != BPF_FUNC_sk_redirect_map &&
        func_id != BPF_FUNC_sock_map_update &&
        func_id != BPF_FUNC_msg_redirect_map &&
        func_id != BPF_FUNC_sk_select_reuseport &&
        func_id != BPF_FUNC_map_lookup_elem &&
        !may_update_sockmap(env, func_id))
      goto error;
    break;
  case BPF_MAP_TYPE_SOCKHASH:
    if (func_id != BPF_FUNC_sk_redirect_hash &&
        func_id != BPF_FUNC_sock_hash_update &&
        func_id != BPF_FUNC_msg_redirect_hash &&
        func_id != BPF_FUNC_sk_select_reuseport &&
        func_id != BPF_FUNC_map_lookup_elem &&
        !may_update_sockmap(env, func_id))
      goto error;
    break;
  case BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:
    if (func_id != BPF_FUNC_sk_select_reuseport)
      goto error;
    break;
  case BPF_MAP_TYPE_QUEUE:
  case BPF_MAP_TYPE_STACK:
    if (func_id != BPF_FUNC_map_peek_elem && func_id != BPF_FUNC_map_pop_elem &&
        func_id != BPF_FUNC_map_push_elem)
      goto error;
    break;
  case BPF_MAP_TYPE_SK_STORAGE:
    if (func_id != BPF_FUNC_sk_storage_get &&
        func_id != BPF_FUNC_sk_storage_delete && func_id != BPF_FUNC_kptr_xchg)
      goto error;
    break;
  case BPF_MAP_TYPE_INODE_STORAGE:
    if (func_id != BPF_FUNC_inode_storage_get &&
        func_id != BPF_FUNC_inode_storage_delete &&
        func_id != BPF_FUNC_kptr_xchg)
      goto error;
    break;
  case BPF_MAP_TYPE_TASK_STORAGE:
    if (func_id != BPF_FUNC_task_storage_get &&
        func_id != BPF_FUNC_task_storage_delete &&
        func_id != BPF_FUNC_kptr_xchg)
      goto error;
    break;
  case BPF_MAP_TYPE_CGRP_STORAGE:
    if (func_id != BPF_FUNC_cgrp_storage_get &&
        func_id != BPF_FUNC_cgrp_storage_delete &&
        func_id != BPF_FUNC_kptr_xchg)
      goto error;
    break;
  case BPF_MAP_TYPE_BLOOM_FILTER:
    if (func_id != BPF_FUNC_map_peek_elem && func_id != BPF_FUNC_map_push_elem)
      goto error;
    break;
  case BPF_MAP_TYPE_INSN_ARRAY:
    goto error;
  default:
    break;
  }

  /* ... and second from the function itself. */
  switch (func_id) {
  case BPF_FUNC_tail_call:
    if (map->map_type != BPF_MAP_TYPE_PROG_ARRAY)
      goto error;
    if (env->subprog_cnt > 1 && !allow_tail_call_in_subprogs(env)) {
      verbose(env,
              "mixing of tail_calls and bpf-to-bpf calls is not supported\n");
      return -EINVAL;
    }
    break;
  case BPF_FUNC_perf_event_read:
  case BPF_FUNC_perf_event_output:
  case BPF_FUNC_perf_event_read_value:
  case BPF_FUNC_skb_output:
  case BPF_FUNC_xdp_output:
    if (map->map_type != BPF_MAP_TYPE_PERF_EVENT_ARRAY)
      goto error;
    break;
  case BPF_FUNC_ringbuf_output:
  case BPF_FUNC_ringbuf_reserve:
  case BPF_FUNC_ringbuf_query:
  case BPF_FUNC_ringbuf_reserve_dynptr:
  case BPF_FUNC_ringbuf_submit_dynptr:
  case BPF_FUNC_ringbuf_discard_dynptr:
    if (map->map_type != BPF_MAP_TYPE_RINGBUF)
      goto error;
    break;
  case BPF_FUNC_user_ringbuf_drain:
    if (map->map_type != BPF_MAP_TYPE_USER_RINGBUF)
      goto error;
    break;
  case BPF_FUNC_get_stackid:
    if (map->map_type != BPF_MAP_TYPE_STACK_TRACE)
      goto error;
    break;
  case BPF_FUNC_current_task_under_cgroup:
  case BPF_FUNC_skb_under_cgroup:
    if (map->map_type != BPF_MAP_TYPE_CGROUP_ARRAY)
      goto error;
    break;
  case BPF_FUNC_redirect_map:
    if (map->map_type != BPF_MAP_TYPE_DEVMAP &&
        map->map_type != BPF_MAP_TYPE_DEVMAP_HASH &&
        map->map_type != BPF_MAP_TYPE_CPUMAP &&
        map->map_type != BPF_MAP_TYPE_XSKMAP)
      goto error;
    break;
  case BPF_FUNC_sk_redirect_map:
  case BPF_FUNC_msg_redirect_map:
  case BPF_FUNC_sock_map_update:
    if (map->map_type != BPF_MAP_TYPE_SOCKMAP)
      goto error;
    break;
  case BPF_FUNC_sk_redirect_hash:
  case BPF_FUNC_msg_redirect_hash:
  case BPF_FUNC_sock_hash_update:
    if (map->map_type != BPF_MAP_TYPE_SOCKHASH)
      goto error;
    break;
  case BPF_FUNC_get_local_storage:
    if (map->map_type != BPF_MAP_TYPE_CGROUP_STORAGE &&
        map->map_type != BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE)
      goto error;
    break;
  case BPF_FUNC_sk_select_reuseport:
    if (map->map_type != BPF_MAP_TYPE_REUSEPORT_SOCKARRAY &&
        map->map_type != BPF_MAP_TYPE_SOCKMAP &&
        map->map_type != BPF_MAP_TYPE_SOCKHASH)
      goto error;
    break;
  case BPF_FUNC_map_pop_elem:
    if (map->map_type != BPF_MAP_TYPE_QUEUE &&
        map->map_type != BPF_MAP_TYPE_STACK)
      goto error;
    break;
  case BPF_FUNC_map_peek_elem:
  case BPF_FUNC_map_push_elem:
    if (map->map_type != BPF_MAP_TYPE_QUEUE &&
        map->map_type != BPF_MAP_TYPE_STACK &&
        map->map_type != BPF_MAP_TYPE_BLOOM_FILTER)
      goto error;
    break;
  case BPF_FUNC_map_lookup_percpu_elem:
    if (map->map_type != BPF_MAP_TYPE_PERCPU_ARRAY &&
        map->map_type != BPF_MAP_TYPE_PERCPU_HASH &&
        map->map_type != BPF_MAP_TYPE_LRU_PERCPU_HASH)
      goto error;
    break;
  case BPF_FUNC_sk_storage_get:
  case BPF_FUNC_sk_storage_delete:
    if (map->map_type != BPF_MAP_TYPE_SK_STORAGE)
      goto error;
    break;
  case BPF_FUNC_inode_storage_get:
  case BPF_FUNC_inode_storage_delete:
    if (map->map_type != BPF_MAP_TYPE_INODE_STORAGE)
      goto error;
    break;
  case BPF_FUNC_task_storage_get:
  case BPF_FUNC_task_storage_delete:
    if (map->map_type != BPF_MAP_TYPE_TASK_STORAGE)
      goto error;
    break;
  case BPF_FUNC_cgrp_storage_get:
  case BPF_FUNC_cgrp_storage_delete:
    if (map->map_type != BPF_MAP_TYPE_CGRP_STORAGE)
      goto error;
    break;
  default:
    break;
  }

  return 0;
error:
  verbose(env, "cannot pass map_type %d into func %s#%d\n", map->map_type,
          func_id_name(func_id), func_id);
  return -EINVAL;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_map_kptr_access(struct bpf_verifier_env *env, u32 regno,
                                 int value_regno, int insn_idx,
                                 struct btf_field *kptr_field) {
  struct bpf_insn *insn = &env->prog->insnsi[insn_idx];
  int class = BPF_CLASS(insn->code);
  struct bpf_reg_state *val_reg;
  int ret;

  /* Things we already checked for in check_map_access and caller:
   *  - Reject cases where variable offset may touch kptr
   *  - size of access (must be BPF_DW)
   *  - tnum_is_const(reg->var_off)
   *  - kptr_field->offset == off + reg->var_off.value
   */
  /* Only BPF_[LDX,STX,ST] | BPF_MEM | BPF_DW is supported */
  if (BPF_MODE(insn->code) != BPF_MEM) {
    verbose(
        env,
        "kptr in map can only be accessed using BPF_MEM instruction mode\n");
    return -EACCES;
  }

  /* We only allow loading referenced kptr, since it will be marked as
   * untrusted, similar to unreferenced kptr.
   */
  if (class != BPF_LDX && (kptr_field->type == BPF_KPTR_REF ||
                           kptr_field->type == BPF_KPTR_PERCPU)) {
    verbose(env, "store to referenced kptr disallowed\n");
    return -EACCES;
  }
  if (class != BPF_LDX && kptr_field->type == BPF_UPTR) {
    verbose(env, "store to uptr disallowed\n");
    return -EACCES;
  }

  if (class == BPF_LDX) {
    if (kptr_field->type == BPF_UPTR)
      return mark_uptr_ld_reg(env, value_regno, kptr_field);

    /* We can simply mark the value_regno receiving the pointer
     * value from map as PTR_TO_BTF_ID, with the correct type.
     */
    ret = mark_btf_ld_reg(env, cur_regs(env), value_regno, PTR_TO_BTF_ID,
                          kptr_field->kptr.btf, kptr_field->kptr.btf_id,
                          btf_ld_kptr_type(env, kptr_field));
    if (ret < 0)
      return ret;
  } else if (class == BPF_STX) {
    val_reg = reg_state(env, value_regno);
    if (!register_is_null(val_reg) &&
        map_kptr_match_type(env, kptr_field, val_reg, value_regno))
      return -EACCES;
  } else if (class == BPF_ST) {
    if (insn->imm) {
      verbose(env, "BPF_ST imm must be 0 when storing to kptr at off=%u\n",
              kptr_field->offset);
      return -EACCES;
    }
  } else {
    verbose(env,
            "kptr in map can only be accessed using BPF_LDX/BPF_STX/BPF_ST\n");
    return -EACCES;
  }
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_map_prog_compatibility(struct bpf_verifier_env *env,
                                        struct bpf_map *map,
                                        struct bpf_prog *prog)

{
  enum bpf_prog_type prog_type = resolve_prog_type(prog);

  if (map->excl_prog_sha &&
      memcmp(map->excl_prog_sha, prog->digest, SHA256_DIGEST_SIZE)) {
    verbose(env, "program's hash doesn't match map's excl_prog_hash\n");
    return -EACCES;
  }

  if (btf_record_has_field(map->record, BPF_LIST_HEAD) ||
      btf_record_has_field(map->record, BPF_RB_ROOT)) {
    if (is_tracing_prog_type(prog_type)) {
      verbose(env, "tracing progs cannot use bpf_{list_head,rb_root} yet\n");
      return -EINVAL;
    }
  }

  if (btf_record_has_field(map->record, BPF_SPIN_LOCK | BPF_RES_SPIN_LOCK)) {
    if (prog_type == BPF_PROG_TYPE_SOCKET_FILTER) {
      verbose(env, "socket filter progs cannot use bpf_spin_lock yet\n");
      return -EINVAL;
    }

    if (is_tracing_prog_type(prog_type)) {
      verbose(env, "tracing progs cannot use bpf_spin_lock yet\n");
      return -EINVAL;
    }
  }

  if ((bpf_prog_is_offloaded(prog->aux) || bpf_map_is_offloaded(map)) &&
      !bpf_offload_prog_map_match(prog, map)) {
    verbose(env, "offload device mismatch between prog and map\n");
    return -EINVAL;
  }

  if (map->map_type == BPF_MAP_TYPE_STRUCT_OPS) {
    verbose(env, "bpf_struct_ops map cannot be used in prog\n");
    return -EINVAL;
  }

  if (prog->sleepable)
    switch (map->map_type) {
    case BPF_MAP_TYPE_HASH:
    case BPF_MAP_TYPE_LRU_HASH:
    case BPF_MAP_TYPE_ARRAY:
    case BPF_MAP_TYPE_PERCPU_HASH:
    case BPF_MAP_TYPE_PERCPU_ARRAY:
    case BPF_MAP_TYPE_LRU_PERCPU_HASH:
    case BPF_MAP_TYPE_ARRAY_OF_MAPS:
    case BPF_MAP_TYPE_HASH_OF_MAPS:
    case BPF_MAP_TYPE_RINGBUF:
    case BPF_MAP_TYPE_USER_RINGBUF:
    case BPF_MAP_TYPE_INODE_STORAGE:
    case BPF_MAP_TYPE_SK_STORAGE:
    case BPF_MAP_TYPE_TASK_STORAGE:
    case BPF_MAP_TYPE_CGRP_STORAGE:
    case BPF_MAP_TYPE_QUEUE:
    case BPF_MAP_TYPE_STACK:
    case BPF_MAP_TYPE_ARENA:
    case BPF_MAP_TYPE_INSN_ARRAY:
    case BPF_MAP_TYPE_PROG_ARRAY:
      break;
    default:
      verbose(env, "Sleepable programs can only use array, hash, ringbuf and "
                   "local storage maps\n");
      return -EINVAL;
    }

  if (bpf_map_is_cgroup_storage(map) &&
      bpf_cgroup_storage_assign(env->prog->aux, map)) {
    verbose(env, "only one cgroup storage of each type is allowed\n");
    return -EBUSY;
  }

  if (map->map_type == BPF_MAP_TYPE_ARENA) {
    if (env->prog->aux->arena) {
      verbose(env, "Only one arena per program\n");
      return -EBUSY;
    }
    if (!env->allow_ptr_leaks || !env->bpf_capable) {
      verbose(env, "CAP_BPF and CAP_PERFMON are required to use arena\n");
      return -EPERM;
    }
    if (!env->prog->jit_requested) {
      verbose(env, "JIT is required to use arena\n");
      return -EOPNOTSUPP;
    }
    if (!bpf_jit_supports_arena()) {
      verbose(env, "JIT doesn't support arena\n");
      return -EOPNOTSUPP;
    }
    env->prog->aux->arena = (void *)map;
    if (!bpf_arena_get_user_vm_start(env->prog->aux->arena)) {
      verbose(env,
              "arena's user address must be set via map_extra or mmap()\n");
      return -EINVAL;
    }
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_max_stack_depth(struct bpf_verifier_env *env) {
  enum priv_stack_mode priv_stack_mode = PRIV_STACK_UNKNOWN;
  struct bpf_subprog_info *si = env->subprog_info;
  bool priv_stack_supported;
  int ret;

  for (int i = 0; i < env->subprog_cnt; i++) {
    if (si[i].has_tail_call) {
      priv_stack_mode = NO_PRIV_STACK;
      break;
    }
  }

  if (priv_stack_mode == PRIV_STACK_UNKNOWN)
    priv_stack_mode = bpf_enable_priv_stack(env->prog);

  /* All async_cb subprogs use normal kernel stack. If a particular
   * subprog appears in both main prog and async_cb subtree, that
   * subprog will use normal kernel stack to avoid potential nesting.
   * The reverse subprog traversal ensures when main prog subtree is
   * checked, the subprogs appearing in async_cb subtrees are already
   * marked as using normal kernel stack, so stack size checking can
   * be done properly.
   */
  for (int i = env->subprog_cnt - 1; i >= 0; i--) {
    if (!i || si[i].is_async_cb) {
      priv_stack_supported = !i && priv_stack_mode == PRIV_STACK_ADAPTIVE;
      ret = check_max_stack_depth_subprog(env, i, priv_stack_supported);
      if (ret < 0)
        return ret;
    }
  }

  for (int i = 0; i < env->subprog_cnt; i++) {
    if (si[i].priv_stack_mode == PRIV_STACK_ADAPTIVE) {
      env->prog->aux->jits_use_priv_stack = true;
      break;
    }
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_max_stack_depth_subprog(struct bpf_verifier_env *env, int idx,
                                         bool priv_stack_supported) {
  struct bpf_subprog_info *subprog = env->subprog_info;
  struct bpf_insn *insn = env->prog->insnsi;
  int depth = 0, frame = 0, i, subprog_end, subprog_depth;
  bool tail_call_reachable = false;
  int ret_insn[MAX_CALL_FRAMES];
  int ret_prog[MAX_CALL_FRAMES];
  int j;

  i = subprog[idx].start;
  if (!priv_stack_supported)
    subprog[idx].priv_stack_mode = NO_PRIV_STACK;
process_func:
  /* protect against potential stack overflow that might happen when
   * bpf2bpf calls get combined with tailcalls. Limit the caller's stack
   * depth for such case down to 256 so that the worst case scenario
   * would result in 8k stack size (32 which is tailcall limit * 256 =
   * 8k).
   *
   * To get the idea what might happen, see an example:
   * func1 -> sub rsp, 128
   *  subfunc1 -> sub rsp, 256
   *  tailcall1 -> add rsp, 256
   *   func2 -> sub rsp, 192 (total stack size = 128 + 192 = 320)
   *   subfunc2 -> sub rsp, 64
   *   subfunc22 -> sub rsp, 128
   *   tailcall2 -> add rsp, 128
   *    func3 -> sub rsp, 32 (total stack size 128 + 192 + 64 + 32 = 416)
   *
   * tailcall will unwind the current stack frame but it will not get rid
   * of caller's stack as shown on the example above.
   */
  if (idx && subprog[idx].has_tail_call && depth >= 256) {
    verbose(env,
            "tail_calls are not allowed when call stack of previous frames is "
            "%d bytes. Too large\n",
            depth);
    return -EACCES;
  }

  subprog_depth = round_up_stack_depth(env, subprog[idx].stack_depth);
  if (priv_stack_supported) {
    /* Request private stack support only if the subprog stack
     * depth is no less than BPF_PRIV_STACK_MIN_SIZE. This is to
     * avoid jit penalty if the stack usage is small.
     */
    if (subprog[idx].priv_stack_mode == PRIV_STACK_UNKNOWN &&
        subprog_depth >= BPF_PRIV_STACK_MIN_SIZE)
      subprog[idx].priv_stack_mode = PRIV_STACK_ADAPTIVE;
  }

  if (subprog[idx].priv_stack_mode == PRIV_STACK_ADAPTIVE) {
    if (subprog_depth > MAX_BPF_STACK) {
      verbose(env, "stack size of subprog %d is %d. Too large\n", idx,
              subprog_depth);
      return -EACCES;
    }
  } else {
    depth += subprog_depth;
    if (depth > MAX_BPF_STACK) {
      verbose(env, "combined stack size of %d calls is %d. Too large\n",
              frame + 1, depth);
      return -EACCES;
    }
  }
continue_func:
  subprog_end = subprog[idx + 1].start;
  for (; i < subprog_end; i++) {
    int next_insn, sidx;

    if (bpf_pseudo_kfunc_call(insn + i) && !insn[i].off) {
      bool err = false;

      if (!is_bpf_throw_kfunc(insn + i))
        continue;
      if (subprog[idx].is_cb)
        err = true;
      for (int c = 0; c < frame && !err; c++) {
        if (subprog[ret_prog[c]].is_cb) {
          err = true;
          break;
        }
      }
      if (!err)
        continue;
      verbose(env,
              "bpf_throw kfunc (insn %d) cannot be called from callback "
              "subprog %d\n",
              i, idx);
      return -EINVAL;
    }

    if (!bpf_pseudo_call(insn + i) && !bpf_pseudo_func(insn + i))
      continue;
    /* remember insn and function to return to */
    ret_insn[frame] = i + 1;
    ret_prog[frame] = idx;

    /* find the callee */
    next_insn = i + insn[i].imm + 1;
    sidx = find_subprog(env, next_insn);
    if (verifier_bug_if(sidx < 0, env, "callee not found at insn %d",
                        next_insn))
      return -EFAULT;
    if (subprog[sidx].is_async_cb) {
      if (subprog[sidx].has_tail_call) {
        verifier_bug(env, "subprog has tail_call and async cb");
        return -EFAULT;
      }
      /* async callbacks don't increase bpf prog stack size unless called
       * directly */
      if (!bpf_pseudo_call(insn + i))
        continue;
      if (subprog[sidx].is_exception_cb) {
        verbose(env, "insn %d cannot call exception cb directly", i);
        return -EINVAL;
      }
    }
    i = next_insn;
    idx = sidx;
    if (!priv_stack_supported)
      subprog[idx].priv_stack_mode = NO_PRIV_STACK;

    if (subprog[idx].has_tail_call)
      tail_call_reachable = true;

    frame++;
    if (frame >= MAX_CALL_FRAMES) {
      verbose(env, "the call stack of %d frames is too deep !\n", frame);
      return -E2BIG;
    }
    goto process_func;
  }
  /* if tail call got detected across bpf2bpf calls then mark each of the
   * currently present subprog frames as tail call reachable subprogs;
   * this info will be utilized by JIT so that we will be preserving the
   * tail call counter throughout bpf2bpf calls combined with tailcalls
   */
  if (tail_call_reachable)
    for (j = 0; j < frame; j++) {
      if (subprog[ret_prog[j]].is_exception_cb) {
        verbose(env, "cannot tail call within exception cb\n");
        return -EINVAL;
      }
      subprog[ret_prog[j]].tail_call_reachable = true;
    }
  if (subprog[0].tail_call_reachable)
    env->prog->aux->tail_call_reachable = true;

  /* end of for() loop means the last insn of the 'subprog'
   * was reached. Doesn't matter whether it was JA or EXIT
   */
  if (frame == 0)
    return 0;
  if (subprog[idx].priv_stack_mode != PRIV_STACK_ADAPTIVE)
    depth -= round_up_stack_depth(env, subprog[idx].stack_depth);
  frame--;
  i = ret_insn[frame];
  idx = ret_prog[frame];
  goto continue_func;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_mem_access(struct bpf_verifier_env *env, int insn_idx,
                            u32 regno, int off, int bpf_size,
                            enum bpf_access_type t, int value_regno,
                            bool strict_alignment_once, bool is_ldsx) {
  struct bpf_reg_state *regs = cur_regs(env);
  struct bpf_reg_state *reg = regs + regno;
  int size, err = 0;

  size = bpf_size_to_bytes(bpf_size);
  if (size < 0)
    return size;

  /* alignment checks will add in reg->off themselves */
  err = check_ptr_alignment(env, reg, off, size, strict_alignment_once);
  if (err)
    return err;

  /* for access checks, reg->off is just part of off */
  off += reg->off;

  if (reg->type == PTR_TO_MAP_KEY) {
    if (t == BPF_WRITE) {
      verbose(env, "write to change key R%d not allowed\n", regno);
      return -EACCES;
    }

    err = check_mem_region_access(env, regno, off, size, reg->map_ptr->key_size,
                                  false);
    if (err)
      return err;
    if (value_regno >= 0)
      mark_reg_unknown(env, regs, value_regno);
  } else if (reg->type == PTR_TO_MAP_VALUE) {
    struct btf_field *kptr_field = NULL;

    if (t == BPF_WRITE && value_regno >= 0 &&
        is_pointer_value(env, value_regno)) {
      verbose(env, "R%d leaks addr into map\n", value_regno);
      return -EACCES;
    }
    err = check_map_access_type(env, regno, off, size, t);
    if (err)
      return err;
    err = check_map_access(env, regno, off, size, false, ACCESS_DIRECT);
    if (err)
      return err;
    if (tnum_is_const(reg->var_off))
      kptr_field = btf_record_find(
          reg->map_ptr->record, off + reg->var_off.value, BPF_KPTR | BPF_UPTR);
    if (kptr_field) {
      err =
          check_map_kptr_access(env, regno, value_regno, insn_idx, kptr_field);
    } else if (t == BPF_READ && value_regno >= 0) {
      struct bpf_map *map = reg->map_ptr;

      /*
       * If map is read-only, track its contents as scalars,
       * unless it is an insn array (see the special case below)
       */
      if (tnum_is_const(reg->var_off) && bpf_map_is_rdonly(map) &&
          map->ops->map_direct_value_addr &&
          map->map_type != BPF_MAP_TYPE_INSN_ARRAY) {
        int map_off = off + reg->var_off.value;
        u64 val = 0;

        err = bpf_map_direct_read(map, map_off, size, &val, is_ldsx);
        if (err)
          return err;

        regs[value_regno].type = SCALAR_VALUE;
        inner_mark_reg_known(&regs[value_regno], val);
      } else if (map->map_type == BPF_MAP_TYPE_INSN_ARRAY) {
        if (bpf_size != BPF_DW) {
          verbose(env, "Invalid read of %d bytes from insn_array\n", size);
          return -EACCES;
        }
        copy_register_state(&regs[value_regno], reg);
        regs[value_regno].type = PTR_TO_INSN;
      } else {
        mark_reg_unknown(env, regs, value_regno);
      }
    }
  } else if (base_type(reg->type) == PTR_TO_MEM) {
    bool rdonly_mem = type_is_rdonly_mem(reg->type);
    bool rdonly_untrusted = rdonly_mem && (reg->type & PTR_UNTRUSTED);

    if (type_may_be_null(reg->type)) {
      verbose(env, "R%d invalid mem access '%s'\n", regno,
              reg_type_str(env, reg->type));
      return -EACCES;
    }

    if (t == BPF_WRITE && rdonly_mem) {
      verbose(env, "R%d cannot write into %s\n", regno,
              reg_type_str(env, reg->type));
      return -EACCES;
    }

    if (t == BPF_WRITE && value_regno >= 0 &&
        is_pointer_value(env, value_regno)) {
      verbose(env, "R%d leaks addr into mem\n", value_regno);
      return -EACCES;
    }

    /*
     * Accesses to untrusted PTR_TO_MEM are done through probe
     * instructions, hence no need to check bounds in that case.
     */
    if (!rdonly_untrusted)
      err =
          check_mem_region_access(env, regno, off, size, reg->mem_size, false);
    if (!err && value_regno >= 0 && (t == BPF_READ || rdonly_mem))
      mark_reg_unknown(env, regs, value_regno);
  } else if (reg->type == PTR_TO_CTX) {
    struct bpf_retval_range range;
    struct bpf_insn_access_aux info = {
        .reg_type = SCALAR_VALUE,
        .is_ldsx = is_ldsx,
        .log = &env->log,
    };

    if (t == BPF_WRITE && value_regno >= 0 &&
        is_pointer_value(env, value_regno)) {
      verbose(env, "R%d leaks addr into ctx\n", value_regno);
      return -EACCES;
    }

    err = check_ptr_off_reg(env, reg, regno);
    if (err < 0)
      return err;

    err = check_ctx_access(env, insn_idx, off, size, t, &info);
    if (err)
      verbose_linfo(env, insn_idx, "; ");
    if (!err && t == BPF_READ && value_regno >= 0) {
      /* ctx access returns either a scalar, or a
       * PTR_TO_PACKET[_META,_END]. In the latter
       * case, we know the offset is zero.
       */
      if (info.reg_type == SCALAR_VALUE) {
        if (info.is_retval && get_func_retval_range(env->prog, &range)) {
          err = inner_mark_reg_s32_range(env, regs, value_regno, range.minval,
                                         range.maxval);
          if (err)
            return err;
        } else {
          mark_reg_unknown(env, regs, value_regno);
        }
      } else {
        mark_reg_known_zero(env, regs, value_regno);
        if (type_may_be_null(info.reg_type))
          regs[value_regno].id = ++env->id_gen;
        /* A load of ctx field could have different
         * actual load size with the one encoded in the
         * insn. When the dst is PTR, it is for sure not
         * a sub-register.
         */
        regs[value_regno].subreg_def = DEF_NOT_SUBREG;
        if (base_type(info.reg_type) == PTR_TO_BTF_ID) {
          regs[value_regno].btf = info.btf;
          regs[value_regno].btf_id = info.btf_id;
          regs[value_regno].ref_obj_id = info.ref_obj_id;
        }
      }
      regs[value_regno].type = info.reg_type;
    }

  } else if (reg->type == PTR_TO_STACK) {
    /* Basic bounds checks. */
    err = check_stack_access_within_bounds(env, regno, off, size, t);
    if (err)
      return err;

    if (t == BPF_READ)
      err = check_stack_read(env, regno, off, size, value_regno);
    else
      err = check_stack_write(env, regno, off, size, value_regno, insn_idx);
  } else if (reg_is_pkt_pointer(reg)) {
    if (t == BPF_WRITE && !may_access_direct_pkt_data(env, NULL, t)) {
      verbose(env, "cannot write into packet\n");
      return -EACCES;
    }
    if (t == BPF_WRITE && value_regno >= 0 &&
        is_pointer_value(env, value_regno)) {
      verbose(env, "R%d leaks addr into packet\n", value_regno);
      return -EACCES;
    }
    err = check_packet_access(env, regno, off, size, false);
    if (!err && t == BPF_READ && value_regno >= 0)
      mark_reg_unknown(env, regs, value_regno);
  } else if (reg->type == PTR_TO_FLOW_KEYS) {
    if (t == BPF_WRITE && value_regno >= 0 &&
        is_pointer_value(env, value_regno)) {
      verbose(env, "R%d leaks addr into flow keys\n", value_regno);
      return -EACCES;
    }

    err = check_flow_keys_access(env, off, size);
    if (!err && t == BPF_READ && value_regno >= 0)
      mark_reg_unknown(env, regs, value_regno);
  } else if (type_is_sk_pointer(reg->type)) {
    if (t == BPF_WRITE) {
      verbose(env, "R%d cannot write into %s\n", regno,
              reg_type_str(env, reg->type));
      return -EACCES;
    }
    err = check_sock_access(env, insn_idx, regno, off, size, t);
    if (!err && value_regno >= 0)
      mark_reg_unknown(env, regs, value_regno);
  } else if (reg->type == PTR_TO_TP_BUFFER) {
    err = check_tp_buffer_access(env, reg, regno, off, size);
    if (!err && t == BPF_READ && value_regno >= 0)
      mark_reg_unknown(env, regs, value_regno);
  } else if (base_type(reg->type) == PTR_TO_BTF_ID &&
             !type_may_be_null(reg->type)) {
    err = check_ptr_to_btf_access(env, regs, regno, off, size, t, value_regno);
  } else if (reg->type == CONST_PTR_TO_MAP) {
    err = check_ptr_to_map_access(env, regs, regno, off, size, t, value_regno);
  } else if (base_type(reg->type) == PTR_TO_BUF &&
             !type_may_be_null(reg->type)) {
    bool rdonly_mem = type_is_rdonly_mem(reg->type);
    u32 *max_access;

    if (rdonly_mem) {
      if (t == BPF_WRITE) {
        verbose(env, "R%d cannot write into %s\n", regno,
                reg_type_str(env, reg->type));
        return -EACCES;
      }
      max_access = &env->prog->aux->max_rdonly_access;
    } else {
      max_access = &env->prog->aux->max_rdwr_access;
    }

    err = check_buffer_access(env, reg, regno, off, size, false, max_access);

    if (!err && value_regno >= 0 && (rdonly_mem || t == BPF_READ))
      mark_reg_unknown(env, regs, value_regno);
  } else if (reg->type == PTR_TO_ARENA) {
    if (t == BPF_READ && value_regno >= 0)
      mark_reg_unknown(env, regs, value_regno);
  } else {
    verbose(env, "R%d invalid mem access '%s'\n", regno,
            reg_type_str(env, reg->type));
    return -EACCES;
  }

  if (!err && size < BPF_REG_SIZE && value_regno >= 0 && t == BPF_READ &&
      regs[value_regno].type == SCALAR_VALUE) {
    if (!is_ldsx)
      /* b/h/w load zero-extends, mark upper bits as known 0 */
      coerce_reg_to_size(&regs[value_regno], size);
    else
      coerce_reg_to_size_sx(&regs[value_regno], size);
  }
  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_mem_arg_rw_flag_ok(const struct bpf_func_proto *fn) {
  int i;

  for (i = 0; i < ARRAY_SIZE(fn->arg_type); i++) {
    enum bpf_arg_type arg_type = fn->arg_type[i];

    if (base_type(arg_type) != ARG_PTR_TO_MEM)
      continue;
    if (!(arg_type & (MEM_WRITE | MEM_RDONLY)))
      return false;
  }

  return true;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_mem_reg(struct bpf_verifier_env *env,
                         struct bpf_reg_state *reg, u32 regno, u32 mem_size) {
  bool may_be_null = type_may_be_null(reg->type);
  struct bpf_reg_state saved_reg;
  int err;

  if (register_is_null(reg))
    return 0;

  /* Assuming that the register contains a value check if the memory
   * access is safe. Temporarily save and restore the register's state as
   * the conversion shouldn't be visible to a caller.
   */
  if (may_be_null) {
    saved_reg = *reg;
    mark_ptr_not_null_reg(reg);
  }

  err = check_helper_mem_access(env, regno, mem_size, BPF_READ, true, NULL);
  err = err
            ?: check_helper_mem_access(env, regno, mem_size, BPF_WRITE, true,
                                       NULL);

  if (may_be_null)
    *reg = saved_reg;

  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_mem_region_access(struct bpf_verifier_env *env, u32 regno,
                                   int off, int size, u32 mem_size,
                                   bool zero_size_allowed) {
  struct bpf_verifier_state *vstate = env->cur_state;
  struct bpf_func_state *state = vstate->frame[vstate->curframe];
  struct bpf_reg_state *reg = &state->regs[regno];
  int err;

  /* We may have adjusted the register pointing to memory region, so we
   * need to try adding each of min_value and max_value to off
   * to make sure our theoretical access will be safe.
   *
   * The minimum value is only important with signed
   * comparisons where we can't assume the floor of a
   * value is 0.  If we are using signed variables for our
   * index'es we need to make sure that whatever we use
   * will have a set floor within our range.
   */
  if (reg->smin_value < 0 &&
      (reg->smin_value == S64_MIN ||
       (off + reg->smin_value != (s64)(s32)(off + reg->smin_value)) ||
       reg->smin_value + off < 0)) {
    verbose(env,
            "R%d min value is negative, either use unsigned index or do a if "
            "(index >=0) check.\n",
            regno);
    return -EACCES;
  }
  err = inner_check_mem_access(env, regno, reg->smin_value + off, size,
                               mem_size, zero_size_allowed);
  if (err) {
    verbose(env, "R%d min value is outside of the allowed memory range\n",
            regno);
    return err;
  }

  /* If we haven't set a max value then we need to bail since we can't be
   * sure we won't do bad things.
   * If reg->umax_value + off could overflow, treat that as unbounded too.
   */
  if (reg->umax_value >= BPF_MAX_VAR_OFF) {
    verbose(env,
            "R%d unbounded memory access, make sure to bounds check any such "
            "access\n",
            regno);
    return -EACCES;
  }
  err = inner_check_mem_access(env, regno, reg->umax_value + off, size,
                               mem_size, zero_size_allowed);
  if (err) {
    verbose(env, "R%d max value is outside of the allowed memory range\n",
            regno);
    return err;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_mem_size_reg(struct bpf_verifier_env *env,
                              struct bpf_reg_state *reg, u32 regno,
                              enum bpf_access_type access_type,
                              bool zero_size_allowed,
                              struct bpf_call_arg_meta *meta) {
  int err;

  /* This is used to refine r0 return value bounds for helpers
   * that enforce this value as an upper bound on return values.
   * See do_refine_retval_range() for helpers that can refine
   * the return value. C type of helper is u32 so we pull register
   * bound from umax_value however, if negative verifier errors
   * out. Only upper bounds can be learned because retval is an
   * int type and negative retvals are allowed.
   */
  meta->msize_max_value = reg->umax_value;

  /* The register is SCALAR_VALUE; the access check happens using
   * its boundaries. For unprivileged variable accesses, disable
   * raw mode so that the program is required to initialize all
   * the memory that the helper could just partially fill up.
   */
  if (!tnum_is_const(reg->var_off))
    meta = NULL;

  if (reg->smin_value < 0) {
    verbose(
        env,
        "R%d min value is negative, either use unsigned or 'var &= const'\n",
        regno);
    return -EACCES;
  }

  if (reg->umin_value == 0 && !zero_size_allowed) {
    verbose(env, "R%d invalid zero-sized read: u64=[%lld,%lld]\n", regno,
            reg->umin_value, reg->umax_value);
    return -EACCES;
  }

  if (reg->umax_value >= BPF_MAX_VAR_SIZ) {
    verbose(env,
            "R%d unbounded memory access, use 'var &= const' or 'if (var < "
            "const)'\n",
            regno);
    return -EACCES;
  }
  err = check_helper_mem_access(env, regno - 1, reg->umax_value, access_type,
                                zero_size_allowed, meta);
  if (!err)
    err = mark_chain_precision(env, regno);
  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_packet_access(struct bpf_verifier_env *env, u32 regno, int off,
                               int size, bool zero_size_allowed) {
  struct bpf_reg_state *reg = reg_state(env, regno);
  int err;

  /* We may have added a variable offset to the packet pointer; but any
   * reg->range we have comes after that.  We are only checking the fixed
   * offset.
   */

  /* We don't allow negative numbers, because we aren't tracking enough
   * detail to prove they're safe.
   */
  if (reg->smin_value < 0) {
    verbose(env,
            "R%d min value is negative, either use unsigned index or do a if "
            "(index >=0) check.\n",
            regno);
    return -EACCES;
  }

  err = reg->range < 0 ? -EINVAL
                       : inner_check_mem_access(env, regno, off, size,
                                                reg->range, zero_size_allowed);
  if (err) {
    verbose(env, "R%d offset is outside of the packet\n", regno);
    return err;
  }

  /* inner_check_mem_access has made sure "off + size - 1" is within u16.
   * reg->umax_value can't be bigger than MAX_PACKET_OFF which is 0xffff,
   * otherwise find_good_pkt_pointers would have refused to set range info
   * that inner_check_mem_access would have rejected this pkt access.
   * Therefore, "off + reg->umax_value + size - 1" won't overflow u32.
   */
  env->prog->aux->max_pkt_offset = max_t(u32, env->prog->aux->max_pkt_offset,
                                         off + reg->umax_value + size - 1);

  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_pkt_ptr_alignment(struct bpf_verifier_env *env,
                                   const struct bpf_reg_state *reg, int off,
                                   int size, bool strict) {
  struct tnum reg_off;
  int ip_align;

  /* Byte size accesses are always allowed. */
  if (!strict || size == 1)
    return 0;

  /* For platforms that do not have a Kconfig enabling
   * CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS the value of
   * NET_IP_ALIGN is universally set to '2'.  And on platforms
   * that do set CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS, we get
   * to this code only in strict mode where we want to emulate
   * the NET_IP_ALIGN==2 checking.  Therefore use an
   * unconditional IP align value of '2'.
   */
  ip_align = 2;

  reg_off = tnum_add(reg->var_off, tnum_const(ip_align + reg->off + off));
  if (!tnum_is_aligned(reg_off, size)) {
    char tn_buf[48];

    tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
    verbose(env, "misaligned packet access off %d+%s+%d+%d size %d\n", ip_align,
            tn_buf, reg->off, off, size);
    return -EACCES;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_pseudo_btf_id(struct bpf_verifier_env *env,
                               struct bpf_insn *insn,
                               struct bpf_insn_aux_data *aux) {
  struct btf *btf;
  int btf_fd;
  int err;

  btf_fd = insn[1].imm;
  if (btf_fd) {
    btf = btf_get_by_fd(btf_fd);
    if (IS_ERR(btf)) {
      verbose(env, "invalid module BTF object FD specified.\n");
      return -EINVAL;
    }
  } else {
    if (!btf_vmlinux) {
      verbose(env, "kernel is missing BTF, make sure CONFIG_DEBUG_INFO_BTF=y "
                   "is specified in Kconfig.\n");
      return -EINVAL;
    }
    btf_get(btf_vmlinux);
    btf = btf_vmlinux;
  }

  err = inner_check_pseudo_btf_id(env, insn, aux, btf);
  if (err) {
    btf_put(btf);
    return err;
  }

  return inner_add_used_btf(env, btf);
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_ptr_alignment(struct bpf_verifier_env *env,
                               const struct bpf_reg_state *reg, int off,
                               int size, bool strict_alignment_once) {
  bool strict = env->strict_alignment || strict_alignment_once;
  const char *pointer_desc = "";

  switch (reg->type) {
  case PTR_TO_PACKET:
  case PTR_TO_PACKET_META:
    /* Special case, because of NET_IP_ALIGN. Given metadata sits
     * right in front, treat it the very same way.
     */
    return check_pkt_ptr_alignment(env, reg, off, size, strict);
  case PTR_TO_FLOW_KEYS:
    pointer_desc = "flow keys ";
    break;
  case PTR_TO_MAP_KEY:
    pointer_desc = "key ";
    break;
  case PTR_TO_MAP_VALUE:
    pointer_desc = "value ";
    if (reg->map_ptr->map_type == BPF_MAP_TYPE_INSN_ARRAY)
      strict = true;
    break;
  case PTR_TO_CTX:
    pointer_desc = "context ";
    break;
  case PTR_TO_STACK:
    pointer_desc = "stack ";
    /* The stack spill tracking logic in check_stack_write_fixed_off()
     * and check_stack_read_fixed_off() relies on stack accesses being
     * aligned.
     */
    strict = true;
    break;
  case PTR_TO_SOCKET:
    pointer_desc = "sock ";
    break;
  case PTR_TO_SOCK_COMMON:
    pointer_desc = "sock_common ";
    break;
  case PTR_TO_TCP_SOCK:
    pointer_desc = "tcp_sock ";
    break;
  case PTR_TO_XDP_SOCK:
    pointer_desc = "xdp_sock ";
    break;
  case PTR_TO_ARENA:
    return 0;
  default:
    break;
  }
  return check_generic_ptr_alignment(env, reg, pointer_desc, off, size, strict);
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_ptr_off_reg(struct bpf_verifier_env *env,
                             const struct bpf_reg_state *reg, int regno) {
  return inner_check_ptr_off_reg(env, reg, regno, false);
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_ptr_to_btf_access(struct bpf_verifier_env *env,
                                   struct bpf_reg_state *regs, int regno,
                                   int off, int size,
                                   enum bpf_access_type atype,
                                   int value_regno) {
  struct bpf_reg_state *reg = regs + regno;
  const struct btf_type *t = btf_type_by_id(reg->btf, reg->btf_id);
  const char *tname = btf_name_by_offset(reg->btf, t->name_off);
  const char *field_name = NULL;
  enum bpf_type_flag flag = 0;
  u32 btf_id = 0;
  int ret;

  if (!env->allow_ptr_leaks) {
    verbose(
        env,
        "'struct %s' access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN\n",
        tname);
    return -EPERM;
  }
  if (!env->prog->gpl_compatible && btf_is_kernel(reg->btf)) {
    verbose(
        env,
        "Cannot access kernel 'struct %s' from non-GPL compatible program\n",
        tname);
    return -EINVAL;
  }
  if (off < 0) {
    verbose(env, "R%d is ptr_%s invalid negative access: off=%d\n", regno,
            tname, off);
    return -EACCES;
  }
  if (!tnum_is_const(reg->var_off) || reg->var_off.value) {
    char tn_buf[48];

    tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
    verbose(env, "R%d is ptr_%s invalid variable offset: off=%d, var_off=%s\n",
            regno, tname, off, tn_buf);
    return -EACCES;
  }

  if (reg->type & MEM_USER) {
    verbose(env, "R%d is ptr_%s access user memory: off=%d\n", regno, tname,
            off);
    return -EACCES;
  }

  if (reg->type & MEM_PERCPU) {
    verbose(env, "R%d is ptr_%s access percpu memory: off=%d\n", regno, tname,
            off);
    return -EACCES;
  }

  if (env->ops->btf_struct_access && !type_is_alloc(reg->type) &&
      atype == BPF_WRITE) {
    if (!btf_is_kernel(reg->btf)) {
      verifier_bug(env, "reg->btf must be kernel btf");
      return -EFAULT;
    }
    ret = env->ops->btf_struct_access(&env->log, reg, off, size);
  } else {
    /* Writes are permitted with default btf_struct_access for
     * program allocated objects (which always have ref_obj_id > 0),
     * but not for untrusted PTR_TO_BTF_ID | MEM_ALLOC.
     */
    if (atype != BPF_READ && !type_is_ptr_alloc_obj(reg->type)) {
      verbose(env, "only read is supported\n");
      return -EACCES;
    }

    if (type_is_alloc(reg->type) && !type_is_non_owning_ref(reg->type) &&
        !(reg->type & MEM_RCU) && !reg->ref_obj_id) {
      verifier_bug(env, "ref_obj_id for allocated object must be non-zero");
      return -EFAULT;
    }

    ret = btf_struct_access(&env->log, reg, off, size, atype, &btf_id, &flag,
                            &field_name);
  }

  if (ret < 0)
    return ret;

  if (ret != PTR_TO_BTF_ID) {
    /* just mark; */

  } else if (type_flag(reg->type) & PTR_UNTRUSTED) {
    /* If this is an untrusted pointer, all pointers formed by walking it
     * also inherit the untrusted flag.
     */
    flag = PTR_UNTRUSTED;

  } else if (is_trusted_reg(reg) || is_rcu_reg(reg)) {
    /* By default any pointer obtained from walking a trusted pointer is no
     * longer trusted, unless the field being accessed has explicitly been
     * marked as inheriting its parent's state of trust (either full or RCU).
     * For example:
     * 'cgroups' pointer is untrusted if task->cgroups dereference
     * happened in a sleepable program outside of bpf_rcu_read_lock()
     * section. In a non-sleepable program it's trusted while in RCU CS (aka
     * MEM_RCU). Note bpf_rcu_read_unlock() converts MEM_RCU pointers to
     * PTR_UNTRUSTED.
     *
     * A regular RCU-protected pointer with __rcu tag can also be deemed
     * trusted if we are in an RCU CS. Such pointer can be NULL.
     */
    if (type_is_trusted(env, reg, field_name, btf_id)) {
      flag |= PTR_TRUSTED;
    } else if (type_is_trusted_or_null(env, reg, field_name, btf_id)) {
      flag |= PTR_TRUSTED | PTR_MAYBE_NULL;
    } else if (in_rcu_cs(env) && !type_may_be_null(reg->type)) {
      if (type_is_rcu(env, reg, field_name, btf_id)) {
        /* ignore __rcu tag and mark it MEM_RCU */
        flag |= MEM_RCU;
      } else if (flag & MEM_RCU ||
                 type_is_rcu_or_null(env, reg, field_name, btf_id)) {
        /* __rcu tagged pointers can be NULL */
        flag |= MEM_RCU | PTR_MAYBE_NULL;

        /* We always trust them */
        if (type_is_rcu_or_null(env, reg, field_name, btf_id) &&
            flag & PTR_UNTRUSTED)
          flag &= ~PTR_UNTRUSTED;
      } else if (flag & (MEM_PERCPU | MEM_USER)) {
        /* keep as-is */
      } else {
        /* walking unknown pointers yields old deprecated PTR_TO_BTF_ID */
        clear_trusted_flags(&flag);
      }
    } else {
      /*
       * If not in RCU CS or MEM_RCU pointer can be NULL then
       * aggressively mark as untrusted otherwise such
       * pointers will be plain PTR_TO_BTF_ID without flags
       * and will be allowed to be passed into helpers for
       * compat reasons.
       */
      flag = PTR_UNTRUSTED;
    }
  } else {
    /* Old compat. Deprecated */
    clear_trusted_flags(&flag);
  }

  if (atype == BPF_READ && value_regno >= 0) {
    ret = mark_btf_ld_reg(env, regs, value_regno, ret, reg->btf, btf_id, flag);
    if (ret < 0)
      return ret;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_ptr_to_map_access(struct bpf_verifier_env *env,
                                   struct bpf_reg_state *regs, int regno,
                                   int off, int size,
                                   enum bpf_access_type atype,
                                   int value_regno) {
  struct bpf_reg_state *reg = regs + regno;
  struct bpf_map *map = reg->map_ptr;
  struct bpf_reg_state map_reg;
  enum bpf_type_flag flag = 0;
  const struct btf_type *t;
  const char *tname;
  u32 btf_id;
  int ret;

  if (!btf_vmlinux) {
    verbose(env,
            "map_ptr access not supported without CONFIG_DEBUG_INFO_BTF\n");
    return -ENOTSUPP;
  }

  if (!map->ops->map_btf_id || !*map->ops->map_btf_id) {
    verbose(env, "map_ptr access not supported for map type %d\n",
            map->map_type);
    return -ENOTSUPP;
  }

  t = btf_type_by_id(btf_vmlinux, *map->ops->map_btf_id);
  tname = btf_name_by_offset(btf_vmlinux, t->name_off);

  if (!env->allow_ptr_leaks) {
    verbose(
        env,
        "'struct %s' access is allowed only to CAP_PERFMON and CAP_SYS_ADMIN\n",
        tname);
    return -EPERM;
  }

  if (off < 0) {
    verbose(env, "R%d is %s invalid negative access: off=%d\n", regno, tname,
            off);
    return -EACCES;
  }

  if (atype != BPF_READ) {
    verbose(env, "only read from %s is supported\n", tname);
    return -EACCES;
  }

  /* Simulate access to a PTR_TO_BTF_ID */
  memset(&map_reg, 0, sizeof(map_reg));
  ret = mark_btf_ld_reg(env, &map_reg, 0, PTR_TO_BTF_ID, btf_vmlinux,
                        *map->ops->map_btf_id, 0);
  if (ret < 0)
    return ret;
  ret = btf_struct_access(&env->log, &map_reg, off, size, atype, &btf_id, &flag,
                          NULL);
  if (ret < 0)
    return ret;

  if (value_regno >= 0) {
    ret =
        mark_btf_ld_reg(env, regs, value_regno, ret, btf_vmlinux, btf_id, flag);
    if (ret < 0)
      return ret;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_raw_mode_ok(const struct bpf_func_proto *fn) {
  int count = 0;

  if (arg_type_is_raw_mem(fn->arg1_type))
    count++;
  if (arg_type_is_raw_mem(fn->arg2_type))
    count++;
  if (arg_type_is_raw_mem(fn->arg3_type))
    count++;
  if (arg_type_is_raw_mem(fn->arg4_type))
    count++;
  if (arg_type_is_raw_mem(fn->arg5_type))
    count++;

  /* We only support one arg being in raw mode at the moment,
   * which is sufficient for the helper functions we have
   * right now.
   */
  return count <= 1;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_reference_leak(struct bpf_verifier_env *env,
                                bool exception_exit) {
  struct bpf_verifier_state *state = env->cur_state;
  enum bpf_prog_type type = resolve_prog_type(env->prog);
  struct bpf_reg_state *reg = reg_state(env, BPF_REG_0);
  bool refs_lingering = false;
  int i;

  if (!exception_exit && cur_func(env)->frameno)
    return 0;

  for (i = 0; i < state->acquired_refs; i++) {
    if (state->refs[i].type != REF_TYPE_PTR)
      continue;
    /* Allow struct_ops programs to return a referenced kptr back to
     * kernel. Type checks are performed later in check_return_code.
     */
    if (type == BPF_PROG_TYPE_STRUCT_OPS && !exception_exit &&
        reg->ref_obj_id == state->refs[i].id)
      continue;
    verbose(env, "Unreleased reference id=%d alloc_insn=%d\n",
            state->refs[i].id, state->refs[i].insn_idx);
    refs_lingering = true;
  }
  return refs_lingering ? -EINVAL : 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_reg_allocation_locked(struct bpf_verifier_env *env,
                                       struct bpf_reg_state *reg) {
  struct bpf_reference_state *s;
  void *ptr;
  u32 id;

  switch ((int)reg->type) {
  case PTR_TO_MAP_VALUE:
    ptr = reg->map_ptr;
    break;
  case PTR_TO_BTF_ID | MEM_ALLOC:
    ptr = reg->btf;
    break;
  default:
    verifier_bug(env, "unknown reg type for lock check");
    return -EFAULT;
  }
  id = reg->id;

  if (!env->cur_state->active_locks)
    return -EINVAL;
  s = find_lock_state(env->cur_state, REF_TYPE_LOCK_MASK, id, ptr);
  if (!s) {
    verbose(env, "held lock and object are not in the same allocation\n");
    return -EINVAL;
  }
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_reg_arg(struct bpf_verifier_env *env, u32 regno,
                         enum reg_arg_type t) {
  struct bpf_verifier_state *vstate = env->cur_state;
  struct bpf_func_state *state = vstate->frame[vstate->curframe];

  return inner_check_reg_arg(env, state->regs, regno, t);
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_reg_const_str(struct bpf_verifier_env *env,
                               struct bpf_reg_state *reg, u32 regno) {
  struct bpf_map *map = reg->map_ptr;
  int err;
  int map_off;
  u64 map_addr;
  char *str_ptr;

  if (reg->type != PTR_TO_MAP_VALUE)
    return -EINVAL;

  if (map->map_type == BPF_MAP_TYPE_INSN_ARRAY) {
    verbose(
        env,
        "R%d points to insn_array map which cannot be used as const string\n",
        regno);
    return -EACCES;
  }

  if (!bpf_map_is_rdonly(map)) {
    verbose(env, "R%d does not point to a readonly map'\n", regno);
    return -EACCES;
  }

  if (!tnum_is_const(reg->var_off)) {
    verbose(env, "R%d is not a constant address'\n", regno);
    return -EACCES;
  }

  if (!map->ops->map_direct_value_addr) {
    verbose(env, "no direct value access support for this map type\n");
    return -EACCES;
  }

  err = check_map_access(env, regno, reg->off, map->value_size - reg->off,
                         false, ACCESS_HELPER);
  if (err)
    return err;

  map_off = reg->off + reg->var_off.value;
  err = map->ops->map_direct_value_addr(map, &map_addr, map_off);
  if (err) {
    verbose(env, "direct value access on string failed\n");
    return err;
  }

  str_ptr = (char *)(long)(map_addr);
  if (!strnchr(str_ptr + map_off, map->value_size - map_off, 0)) {
    verbose(env, "string is not zero-terminated\n");
    return -EINVAL;
  }
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_reg_sane_offset(struct bpf_verifier_env *env,
                                  const struct bpf_reg_state *reg,
                                  enum bpf_reg_type type) {
  bool known = tnum_is_const(reg->var_off);
  s64 val = reg->var_off.value;
  s64 smin = reg->smin_value;

  if (known && (val >= BPF_MAX_VAR_OFF || val <= -BPF_MAX_VAR_OFF)) {
    verbose(env, "math between %s pointer and %lld is not allowed\n",
            reg_type_str(env, type), val);
    return false;
  }

  if (reg->off >= BPF_MAX_VAR_OFF || reg->off <= -BPF_MAX_VAR_OFF) {
    verbose(env, "%s pointer offset %d is not allowed\n",
            reg_type_str(env, type), reg->off);
    return false;
  }

  if (smin == S64_MIN) {
    verbose(env,
            "math between %s pointer and register with unbounded min value is "
            "not allowed\n",
            reg_type_str(env, type));
    return false;
  }

  if (smin >= BPF_MAX_VAR_OFF || smin <= -BPF_MAX_VAR_OFF) {
    verbose(env, "value %lld makes %s pointer be out of bounds\n", smin,
            reg_type_str(env, type));
    return false;
  }

  return true;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_reg_type(struct bpf_verifier_env *env, u32 regno,
                          enum bpf_arg_type arg_type, const u32 *arg_btf_id,
                          struct bpf_call_arg_meta *meta) {
  struct bpf_reg_state *reg = reg_state(env, regno);
  enum bpf_reg_type expected, type = reg->type;
  const struct bpf_reg_types *compatible;
  int i, j;

  compatible = compatible_reg_types[base_type(arg_type)];
  if (!compatible) {
    verifier_bug(env, "unsupported arg type %d", arg_type);
    return -EFAULT;
  }

  /* ARG_PTR_TO_MEM + RDONLY is compatible with PTR_TO_MEM and PTR_TO_MEM +
   * RDONLY, but ARG_PTR_TO_MEM is compatible only with PTR_TO_MEM and NOT with
   * PTR_TO_MEM + RDONLY
   *
   * Same for MAYBE_NULL:
   *
   * ARG_PTR_TO_MEM + MAYBE_NULL is compatible with PTR_TO_MEM and PTR_TO_MEM +
   * MAYBE_NULL, but ARG_PTR_TO_MEM is compatible only with PTR_TO_MEM but NOT
   * with PTR_TO_MEM + MAYBE_NULL
   *
   * ARG_PTR_TO_MEM is compatible with PTR_TO_MEM that is tagged with a dynptr
   * type.
   *
   * Therefore we fold these flags depending on the arg_type before comparison.
   */
  if (arg_type & MEM_RDONLY)
    type &= ~MEM_RDONLY;
  if (arg_type & PTR_MAYBE_NULL)
    type &= ~PTR_MAYBE_NULL;
  if (base_type(arg_type) == ARG_PTR_TO_MEM)
    type &= ~DYNPTR_TYPE_FLAG_MASK;

  /* Local kptr types are allowed as the source argument of bpf_kptr_xchg */
  if (meta->func_id == BPF_FUNC_kptr_xchg && type_is_alloc(type) &&
      regno == BPF_REG_2) {
    type &= ~MEM_ALLOC;
    type &= ~MEM_PERCPU;
  }

  for (i = 0; i < ARRAY_SIZE(compatible->types); i++) {
    expected = compatible->types[i];
    if (expected == NOT_INIT)
      break;

    if (type == expected)
      goto found;
  }

  verbose(env, "R%d type=%s expected=", regno, reg_type_str(env, reg->type));
  for (j = 0; j + 1 < i; j++)
    verbose(env, "%s, ", reg_type_str(env, compatible->types[j]));
  verbose(env, "%s\n", reg_type_str(env, compatible->types[j]));
  return -EACCES;

found:
  if (base_type(reg->type) != PTR_TO_BTF_ID)
    return 0;

  if (compatible == &mem_types) {
    if (!(arg_type & MEM_RDONLY)) {
      verbose(env, "%s() may write into memory pointed by R%d type=%s\n",
              func_id_name(meta->func_id), regno, reg_type_str(env, reg->type));
      return -EACCES;
    }
    return 0;
  }

  switch ((int)reg->type) {
  case PTR_TO_BTF_ID:
  case PTR_TO_BTF_ID | PTR_TRUSTED:
  case PTR_TO_BTF_ID | PTR_TRUSTED | PTR_MAYBE_NULL:
  case PTR_TO_BTF_ID | MEM_RCU:
  case PTR_TO_BTF_ID | PTR_MAYBE_NULL:
  case PTR_TO_BTF_ID | PTR_MAYBE_NULL | MEM_RCU: {
    /* For bpf_sk_release, it needs to match against first member
     * 'struct sock_common', hence make an exception for it. This
     * allows bpf_sk_release to work for multiple socket types.
     */
    bool strict_type_match =
        arg_type_is_release(arg_type) && meta->func_id != BPF_FUNC_sk_release;

    if (type_may_be_null(reg->type) &&
        (!type_may_be_null(arg_type) || arg_type_is_release(arg_type))) {
      verbose(env, "Possibly NULL pointer passed to helper arg%d\n", regno);
      return -EACCES;
    }

    if (!arg_btf_id) {
      if (!compatible->btf_id) {
        verifier_bug(env, "missing arg compatible BTF ID");
        return -EFAULT;
      }
      arg_btf_id = compatible->btf_id;
    }

    if (meta->func_id == BPF_FUNC_kptr_xchg) {
      if (map_kptr_match_type(env, meta->kptr_field, reg, regno))
        return -EACCES;
    } else {
      if (arg_btf_id == BPF_PTR_POISON) {
        verbose(env, "verifier internal error:");
        verbose(env, "R%d has non-overwritten BPF_PTR_POISON type\n", regno);
        return -EACCES;
      }

      if (!btf_struct_ids_match(&env->log, reg->btf, reg->btf_id, reg->off,
                                btf_vmlinux, *arg_btf_id, strict_type_match)) {
        verbose(env, "R%d is of type %s but %s is expected\n", regno,
                btf_type_name(reg->btf, reg->btf_id),
                btf_type_name(btf_vmlinux, *arg_btf_id));
        return -EACCES;
      }
    }
    break;
  }
  case PTR_TO_BTF_ID | MEM_ALLOC:
  case PTR_TO_BTF_ID | MEM_PERCPU | MEM_ALLOC:
    if (meta->func_id != BPF_FUNC_spin_lock &&
        meta->func_id != BPF_FUNC_spin_unlock &&
        meta->func_id != BPF_FUNC_kptr_xchg) {
      verifier_bug(env, "unimplemented handling of MEM_ALLOC");
      return -EFAULT;
    }
    /* Check if local kptr in src arg matches kptr in dst arg */
    if (meta->func_id == BPF_FUNC_kptr_xchg && regno == BPF_REG_2) {
      if (map_kptr_match_type(env, meta->kptr_field, reg, regno))
        return -EACCES;
    }
    break;
  case PTR_TO_BTF_ID | MEM_PERCPU:
  case PTR_TO_BTF_ID | MEM_PERCPU | MEM_RCU:
  case PTR_TO_BTF_ID | MEM_PERCPU | PTR_TRUSTED:
    /* Handled by helper specific checks */
    break;
  default:
    verifier_bug(env, "invalid PTR_TO_BTF_ID register for type match");
    return -EFAULT;
  }
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_resource_leak(struct bpf_verifier_env *env,
                               bool exception_exit, bool check_lock,
                               const char *prefix) {
  int err;

  if (check_lock && env->cur_state->active_locks) {
    verbose(env, "%s cannot be used inside bpf_spin_lock-ed region\n", prefix);
    return -EINVAL;
  }

  err = check_reference_leak(env, exception_exit);
  if (err) {
    verbose(env, "%s would lead to reference leak\n", prefix);
    return err;
  }

  if (check_lock && env->cur_state->active_irq_id) {
    verbose(env, "%s cannot be used inside bpf_local_irq_save-ed region\n",
            prefix);
    return -EINVAL;
  }

  if (check_lock && env->cur_state->active_rcu_locks) {
    verbose(env, "%s cannot be used inside bpf_rcu_read_lock-ed region\n",
            prefix);
    return -EINVAL;
  }

  if (check_lock && env->cur_state->active_preempt_locks) {
    verbose(env, "%s cannot be used inside bpf_preempt_disable-ed region\n",
            prefix);
    return -EINVAL;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_return_code(struct bpf_verifier_env *env, int regno,
                             const char *reg_name) {
  const char *exit_ctx = "At program exit";
  struct tnum enforce_attach_type_range = tnum_unknown;
  const struct bpf_prog *prog = env->prog;
  struct bpf_reg_state *reg = reg_state(env, regno);
  struct bpf_retval_range range = retval_range(0, 1);
  enum bpf_prog_type prog_type = resolve_prog_type(env->prog);
  int err;
  struct bpf_func_state *frame = env->cur_state->frame[0];
  const bool is_subprog = frame->subprogno;
  bool return_32bit = false;
  const struct btf_type *reg_type, *ret_type = NULL;

  /* LSM and struct_ops func-ptr's return type could be "void" */
  if (!is_subprog || frame->in_exception_callback_fn) {
    switch (prog_type) {
    case BPF_PROG_TYPE_LSM:
      if (prog->expected_attach_type == BPF_LSM_CGROUP)
        /* See below, can be 0 or 0-1 depending on hook. */
        break;
      if (!prog->aux->attach_func_proto->type)
        return 0;
      break;
    case BPF_PROG_TYPE_STRUCT_OPS:
      if (!prog->aux->attach_func_proto->type)
        return 0;

      if (frame->in_exception_callback_fn)
        break;

      /* Allow a struct_ops program to return a referenced kptr if it
       * matches the operator's return type and is in its unmodified
       * form. A scalar zero (i.e., a null pointer) is also allowed.
       */
      reg_type = reg->btf ? btf_type_by_id(reg->btf, reg->btf_id) : NULL;
      ret_type = btf_type_resolve_ptr(prog->aux->attach_btf,
                                      prog->aux->attach_func_proto->type, NULL);
      if (ret_type && ret_type == reg_type && reg->ref_obj_id)
        return inner_check_ptr_off_reg(env, reg, regno, false);
      break;
    default:
      break;
    }
  }

  /* eBPF calling convention is such that R0 is used
   * to return the value from eBPF program.
   * Make sure that it's readable at this time
   * of bpf_exit, which means that program wrote
   * something into it earlier
   */
  err = check_reg_arg(env, regno, SRC_OP);
  if (err)
    return err;

  if (is_pointer_value(env, regno)) {
    verbose(env, "R%d leaks addr as return value\n", regno);
    return -EACCES;
  }

  if (frame->in_async_callback_fn) {
    exit_ctx = "At async callback return";
    range = frame->callback_ret_range;
    goto enforce_retval;
  }

  if (is_subprog && !frame->in_exception_callback_fn) {
    if (reg->type != SCALAR_VALUE) {
      verbose(
          env,
          "At subprogram exit the register R%d is not a scalar value (%s)\n",
          regno, reg_type_str(env, reg->type));
      return -EINVAL;
    }
    return 0;
  }

  switch (prog_type) {
  case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
    if (env->prog->expected_attach_type == BPF_CGROUP_UDP4_RECVMSG ||
        env->prog->expected_attach_type == BPF_CGROUP_UDP6_RECVMSG ||
        env->prog->expected_attach_type == BPF_CGROUP_UNIX_RECVMSG ||
        env->prog->expected_attach_type == BPF_CGROUP_INET4_GETPEERNAME ||
        env->prog->expected_attach_type == BPF_CGROUP_INET6_GETPEERNAME ||
        env->prog->expected_attach_type == BPF_CGROUP_UNIX_GETPEERNAME ||
        env->prog->expected_attach_type == BPF_CGROUP_INET4_GETSOCKNAME ||
        env->prog->expected_attach_type == BPF_CGROUP_INET6_GETSOCKNAME ||
        env->prog->expected_attach_type == BPF_CGROUP_UNIX_GETSOCKNAME)
      range = retval_range(1, 1);
    if (env->prog->expected_attach_type == BPF_CGROUP_INET4_BIND ||
        env->prog->expected_attach_type == BPF_CGROUP_INET6_BIND)
      range = retval_range(0, 3);
    break;
  case BPF_PROG_TYPE_CGROUP_SKB:
    if (env->prog->expected_attach_type == BPF_CGROUP_INET_EGRESS) {
      range = retval_range(0, 3);
      enforce_attach_type_range = tnum_range(2, 3);
    }
    break;
  case BPF_PROG_TYPE_CGROUP_SOCK:
  case BPF_PROG_TYPE_SOCK_OPS:
  case BPF_PROG_TYPE_CGROUP_DEVICE:
  case BPF_PROG_TYPE_CGROUP_SYSCTL:
  case BPF_PROG_TYPE_CGROUP_SOCKOPT:
    break;
  case BPF_PROG_TYPE_RAW_TRACEPOINT:
    if (!env->prog->aux->attach_btf_id)
      return 0;
    range = retval_range(0, 0);
    break;
  case BPF_PROG_TYPE_TRACING:
    switch (env->prog->expected_attach_type) {
    case BPF_TRACE_FENTRY:
    case BPF_TRACE_FEXIT:
    case BPF_TRACE_FSESSION:
      range = retval_range(0, 0);
      break;
    case BPF_TRACE_RAW_TP:
    case BPF_MODIFY_RETURN:
      return 0;
    case BPF_TRACE_ITER:
      break;
    default:
      return -ENOTSUPP;
    }
    break;
  case BPF_PROG_TYPE_KPROBE:
    switch (env->prog->expected_attach_type) {
    case BPF_TRACE_KPROBE_SESSION:
    case BPF_TRACE_UPROBE_SESSION:
      range = retval_range(0, 1);
      break;
    default:
      return 0;
    }
    break;
  case BPF_PROG_TYPE_SK_LOOKUP:
    range = retval_range(SK_DROP, SK_PASS);
    break;

  case BPF_PROG_TYPE_LSM:
    if (env->prog->expected_attach_type != BPF_LSM_CGROUP) {
      /* no range found, any return value is allowed */
      if (!get_func_retval_range(env->prog, &range))
        return 0;
      /* no restricted range, any return value is allowed */
      if (range.minval == S32_MIN && range.maxval == S32_MAX)
        return 0;
      return_32bit = true;
    } else if (!env->prog->aux->attach_func_proto->type) {
      /* Make sure programs that attach to void
       * hooks don't try to modify return value.
       */
      range = retval_range(1, 1);
    }
    break;

  case BPF_PROG_TYPE_NETFILTER:
    range = retval_range(NF_DROP, NF_ACCEPT);
    break;
  case BPF_PROG_TYPE_STRUCT_OPS:
    if (!ret_type)
      return 0;
    range = retval_range(0, 0);
    break;
  case BPF_PROG_TYPE_EXT:
    /* freplace program can return anything as its return value
     * depends on the to-be-replaced kernel func or bpf program.
     */
  default:
    return 0;
  }

enforce_retval:
  if (reg->type != SCALAR_VALUE) {
    verbose(env, "%s the register R%d is not a known value (%s)\n", exit_ctx,
            regno, reg_type_str(env, reg->type));
    return -EINVAL;
  }

  err = mark_chain_precision(env, regno);
  if (err)
    return err;

  if (!retval_range_within(range, reg, return_32bit)) {
    verbose_invalid_scalar(env, reg, range, exit_ctx, reg_name);
    if (!is_subprog && prog->expected_attach_type == BPF_LSM_CGROUP &&
        prog_type == BPF_PROG_TYPE_LSM && !prog->aux->attach_func_proto->type)
      verbose(env, "Note, BPF_LSM_CGROUP that attach to void LSM hooks can't "
                   "modify return value!\n");
    return -EINVAL;
  }

  if (!tnum_is_unknown(enforce_attach_type_range) &&
      tnum_in(enforce_attach_type_range, reg->var_off))
    env->prog->enforce_expected_attach_type = 1;
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static bool check_scalar_ids(u32 old_id, u32 cur_id, struct bpf_idmap *idmap) {
  if (!old_id)
    return true;

  cur_id = cur_id ? cur_id : ++idmap->tmp_id_gen;

  return check_ids(old_id, cur_id, idmap);
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_sock_access(struct bpf_verifier_env *env, int insn_idx,
                             u32 regno, int off, int size,
                             enum bpf_access_type t) {
  struct bpf_reg_state *reg = reg_state(env, regno);
  struct bpf_insn_access_aux info = {};
  bool valid;

  if (reg->smin_value < 0) {
    verbose(env,
            "R%d min value is negative, either use unsigned index or do a if "
            "(index >=0) check.\n",
            regno);
    return -EACCES;
  }

  switch (reg->type) {
  case PTR_TO_SOCK_COMMON:
    valid = bpf_sock_common_is_valid_access(off, size, t, &info);
    break;
  case PTR_TO_SOCKET:
    valid = bpf_sock_is_valid_access(off, size, t, &info);
    break;
  case PTR_TO_TCP_SOCK:
    valid = bpf_tcp_sock_is_valid_access(off, size, t, &info);
    break;
  case PTR_TO_XDP_SOCK:
    valid = bpf_xdp_sock_is_valid_access(off, size, t, &info);
    break;
  default:
    valid = false;
  }

  if (valid) {
    env->insn_aux_data[insn_idx].ctx_field_size = info.ctx_field_size;
    return 0;
  }

  verbose(env, "R%d invalid %s access off=%d size=%d\n", regno,
          reg_type_str(env, reg->type), off, size);

  return -EACCES;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_special_kfunc(struct bpf_verifier_env *env,
                               struct bpf_kfunc_call_arg_meta *meta,
                               struct bpf_reg_state *regs,
                               struct bpf_insn_aux_data *insn_aux,
                               const struct btf_type *ptr_type,
                               struct btf *desc_btf) {
  const struct btf_type *ret_t;
  int err = 0;

  if (meta->btf != btf_vmlinux)
    return 0;

  if (meta->func_id == special_kfunc_list[KF_bpf_obj_new_impl] ||
      meta->func_id == special_kfunc_list[KF_bpf_percpu_obj_new_impl]) {
    struct btf_struct_meta *struct_meta;
    struct btf *ret_btf;
    u32 ret_btf_id;

    if (meta->func_id == special_kfunc_list[KF_bpf_obj_new_impl] &&
        !bpf_global_ma_set)
      return -ENOMEM;

    if (((u64)(u32)meta->arg_constant.value) != meta->arg_constant.value) {
      verbose(env, "local type ID argument must be in range [0, U32_MAX]\n");
      return -EINVAL;
    }

    ret_btf = env->prog->aux->btf;
    ret_btf_id = meta->arg_constant.value;

    /* This may be NULL due to user not supplying a BTF */
    if (!ret_btf) {
      verbose(env, "bpf_obj_new/bpf_percpu_obj_new requires prog BTF\n");
      return -EINVAL;
    }

    ret_t = btf_type_by_id(ret_btf, ret_btf_id);
    if (!ret_t || !__btf_type_is_struct(ret_t)) {
      verbose(env, "bpf_obj_new/bpf_percpu_obj_new type ID argument must be of "
                   "a struct\n");
      return -EINVAL;
    }

    if (meta->func_id == special_kfunc_list[KF_bpf_percpu_obj_new_impl]) {
      if (ret_t->size > BPF_GLOBAL_PERCPU_MA_MAX_SIZE) {
        verbose(env, "bpf_percpu_obj_new type size (%d) is greater than %d\n",
                ret_t->size, BPF_GLOBAL_PERCPU_MA_MAX_SIZE);
        return -EINVAL;
      }

      if (!bpf_global_percpu_ma_set) {
        mutex_lock(&bpf_percpu_ma_lock);
        if (!bpf_global_percpu_ma_set) {
          /* Charge memory allocated with bpf_global_percpu_ma to
           * root memcg. The obj_cgroup for root memcg is NULL.
           */
          err = bpf_mem_alloc_percpu_init(&bpf_global_percpu_ma, NULL);
          if (!err)
            bpf_global_percpu_ma_set = true;
        }
        mutex_unlock(&bpf_percpu_ma_lock);
        if (err)
          return err;
      }

      mutex_lock(&bpf_percpu_ma_lock);
      err = bpf_mem_alloc_percpu_unit_init(&bpf_global_percpu_ma, ret_t->size);
      mutex_unlock(&bpf_percpu_ma_lock);
      if (err)
        return err;
    }

    struct_meta = btf_find_struct_meta(ret_btf, ret_btf_id);
    if (meta->func_id == special_kfunc_list[KF_bpf_percpu_obj_new_impl]) {
      if (!inner_btf_type_is_scalar_struct(env, ret_btf, ret_t, 0)) {
        verbose(env, "bpf_percpu_obj_new type ID argument must be of a struct "
                     "of scalars\n");
        return -EINVAL;
      }

      if (struct_meta) {
        verbose(env, "bpf_percpu_obj_new type ID argument must not contain "
                     "special fields\n");
        return -EINVAL;
      }
    }

    mark_reg_known_zero(env, regs, BPF_REG_0);
    regs[BPF_REG_0].type = PTR_TO_BTF_ID | MEM_ALLOC;
    regs[BPF_REG_0].btf = ret_btf;
    regs[BPF_REG_0].btf_id = ret_btf_id;
    if (meta->func_id == special_kfunc_list[KF_bpf_percpu_obj_new_impl])
      regs[BPF_REG_0].type |= MEM_PERCPU;

    insn_aux->obj_new_size = ret_t->size;
    insn_aux->kptr_struct_meta = struct_meta;
  } else if (meta->func_id ==
             special_kfunc_list[KF_bpf_refcount_acquire_impl]) {
    mark_reg_known_zero(env, regs, BPF_REG_0);
    regs[BPF_REG_0].type = PTR_TO_BTF_ID | MEM_ALLOC;
    regs[BPF_REG_0].btf = meta->arg_btf;
    regs[BPF_REG_0].btf_id = meta->arg_btf_id;

    insn_aux->kptr_struct_meta =
        btf_find_struct_meta(meta->arg_btf, meta->arg_btf_id);
  } else if (is_list_node_type(ptr_type)) {
    struct btf_field *field = meta->arg_list_head.field;

    mark_reg_graph_node(regs, BPF_REG_0, &field->graph_root);
  } else if (is_rbtree_node_type(ptr_type)) {
    struct btf_field *field = meta->arg_rbtree_root.field;

    mark_reg_graph_node(regs, BPF_REG_0, &field->graph_root);
  } else if (meta->func_id == special_kfunc_list[KF_bpf_cast_to_kern_ctx]) {
    mark_reg_known_zero(env, regs, BPF_REG_0);
    regs[BPF_REG_0].type = PTR_TO_BTF_ID | PTR_TRUSTED;
    regs[BPF_REG_0].btf = desc_btf;
    regs[BPF_REG_0].btf_id = meta->ret_btf_id;
  } else if (meta->func_id == special_kfunc_list[KF_bpf_rdonly_cast]) {
    ret_t = btf_type_by_id(desc_btf, meta->arg_constant.value);
    if (!ret_t) {
      verbose(env, "Unknown type ID %lld passed to kfunc bpf_rdonly_cast\n",
              meta->arg_constant.value);
      return -EINVAL;
    } else if (btf_type_is_struct(ret_t)) {
      mark_reg_known_zero(env, regs, BPF_REG_0);
      regs[BPF_REG_0].type = PTR_TO_BTF_ID | PTR_UNTRUSTED;
      regs[BPF_REG_0].btf = desc_btf;
      regs[BPF_REG_0].btf_id = meta->arg_constant.value;
    } else if (btf_type_is_void(ret_t)) {
      mark_reg_known_zero(env, regs, BPF_REG_0);
      regs[BPF_REG_0].type = PTR_TO_MEM | MEM_RDONLY | PTR_UNTRUSTED;
      regs[BPF_REG_0].mem_size = 0;
    } else {
      verbose(env, "kfunc bpf_rdonly_cast type ID argument must be of a struct "
                   "or void\n");
      return -EINVAL;
    }
  } else if (meta->func_id == special_kfunc_list[KF_bpf_dynptr_slice] ||
             meta->func_id == special_kfunc_list[KF_bpf_dynptr_slice_rdwr]) {
    enum bpf_type_flag type_flag =
        get_dynptr_type_flag(meta->initialized_dynptr.type);

    mark_reg_known_zero(env, regs, BPF_REG_0);

    if (!meta->arg_constant.found) {
      verifier_bug(env, "bpf_dynptr_slice(_rdwr) no constant size");
      return -EFAULT;
    }

    regs[BPF_REG_0].mem_size = meta->arg_constant.value;

    /* PTR_MAYBE_NULL will be added when is_kfunc_ret_null is checked */
    regs[BPF_REG_0].type = PTR_TO_MEM | type_flag;

    if (meta->func_id == special_kfunc_list[KF_bpf_dynptr_slice]) {
      regs[BPF_REG_0].type |= MEM_RDONLY;
    } else {
      /* this will set env->seen_direct_write to true */
      if (!may_access_direct_pkt_data(env, NULL, BPF_WRITE)) {
        verbose(env, "the prog does not allow writes to packet data\n");
        return -EINVAL;
      }
    }

    if (!meta->initialized_dynptr.id) {
      verifier_bug(env, "no dynptr id");
      return -EFAULT;
    }
    regs[BPF_REG_0].dynptr_id = meta->initialized_dynptr.id;

    /* we don't need to set BPF_REG_0's ref obj id
     * because packet slices are not refcounted (see
     * dynptr_type_refcounted)
     */
  } else {
    return 0;
  }

  return 1;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int
check_stack_access_for_ptr_arithmetic(struct bpf_verifier_env *env, int regno,
                                      const struct bpf_reg_state *reg,
                                      int off) {
  if (!tnum_is_const(reg->var_off)) {
    char tn_buf[48];

    tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
    verbose(
        env,
        "R%d variable stack access prohibited for !root, var_off=%s off=%d\n",
        regno, tn_buf, off);
    return -EACCES;
  }

  if (off >= 0 || off < -MAX_BPF_STACK) {
    verbose(env,
            "R%d stack pointer arithmetic goes out of range, "
            "prohibited for !root; off=%d\n",
            regno, off);
    return -EACCES;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_stack_access_within_bounds(struct bpf_verifier_env *env,
                                            int regno, int off, int access_size,
                                            enum bpf_access_type type) {
  struct bpf_reg_state *reg = reg_state(env, regno);
  struct bpf_func_state *state = func(env, reg);
  s64 min_off, max_off;
  int err;
  char *err_extra;

  if (type == BPF_READ)
    err_extra = " read from";
  else
    err_extra = " write to";

  if (tnum_is_const(reg->var_off)) {
    min_off = (s64)reg->var_off.value + off;
    max_off = min_off + access_size;
  } else {
    if (reg->smax_value >= BPF_MAX_VAR_OFF ||
        reg->smin_value <= -BPF_MAX_VAR_OFF) {
      verbose(env, "invalid unbounded variable-offset%s stack R%d\n", err_extra,
              regno);
      return -EACCES;
    }
    min_off = reg->smin_value + off;
    max_off = reg->smax_value + off + access_size;
  }

  err = check_stack_slot_within_bounds(env, min_off, state, type);
  if (!err && max_off > 0)
    err = -EINVAL; /* out of stack access into non-negative offsets */
  if (!err && access_size < 0)
    /* access_size should not be negative (or overflow an int); others checks
     * along the way should have prevented such an access.
     */
    err = -EFAULT; /* invalid negative access size; integer overflow? */

  if (err) {
    if (tnum_is_const(reg->var_off)) {
      verbose(env, "invalid%s stack R%d off=%d size=%d\n", err_extra, regno,
              off, access_size);
    } else {
      char tn_buf[48];

      tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
      verbose(env,
              "invalid variable-offset%s stack R%d var_off=%s off=%d size=%d\n",
              err_extra, regno, tn_buf, off, access_size);
    }
    return err;
  }

  /* Note that there is no stack access with offset zero, so the needed stack
   * size is -min_off, not -min_off+1.
   */
  return grow_stack_state(env, state, -min_off /* size */);
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_stack_range_initialized(struct bpf_verifier_env *env,
                                         int regno, int off, int access_size,
                                         bool zero_size_allowed,
                                         enum bpf_access_type type,
                                         struct bpf_call_arg_meta *meta) {
  struct bpf_reg_state *reg = reg_state(env, regno);
  struct bpf_func_state *state = func(env, reg);
  int err, min_off, max_off, i, j, slot, spi;
  /* Some accesses can write anything into the stack, others are
   * read-only.
   */
  bool clobber = false;

  if (access_size == 0 && !zero_size_allowed) {
    verbose(env, "invalid zero-sized read\n");
    return -EACCES;
  }

  if (type == BPF_WRITE)
    clobber = true;

  err = check_stack_access_within_bounds(env, regno, off, access_size, type);
  if (err)
    return err;

  if (tnum_is_const(reg->var_off)) {
    min_off = max_off = reg->var_off.value + off;
  } else {
    /* Variable offset is prohibited for unprivileged mode for
     * simplicity since it requires corresponding support in
     * Spectre masking for stack ALU.
     * See also retrieve_ptr_limit().
     */
    if (!env->bypass_spec_v1) {
      char tn_buf[48];

      tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
      verbose(
          env,
          "R%d variable offset stack access prohibited for !root, var_off=%s\n",
          regno, tn_buf);
      return -EACCES;
    }
    /* Only initialized buffer on stack is allowed to be accessed
     * with variable offset. With uninitialized buffer it's hard to
     * guarantee that whole memory is marked as initialized on
     * helper return since specific bounds are unknown what may
     * cause uninitialized stack leaking.
     */
    if (meta && meta->raw_mode)
      meta = NULL;

    min_off = reg->smin_value + off;
    max_off = reg->smax_value + off;
  }

  if (meta && meta->raw_mode) {
    /* Ensure we won't be overwriting dynptrs when simulating byte
     * by byte access in check_helper_call using meta.access_size.
     * This would be a problem if we have a helper in the future
     * which takes:
     *
     *	helper(uninit_mem, len, dynptr)
     *
     * Now, uninint_mem may overlap with dynptr pointer. Hence, it
     * may end up writing to dynptr itself when touching memory from
     * arg 1. This can be relaxed on a case by case basis for known
     * safe cases, but reject due to the possibilitiy of aliasing by
     * default.
     */
    for (i = min_off; i < max_off + access_size; i++) {
      int stack_off = -i - 1;

      spi = inner_get_spi(i);
      /* raw_mode may write past allocated_stack */
      if (state->allocated_stack <= stack_off)
        continue;
      if (state->stack[spi].slot_type[stack_off % BPF_REG_SIZE] ==
          STACK_DYNPTR) {
        verbose(env, "potential write to dynptr at off=%d disallowed\n", i);
        return -EACCES;
      }
    }
    meta->access_size = access_size;
    meta->regno = regno;
    return 0;
  }

  for (i = min_off; i < max_off + access_size; i++) {
    u8 *stype;

    slot = -i - 1;
    spi = slot / BPF_REG_SIZE;
    if (state->allocated_stack <= slot) {
      verbose(env, "allocated_stack too small\n");
      return -EFAULT;
    }

    stype = &state->stack[spi].slot_type[slot % BPF_REG_SIZE];
    if (*stype == STACK_MISC)
      goto mark;
    if ((*stype == STACK_ZERO) ||
        (*stype == STACK_INVALID && env->allow_uninit_stack)) {
      if (clobber) {
        /* helper can write anything into the stack */
        *stype = STACK_MISC;
      }
      goto mark;
    }

    if (is_spilled_reg(&state->stack[spi]) &&
        (state->stack[spi].spilled_ptr.type == SCALAR_VALUE ||
         env->allow_ptr_leaks)) {
      if (clobber) {
        inner_mark_reg_unknown(env, &state->stack[spi].spilled_ptr);
        for (j = 0; j < BPF_REG_SIZE; j++)
          scrub_spilled_slot(&state->stack[spi].slot_type[j]);
      }
      goto mark;
    }

    if (tnum_is_const(reg->var_off)) {
      verbose(env, "invalid read from stack R%d off %d+%d size %d\n", regno,
              min_off, i - min_off, access_size);
    } else {
      char tn_buf[48];

      tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
      verbose(env, "invalid read from stack R%d var_off %s+%d size %d\n", regno,
              tn_buf, i - min_off, access_size);
    }
    return -EACCES;
  mark:
    /* reading any byte out of 8-byte 'spill_slot' will cause
     * the whole slot to be marked as 'read'
     */
    err = bpf_mark_stack_read(env, reg->frameno, env->insn_idx, BIT(spi));
    if (err)
      return err;
    /* We do not call bpf_mark_stack_write(), as we can not
     * be sure that whether stack slot is written to or not. Hence,
     * we must still conservatively propagate reads upwards even if
     * helper may write to the entire memory range.
     */
  }
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_stack_read(struct bpf_verifier_env *env, int ptr_regno,
                            int off, int size, int dst_regno) {
  struct bpf_reg_state *reg = reg_state(env, ptr_regno);
  struct bpf_func_state *state = func(env, reg);
  int err;
  /* Some accesses are only permitted with a static offset. */
  bool var_off = !tnum_is_const(reg->var_off);

  /* The offset is required to be static when reads don't go to a
   * register, in order to not leak pointers (see
   * check_stack_read_fixed_off).
   */
  if (dst_regno < 0 && var_off) {
    char tn_buf[48];

    tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
    verbose(env,
            "variable offset stack pointer cannot be passed into helper "
            "function; var_off=%s off=%d size=%d\n",
            tn_buf, off, size);
    return -EACCES;
  }
  /* Variable offset is prohibited for unprivileged mode for simplicity
   * since it requires corresponding support in Spectre masking for stack
   * ALU. See also retrieve_ptr_limit(). The check in
   * check_stack_access_for_ptr_arithmetic() called by
   * adjust_ptr_min_max_vals() prevents users from creating stack pointers
   * with variable offsets, therefore no check is required here. Further,
   * just checking it here would be insufficient as speculative stack
   * writes could still lead to unsafe speculative behaviour.
   */
  if (!var_off) {
    off += reg->var_off.value;
    err = check_stack_read_fixed_off(env, state, off, size, dst_regno);
  } else {
    /* Variable offset stack reads need more conservative handling
     * than fixed offset ones. Note that dst_regno >= 0 on this
     * branch.
     */
    err = check_stack_read_var_off(env, ptr_regno, off, size, dst_regno);
  }
  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_stack_read_fixed_off(struct bpf_verifier_env *env,
                                      /* func where src register points to */
                                      struct bpf_func_state *reg_state, int off,
                                      int size, int dst_regno) {
  struct bpf_verifier_state *vstate = env->cur_state;
  struct bpf_func_state *state = vstate->frame[vstate->curframe];
  int i, slot = -off - 1, spi = slot / BPF_REG_SIZE;
  struct bpf_reg_state *reg;
  u8 *stype, type;
  int insn_flags = insn_stack_access_flags(reg_state->frameno, spi);
  int err;

  stype = reg_state->stack[spi].slot_type;
  reg = &reg_state->stack[spi].spilled_ptr;

  mark_stack_slot_scratched(env, spi);
  check_fastcall_stack_contract(env, state, env->insn_idx, off);
  err = bpf_mark_stack_read(env, reg_state->frameno, env->insn_idx, BIT(spi));
  if (err)
    return err;

  if (is_spilled_reg(&reg_state->stack[spi])) {
    u8 spill_size = 1;

    for (i = BPF_REG_SIZE - 1; i > 0 && stype[i - 1] == STACK_SPILL; i--)
      spill_size++;

    if (size != BPF_REG_SIZE || spill_size != BPF_REG_SIZE) {
      if (reg->type != SCALAR_VALUE) {
        verbose_linfo(env, env->insn_idx, "; ");
        verbose(env, "invalid size of register fill\n");
        return -EACCES;
      }

      if (dst_regno < 0)
        return 0;

      if (size <= spill_size &&
          bpf_stack_narrow_access_ok(off, size, spill_size)) {
        /* The earlier check_reg_arg() has decided the
         * subreg_def for this insn.  Save it first.
         */
        s32 subreg_def = state->regs[dst_regno].subreg_def;

        if (env->bpf_capable && size == 4 && spill_size == 4 &&
            get_reg_width(reg) <= 32)
          /* Ensure stack slot has an ID to build a relation
           * with the destination register on fill.
           */
          assign_scalar_id_before_mov(env, reg);
        copy_register_state(&state->regs[dst_regno], reg);
        state->regs[dst_regno].subreg_def = subreg_def;

        /* Break the relation on a narrowing fill.
         * coerce_reg_to_size will adjust the boundaries.
         */
        if (get_reg_width(reg) > size * BITS_PER_BYTE)
          state->regs[dst_regno].id = 0;
      } else {
        int spill_cnt = 0, zero_cnt = 0;

        for (i = 0; i < size; i++) {
          type = stype[(slot - i) % BPF_REG_SIZE];
          if (type == STACK_SPILL) {
            spill_cnt++;
            continue;
          }
          if (type == STACK_MISC)
            continue;
          if (type == STACK_ZERO) {
            zero_cnt++;
            continue;
          }
          if (type == STACK_INVALID && env->allow_uninit_stack)
            continue;
          verbose(env, "invalid read from stack off %d+%d size %d\n", off, i,
                  size);
          return -EACCES;
        }

        if (spill_cnt == size && tnum_is_const(reg->var_off) &&
            reg->var_off.value == 0) {
          inner_mark_reg_const_zero(env, &state->regs[dst_regno]);
          /* this IS register fill, so keep insn_flags */
        } else if (zero_cnt == size) {
          /* similarly to mark_reg_stack_read(), preserve zeroes */
          inner_mark_reg_const_zero(env, &state->regs[dst_regno]);
          insn_flags = 0; /* not restoring original register state */
        } else {
          mark_reg_unknown(env, state->regs, dst_regno);
          insn_flags = 0; /* not restoring original register state */
        }
      }
    } else if (dst_regno >= 0) {
      /* restore register state from stack */
      if (env->bpf_capable)
        /* Ensure stack slot has an ID to build a relation
         * with the destination register on fill.
         */
        assign_scalar_id_before_mov(env, reg);
      copy_register_state(&state->regs[dst_regno], reg);
      /* mark reg as written since spilled pointer state likely
       * has its liveness marks cleared by is_state_visited()
       * which resets stack/reg liveness for state transitions
       */
    } else if (inner_is_pointer_value(env->allow_ptr_leaks, reg)) {
      /* If dst_regno==-1, the caller is asking us whether
       * it is acceptable to use this value as a SCALAR_VALUE
       * (e.g. for XADD).
       * We must not allow unprivileged callers to do that
       * with spilled pointers.
       */
      verbose(env, "leaking pointer from stack off %d\n", off);
      return -EACCES;
    }
  } else {
    for (i = 0; i < size; i++) {
      type = stype[(slot - i) % BPF_REG_SIZE];
      if (type == STACK_MISC)
        continue;
      if (type == STACK_ZERO)
        continue;
      if (type == STACK_INVALID && env->allow_uninit_stack)
        continue;
      verbose(env, "invalid read from stack off %d+%d size %d\n", off, i, size);
      return -EACCES;
    }
    if (dst_regno >= 0)
      mark_reg_stack_read(env, reg_state, off, off + size, dst_regno);
    insn_flags = 0; /* we are not restoring spilled register */
  }
  if (insn_flags)
    return push_jmp_history(env, env->cur_state, insn_flags, 0);
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_stack_read_var_off(struct bpf_verifier_env *env, int ptr_regno,
                                    int off, int size, int dst_regno) {
  /* The state of the source register. */
  struct bpf_reg_state *reg = reg_state(env, ptr_regno);
  struct bpf_func_state *ptr_state = func(env, reg);
  int err;
  int min_off, max_off;

  /* Note that we pass a NULL meta, so raw access will not be permitted.
   */
  err = check_stack_range_initialized(env, ptr_regno, off, size, false,
                                      BPF_READ, NULL);
  if (err)
    return err;

  min_off = reg->smin_value + off;
  max_off = reg->smax_value + off;
  mark_reg_stack_read(env, ptr_state, min_off, max_off + size, dst_regno);
  check_fastcall_stack_contract(env, ptr_state, env->insn_idx, min_off);
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_stack_slot_within_bounds(struct bpf_verifier_env *env, s64 off,
                                          struct bpf_func_state *state,
                                          enum bpf_access_type t) {
  int min_valid_off;

  if (t == BPF_WRITE || env->allow_uninit_stack)
    min_valid_off = -MAX_BPF_STACK;
  else
    min_valid_off = -state->allocated_stack;

  if (off < min_valid_off || off > -1)
    return -EACCES;
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_stack_write(struct bpf_verifier_env *env, int ptr_regno,
                             int off, int size, int value_regno, int insn_idx) {
  struct bpf_reg_state *reg = reg_state(env, ptr_regno);
  struct bpf_func_state *state = func(env, reg);
  int err;

  if (tnum_is_const(reg->var_off)) {
    off += reg->var_off.value;
    err = check_stack_write_fixed_off(env, state, off, size, value_regno,
                                      insn_idx);
  } else {
    /* Variable offset stack reads need more conservative handling
     * than fixed offset ones.
     */
    err = check_stack_write_var_off(env, state, ptr_regno, off, size,
                                    value_regno, insn_idx);
  }
  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_stack_write_fixed_off(struct bpf_verifier_env *env,
                                       /* stack frame we're writing to */
                                       struct bpf_func_state *state, int off,
                                       int size, int value_regno,
                                       int insn_idx) {
  struct bpf_func_state *cur; /* state of the current function */
  int i, slot = -off - 1, spi = slot / BPF_REG_SIZE, err;
  struct bpf_insn *insn = &env->prog->insnsi[insn_idx];
  struct bpf_reg_state *reg = NULL;
  int insn_flags = insn_stack_access_flags(state->frameno, spi);

  /* caller checked that off % size == 0 and -MAX_BPF_STACK <= off < 0,
   * so it's aligned access and [off, off + size) are within stack limits
   */
  if (!env->allow_ptr_leaks && is_spilled_reg(&state->stack[spi]) &&
      !is_spilled_scalar_reg(&state->stack[spi]) && size != BPF_REG_SIZE) {
    verbose(env, "attempt to corrupt spilled pointer on stack\n");
    return -EACCES;
  }

  cur = env->cur_state->frame[env->cur_state->curframe];
  if (value_regno >= 0)
    reg = &cur->regs[value_regno];
  if (!env->bypass_spec_v4) {
    bool sanitize = reg && is_spillable_regtype(reg->type);

    for (i = 0; i < size; i++) {
      u8 type = state->stack[spi].slot_type[i];

      if (type != STACK_MISC && type != STACK_ZERO) {
        sanitize = true;
        break;
      }
    }

    if (sanitize)
      env->insn_aux_data[insn_idx].nospec_result = true;
  }

  err = destroy_if_dynptr_stack_slot(env, state, spi);
  if (err)
    return err;

  if (!(off % BPF_REG_SIZE) && size == BPF_REG_SIZE) {
    /* only mark the slot as written if all 8 bytes were written
     * otherwise read propagation may incorrectly stop too soon
     * when stack slots are partially written.
     * This heuristic means that read propagation will be
     * conservative, since it will add reg_live_read marks
     * to stack slots all the way to first state when programs
     * writes+reads less than 8 bytes
     */
    bpf_mark_stack_write(env, state->frameno, BIT(spi));
  }

  check_fastcall_stack_contract(env, state, insn_idx, off);
  mark_stack_slot_scratched(env, spi);
  if (reg && !(off % BPF_REG_SIZE) && reg->type == SCALAR_VALUE &&
      env->bpf_capable) {
    bool reg_value_fits;

    reg_value_fits = get_reg_width(reg) <= BITS_PER_BYTE * size;
    /* Make sure that reg had an ID to build a relation on spill. */
    if (reg_value_fits)
      assign_scalar_id_before_mov(env, reg);
    save_register_state(env, state, spi, reg, size);
    /* Break the relation on a narrowing spill. */
    if (!reg_value_fits)
      state->stack[spi].spilled_ptr.id = 0;
  } else if (!reg && !(off % BPF_REG_SIZE) && is_bpf_st_mem(insn) &&
             env->bpf_capable) {
    struct bpf_reg_state *tmp_reg = &env->fake_reg[0];

    memset(tmp_reg, 0, sizeof(*tmp_reg));
    inner_mark_reg_known(tmp_reg, insn->imm);
    tmp_reg->type = SCALAR_VALUE;
    save_register_state(env, state, spi, tmp_reg, size);
  } else if (reg && is_spillable_regtype(reg->type)) {
    /* register containing pointer is being spilled into stack */
    if (size != BPF_REG_SIZE) {
      verbose_linfo(env, insn_idx, "; ");
      verbose(env, "invalid size of register spill\n");
      return -EACCES;
    }
    if (state != cur && reg->type == PTR_TO_STACK) {
      verbose(
          env,
          "cannot spill pointers to stack into stack frame of the caller\n");
      return -EINVAL;
    }
    save_register_state(env, state, spi, reg, size);
  } else {
    u8 type = STACK_MISC;

    /* regular write of data into stack destroys any spilled ptr */
    state->stack[spi].spilled_ptr.type = NOT_INIT;
    /* Mark slots as STACK_MISC if they belonged to spilled ptr/dynptr/iter. */
    if (is_stack_slot_special(&state->stack[spi]))
      for (i = 0; i < BPF_REG_SIZE; i++)
        scrub_spilled_slot(&state->stack[spi].slot_type[i]);

    /* when we zero initialize stack slots mark them as such */
    if ((reg && register_is_null(reg)) ||
        (!reg && is_bpf_st_mem(insn) && insn->imm == 0)) {
      /* STACK_ZERO case happened because register spill
       * wasn't properly aligned at the stack slot boundary,
       * so it's not a register spill anymore; force
       * originating register to be precise to make
       * STACK_ZERO correct for subsequent states
       */
      err = mark_chain_precision(env, value_regno);
      if (err)
        return err;
      type = STACK_ZERO;
    }

    /* Mark slots affected by this stack write. */
    for (i = 0; i < size; i++)
      state->stack[spi].slot_type[(slot - i) % BPF_REG_SIZE] = type;
    insn_flags = 0; /* not a register spill */
  }

  if (insn_flags)
    return push_jmp_history(env, env->cur_state, insn_flags, 0);
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_stack_write_var_off(struct bpf_verifier_env *env,
                                     /* func where register points to */
                                     struct bpf_func_state *state,
                                     int ptr_regno, int off, int size,
                                     int value_regno, int insn_idx) {
  struct bpf_func_state *cur; /* state of the current function */
  int min_off, max_off;
  int i, err;
  struct bpf_reg_state *ptr_reg = NULL, *value_reg = NULL;
  struct bpf_insn *insn = &env->prog->insnsi[insn_idx];
  bool writing_zero = false;
  /* set if the fact that we're writing a zero is used to let any
   * stack slots remain STACK_ZERO
   */
  bool zero_used = false;

  cur = env->cur_state->frame[env->cur_state->curframe];
  ptr_reg = &cur->regs[ptr_regno];
  min_off = ptr_reg->smin_value + off;
  max_off = ptr_reg->smax_value + off + size;
  if (value_regno >= 0)
    value_reg = &cur->regs[value_regno];
  if ((value_reg && register_is_null(value_reg)) ||
      (!value_reg && is_bpf_st_mem(insn) && insn->imm == 0))
    writing_zero = true;

  for (i = min_off; i < max_off; i++) {
    int spi;

    spi = inner_get_spi(i);
    err = destroy_if_dynptr_stack_slot(env, state, spi);
    if (err)
      return err;
  }

  check_fastcall_stack_contract(env, state, insn_idx, min_off);
  /* Variable offset writes destroy any spilled pointers in range. */
  for (i = min_off; i < max_off; i++) {
    u8 new_type, *stype;
    int slot, spi;

    slot = -i - 1;
    spi = slot / BPF_REG_SIZE;
    stype = &state->stack[spi].slot_type[slot % BPF_REG_SIZE];
    mark_stack_slot_scratched(env, spi);

    if (!env->allow_ptr_leaks && *stype != STACK_MISC && *stype != STACK_ZERO) {
      /* Reject the write if range we may write to has not
       * been initialized beforehand. If we didn't reject
       * here, the ptr status would be erased below (even
       * though not all slots are actually overwritten),
       * possibly opening the door to leaks.
       *
       * We do however catch STACK_INVALID case below, and
       * only allow reading possibly uninitialized memory
       * later for CAP_PERFMON, as the write may not happen to
       * that slot.
       */
      verbose(env,
              "spilled ptr in range of var-offset stack write; insn %d, ptr "
              "off: %d",
              insn_idx, i);
      return -EINVAL;
    }

    /* If writing_zero and the spi slot contains a spill of value 0,
     * maintain the spill type.
     */
    if (writing_zero && *stype == STACK_SPILL &&
        is_spilled_scalar_reg(&state->stack[spi])) {
      struct bpf_reg_state *spill_reg = &state->stack[spi].spilled_ptr;

      if (tnum_is_const(spill_reg->var_off) && spill_reg->var_off.value == 0) {
        zero_used = true;
        continue;
      }
    }

    /* Erase all other spilled pointers. */
    state->stack[spi].spilled_ptr.type = NOT_INIT;

    /* Update the slot type. */
    new_type = STACK_MISC;
    if (writing_zero && *stype == STACK_ZERO) {
      new_type = STACK_ZERO;
      zero_used = true;
    }
    /* If the slot is STACK_INVALID, we check whether it's OK to
     * pretend that it will be initialized by this write. The slot
     * might not actually be written to, and so if we mark it as
     * initialized future reads might leak uninitialized memory.
     * For privileged programs, we will accept such reads to slots
     * that may or may not be written because, if we're reject
     * them, the error would be too confusing.
     */
    if (*stype == STACK_INVALID && !env->allow_uninit_stack) {
      verbose(env,
              "uninit stack in range of var-offset write prohibited for !root; "
              "insn %d, off: %d",
              insn_idx, i);
      return -EINVAL;
    }
    *stype = new_type;
  }
  if (zero_used) {
    /* backtracking doesn't work for STACK_ZERO yet. */
    err = mark_chain_precision(env, value_regno);
    if (err)
      return err;
  }
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_store_reg(struct bpf_verifier_env *env, struct bpf_insn *insn,
                           bool strict_alignment_once) {
  struct bpf_reg_state *regs = cur_regs(env);
  enum bpf_reg_type dst_reg_type;
  int err;

  /* check src1 operand */
  err = check_reg_arg(env, insn->src_reg, SRC_OP);
  if (err)
    return err;

  /* check src2 operand */
  err = check_reg_arg(env, insn->dst_reg, SRC_OP);
  if (err)
    return err;

  dst_reg_type = regs[insn->dst_reg].type;

  /* Check if (dst_reg + off) is writeable. */
  err = check_mem_access(env, env->insn_idx, insn->dst_reg, insn->off,
                         BPF_SIZE(insn->code), BPF_WRITE, insn->src_reg,
                         strict_alignment_once, false);
  err = err ?: save_aux_ptr_type(env, dst_reg_type, false);

  return err;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_struct_ops_btf_id(struct bpf_verifier_env *env) {
  const struct btf_type *t, *func_proto;
  const struct bpf_struct_ops_desc *st_ops_desc;
  const struct bpf_struct_ops *st_ops;
  const struct btf_member *member;
  struct bpf_prog *prog = env->prog;
  bool has_refcounted_arg = false;
  u32 btf_id, member_idx, member_off;
  struct btf *btf;
  const char *mname;
  int i, err;

  if (!prog->gpl_compatible) {
    verbose(env, "struct ops programs must have a GPL compatible license\n");
    return -EINVAL;
  }

  if (!prog->aux->attach_btf_id)
    return -ENOTSUPP;

  btf = prog->aux->attach_btf;
  if (btf_is_module(btf)) {
    /* Make sure st_ops is valid through the lifetime of env */
    env->attach_btf_mod = btf_try_get_module(btf);
    if (!env->attach_btf_mod) {
      verbose(env, "struct_ops module %s is not found\n", btf_get_name(btf));
      return -ENOTSUPP;
    }
  }

  btf_id = prog->aux->attach_btf_id;
  st_ops_desc = bpf_struct_ops_find(btf, btf_id);
  if (!st_ops_desc) {
    verbose(env, "attach_btf_id %u is not a supported struct\n", btf_id);
    return -ENOTSUPP;
  }
  st_ops = st_ops_desc->st_ops;

  t = st_ops_desc->type;
  member_idx = prog->expected_attach_type;
  if (member_idx >= btf_type_vlen(t)) {
    verbose(env, "attach to invalid member idx %u of struct %s\n", member_idx,
            st_ops->name);
    return -EINVAL;
  }

  member = &btf_type_member(t)[member_idx];
  mname = btf_name_by_offset(btf, member->name_off);
  func_proto = btf_type_resolve_func_ptr(btf, member->type, NULL);
  if (!func_proto) {
    verbose(env, "attach to invalid member %s(@idx %u) of struct %s\n", mname,
            member_idx, st_ops->name);
    return -EINVAL;
  }

  member_off = __btf_member_bit_offset(t, member) / 8;
  err = bpf_struct_ops_supported(st_ops, member_off);
  if (err) {
    verbose(env, "attach to unsupported member %s of struct %s\n", mname,
            st_ops->name);
    return err;
  }

  if (st_ops->check_member) {
    err = st_ops->check_member(t, member, prog);

    if (err) {
      verbose(env, "attach to unsupported member %s of struct %s\n", mname,
              st_ops->name);
      return err;
    }
  }

  if (prog->aux->priv_stack_requested && !bpf_jit_supports_private_stack()) {
    verbose(env, "Private stack not supported by jit\n");
    return -EACCES;
  }

  for (i = 0; i < st_ops_desc->arg_info[member_idx].cnt; i++) {
    if (st_ops_desc->arg_info[member_idx].info->refcounted) {
      has_refcounted_arg = true;
      break;
    }
  }

  /* Tail call is not allowed for programs with refcounted arguments since we
   * cannot guarantee that valid refcounted kptrs will be passed to the callee.
   */
  for (i = 0; i < env->subprog_cnt; i++) {
    if (has_refcounted_arg && env->subprog_info[i].has_tail_call) {
      verbose(env, "program with __ref argument cannot tail call\n");
      return -EINVAL;
    }
  }

  prog->aux->st_ops = st_ops;
  prog->aux->attach_st_ops_member_off = member_off;

  prog->aux->attach_func_proto = func_proto;
  prog->aux->attach_func_name = mname;
  env->ops = st_ops->verifier_ops;

  return bpf_prog_ctx_arg_info_init(prog,
                                    st_ops_desc->arg_info[member_idx].info,
                                    st_ops_desc->arg_info[member_idx].cnt);
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_subprogs(struct bpf_verifier_env *env) {
  int i, subprog_start, subprog_end, off, cur_subprog = 0;
  struct bpf_subprog_info *subprog = env->subprog_info;
  struct bpf_insn *insn = env->prog->insnsi;
  int insn_cnt = env->prog->len;

  /* now check that all jumps are within the same subprog */
  subprog_start = subprog[cur_subprog].start;
  subprog_end = subprog[cur_subprog + 1].start;
  for (i = 0; i < insn_cnt; i++) {
    u8 code = insn[i].code;

    if (code == (BPF_JMP | BPF_CALL) && insn[i].src_reg == 0 &&
        insn[i].imm == BPF_FUNC_tail_call) {
      subprog[cur_subprog].has_tail_call = true;
      subprog[cur_subprog].tail_call_reachable = true;
    }
    if (BPF_CLASS(code) == BPF_LD &&
        (BPF_MODE(code) == BPF_ABS || BPF_MODE(code) == BPF_IND))
      subprog[cur_subprog].has_ld_abs = true;
    if (BPF_CLASS(code) != BPF_JMP && BPF_CLASS(code) != BPF_JMP32)
      goto next;
    if (BPF_OP(code) == BPF_CALL)
      goto next;
    if (BPF_OP(code) == BPF_EXIT) {
      subprog[cur_subprog].exit_idx = i;
      goto next;
    }
    off = i + bpf_jmp_offset(&insn[i]) + 1;
    if (off < subprog_start || off >= subprog_end) {
      verbose(env, "jump out of range from insn %d to %d\n", i, off);
      return -EINVAL;
    }
  next:
    if (i == subprog_end - 1) {
      /* to avoid fall-through from one subprog into another
       * the last insn of the subprog should be either exit
       * or unconditional jump back or bpf_throw call
       */
      if (code != (BPF_JMP | BPF_EXIT) && code != (BPF_JMP32 | BPF_JA) &&
          code != (BPF_JMP | BPF_JA)) {
        verbose(env, "last insn is not an exit or jmp\n");
        return -EINVAL;
      }
      subprog_start = subprog_end;
      cur_subprog++;
      if (cur_subprog < env->subprog_cnt)
        subprog_end = subprog[cur_subprog + 1].start;
    }
  }
  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int check_tp_buffer_access(struct bpf_verifier_env *env,
                                  const struct bpf_reg_state *reg, int regno,
                                  int off, int size) {
  int err;

  err = inner_check_buffer_access(env, "tracepoint", reg, regno, off, size);
  if (err)
    return err;

  if (off + size > env->prog->aux->max_tp_access)
    env->prog->aux->max_tp_access = off + size;

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int inner_check_buffer_access(struct bpf_verifier_env *env,
                                     const char *buf_info,
                                     const struct bpf_reg_state *reg, int regno,
                                     int off, int size) {
  if (off < 0) {
    verbose(env, "R%d invalid %s buffer access: off=%d, size=%d\n", regno,
            buf_info, off, size);
    return -EACCES;
  }
  if (!tnum_is_const(reg->var_off) || reg->var_off.value) {
    char tn_buf[48];

    tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
    verbose(env, "R%d invalid variable buffer offset: off=%d, var_off=%s\n",
            regno, off, tn_buf);
    return -EACCES;
  }

  return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int inner_check_mem_access(struct bpf_verifier_env *env, int regno,
                                  int off, int size, u32 mem_size,
                                  bool zero_size_allowed) {
  bool size_ok = size > 0 || (size == 0 && zero_size_allowed);
  struct bpf_reg_state *reg;

  if (off >= 0 && size_ok && (u64)off + size <= mem_size)
    return 0;

  reg = &cur_regs(env)[regno];
  switch (reg->type) {
  case PTR_TO_MAP_KEY:
    verbose(env, "invalid access to map key, key_size=%d off=%d size=%d\n",
            mem_size, off, size);
    break;
  case PTR_TO_MAP_VALUE:
    verbose(env, "invalid access to map value, value_size=%d off=%d size=%d\n",
            mem_size, off, size);
    break;
  case PTR_TO_PACKET:
  case PTR_TO_PACKET_META:
  case PTR_TO_PACKET_END:
    verbose(
        env,
        "invalid access to packet, off=%d size=%d, R%d(id=%d,off=%d,r=%d)\n",
        off, size, regno, reg->id, off, mem_size);
    break;
  case PTR_TO_MEM:
  default:
    verbose(env, "invalid access to memory, mem_size=%u off=%d size=%d\n",
            mem_size, off, size);
  }

  return -EACCES;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int inner_check_pseudo_btf_id(struct bpf_verifier_env *env,
				 struct bpf_insn *insn,
				 struct bpf_insn_aux_data *aux,
				 struct btf *btf)
{
	const struct btf_var_secinfo *vsi;
	const struct btf_type *datasec;
	const struct btf_type *t;
	const char *sym_name;
	bool percpu = false;
	u32 type, id = insn->imm;
	s32 datasec_id;
	u64 addr;
	int i;

	t = btf_type_by_id(btf, id);
	if (!t) {
		verbose(env, "ldimm64 insn specifies invalid btf_id %d.\n", id);
		return -ENOENT;
	}

	if (!btf_type_is_var(t) && !btf_type_is_func(t)) {
		verbose(env, "pseudo btf_id %d in ldimm64 isn't KIND_VAR or KIND_FUNC\n", id);
		return -EINVAL;
	}

	sym_name = btf_name_by_offset(btf, t->name_off);
	addr = kallsyms_lookup_name(sym_name);
	if (!addr) {
		verbose(env, "ldimm64 failed to find the address for kernel symbol '%s'.\n",
			sym_name);
		return -ENOENT;
	}
	insn[0].imm = (u32)addr;
	insn[1].imm = addr >> 32;

	if (btf_type_is_func(t)) {
		aux->btf_var.reg_type = PTR_TO_MEM | MEM_RDONLY;
		aux->btf_var.mem_size = 0;
		return 0;
	}

	datasec_id = find_btf_percpu_datasec(btf);
	if (datasec_id > 0) {
		datasec = btf_type_by_id(btf, datasec_id);
		for_each_vsi(i, datasec, vsi) {
			if (vsi->type == id) {
				percpu = true;
				break;
			}
		}
	}

	type = t->type;
	t = btf_type_skip_modifiers(btf, type, NULL);
	if (percpu) {
		aux->btf_var.reg_type = PTR_TO_BTF_ID | MEM_PERCPU;
		aux->btf_var.btf = btf;
		aux->btf_var.btf_id = type;
	} else if (!btf_type_is_struct(t)) {
		const struct btf_type *ret;
		const char *tname;
		u32 tsize;

		/* resolve the type size of ksym. */
		ret = btf_resolve_size(btf, t, &tsize);
		if (IS_ERR(ret)) {
			tname = btf_name_by_offset(btf, t->name_off);
			verbose(env, "ldimm64 unable to resolve the size of type '%s': %ld\n",
				tname, PTR_ERR(ret));
			return -EINVAL;
		}
		aux->btf_var.reg_type = PTR_TO_MEM | MEM_RDONLY;
		aux->btf_var.mem_size = tsize;
	} else {
		aux->btf_var.reg_type = PTR_TO_BTF_ID;
		aux->btf_var.btf = btf;
		aux->btf_var.btf_id = type;
	}

	return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int inner_check_ptr_off_reg(struct bpf_verifier_env *env,
			       const struct bpf_reg_state *reg, int regno,
			       bool fixed_off_ok)
{
	/* Access to this pointer-typed register or passing it to a helper
	 * is only allowed in its original, unmodified form.
	 */

	if (reg->off < 0) {
		verbose(env, "negative offset %s ptr R%d off=%d disallowed\n",
			reg_type_str(env, reg->type), regno, reg->off);
		return -EACCES;
	}

	if (!fixed_off_ok && reg->off) {
		verbose(env, "dereference of modified %s ptr R%d off=%d disallowed\n",
			reg_type_str(env, reg->type), regno, reg->off);
		return -EACCES;
	}

	if (!tnum_is_const(reg->var_off) || reg->var_off.value) {
		char tn_buf[48];

		tnum_strn(tn_buf, sizeof(tn_buf), reg->var_off);
		verbose(env, "variable %s access var_off=%s disallowed\n",
			reg_type_str(env, reg->type), tn_buf);
		return -EACCES;
	}

	return 0;
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
static int inner_check_reg_arg(struct bpf_verifier_env *env, struct bpf_reg_state *regs, u32 regno,
			   enum reg_arg_type t)
{
	struct bpf_insn *insn = env->prog->insnsi + env->insn_idx;
	struct bpf_reg_state *reg;
	bool rw64;

	if (regno >= MAX_BPF_REG) {
		verbose(env, "R%d is invalid\n", regno);
		return -EINVAL;
	}

	mark_reg_scratched(env, regno);

	reg = &regs[regno];
	rw64 = is_reg64(insn, regno, reg, t);
	if (t == SRC_OP) {
		/* check whether register used as source operand can be read */
		if (reg->type == NOT_INIT) {
			verbose(env, "R%d !read_ok\n", regno);
			return -EACCES;
		}
		/* We don't need to worry about FP liveness because it's read-only */
		if (regno == BPF_REG_FP)
			return 0;

		if (rw64)
			mark_insn_zext(env, reg);

		return 0;
	} else {
		/* check whether register used as dest operand can be written to */
		if (regno == BPF_REG_FP) {
			verbose(env, "frame pointer is read only\n");
			return -EACCES;
		}
		reg->subreg_def = rw64 ? DEF_NOT_SUBREG : env->insn_idx + 1;
		if (t == DST_OP)
			mark_reg_unknown(env, regs, regno);
	}
	return 0;
}
