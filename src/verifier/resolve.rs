//! Missing types: BpfVerifierEnv, BpfCallArgMeta, BpfArgType, BpfInsn, BpfMap

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, meta, arg_type))]
pub fn resolve_map_arg_type(
    env: &mut BpfVerifierEnv,
    meta: &BpfCallArgMeta,
    arg_type: &mut BpfArgType,
) -> Result<i32> {
    let map = meta.map.ptr;
    if map.is_none() {
        return Err(anyhow!("resolve_map_arg_type failed"));
    }
    let map = map.unwrap();

    match map.map_type {
        BPF_MAP_TYPE_SOCKMAP | BPF_MAP_TYPE_SOCKHASH => {
            if *arg_type == ARG_PTR_TO_MAP_VALUE {
                *arg_type = ARG_PTR_TO_BTF_ID_SOCK_COMMON;
            } else {
                verbose(env, "invalid arg_type for sockmap/sockhash\n");
                return Err(anyhow!("resolve_map_arg_type failed"));
            }
        }
        BPF_MAP_TYPE_BLOOM_FILTER => {
            if meta.func_id == BPF_FUNC_map_peek_elem {
                *arg_type = ARG_PTR_TO_MAP_VALUE;
            }
        }
        _ => {}
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn resolve_pseudo_ldimm64(env: &mut BpfVerifierEnv) -> Result<i32> {
    bpf_prog_calc_tag(env.prog)?;

    let insn_cnt = env.prog.len as usize;
    let mut i = 0usize;
    while i < insn_cnt {
        let insn = env.prog.insnsi[i];

        if BPF_CLASS(insn.code) == BPF_LDX
            && ((BPF_MODE(insn.code) != BPF_MEM && BPF_MODE(insn.code) != BPF_MEMSX) || insn.imm != 0)
        {
            verbose(env, "BPF_LDX uses reserved fields\n");
            return Err(anyhow!("resolve_pseudo_ldimm64 failed"));
        }

        if insn.code == (BPF_LD | BPF_IMM | BPF_DW) {
            if i == insn_cnt - 1 {
                return Err(anyhow!("resolve_pseudo_ldimm64 failed"));
            }
            let next = env.prog.insnsi[i + 1];
            if next.code != 0 || next.dst_reg != 0 || next.src_reg != 0 || next.off != 0 {
                verbose(env, "invalid bpf_ld_imm64 insn\n");
                return Err(anyhow!("resolve_pseudo_ldimm64 failed"));
            }

            if insn.src_reg == 0 {
                i += 2;
                continue;
            }

            if !bpf_opcode_in_insntable(insn.code) {
                verbose(env, format!("unknown opcode {:02x}\n", insn.code));
                return Err(anyhow!("resolve_pseudo_ldimm64 failed"));
            }

            i += 2;
            continue;
        }

        if !bpf_opcode_in_insntable(insn.code) {
            verbose(env, format!("unknown opcode {:02x}\n", insn.code));
            return Err(anyhow!("resolve_pseudo_ldimm64 failed"));
        }
        i += 1;
    }

    Ok(0)
}
