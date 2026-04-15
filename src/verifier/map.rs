//! Missing types: BpfVerifierEnv, BtfField, BpfRegState, BpfMap, BpfFuncState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, kptr_field, reg))]
pub fn map_kptr_match_type(
    env: &mut BpfVerifierEnv,
    kptr_field: &BtfField,
    reg: &mut BpfRegState,
    regno: u32,
) -> Result<i32> {
    let targ_name = btf_type_name(kptr_field.kptr.btf, kptr_field.kptr.btf_id);
    let perm_flags: u32;
    let mut reg_name = "";

    if btf_is_kernel(reg.btf) {
        let mut flags = PTR_MAYBE_NULL | PTR_TRUSTED | MEM_RCU;
        if kptr_field.r#type == BPF_KPTR_UNREF {
            flags |= PTR_UNTRUSTED;
        }
        perm_flags = flags;
    } else {
        let mut flags = PTR_MAYBE_NULL | MEM_ALLOC;
        if kptr_field.r#type == BPF_KPTR_PERCPU {
            flags |= MEM_PERCPU;
        }
        perm_flags = flags;
    }

    if base_type(reg.r#type) != PTR_TO_BTF_ID || (type_flag(reg.r#type) & !perm_flags) != 0 {
        verbose(
            env,
            format!("invalid kptr access, R{} type={}{} ", regno, reg_type_str(env, reg.r#type), reg_name),
        );
        verbose(
            env,
            format!("expected={}{}\n", reg_type_str(env, PTR_TO_BTF_ID), targ_name),
        );
        return Err(anyhow!("map_kptr_match_type failed"));
    }

    reg_name = btf_type_name(reg.btf, reg.btf_id);
    if inner_check_ptr_off_reg(env, reg, regno, true) != 0 {
        return Err(anyhow!("map_kptr_match_type failed"));
    }

    if !btf_struct_ids_match(
        &mut env.log,
        reg.btf,
        reg.btf_id,
        reg.off,
        kptr_field.kptr.btf,
        kptr_field.kptr.btf_id,
        kptr_field.r#type != BPF_KPTR_UNREF,
    ) {
        verbose(
            env,
            format!("invalid kptr access, R{} type={}{} expected={}{}\n", regno, reg_type_str(env, reg.r#type), reg_name, reg_type_str(env, PTR_TO_BTF_ID), targ_name),
        );
        return Err(anyhow!("map_kptr_match_type failed"));
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(map))]
pub fn map_mem_size(map: &BpfMap) -> Result<u32> {
    if map.map_type == BPF_MAP_TYPE_INSN_ARRAY {
        return Ok(map.max_entries * core::mem::size_of::<usize>() as u32);
    }
    Ok(map.value_size)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, caller, callee))]
pub fn map_set_for_each_callback_args(
    env: &mut BpfVerifierEnv,
    caller: &mut BpfFuncState,
    callee: &mut BpfFuncState,
) -> Result<i32> {
    callee.regs[BPF_REG_1 as usize] = caller.regs[BPF_REG_1 as usize];

    callee.regs[BPF_REG_2 as usize].r#type = PTR_TO_MAP_KEY;
    inner_mark_reg_known_zero(&mut callee.regs[BPF_REG_2 as usize]);
    callee.regs[BPF_REG_2 as usize].map_ptr = caller.regs[BPF_REG_1 as usize].map_ptr;

    callee.regs[BPF_REG_3 as usize].r#type = PTR_TO_MAP_VALUE;
    inner_mark_reg_known_zero(&mut callee.regs[BPF_REG_3 as usize]);
    callee.regs[BPF_REG_3 as usize].map_ptr = caller.regs[BPF_REG_1 as usize].map_ptr;

    callee.regs[BPF_REG_4 as usize] = caller.regs[BPF_REG_3 as usize];
    inner_mark_reg_not_init(env, &mut callee.regs[BPF_REG_5 as usize]);

    Ok(0)
}
