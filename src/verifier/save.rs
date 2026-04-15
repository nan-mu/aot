//! Missing types: BpfVerifierEnv, BpfRegType, BpfFuncState, BpfRegState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn save_aux_ptr_type(
    env: &mut BpfVerifierEnv,
    r#type: BpfRegType,
    allow_trust_mismatch: bool,
) -> Result<i32> {
    let prev_type = &mut env.insn_aux_data[env.insn_idx as usize].ptr_type;

    if *prev_type == NOT_INIT {
        *prev_type = r#type;
        return Ok(0);
    }

    if reg_type_mismatch(r#type, *prev_type)? {
        if allow_trust_mismatch && is_ptr_to_mem_or_btf_id(r#type) && is_ptr_to_mem_or_btf_id(*prev_type) {
            let mut merged_type = if is_ptr_to_mem(r#type) || is_ptr_to_mem(*prev_type) {
                PTR_TO_MEM
            } else {
                PTR_TO_BTF_ID
            };
            if (r#type & PTR_UNTRUSTED) != 0 || (*prev_type & PTR_UNTRUSTED) != 0 {
                merged_type |= PTR_UNTRUSTED;
            }
            if (r#type & MEM_RDONLY) != 0 || (*prev_type & MEM_RDONLY) != 0 {
                merged_type |= MEM_RDONLY;
            }
            *prev_type = merged_type;
        } else {
            verbose(env, "same insn cannot be used with different pointers\n");
            return Err(anyhow!("save_aux_ptr_type failed"));
        }
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, state, reg))]
pub fn save_register_state(
    env: &mut BpfVerifierEnv,
    state: &mut BpfFuncState,
    spi: i32,
    reg: &mut BpfRegState,
    size: i32,
) -> Result<()> {
    copy_register_state(&mut state.stack[spi as usize].spilled_ptr, reg);

    let mut i = BPF_REG_SIZE as i32;
    while i > BPF_REG_SIZE as i32 - size {
        state.stack[spi as usize].slot_type[(i - 1) as usize] = STACK_SPILL;
        i -= 1;
    }

    while i > 0 {
        let idx = (i - 1) as usize;
        mark_stack_slot_misc(env, &mut state.stack[spi as usize].slot_type[idx]);
        i -= 1;
    }

    Ok(())
}
