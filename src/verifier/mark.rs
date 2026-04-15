//! Missing types: BpfVerifierEnv, BpfVerifierState, BpfFuncState, BpfRegState, Btf, BpfSubprogInfo, BpfKfuncCallArgMeta, BpfArgType, BtfFieldGraphRoot, BtfField

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(_env, st))]
pub fn mark_all_scalars_imprecise(_env: &mut BpfVerifierEnv, st: &mut BpfVerifierState) -> Result<()> {
    for i in 0..=st.curframe as usize {
        let func: &mut BpfFuncState = &mut st.frame[i];
        for j in 0..BPF_REG_FP as usize {
            let reg: &mut BpfRegState = &mut func.regs[j];
            if reg.r#type == SCALAR_VALUE {
                reg.precise = false;
            }
        }
        for j in 0..(func.allocated_stack / BPF_REG_SIZE as i32) as usize {
            if !is_spilled_reg(&func.stack[j]) {
                continue;
            }
            let reg: &mut BpfRegState = &mut func.stack[j].spilled_ptr;
            if reg.r#type == SCALAR_VALUE {
                reg.precise = false;
            }
        }
    }
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, st))]
pub fn mark_all_scalars_precise(env: &mut BpfVerifierEnv, mut st: &mut BpfVerifierState) -> Result<()> {
    if (env.log.level & BPF_LOG_LEVEL2) != 0 {
        verbose(env, format!("mark_precise: frame{}: falling back to forcing all scalars precise\n", st.curframe));
    }

    while let Some(parent) = st.parent.as_mut() {
        st = parent;
        for i in 0..=st.curframe as usize {
            let func: &mut BpfFuncState = &mut st.frame[i];
            for j in 0..BPF_REG_FP as usize {
                let reg: &mut BpfRegState = &mut func.regs[j];
                if reg.r#type == SCALAR_VALUE && !reg.precise {
                    reg.precise = true;
                }
            }
            for j in 0..(func.allocated_stack / BPF_REG_SIZE as i32) as usize {
                if !is_spilled_reg(&func.stack[j]) {
                    continue;
                }
                let reg: &mut BpfRegState = &mut func.stack[j].spilled_ptr;
                if reg.r#type == SCALAR_VALUE && !reg.precise {
                    reg.precise = true;
                }
            }
        }
    }
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn mark_chain_precision(env: &mut BpfVerifierEnv, regno: i32) -> Result<i32> {
    inner_mark_chain_precision(env, env.cur_state, regno, None)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, starting_state))]
pub fn mark_chain_precision_batch(env: &mut BpfVerifierEnv, starting_state: &mut BpfVerifierState) -> Result<i32> {
    inner_mark_chain_precision(env, starting_state, -1, None)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn mark_dynptr_read(env: &mut BpfVerifierEnv, reg: &mut BpfRegState) -> Result<i32> {
    if reg.r#type == CONST_PTR_TO_DYNPTR {
        return Ok(0);
    }
    let spi = dynptr_get_spi(env, reg)?;
    mark_stack_slot_obj_read(env, reg, spi, BPF_DYNPTR_NR_SLOTS)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn mark_irq_flag_read(env: &mut BpfVerifierEnv, reg: &mut BpfRegState) -> Result<i32> {
    let spi = irq_flag_get_spi(env, reg)?;
    mark_stack_slot_obj_read(env, reg, spi, 1)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn mark_iter_read(env: &mut BpfVerifierEnv, reg: &mut BpfRegState, spi: i32, nr_slots: i32) -> Result<i32> {
    let _ = spi;
    mark_stack_slot_obj_read(env, reg, spi, nr_slots)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn mark_force_checkpoint(env: &mut BpfVerifierEnv, idx: i32) -> Result<()> {
    env.insn_aux_data[idx as usize].force_checkpoint = true;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn mark_jmp_point(env: &mut BpfVerifierEnv, idx: i32) -> Result<()> {
    env.insn_aux_data[idx as usize].jmp_point = true;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn mark_prune_point(env: &mut BpfVerifierEnv, idx: i32) -> Result<()> {
    env.insn_aux_data[idx as usize].prune_point = true;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, regs))]
pub fn mark_reg_known_zero(env: &mut BpfVerifierEnv, regs: &mut [BpfRegState], regno: u32) -> Result<()> {
    if regno >= MAX_BPF_REG as u32 {
        verbose(env, format!("mark_reg_known_zero(regs, {})\n", regno));
        for r in regs.iter_mut().take(MAX_BPF_REG as usize) {
            inner_mark_reg_not_init(env, r);
        }
        return Ok(());
    }
    inner_mark_reg_known_zero(&mut regs[regno as usize]);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, regs))]
pub fn mark_reg_not_init(env: &mut BpfVerifierEnv, regs: &mut [BpfRegState], regno: u32) -> Result<()> {
    if regno >= MAX_BPF_REG as u32 {
        verbose(env, format!("mark_reg_not_init(regs, {})\n", regno));
        for r in regs.iter_mut().take(BPF_REG_FP as usize) {
            inner_mark_reg_not_init(env, r);
        }
        return Ok(());
    }
    inner_mark_reg_not_init(env, &mut regs[regno as usize]);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, regs))]
pub fn mark_reg_unknown(env: &mut BpfVerifierEnv, regs: &mut [BpfRegState], regno: u32) -> Result<()> {
    if regno >= MAX_BPF_REG as u32 {
        verbose(env, format!("mark_reg_unknown(regs, {})\n", regno));
        for r in regs.iter_mut().take(BPF_REG_FP as usize) {
            inner_mark_reg_not_init(env, r);
        }
        return Ok(());
    }
    inner_mark_reg_unknown(env, &mut regs[regno as usize]);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn mark_stack_slot_obj_read(env: &mut BpfVerifierEnv, reg: &mut BpfRegState, spi: i32, nr_slots: i32) -> Result<i32> {
    for i in 0..nr_slots {
        bpf_mark_stack_read(env, reg.frameno, env.insn_idx, BIT((spi - i) as u32))?;
        mark_stack_slot_scratched(env, spi - i);
    }
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn mark_subprog_changes_pkt_data(env: &mut BpfVerifierEnv, off: i32) -> Result<()> {
    let subprog = bpf_find_containing_subprog(env, off);
    subprog.changes_pkt_data = true;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn mark_subprog_might_sleep(env: &mut BpfVerifierEnv, off: i32) -> Result<()> {
    let subprog = bpf_find_containing_subprog(env, off);
    subprog.might_sleep = true;
    Ok(())
}
