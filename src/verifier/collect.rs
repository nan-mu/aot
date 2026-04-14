//! Missing types: BpfVerifierEnv, BpfVerifierState, LinkedRegs, BpfInsnAuxData, BpfFuncState, BpfRegState, LinkedReg

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, vstate, linked_regs))]
pub fn collect_linked_regs(
    env: &mut BpfVerifierEnv,
    vstate: &mut BpfVerifierState,
    mut id: u32,
    linked_regs: &mut LinkedRegs,
) -> Result<()> {
    let aux: &mut [BpfInsnAuxData] = env.insn_aux_data;

    id &= !BPF_ADD_CONST;
    for i in (0..=vstate.curframe as usize).rev() {
        let live_regs = aux[frame_insn_idx(vstate, i as i32) as usize].live_regs_before;
        let func: &mut BpfFuncState = vstate.frame[i];

        for j in 0..BPF_REG_FP as usize {
            if (live_regs & BIT(j as u32)) == 0 {
                continue;
            }
            let reg: &mut BpfRegState = &mut func.regs[j];
            inner_collect_linked_regs(linked_regs, reg, id, i as u32, j as u32, true)?;
        }

        for j in 0..(func.allocated_stack / BPF_REG_SIZE) as usize {
            if !is_spilled_reg(&func.stack[j]) {
                continue;
            }
            let reg: &mut BpfRegState = &mut func.stack[j].spilled_ptr;
            inner_collect_linked_regs(linked_regs, reg, id, i as u32, j as u32, false)?;
        }
    }

    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg_set, reg))]
pub fn inner_collect_linked_regs(
    reg_set: &mut LinkedRegs,
    reg: &mut BpfRegState,
    id: u32,
    frameno: u32,
    spi_or_reg: u32,
    is_reg: bool,
) -> Result<()> {
    if reg.r#type != SCALAR_VALUE || (reg.id & !BPF_ADD_CONST) != id {
        return Ok(());
    }

    let e: &mut LinkedReg = linked_regs_push(reg_set);
    e.frameno = frameno;
    e.is_reg = is_reg;
    e.regno = spi_or_reg;
    Ok(())
}
