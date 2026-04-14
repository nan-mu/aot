//! Missing types: BacktrackState, BpfVerifierEnv, BpfJmpHistoryEntry, LinkedRegs, LinkedReg

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_clear_frame_reg(bt: &mut BacktrackState, frame: u32, reg: u32) -> Result<()> {
    bt.reg_masks[frame as usize] &= !(1u32 << reg);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_clear_frame_slot(bt: &mut BacktrackState, frame: u32, slot: u32) -> Result<()> {
    bt.stack_masks[frame as usize] &= !(1u64 << slot);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_clear_reg(bt: &mut BacktrackState, reg: u32) -> Result<()> {
    bt_clear_frame_reg(bt, bt.frame, reg)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_empty(bt: &mut BacktrackState) -> Result<u32> {
    let mut mask: u64 = 0;
    for i in 0..=bt.frame as usize {
        mask |= bt.reg_masks[i] as u64 | bt.stack_masks[i];
    }
    Ok((mask == 0) as u32)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_frame_reg_mask(bt: &mut BacktrackState, frame: u32) -> Result<u32> {
    Ok(bt.reg_masks[frame as usize])
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_frame_stack_mask(bt: &mut BacktrackState, frame: u32) -> Result<u64> {
    Ok(bt.stack_masks[frame as usize])
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_init(bt: &mut BacktrackState, frame: u32) -> Result<()> {
    bt.frame = frame;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_is_frame_reg_set(bt: &mut BacktrackState, frame: u32, reg: u32) -> Result<bool> {
    Ok((bt.reg_masks[frame as usize] & (1u32 << reg)) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_is_frame_slot_set(bt: &mut BacktrackState, frame: u32, slot: u32) -> Result<bool> {
    Ok((bt.stack_masks[frame as usize] & (1u64 << slot)) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_is_reg_set(bt: &mut BacktrackState, reg: u32) -> Result<bool> {
    Ok((bt.reg_masks[bt.frame as usize] & (1u32 << reg)) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_reg_mask(bt: &mut BacktrackState) -> Result<u32> {
    Ok(bt.reg_masks[bt.frame as usize])
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_reset(bt: &mut BacktrackState) -> Result<()> {
    let env = bt.env;
    *bt = BacktrackState::default();
    bt.env = env;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_set_frame_reg(bt: &mut BacktrackState, frame: u32, reg: u32) -> Result<()> {
    bt.reg_masks[frame as usize] |= 1u32 << reg;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_set_frame_slot(bt: &mut BacktrackState, frame: u32, slot: u32) -> Result<()> {
    bt.stack_masks[frame as usize] |= 1u64 << slot;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_set_reg(bt: &mut BacktrackState, reg: u32) -> Result<()> {
    bt_set_frame_reg(bt, bt.frame, reg)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_stack_mask(bt: &mut BacktrackState) -> Result<u64> {
    Ok(bt.stack_masks[bt.frame as usize])
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_subprog_enter(bt: &mut BacktrackState) -> Result<i32> {
    if bt.frame == (MAX_CALL_FRAMES - 1) as u32 {
        verifier_bug(bt.env, format!("subprog enter from frame {}", bt.frame));
        return Err(anyhow!("bt_subprog_enter failed"));
    }
    bt.frame += 1;
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt))]
pub fn bt_subprog_exit(bt: &mut BacktrackState) -> Result<i32> {
    if bt.frame == 0 {
        verifier_bug(bt.env, "subprog exit from frame 0");
        return Err(anyhow!("bt_subprog_exit failed"));
    }
    bt.frame -= 1;
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(bt, hist))]
pub fn bt_sync_linked_regs(bt: &mut BacktrackState, hist: &BpfJmpHistoryEntry) -> Result<()> {
    if hist.linked_regs == 0 {
        return Ok(());
    }

    let mut linked_regs = LinkedRegs::default();
    linked_regs_unpack(hist.linked_regs, &mut linked_regs);

    let mut some_precise = false;
    for i in 0..linked_regs.cnt as usize {
        let e: &LinkedReg = &linked_regs.entries[i];
        if (e.is_reg && bt_is_frame_reg_set(bt, e.frameno, e.regno)?)
            || (!e.is_reg && bt_is_frame_slot_set(bt, e.frameno, e.spi)?)
        {
            some_precise = true;
            break;
        }
    }

    if !some_precise {
        return Ok(());
    }

    for i in 0..linked_regs.cnt as usize {
        let e: &LinkedReg = &linked_regs.entries[i];
        if e.is_reg {
            bt_set_frame_reg(bt, e.frameno, e.regno)?;
        } else {
            bt_set_frame_slot(bt, e.frameno, e.spi)?;
        }
    }

    Ok(())
}
