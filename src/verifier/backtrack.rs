//! Missing types: BpfVerifierEnv, BpfJmpHistoryEntry, BacktrackState, BpfInsn

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, hist, bt))]
pub fn backtrack_insn(
    env: &mut BpfVerifierEnv,
    idx: i32,
    subseq_idx: i32,
    hist: &BpfJmpHistoryEntry,
    bt: &mut BacktrackState,
) -> Result<i32> {
    let insn: &BpfInsn = &env.prog.insnsi[idx as usize];
    let class = BPF_CLASS(insn.code);
    let opcode = BPF_OP(insn.code);

    if insn.code == 0 {
        return Ok(0);
    }

    /* If there is a history record that some registers gained range at this insn,
     * propagate precision marks to those registers, so that bt_is_reg_set()
     * accounts for these registers.
     */
    bt_sync_linked_regs(bt, hist);

    if class == BPF_ALU || class == BPF_ALU64 {
        if !bt_is_reg_set(bt, insn.dst_reg as u32) {
            return Ok(0);
        }

        if opcode == BPF_MOV && BPF_SRC(insn.code) == BPF_X && insn.src_reg != BPF_REG_FP {
            bt_clear_reg(bt, insn.dst_reg as u32);
            bt_set_reg(bt, insn.src_reg as u32);
            return Ok(0);
        }

        if opcode == BPF_MOV {
            bt_clear_reg(bt, insn.dst_reg as u32);
            return Ok(0);
        }
    }

    if class == BPF_LDX || is_atomic_load_insn(insn) || is_atomic_fetch_insn(insn) {
        let dreg = insn.dst_reg as u32;
        if !bt_is_reg_set(bt, dreg) {
            return Ok(0);
        }
        bt_clear_reg(bt, dreg);

        if (hist.flags & INSN_F_STACK_ACCESS) != 0 {
            let spi = insn_stack_access_spi(hist.flags);
            let fr = insn_stack_access_frameno(hist.flags);
            bt_set_frame_slot(bt, fr, spi);
        }
        return Ok(0);
    }

    if class == BPF_STX || class == BPF_ST {
        if bt_is_reg_set(bt, insn.dst_reg as u32) {
            return Err(anyhow!("backtrack_insn failed"));
        }
        return Ok(0);
    }

    if class == BPF_JMP || class == BPF_JMP32 {
        if opcode == BPF_CALL {
            bt_clear_reg(bt, BPF_REG_0 as u32);
            if insn.src_reg == BPF_REG_0 && insn.imm == BPF_FUNC_tail_call && subseq_idx - idx != 1 {
                if bt_subprog_enter(bt) != 0 {
                    return Err(anyhow!("backtrack_insn failed"));
                }
            }
            return Ok(0);
        }

        if opcode == BPF_EXIT {
            bt_clear_reg(bt, BPF_REG_0 as u32);
            if bt_subprog_enter(bt) != 0 {
                return Err(anyhow!("backtrack_insn failed"));
            }
            return Ok(0);
        }
    }

    /* Propagate precision marks to linked registers, to account for
     * registers marked as precise in this function.
     */
    bt_sync_linked_regs(bt, hist);
    Ok(0)
}
