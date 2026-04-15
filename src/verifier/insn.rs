//! Missing types: BpfInsn

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(insn))]
pub fn insn_def_regno(insn: &BpfInsn) -> Result<i32> {
    match BPF_CLASS(insn.code) {
        BPF_JMP | BPF_JMP32 | BPF_ST => Ok(-1),
        BPF_STX => {
            if BPF_MODE(insn.code) == BPF_ATOMIC || BPF_MODE(insn.code) == BPF_PROBE_ATOMIC {
                if insn.imm == BPF_CMPXCHG {
                    Ok(BPF_REG_0 as i32)
                } else if insn.imm == BPF_LOAD_ACQ {
                    Ok(insn.dst_reg as i32)
                } else if (insn.imm & BPF_FETCH) != 0 {
                    Ok(insn.src_reg as i32)
                } else {
                    Ok(-1)
                }
            } else {
                Ok(-1)
            }
        }
        _ => Ok(insn.dst_reg as i32),
    }
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(insn))]
pub fn insn_has_def32(insn: &BpfInsn) -> Result<bool> {
    let dst_reg = insn_def_regno(insn)?;
    if dst_reg == -1 {
        return Ok(false);
    }
    Ok(!is_reg64(insn, dst_reg, None, DST_OP))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn insn_is_cond_jump(code: u8) -> Result<bool> {
    let op = BPF_OP(code);
    if BPF_CLASS(code) == BPF_JMP32 {
        return Ok(op != BPF_JA);
    }
    if BPF_CLASS(code) != BPF_JMP {
        return Ok(false);
    }
    Ok(op != BPF_JA && op != BPF_EXIT && op != BPF_CALL)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn insn_stack_access_flags(frameno: i32, spi: i32) -> Result<i32> {
    Ok(INSN_F_STACK_ACCESS | (spi << INSN_F_SPI_SHIFT) | frameno)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn insn_stack_access_frameno(insn_flags: i32) -> Result<i32> {
    Ok(insn_flags & INSN_F_FRAMENO_MASK)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn insn_stack_access_spi(insn_flags: i32) -> Result<i32> {
    Ok((insn_flags >> INSN_F_SPI_SHIFT) & INSN_F_SPI_MASK)
}
