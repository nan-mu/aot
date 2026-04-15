//! Missing types: LinkedRegs, LinkedReg

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(s))]
pub fn linked_regs_pack(s: &LinkedRegs) -> Result<u64> {
    let mut val: u64 = 0;

    for i in 0..s.cnt as usize {
        let e: &LinkedReg = &s.entries[i];
        let mut tmp: u64 = 0;

        tmp |= e.frameno as u64;
        tmp |= (e.spi as u64) << LR_SPI_OFF;
        tmp |= ((if e.is_reg { 1 } else { 0 }) as u64) << LR_IS_REG_OFF;

        val <<= LR_ENTRY_BITS;
        val |= tmp;
    }
    val <<= LR_SIZE_BITS;
    val |= s.cnt as u64;
    Ok(val)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(s))]
pub fn linked_regs_push(s: &mut LinkedRegs) -> Result<Option<&mut LinkedReg>> {
    if s.cnt < LINKED_REGS_MAX {
        let idx = s.cnt as usize;
        s.cnt += 1;
        return Ok(Some(&mut s.entries[idx]));
    }
    Ok(None)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(s))]
pub fn linked_regs_unpack(mut val: u64, s: &mut LinkedRegs) -> Result<()> {
    s.cnt = (val & LR_SIZE_MASK) as u32;
    val >>= LR_SIZE_BITS;

    for i in 0..s.cnt as usize {
        let e: &mut LinkedReg = &mut s.entries[i];

        e.frameno = (val & LR_FRAMENO_MASK) as i32;
        e.spi = ((val >> LR_SPI_OFF) & LR_SPI_MASK) as i32;
        e.is_reg = ((val >> LR_IS_REG_OFF) & 0x1) != 0;
        val >>= LR_ENTRY_BITS;
    }

    Ok(())
}
