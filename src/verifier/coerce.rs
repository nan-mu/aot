//! Missing types: BpfRegState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn coerce_reg_to_size(reg: &mut BpfRegState, size: i32) -> Result<()> {
    let mask: u64;

    /* clear high bits in bit representation */
    reg.var_off = tnum_cast(reg.var_off, size);

    /* fix arithmetic bounds */
    mask = ((1u64) << (size * 8)) - 1;
    if (reg.umin_value & !mask) == (reg.umax_value & !mask) {
        reg.umin_value &= mask;
        reg.umax_value &= mask;
    } else {
        reg.umin_value = 0;
        reg.umax_value = mask;
    }
    reg.smin_value = reg.umin_value as i64;
    reg.smax_value = reg.umax_value as i64;

    /* If size is smaller than 32bit register the 32bit register
     * values are also truncated so we push 64-bit bounds into
     * 32-bit bounds. Above were truncated < 32-bits already.
     */
    if size < 4 {
        inner_mark_reg32_unbounded(reg);
    }

    reg_bounds_sync(reg);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn coerce_reg_to_size_sx(reg: &mut BpfRegState, size: i32) -> Result<()> {
    if tnum_is_const(reg.var_off) {
        let mut v = reg.var_off.value;
        if size == 1 {
            v = (v as i8) as i64 as u64;
        } else if size == 2 {
            v = (v as i16) as i64 as u64;
        } else {
            v = (v as i32) as i64 as u64;
        }
        reg.var_off = tnum_const(v);
        reg.smax_value = v as i64;
        reg.smin_value = v as i64;
        reg.umax_value = v;
        reg.umin_value = v;
        reg.s32_max_value = v as i32;
        reg.s32_min_value = v as i32;
        reg.u32_max_value = v as u32;
        reg.u32_min_value = v as u32;
        return Ok(());
    }

    set_sext64_default_val(reg, size);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn coerce_subreg_to_size_sx(reg: &mut BpfRegState, size: i32) -> Result<()> {
    if tnum_is_const(reg.var_off) {
        let mut v = reg.var_off.value as u32;
        if size == 1 {
            v = (v as i8) as i32 as u32;
        } else {
            v = (v as i16) as i32 as u32;
        }
        reg.var_off = tnum_const(v as u64);
        reg.s32_min_value = v as i32;
        reg.s32_max_value = v as i32;
        reg.u32_min_value = v;
        reg.u32_max_value = v;
        return Ok(());
    }

    set_sext32_default_val(reg, size);
    Ok(())
}
