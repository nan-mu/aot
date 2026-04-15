//! Missing types: BpfRegState, BpfIdmap

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(rold, rcur, idmap))]
pub fn regs_exact(rold: &BpfRegState, rcur: &BpfRegState, idmap: &mut BpfIdmap) -> Result<bool> {
    Ok(
        regs_equal_except_ids(rold, rcur)
            && check_ids(rold.id, rcur.id, idmap)
            && check_ids(rold.ref_obj_id, rcur.ref_obj_id, idmap),
    )
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg1, reg2))]
pub fn regs_refine_cond_op(
    reg1: &mut BpfRegState,
    reg2: &mut BpfRegState,
    mut opcode: u8,
    is_jmp32: bool,
) -> Result<()> {
    if matches!(opcode, BPF_JGE | BPF_JGT | BPF_JSGE | BPF_JSGT) {
        opcode = flip_opcode(opcode)?;
        core::mem::swap(reg1, reg2);
    }

    match opcode {
        BPF_JEQ => {
            if is_jmp32 {
                reg1.u32_min_value = reg1.u32_min_value.max(reg2.u32_min_value);
                reg1.u32_max_value = reg1.u32_max_value.min(reg2.u32_max_value);
                reg1.s32_min_value = reg1.s32_min_value.max(reg2.s32_min_value);
                reg1.s32_max_value = reg1.s32_max_value.min(reg2.s32_max_value);
                reg2.u32_min_value = reg1.u32_min_value;
                reg2.u32_max_value = reg1.u32_max_value;
                reg2.s32_min_value = reg1.s32_min_value;
                reg2.s32_max_value = reg1.s32_max_value;

                let t = tnum_intersect(tnum_subreg(reg1.var_off), tnum_subreg(reg2.var_off));
                reg1.var_off = tnum_with_subreg(reg1.var_off, t);
                reg2.var_off = tnum_with_subreg(reg2.var_off, t);
            } else {
                reg1.umin_value = reg1.umin_value.max(reg2.umin_value);
                reg1.umax_value = reg1.umax_value.min(reg2.umax_value);
                reg1.smin_value = reg1.smin_value.max(reg2.smin_value);
                reg1.smax_value = reg1.smax_value.min(reg2.smax_value);
                reg2.umin_value = reg1.umin_value;
                reg2.umax_value = reg1.umax_value;
                reg2.smin_value = reg1.smin_value;
                reg2.smax_value = reg1.smax_value;
                reg1.var_off = tnum_intersect(reg1.var_off, reg2.var_off);
                reg2.var_off = reg1.var_off;
            }
        }
        _ => {}
    }

    Ok(())
}
