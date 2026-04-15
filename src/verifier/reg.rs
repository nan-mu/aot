//! Missing types: BpfVerifierEnv, BpfRegState, BtfRecord, BtfField, BpfIdmap

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn reg_bounds_sanity_check(env: &mut BpfVerifierEnv, reg: &mut BpfRegState, ctx: &str) -> Result<i32> {
    let msg: &str;

    if reg.umin_value > reg.umax_value
        || reg.smin_value > reg.smax_value
        || reg.u32_min_value > reg.u32_max_value
        || reg.s32_min_value > reg.s32_max_value
    {
        msg = "range bounds violation";
        if env.test_reg_invariants {
            return Err(anyhow!("{}", msg));
        }
        inner_mark_reg_unbounded(reg);
        return Ok(0);
    }

    if tnum_is_const(reg.var_off) {
        let uval = reg.var_off.value;
        let sval = uval as i64;
        if reg.umin_value != uval
            || reg.umax_value != uval
            || reg.smin_value != sval
            || reg.smax_value != sval
        {
            msg = "const tnum out of sync with range bounds";
            if env.test_reg_invariants {
                return Err(anyhow!("{}", msg));
            }
            inner_mark_reg_unbounded(reg);
            return Ok(0);
        }
    }

    if tnum_subreg_is_const(reg.var_off) {
        let uval32 = tnum_subreg(reg.var_off).value as u32;
        let sval32 = uval32 as i32;
        if reg.u32_min_value != uval32
            || reg.u32_max_value != uval32
            || reg.s32_min_value != sval32
            || reg.s32_max_value != sval32
        {
            msg = "const subreg tnum out of sync with range bounds";
            if env.test_reg_invariants {
                return Err(anyhow!("{}", msg));
            }
            inner_mark_reg_unbounded(reg);
            return Ok(0);
        }
    }

    let _ = ctx;
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reg_bounds_sync(reg: &mut BpfRegState) -> Result<()> {
    inner_update_reg_bounds(reg);
    inner_reg_deduce_bounds(reg);
    inner_reg_deduce_bounds(reg);
    inner_reg_deduce_bounds(reg);
    inner_reg_bound_offset(reg);
    inner_update_reg_bounds(reg);
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reg_btf_record(reg: &BpfRegState) -> Result<Option<&BtfRecord>> {
    if reg.r#type == PTR_TO_MAP_VALUE {
        return Ok(Some(reg.map_ptr.record));
    }
    if type_is_ptr_alloc_obj(reg.r#type) {
        let meta = btf_find_struct_meta(reg.btf, reg.btf_id);
        return Ok(meta.map(|m| m.record));
    }
    Ok(None)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reg_const_value(reg: &BpfRegState, subreg32: bool) -> Result<u64> {
    Ok(if subreg32 {
        tnum_subreg(reg.var_off).value
    } else {
        reg.var_off.value
    })
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reg_find_field_offset(reg: &BpfRegState, off: i32, fields: u32) -> Result<Option<&BtfField>> {
    let rec = reg_btf_record(reg)?;
    if rec.is_none() {
        return Ok(None);
    }
    Ok(btf_record_find(rec.unwrap(), off, fields))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reg_is_dynptr_slice_pkt(reg: &BpfRegState) -> Result<bool> {
    Ok(base_type(reg.r#type) == PTR_TO_MEM
        && (reg.r#type & (DYNPTR_TYPE_SKB | DYNPTR_TYPE_XDP | DYNPTR_TYPE_SKB_META)) != 0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reg_is_init_pkt_pointer(reg: &BpfRegState, which: BpfRegType) -> Result<bool> {
    Ok(reg.r#type == which && reg.id == 0 && reg.off == 0 && tnum_equals_const(reg.var_off, 0))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reg_is_pkt_pointer(reg: &BpfRegState) -> Result<bool> {
    Ok(type_is_pkt_pointer(reg.r#type))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reg_is_pkt_pointer_any(reg: &BpfRegState) -> Result<bool> {
    Ok(reg_is_pkt_pointer(reg)? || reg.r#type == PTR_TO_PACKET_END)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reg_may_point_to_spin_lock(reg: &BpfRegState) -> Result<bool> {
    Ok(btf_record_has_field(reg_btf_record(reg)?, BPF_SPIN_LOCK | BPF_RES_SPIN_LOCK))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(reg))]
pub fn reg_not_null(reg: &BpfRegState) -> Result<bool> {
    let mut t = reg.r#type;
    if type_may_be_null(t) {
        return Ok(false);
    }

    t = base_type(t);
    Ok(t == PTR_TO_SOCKET
        || t == PTR_TO_TCP_SOCK
        || t == PTR_TO_MAP_VALUE
        || t == PTR_TO_MAP_KEY
        || t == PTR_TO_SOCK_COMMON
        || (t == PTR_TO_BTF_ID && is_trusted_reg(reg))
        || (t == PTR_TO_MEM && (reg.r#type & PTR_UNTRUSTED) == 0)
        || t == CONST_PTR_TO_MAP)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, true_reg1, true_reg2, false_reg1, false_reg2))]
pub fn reg_set_min_max(
    env: &mut BpfVerifierEnv,
    true_reg1: &mut BpfRegState,
    true_reg2: &mut BpfRegState,
    false_reg1: &mut BpfRegState,
    false_reg2: &mut BpfRegState,
    opcode: u8,
    is_jmp32: bool,
) -> Result<i32> {
    if false_reg1.r#type != SCALAR_VALUE || false_reg2.r#type != SCALAR_VALUE {
        return Ok(0);
    }
    if core::ptr::eq(false_reg1, false_reg2) {
        return Ok(0);
    }

    regs_refine_cond_op(false_reg1, false_reg2, rev_opcode(opcode), is_jmp32)?;
    reg_bounds_sync(false_reg1)?;
    reg_bounds_sync(false_reg2)?;

    regs_refine_cond_op(true_reg1, true_reg2, opcode, is_jmp32)?;
    reg_bounds_sync(true_reg1)?;
    reg_bounds_sync(true_reg2)?;

    reg_bounds_sanity_check(env, true_reg1, "true_reg1")?;
    reg_bounds_sanity_check(env, true_reg2, "true_reg2")?;
    reg_bounds_sanity_check(env, false_reg1, "false_reg1")?;
    reg_bounds_sanity_check(env, false_reg2, "false_reg2")?;
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn reg_state(env: &mut BpfVerifierEnv, regno: i32) -> Result<&mut BpfRegState> {
    Ok(&mut cur_regs(env)[regno as usize])
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn reg_type_mismatch(src: BpfRegType, prev: BpfRegType) -> Result<bool> {
    Ok(src != prev && (!reg_type_mismatch_ok(src)? || !reg_type_mismatch_ok(prev)?))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn reg_type_mismatch_ok(r#type: BpfRegType) -> Result<bool> {
    Ok(!matches!(
        base_type(r#type),
        PTR_TO_CTX
            | PTR_TO_SOCKET
            | PTR_TO_SOCK_COMMON
            | PTR_TO_TCP_SOCK
            | PTR_TO_XDP_SOCK
            | PTR_TO_BTF_ID
            | PTR_TO_ARENA
    ))
}
