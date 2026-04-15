//! Missing types: Btf, BtfType, BpfVerifierState, BpfRegState, BpfRegType, BpfProg, BpfKfuncDesc, BpfVerifierEnv, BpfReferenceState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(btf))]
pub fn find_btf_percpu_datasec(btf: &Btf) -> Result<i32> {
    let n = btf_nr_types(btf);
    for i in btf_named_start_id(btf, true)..n {
        let t: &BtfType = btf_type_by_id(btf, i as u32);
        if BTF_INFO_KIND(t.info) != BTF_KIND_DATASEC {
            continue;
        }
        let tname = btf_name_by_offset(btf, t.name_off);
        if tname == ".data..percpu" {
            return Ok(i as i32);
        }
    }
    Err(anyhow!("find_btf_percpu_datasec failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(vstate, dst_reg))]
pub fn find_good_pkt_pointers(
    vstate: &mut BpfVerifierState,
    dst_reg: &BpfRegState,
    r#type: BpfRegType,
    range_right_open: bool,
) -> Result<()> {
    if dst_reg.off < 0 || (dst_reg.off == 0 && range_right_open) {
        return Ok(());
    }
    if dst_reg.umax_value > MAX_PACKET_OFF || dst_reg.umax_value + dst_reg.off as u64 > MAX_PACKET_OFF {
        return Ok(());
    }

    let mut new_range = dst_reg.off as i32;
    if range_right_open {
        new_range += 1;
    }

    bpf_for_each_reg_in_vstate(vstate, |reg: &mut BpfRegState| {
        if reg.r#type == r#type && reg.id == dst_reg.id {
            reg.range = core::cmp::max(reg.range, new_range);
        }
    });

    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(prog))]
pub fn find_kfunc_desc(prog: &BpfProg, func_id: u32, offset: u16) -> Result<&BpfKfuncDesc> {
    let desc = BpfKfuncDesc { func_id, offset };
    let tab = prog.aux.kfunc_tab;
    bsearch_kfunc_desc(&desc, tab).ok_or_else(|| anyhow!("find_kfunc_desc failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn find_kfunc_desc_btf(env: &mut BpfVerifierEnv, offset: i16) -> Result<&Btf> {
    if offset < 0 {
        verbose(env, "negative offset disallowed for kernel module function call\n");
        return Err(anyhow!("find_kfunc_desc_btf failed"));
    }
    if offset == 0 {
        return btf_vmlinux_ref().ok_or_else(|| anyhow!("find_kfunc_desc_btf failed"));
    }
    inner_find_kfunc_desc_btf(env, offset)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, btf))]
pub fn find_kfunc_impl_proto(env: &mut BpfVerifierEnv, btf: &Btf, func_name: &str) -> Result<&BtfType> {
    let buf = format!("{}{}", func_name, KF_IMPL_SUFFIX);
    if buf.len() >= TMP_STR_BUF_LEN as usize {
        verbose(env, format!("function name {}{} is too long\n", func_name, KF_IMPL_SUFFIX));
        return Err(anyhow!("find_kfunc_impl_proto failed"));
    }
    let impl_id = btf_find_by_name_kind(btf, &buf, BTF_KIND_FUNC);
    if impl_id <= 0 {
        verbose(env, format!("cannot find function {} in BTF\n", buf));
        return Err(anyhow!("find_kfunc_impl_proto failed"));
    }
    let func = btf_type_by_id(btf, impl_id as u32);
    Ok(btf_type_by_id(btf, func.r#type))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(state))]
pub fn find_lock_state(
    state: &mut BpfVerifierState,
    r#type: RefStateType,
    id: i32,
    ptr: *mut core::ffi::c_void,
) -> Result<Option<&mut BpfReferenceState>> {
    for i in 0..state.acquired_refs as usize {
        let s = &mut state.refs[i];
        if (s.r#type & r#type) == 0 {
            continue;
        }
        if s.id == id && s.ptr == ptr {
            return Ok(Some(s));
        }
    }
    Ok(None)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(state))]
pub fn find_reference_state(state: &BpfVerifierState, ptr_id: i32) -> Result<bool> {
    for i in 0..state.acquired_refs as usize {
        if state.refs[i].id == ptr_id {
            return Ok(true);
        }
    }
    Ok(false)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn find_subprog(env: &mut BpfVerifierEnv, off: i32) -> Result<i32> {
    let p = bpf_find_containing_subprog(env, off);
    if p.is_none() || p.unwrap().start != off {
        return Err(anyhow!("find_subprog failed"));
    }
    Ok((p.unwrap() as *const _ as usize - env.subprog_info.as_ptr() as usize) as i32)
}
