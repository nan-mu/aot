//! Missing types: BpfKfuncBtf, BpfKfuncDesc

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(a, b))]
pub fn kfunc_btf_cmp_by_off(a: &BpfKfuncBtf, b: &BpfKfuncBtf) -> Result<i32> {
    Ok(a.offset - b.offset)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(a, b))]
pub fn kfunc_desc_cmp_by_id_off(a: &BpfKfuncDesc, b: &BpfKfuncDesc) -> Result<i32> {
    /* func_id is not greater than BTF_MAX_TYPE */
    if a.func_id != b.func_id {
        return Ok(a.func_id as i32 - b.func_id as i32);
    }
    Ok(a.offset as i32 - b.offset as i32)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(a, b))]
pub fn kfunc_desc_cmp_by_imm_off(a: &BpfKfuncDesc, b: &BpfKfuncDesc) -> Result<i32> {
    if a.imm != b.imm {
        return Ok(if a.imm < b.imm { -1 } else { 1 });
    }
    if a.offset != b.offset {
        return Ok(if a.offset < b.offset { -1 } else { 1 });
    }
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn kfunc_spin_allowed(btf_id: u32) -> Result<bool> {
    Ok(is_bpf_graph_api_kfunc(btf_id)?
        || is_bpf_iter_num_api_kfunc(btf_id)?
        || is_bpf_res_spin_lock_kfunc(btf_id)?
        || is_bpf_arena_kfunc(btf_id)?
        || is_bpf_stream_kfunc(btf_id)?)
}
