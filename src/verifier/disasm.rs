//! Missing types: BpfInsn, BtfType, Btf

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(data, insn))]
pub fn disasm_kfunc_name(data: *mut core::ffi::c_void, insn: &BpfInsn) -> Result<Option<&'static str>> {
    if insn.src_reg != BPF_PSEUDO_KFUNC_CALL {
        return Ok(None);
    }

    let desc_btf: &Btf = find_kfunc_desc_btf(data, insn.off)?;
    let func: &BtfType = btf_type_by_id(desc_btf, insn.imm as u32);
    Ok(Some(btf_name_by_offset(desc_btf, func.name_off)))
}
