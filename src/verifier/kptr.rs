//! Missing types: BtfRecord, BtfField, BtfStructMeta

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(kptr_field))]
pub fn kptr_pointee_btf_record(kptr_field: &BtfField) -> Result<Option<&BtfRecord>> {
    if btf_is_kernel(kptr_field.kptr.btf) {
        return Ok(None);
    }

    let meta: Option<&BtfStructMeta> = btf_find_struct_meta(kptr_field.kptr.btf, kptr_field.kptr.btf_id);
    Ok(meta.map(|m| &m.record))
}
