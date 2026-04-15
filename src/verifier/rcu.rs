//! Missing types: BtfField

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(field))]
pub fn rcu_safe_kptr(field: &BtfField) -> Result<bool> {
    let kptr = &field.kptr;

    Ok(field.r#type == BPF_KPTR_PERCPU
        || (field.r#type == BPF_KPTR_REF && rcu_protected_object(kptr.btf, kptr.btf_id)))
}
