//! Missing types: BpfVerifierState, BpfIdmap

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(old, cur, idmap))]
pub fn refsafe(old: &BpfVerifierState, cur: &BpfVerifierState, idmap: &mut BpfIdmap) -> Result<bool> {
    if old.acquired_refs != cur.acquired_refs
        || old.active_locks != cur.active_locks
        || old.active_preempt_locks != cur.active_preempt_locks
        || old.active_rcu_locks != cur.active_rcu_locks
    {
        return Ok(false);
    }

    if !check_ids(old.active_irq_id, cur.active_irq_id, idmap)
        || !check_ids(old.active_lock_id, cur.active_lock_id, idmap)
        || old.active_lock_ptr != cur.active_lock_ptr
    {
        return Ok(false);
    }

    for i in 0..old.acquired_refs as usize {
        if !check_ids(old.refs[i].id, cur.refs[i].id, idmap)
            || old.refs[i].r#type != cur.refs[i].r#type
        {
            return Ok(false);
        }

        match old.refs[i].r#type {
            REF_TYPE_PTR | REF_TYPE_IRQ => {}
            REF_TYPE_LOCK | REF_TYPE_RES_LOCK | REF_TYPE_RES_LOCK_IRQ => {
                if old.refs[i].ptr != cur.refs[i].ptr {
                    return Ok(false);
                }
            }
            _ => return Ok(false),
        }
    }

    Ok(true)
}
