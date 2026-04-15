//! Missing types: BpfVerifierEnv, BpfRegState, BtfRecord

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn ref_convert_owning_non_owning(env: &mut BpfVerifierEnv, ref_obj_id: u32) -> Result<i32> {
    let state = &mut env.cur_state;

    if ref_obj_id == 0 {
        return Err(anyhow!("ref_convert_owning_non_owning failed"));
    }

    for i in 0..state.acquired_refs as usize {
        if state.refs[i].id != ref_obj_id {
            continue;
        }

        bpf_for_each_reg_in_vstate(env.cur_state, |reg: &mut BpfRegState| {
            if reg.ref_obj_id == ref_obj_id {
                reg.ref_obj_id = 0;
                let _ = ref_set_non_owning(env, reg);
            }
        });
        return Ok(0);
    }

    Err(anyhow!("ref_convert_owning_non_owning failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn ref_set_non_owning(env: &mut BpfVerifierEnv, reg: &mut BpfRegState) -> Result<i32> {
    let rec: &BtfRecord = reg_btf_record(reg);

    if env.cur_state.active_locks == 0 {
        return Err(anyhow!("ref_set_non_owning failed"));
    }
    if (type_flag(reg.r#type) & NON_OWN_REF) != 0 {
        return Err(anyhow!("ref_set_non_owning failed"));
    }

    reg.r#type |= NON_OWN_REF;
    if rec.refcount_off >= 0 {
        reg.r#type |= MEM_RCU;
    }

    Ok(0)
}
