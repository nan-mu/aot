//! Missing types: BpfVerifierEnv, BpfCallArgMeta, BpfInsnAuxData, BpfMap, BpfRegState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, meta))]
pub fn record_func_key(
    env: &mut BpfVerifierEnv,
    meta: &mut BpfCallArgMeta,
    func_id: i32,
    insn_idx: i32,
) -> Result<i32> {
    let aux: &mut BpfInsnAuxData = &mut env.insn_aux_data[insn_idx as usize];
    let map: &BpfMap = meta.map.ptr;

    if func_id != BPF_FUNC_tail_call {
        return Ok(0);
    }
    if map.map_type != BPF_MAP_TYPE_PROG_ARRAY {
        verbose(env, "expected prog array map for tail call");
        return Err(anyhow!("record_func_key failed"));
    }

    let reg: &mut BpfRegState = reg_state(env, BPF_REG_3);
    let val = reg.var_off.value;
    let max = map.max_entries as u64;

    if !(is_reg_const(reg, false) && val < max) {
        bpf_map_key_store(aux, BPF_MAP_KEY_POISON);
        return Ok(0);
    }

    mark_chain_precision(env, BPF_REG_3)?;
    if bpf_map_key_unseen(aux) {
        bpf_map_key_store(aux, val);
    } else if !bpf_map_key_poisoned(aux) && bpf_map_key_immediate(aux) != val {
        bpf_map_key_store(aux, BPF_MAP_KEY_POISON);
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, meta))]
pub fn record_func_map(
    env: &mut BpfVerifierEnv,
    meta: &mut BpfCallArgMeta,
    func_id: i32,
    insn_idx: i32,
) -> Result<i32> {
    let aux: &mut BpfInsnAuxData = &mut env.insn_aux_data[insn_idx as usize];
    let map: &BpfMap = meta.map.ptr;

    if func_id != BPF_FUNC_tail_call
        && func_id != BPF_FUNC_map_lookup_elem
        && func_id != BPF_FUNC_map_update_elem
        && func_id != BPF_FUNC_map_delete_elem
        && func_id != BPF_FUNC_map_push_elem
        && func_id != BPF_FUNC_map_pop_elem
        && func_id != BPF_FUNC_map_peek_elem
        && func_id != BPF_FUNC_for_each_map_elem
        && func_id != BPF_FUNC_redirect_map
        && func_id != BPF_FUNC_map_lookup_percpu_elem
    {
        return Ok(0);
    }

    if (map.map_flags & BPF_F_RDONLY_PROG) != 0
        && (func_id == BPF_FUNC_map_delete_elem
            || func_id == BPF_FUNC_map_update_elem
            || func_id == BPF_FUNC_map_push_elem
            || func_id == BPF_FUNC_map_pop_elem)
    {
        verbose(env, "write into map forbidden\n");
        return Err(anyhow!("record_func_map failed"));
    }

    if aux.map_ptr_state.map_ptr.is_none() {
        bpf_map_ptr_store(aux, meta.map.ptr, !meta.map.ptr.bypass_spec_v1, false);
    } else if aux.map_ptr_state.map_ptr != Some(meta.map.ptr) {
        bpf_map_ptr_store(aux, meta.map.ptr, !meta.map.ptr.bypass_spec_v1, true);
    }

    Ok(0)
}
