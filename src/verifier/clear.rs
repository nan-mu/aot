//! Missing types: BpfVerifierEnv, BpfRegState, BpfVerifierState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn clear_all_pkt_pointers(env: &mut BpfVerifierEnv) -> Result<()> {
    bpf_for_each_reg_in_vstate(env.cur_state, |reg| {
        if reg_is_pkt_pointer_any(reg) || reg_is_dynptr_slice_pkt(reg) {
            mark_reg_invalid(env, reg);
        }
    });
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, regs))]
pub fn clear_caller_saved_regs(env: &mut BpfVerifierEnv, regs: &mut [BpfRegState]) -> Result<()> {
    /* after the call registers r0 - r5 were scratched */
    for i in 0..CALLER_SAVED_REGS as usize {
        mark_reg_not_init(env, regs, caller_saved[i]);
        inner_check_reg_arg(env, regs, caller_saved[i], DST_OP_NO_MARK);
    }
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn clear_insn_aux_data(env: &mut BpfVerifierEnv, start: i32, len: i32) -> Result<()> {
    let end = start + len;
    let mut i = start;
    while i < end {
        let aux = &mut env.insn_aux_data[i as usize];
        if aux.jt.is_some() {
            aux.jt = None;
        }

        if bpf_is_ldimm64(&env.prog.insnsi[i as usize]) {
            i += 1;
        }
        i += 1;
    }
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(state))]
pub fn clear_jmp_history(state: &mut BpfVerifierState) -> Result<()> {
    state.jmp_history = None;
    state.jmp_history_cnt = 0;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(flag))]
pub fn clear_trusted_flags(flag: &mut u32) -> Result<()> {
    *flag &= !(BPF_REG_TRUSTED_MODIFIERS | MEM_RCU);
    Ok(())
}
