//! Missing types: BpfVerifierEnv, BpfProg, BpfInsn, BpfKfuncDesc, BtfStructMeta, BpfInsnAuxData

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn fixup_call_args(env: &mut BpfVerifierEnv) -> Result<i32> {
    let mut err = 0;

    if env.prog.jit_requested && !bpf_prog_is_offloaded(env.prog.aux) {
        err = jit_subprogs(env)?;
        if err == 0 {
            return Ok(0);
        }
        if err == -EFAULT {
            return Err(anyhow!("fixup_call_args failed"));
        }
    }

    if bpf_prog_has_kfunc_call(env.prog) {
        verbose(env, "calling kernel functions are not allowed in non-JITed programs\n");
        return Err(anyhow!("fixup_call_args failed"));
    }

    for i in 0..env.prog.len as usize {
        let insn = &mut env.prog.insnsi[i];
        if bpf_pseudo_func(insn) {
            verbose(env, "callbacks are not allowed in non-JITed programs\n");
            return Err(anyhow!("fixup_call_args failed"));
        }
        if !bpf_pseudo_call(insn) {
            continue;
        }
        let depth = get_callee_stack_depth(env, insn, i as i32)?;
        bpf_patch_call_args(insn, depth);
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn, insn_buf, cnt))]
pub fn fixup_kfunc_call(
    env: &mut BpfVerifierEnv,
    insn: &mut BpfInsn,
    insn_buf: &mut [BpfInsn],
    insn_idx: i32,
    cnt: &mut i32,
) -> Result<i32> {
    if insn.imm == 0 {
        verbose(env, "invalid kernel function call not eliminated in verifier pass\n");
        return Err(anyhow!("fixup_kfunc_call failed"));
    }

    *cnt = 0;
    let desc: &BpfKfuncDesc = find_kfunc_desc(env.prog, insn.imm as u32, insn.off as u16)?;
    specialize_kfunc(env, desc, insn_idx)?;

    if !bpf_jit_supports_far_kfunc_call() {
        insn.imm = BPF_CALL_IMM(desc.addr);
    }

    if env.insn_aux_data[insn_idx as usize].arg_prog != 0 {
        let regno = env.insn_aux_data[insn_idx as usize].arg_prog;
        let ld_addrs = [BPF_LD_IMM64(regno, env.prog.aux as i64), BpfInsn::default()];
        let mut idx = *cnt as usize;
        insn_buf[idx] = ld_addrs[0];
        idx += 1;
        insn_buf[idx] = ld_addrs[1];
        idx += 1;
        insn_buf[idx] = *insn;
        *cnt = idx as i32 + 1;
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(insn_aux, insn, insn_buf, cnt))]
pub fn inner_fixup_collection_insert_kfunc(
    insn_aux: &BpfInsnAuxData,
    struct_meta_reg: u16,
    node_offset_reg: u16,
    insn: &BpfInsn,
    insn_buf: &mut [BpfInsn],
    cnt: &mut i32,
) -> Result<()> {
    let kptr_struct_meta: &BtfStructMeta = insn_aux.kptr_struct_meta;
    let addr = [BPF_LD_IMM64(struct_meta_reg as u8, kptr_struct_meta as *const _ as i64), BpfInsn::default()];

    insn_buf[0] = addr[0];
    insn_buf[1] = addr[1];
    insn_buf[2] = BPF_MOV64_IMM(node_offset_reg as u8, insn_aux.insert_off as i64);
    insn_buf[3] = *insn;
    *cnt = 4;
    Ok(())
}
