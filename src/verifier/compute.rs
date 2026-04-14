//! Missing types: BpfVerifierEnv, BpfInsn, InsnLiveRegs

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, insn, info))]
pub fn compute_insn_live_regs(
    env: &mut BpfVerifierEnv,
    insn: &BpfInsn,
    info: &mut InsnLiveRegs,
) -> Result<()> {
    let class = BPF_CLASS(insn.code);
    let code = BPF_OP(insn.code);
    let src = BIT(insn.src_reg as u32);
    let dst = BIT(insn.dst_reg as u32);
    let r0 = BIT(0);
    let mut def = 0u16;
    let mut use_mask = 0xffffu16;

    if class == BPF_ALU || class == BPF_ALU64 {
        match code {
            BPF_END => {
                use_mask = dst;
                def = dst;
            }
            BPF_MOV => {
                def = dst;
                use_mask = if BPF_SRC(insn.code) == BPF_K { 0 } else { src };
            }
            _ => {
                def = dst;
                use_mask = if BPF_SRC(insn.code) == BPF_K { dst } else { dst | src };
            }
        }
    }

    if class == BPF_JMP || class == BPF_JMP32 {
        if code == BPF_EXIT {
            def = 0;
            use_mask = r0;
        }
    }

    let _ = env;
    info.def = def;
    info.use_mask = use_mask;
    Ok(())
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn compute_live_registers(env: &mut BpfVerifierEnv) -> Result<i32> {
    let insn_cnt = env.prog.len as usize;
    let mut state = vec![InsnLiveRegs::default(); insn_cnt];

    for i in 0..insn_cnt {
        compute_insn_live_regs(env, &env.prog.insnsi[i], &mut state[i])?;
    }

    for i in 0..insn_cnt {
        env.insn_aux_data[i].live_regs_before = state[i].in_mask;
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn compute_postorder(env: &mut BpfVerifierEnv) -> Result<i32> {
    let mut cur_postorder = 0u32;

    for i in 0..env.subprog_cnt as usize {
        env.subprog_info[i].postorder_start = cur_postorder;
        cur_postorder += 1;
    }

    env.cfg.cur_postorder = cur_postorder as i32;
    Ok(0)
}
