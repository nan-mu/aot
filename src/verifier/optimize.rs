//! Missing types: BpfVerifierEnv, BpfSubprogInfo, BpfInsn

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn optimize_bpf_loop(env: &mut BpfVerifierEnv) -> Result<i32> {
    let subprogs: &mut [BpfSubprogInfo] = &mut env.subprog_info;
    let mut cur_subprog = 0usize;
    let mut delta = 0i32;
    let insn_cnt = env.prog.len as i32;

    let mut stack_depth = subprogs[cur_subprog].stack_depth;
    let mut stack_depth_roundup = round_up(stack_depth as i32, 8) as u16 - stack_depth;
    let mut stack_depth_extra = 0u16;

    let mut i = 0i32;
    while i < insn_cnt {
        let insn = env.prog.insnsi[(i + delta) as usize];
        let inline_state = &env.insn_aux_data[(i + delta) as usize].loop_inline_state;

        if is_bpf_loop_call(&insn)? && inline_state.fit_for_inline {
            stack_depth_extra = BPF_REG_SIZE as u16 * 3 + stack_depth_roundup;
            let mut cnt = 0u32;
            let new_prog = inline_bpf_loop(
                env,
                i + delta,
                -((stack_depth + stack_depth_extra) as i32),
                inline_state.callback_subprogno,
                &mut cnt,
            )?;

            delta += cnt as i32 - 1;
            env.prog = new_prog;
        }

        if subprogs[cur_subprog + 1].start == (i + delta + 1) as u32 {
            subprogs[cur_subprog].stack_depth += stack_depth_extra;
            cur_subprog += 1;
            stack_depth = subprogs[cur_subprog].stack_depth;
            stack_depth_roundup = round_up(stack_depth as i32, 8) as u16 - stack_depth;
            stack_depth_extra = 0;
        }

        i += 1;
    }

    env.prog.aux.stack_depth = env.subprog_info[0].stack_depth;
    Ok(0)
}
