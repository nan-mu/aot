//! Missing types: BpfInsn

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn jit_subprogs(env: &mut BpfVerifierEnv) -> Result<i32> {
    let prog: &mut BpfProg = env.prog;

    if env.subprog_cnt <= 1 {
        return Ok(0);
    }

    for i in 0..prog.len as usize {
        let insn: &mut BpfInsn = &mut prog.insnsi[i];
        if !bpf_pseudo_func(insn) && !bpf_pseudo_call(insn) {
            continue;
        }

        let subprog = find_subprog(env, i as i32 + insn.imm + 1)?;
        insn.off = subprog as i16;
        env.insn_aux_data[i].call_imm = insn.imm;
        insn.imm = 1;
    }

    if bpf_prog_alloc_jited_linfo(prog)? != 0 {
        return Err(anyhow::anyhow!("jit_subprogs failed"));
    }

    let mut func: Vec<Option<BpfProg>> = vec![None; env.subprog_cnt as usize];
    let mut subprog_end = 0;

    for i in 0..env.subprog_cnt as usize {
        let subprog_start = subprog_end;
        subprog_end = env.subprog_info[i + 1].start;
        let len = subprog_end - subprog_start;

        let mut f = bpf_prog_alloc_no_stats(bpf_prog_size(len as usize))
            .ok_or_else(|| anyhow::anyhow!("jit_subprogs failed"))?;
        f.insnsi.copy_from_slice(&prog.insnsi[subprog_start as usize..subprog_end as usize]);
        f.r#type = prog.r#type;
        f.len = len;
        f.is_func = true;
        f.sleepable = prog.sleepable;
        f.aux.func_idx = i as i32;
        f.jit_requested = true;

        let jited = bpf_int_jit_compile(f);
        if !jited.jited {
            return Err(anyhow::anyhow!("jit_subprogs failed"));
        }
        func[i] = Some(jited);
    }

    prog.jited = true;
    Ok(0)
}
