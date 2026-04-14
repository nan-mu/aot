//! Missing types: BpfVerifierEnv, BpfProg, BpfAttr, BpfPtr, BpfInsnAuxData, BpfLineInfo

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn bpf_adj_linfo_after_remove(env: &mut BpfVerifierEnv, off: u32, cnt: u32) -> Result<i32> {
    let prog: &mut BpfProg = env.prog;
    let mut i: u32;
    let l_off: u32;
    let mut l_cnt: u32;
    let mut nr_linfo = prog.aux.nr_linfo;

    if nr_linfo == 0 {
        return Ok(0);
    }

    let linfo: &mut [BpfLineInfo] = prog.aux.linfo;

    /* find first line info to remove, count lines to be removed */
    i = 0;
    while i < nr_linfo {
        if linfo[i as usize].insn_off >= off {
            break;
        }
        i += 1;
    }

    l_off = i;
    l_cnt = 0;
    while i < nr_linfo {
        if linfo[i as usize].insn_off < off + cnt {
            l_cnt += 1;
            i += 1;
        } else {
            break;
        }
    }

    /* First live insn doesn't match first live linfo, it needs to "inherit"
     * last removed linfo. prog is already modified, so prog->len == off
     * means no live instructions after (tail of the program was removed).
     */
    if prog.len != off && l_cnt != 0 && (i == nr_linfo || linfo[i as usize].insn_off != off + cnt) {
        l_cnt -= 1;
        i -= 1;
        linfo[i as usize].insn_off = off + cnt;
    }

    /* remove the line info which refer to the removed instructions */
    if l_cnt != 0 {
        let src = i as usize;
        let dst = l_off as usize;
        let keep = (nr_linfo - i) as usize;
        for k in 0..keep {
            linfo[dst + k] = linfo[src + k].clone();
        }

        prog.aux.nr_linfo -= l_cnt;
        nr_linfo = prog.aux.nr_linfo;
    }

    /* pull all linfo[i].insn_off >= off + cnt in by cnt */
    i = l_off;
    while i < nr_linfo {
        linfo[i as usize].insn_off -= cnt;
        i += 1;
    }

    /* fix up all subprogs (incl. 'exit') which start >= off */
    for idx in 0..=env.subprog_cnt as usize {
        if env.subprog_info[idx].linfo_idx > l_off {
            /* program may have started in the removed region but
             * may not be fully removed
             */
            if env.subprog_info[idx].linfo_idx >= l_off + l_cnt {
                env.subprog_info[idx].linfo_idx -= l_cnt;
            } else {
                env.subprog_info[idx].linfo_idx = l_off;
            }
        }
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn bpf_calls_callback(env: &mut BpfVerifierEnv, insn_idx: i32) -> Result<bool> {
    Ok(env.insn_aux_data[insn_idx as usize].calls_callback)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(prog, attr, uattr))]
pub fn bpf_check(
    prog: &mut BpfProg,
    attr: &BpfAttr,
    uattr: &BpfPtr,
    uattr_size: u32,
) -> Result<i32> {
    let _ = uattr_size;

    if bpf_verifier_ops_count() == 0 {
        return Err(anyhow!("bpf_check failed"));
    }

    let mut env = alloc_verifier_env().context("bpf_check failed")?;
    env.prog = prog;

    init_vlog(&mut env.log, attr.log_level, attr.log_buf, attr.log_size)
        .context("bpf_check failed")?;

    process_fd_array(&mut env, attr, uattr).context("bpf_check failed")?;
    mark_verifier_state_clean(&mut env);

    check_btf_info_early(&mut env, attr, uattr).context("bpf_check failed")?;
    add_subprog_and_kfunc(&mut env).context("bpf_check failed")?;
    check_subprogs(&mut env).context("bpf_check failed")?;
    check_btf_info(&mut env, attr, uattr).context("bpf_check failed")?;

    Ok(0)
}
