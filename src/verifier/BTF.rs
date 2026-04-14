//! Missing types: BpfProg, Btf, BpfVerifierEnv, BpfRegState, BpfSubprogInfo, BpfVerifierLog, BtfField, BtfRecord

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(prog))]
pub fn can_be_sleepable(prog: &BpfProg) -> Result<bool> {
    if prog.r#type == BPF_PROG_TYPE_TRACING {
        return Ok(matches!(
            prog.expected_attach_type,
            BPF_TRACE_FENTRY
                | BPF_TRACE_FEXIT
                | BPF_MODIFY_RETURN
                | BPF_TRACE_ITER
                | BPF_TRACE_FSESSION
        ));
    }

    Ok(
        prog.r#type == BPF_PROG_TYPE_LSM
            || prog.r#type == BPF_PROG_TYPE_KPROBE
            || prog.r#type == BPF_PROG_TYPE_STRUCT_OPS,
    )
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, _btf, regs))]
pub fn btf_check_func_arg_match(
    env: &mut BpfVerifierEnv,
    subprog: i32,
    _btf: &Btf,
    regs: &mut [BpfRegState],
) -> Result<i32> {
    let sub: &BpfSubprogInfo = subprog_info(env, subprog);
    let log: &BpfVerifierLog = &env.log;

    let ret = btf_prepare_func_args(env, subprog);
    if ret != 0 {
        return Err(anyhow!("btf_check_func_arg_match failed"));
    }

    /* check that BTF function arguments match actual types that the
     * verifier sees.
     */
    for i in 0..sub.arg_cnt as usize {
        let regno = i + 1;
        let reg: &BpfRegState = &regs[regno];
        let arg = &sub.args[i];

        if arg.arg_type == ARG_ANYTHING {
            if reg.r#type != SCALAR_VALUE {
                bpf_log(log, format!("R{} is not a scalar\n", regno));
                return Err(anyhow!("btf_check_func_arg_match failed"));
            }
        } else if (arg.arg_type & PTR_UNTRUSTED) != 0 {
            /*
             * Anything is allowed for untrusted arguments, as these are
             * read-only and probe read instructions would protect against
             * invalid memory access.
             */
        } else if arg.arg_type == ARG_PTR_TO_CTX {
            if check_func_arg_reg_off(env, reg, regno as u32, ARG_DONTCARE) < 0 {
                return Err(anyhow!("btf_check_func_arg_match failed"));
            }
            /* If function expects ctx type in BTF check that caller
             * is passing PTR_TO_CTX.
             */
            if reg.r#type != PTR_TO_CTX {
                bpf_log(log, format!("arg#{} expects pointer to ctx\n", i));
                return Err(anyhow!("btf_check_func_arg_match failed"));
            }
        }
    }

    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, regs))]
pub fn btf_check_subprog_call(
    env: &mut BpfVerifierEnv,
    subprog: i32,
    regs: &mut [BpfRegState],
) -> Result<i32> {
    let prog: &mut BpfProg = env.prog;
    let btf: &Btf = prog.aux.btf;

    if prog.aux.func_info.is_none() {
        return Err(anyhow!("btf_check_subprog_call failed"));
    }

    let btf_id = prog.aux.func_info.as_ref().unwrap()[subprog as usize].type_id;
    if btf_id == 0 {
        return Err(anyhow!("btf_check_subprog_call failed"));
    }

    if prog.aux.func_info_aux[subprog as usize].unreliable {
        return Err(anyhow!("btf_check_subprog_call failed"));
    }

    let err = btf_check_func_arg_match(env, subprog, btf, regs)?;
    /* Compiler optimizations can remove arguments from static functions
     * or mismatched type can be passed into a global function.
     * In such cases mark the function as unreliable from BTF point of view.
     */
    if err != 0 {
        prog.aux.func_info_aux[subprog as usize].unreliable = true;
    }
    Ok(err)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, kptr_field))]
pub fn btf_ld_kptr_type(env: &mut BpfVerifierEnv, kptr_field: &BtfField) -> Result<u32> {
    let mut ret = PTR_MAYBE_NULL;

    if rcu_safe_kptr(kptr_field) && in_rcu_cs(env) {
        ret |= MEM_RCU;
        if kptr_field.r#type == BPF_KPTR_PERCPU {
            ret |= MEM_PERCPU;
        } else if !btf_is_kernel(kptr_field.kptr.btf) {
            ret |= MEM_ALLOC;
        }

        let rec: &BtfRecord = kptr_pointee_btf_record(kptr_field);
        if btf_record_has_field(rec, BPF_GRAPH_NODE) {
            ret |= NON_OWN_REF;
        }
    } else {
        ret |= PTR_UNTRUSTED;
    }

    Ok(ret)
}
