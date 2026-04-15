//! Missing types: BpfVerifierEnv, BpfCallArgMeta, BpfProgType

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, meta))]
pub fn may_access_direct_pkt_data(
    env: &mut BpfVerifierEnv,
    meta: Option<&BpfCallArgMeta>,
    t: BpfAccessType,
) -> Result<bool> {
    let prog_type = resolve_prog_type(env.prog);

    match prog_type {
        BPF_PROG_TYPE_LWT_IN
        | BPF_PROG_TYPE_LWT_OUT
        | BPF_PROG_TYPE_LWT_SEG6LOCAL
        | BPF_PROG_TYPE_SK_REUSEPORT
        | BPF_PROG_TYPE_FLOW_DISSECTOR
        | BPF_PROG_TYPE_CGROUP_SKB => {
            if t == BPF_WRITE {
                return Ok(false);
            }
        }
        _ => {}
    }

    match prog_type {
        BPF_PROG_TYPE_SCHED_CLS
        | BPF_PROG_TYPE_SCHED_ACT
        | BPF_PROG_TYPE_XDP
        | BPF_PROG_TYPE_LWT_XMIT
        | BPF_PROG_TYPE_SK_SKB
        | BPF_PROG_TYPE_SK_MSG
        | BPF_PROG_TYPE_LWT_IN
        | BPF_PROG_TYPE_LWT_OUT
        | BPF_PROG_TYPE_LWT_SEG6LOCAL
        | BPF_PROG_TYPE_SK_REUSEPORT
        | BPF_PROG_TYPE_FLOW_DISSECTOR
        | BPF_PROG_TYPE_CGROUP_SKB => {
            if let Some(m) = meta {
                return Ok(m.pkt_access);
            }
            env.seen_direct_write = true;
            Ok(true)
        }
        BPF_PROG_TYPE_CGROUP_SOCKOPT => {
            if t == BPF_WRITE {
                env.seen_direct_write = true;
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn may_access_skb(r#type: BpfProgType) -> Result<bool> {
    Ok(matches!(
        r#type,
        BPF_PROG_TYPE_SOCKET_FILTER | BPF_PROG_TYPE_SCHED_CLS | BPF_PROG_TYPE_SCHED_ACT
    ))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn may_update_sockmap(env: &mut BpfVerifierEnv, func_id: i32) -> Result<bool> {
    let eatype = env.prog.expected_attach_type;
    let r#type = resolve_prog_type(env.prog);

    if func_id != BPF_FUNC_map_update_elem && func_id != BPF_FUNC_map_delete_elem {
        return Ok(false);
    }

    match r#type {
        BPF_PROG_TYPE_TRACING if eatype == BPF_TRACE_ITER => Ok(true),
        BPF_PROG_TYPE_SOCK_OPS if func_id == BPF_FUNC_map_delete_elem => Ok(true),
        BPF_PROG_TYPE_SOCKET_FILTER
        | BPF_PROG_TYPE_SCHED_CLS
        | BPF_PROG_TYPE_SCHED_ACT
        | BPF_PROG_TYPE_XDP
        | BPF_PROG_TYPE_SK_REUSEPORT
        | BPF_PROG_TYPE_FLOW_DISSECTOR
        | BPF_PROG_TYPE_SK_LOOKUP => Ok(true),
        _ => {
            verbose(env, "cannot update sockmap in this context\n");
            Ok(false)
        }
    }
}
