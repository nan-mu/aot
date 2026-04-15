//! Missing types: BpfVerifierEnv, BpfKfuncCallArgMeta, BpfKfuncMeta, BtfType, Btf

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, meta))]
pub fn fetch_kfunc_arg_meta(
    env: &mut BpfVerifierEnv,
    func_id: i32,
    offset: i16,
    meta: &mut BpfKfuncCallArgMeta,
) -> Result<i32> {
    let mut kfunc = BpfKfuncMeta::default();
    let err = fetch_kfunc_meta(env, func_id, offset, &mut kfunc)?;
    if err != 0 {
        return Err(anyhow!("fetch_kfunc_arg_meta failed"));
    }

    *meta = BpfKfuncCallArgMeta::default();
    meta.btf = kfunc.btf;
    meta.func_id = kfunc.id;
    meta.func_proto = kfunc.proto;
    meta.func_name = kfunc.name;

    if kfunc.flags.is_none() || !btf_kfunc_is_allowed(kfunc.btf, kfunc.id, env.prog) {
        return Err(anyhow!("fetch_kfunc_arg_meta failed"));
    }

    meta.kfunc_flags = *kfunc.flags.unwrap();
    Ok(0)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, kfunc))]
pub fn fetch_kfunc_meta(
    env: &mut BpfVerifierEnv,
    func_id: i32,
    offset: i16,
    kfunc: &mut BpfKfuncMeta,
) -> Result<i32> {
    if func_id <= 0 {
        verbose(env, format!("invalid kernel function btf_id {}\n", func_id));
        return Err(anyhow!("fetch_kfunc_meta failed"));
    }

    let btf = find_kfunc_desc_btf(env, offset)?;
    let kfunc_flags = btf_kfunc_flags(btf, func_id as u32, env.prog);

    let func: &BtfType = btf_type_by_id(btf, func_id as u32);
    if !btf_type_is_func(func) {
        verbose(env, format!("kernel btf_id {} is not a function\n", func_id));
        return Err(anyhow!("fetch_kfunc_meta failed"));
    }

    let func_name = btf_name_by_offset(btf, func.name_off);
    let func_proto = if kfunc_flags.is_some() && (*kfunc_flags.unwrap() & KF_IMPLICIT_ARGS) != 0 {
        find_kfunc_impl_proto(env, btf, func_name)
    } else {
        btf_type_by_id(btf, func.r#type)
    };

    if !btf_type_is_func_proto(func_proto) {
        verbose(
            env,
            format!("kernel function btf_id {} does not have a valid func_proto\n", func_id),
        );
        return Err(anyhow!("fetch_kfunc_meta failed"));
    }

    *kfunc = BpfKfuncMeta::default();
    kfunc.btf = btf;
    kfunc.id = func_id as u32;
    kfunc.name = func_name;
    kfunc.proto = func_proto;
    kfunc.flags = kfunc_flags;

    Ok(0)
}
