//! Missing types: BpfVerifierEnv, BpfRegState, BpfKfuncCallArgMeta, BpfArgType

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, do_print_state))]
pub fn process_bpf_exit_full(
    env: &mut BpfVerifierEnv,
    do_print_state: &mut bool,
    exception_exit: bool,
) -> Result<i32> {
    let err = check_resource_leak(
        env,
        exception_exit,
        exception_exit || env.cur_state.curframe == 0,
        if exception_exit {
            "bpf_throw"
        } else {
            "BPF_EXIT instruction in main prog"
        },
    )?;
    if err != 0 {
        return Ok(err);
    }

    if exception_exit {
        return Ok(PROCESS_BPF_EXIT);
    }

    if env.cur_state.curframe != 0 {
        prepare_func_exit(env, &mut env.insn_idx)?;
        *do_print_state = true;
        return Ok(0);
    }

    check_return_code(env, BPF_REG_0, "R0")?;
    Ok(PROCESS_BPF_EXIT)
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn process_fd_array(env: &mut BpfVerifierEnv, attr: &mut BpfAttr, uattr: BpfPtr) -> Result<i32> {
    let size = core::mem::size_of::<i32>() as u32;
    env.fd_array = make_bpfptr(attr.fd_array, uattr.is_kernel);

    if attr.fd_array_cnt == 0 {
        return Ok(0);
    }

    if attr.fd_array_cnt >= (u32::MAX / size) {
        verbose(env, format!("fd_array_cnt is too big ({})\n", attr.fd_array_cnt));
        return Err(anyhow!("process_fd_array failed"));
    }

    for i in 0..attr.fd_array_cnt {
        let mut fd = 0i32;
        if copy_from_bpfptr_offset(&mut fd, env.fd_array, i * size, size) != 0 {
            return Err(anyhow!("process_fd_array failed"));
        }
        add_fd_from_fd_array(env, fd)?;
    }

    Ok(0)
}
