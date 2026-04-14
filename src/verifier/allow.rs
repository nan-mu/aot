//! Missing types: BpfVerifierEnv

use tracing::instrument;

#[instrument(skip(env))]
pub fn allow_tail_call_in_subprogs(env: &BpfVerifierEnv) -> bool {
    env.prog.jit_requested && bpf_jit_supports_subprog_tailcalls()
}
