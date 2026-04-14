#![allow(dead_code)]

#[derive(Clone, Debug, Default)]
pub struct BpfProg {
    pub jit_requested: bool,
    pub jit_supports_subprog_tailcalls: bool,
}

#[derive(Clone, Debug, Default)]
pub struct BpfVerifierEnv {
    pub prog: BpfProg,
}

pub fn allow_tail_call_in_subprogs(env: &BpfVerifierEnv) -> bool {
    env.prog.jit_requested && env.prog.jit_supports_subprog_tailcalls
}
