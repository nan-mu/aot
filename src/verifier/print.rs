//! Missing types: BpfVerifierEnv

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env))]
pub fn print_verification_stats(env: &mut BpfVerifierEnv) -> Result<()> {
    if (env.log.level & BPF_LOG_STATS) != 0 {
        verbose(env, format!("verification time {} usec\n", env.verification_time / 1000));
        verbose(env, "stack depth ");
        for i in 0..env.subprog_cnt as usize {
            let depth = env.subprog_info[i].stack_depth;
            verbose(env, format!("{}", depth));
            if i + 1 < env.subprog_cnt as usize {
                verbose(env, "+");
            }
        }
        verbose(env, "\n");
    }

    verbose(
        env,
        format!(
            "processed {} insns (limit {}) max_states_per_insn {} total_states {} peak_states {} mark_read {}\n",
            env.insn_processed,
            BPF_COMPLEXITY_LIMIT_INSNS,
            env.max_states_per_insn,
            env.total_states,
            env.peak_states,
            env.longest_mark_read_walk
        ),
    );
    Ok(())
}
