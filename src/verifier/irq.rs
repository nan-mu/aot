//! Missing types: BpfVerifierEnv, BpfRegState

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, reg))]
pub fn irq_flag_get_spi(env: &mut BpfVerifierEnv, reg: &BpfRegState) -> Result<i32> {
    stack_slot_obj_get_spi(env, reg, "irq_flag", 1)
}
