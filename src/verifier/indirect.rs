//! Missing types: BpfVerifierEnv, BpfMap, BpfRegState

use anyhow::{anyhow, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, map, pmin_index, pmax_index))]
pub fn indirect_jump_min_max_index(
    env: &mut BpfVerifierEnv,
    regno: i32,
    map: &BpfMap,
    pmin_index: &mut u32,
    pmax_index: &mut u32,
) -> Result<i32> {
    let reg: &BpfRegState = reg_state(env, regno);
    let size: u32 = 8;

    let min_index = reg
        .umin_value
        .checked_add(reg.off as u64)
        .ok_or_else(|| anyhow!("indirect_jump_min_max_index failed"))?;
    if min_index > (u32::MAX as u64) * size as u64 {
        verbose(
            env,
            format!(
                "the sum of R{} umin_value {} and off {} is too big\n",
                regno, reg.umin_value, reg.off
            ),
        );
        return Err(anyhow!("indirect_jump_min_max_index failed"));
    }

    let max_index = reg
        .umax_value
        .checked_add(reg.off as u64)
        .ok_or_else(|| anyhow!("indirect_jump_min_max_index failed"))?;
    if max_index > (u32::MAX as u64) * size as u64 {
        verbose(
            env,
            format!(
                "the sum of R{} umax_value {} and off {} is too big\n",
                regno, reg.umax_value, reg.off
            ),
        );
        return Err(anyhow!("indirect_jump_min_max_index failed"));
    }

    let min_index = (min_index / size as u64) as u32;
    let max_index = (max_index / size as u64) as u32;

    if max_index >= map.max_entries {
        verbose(
            env,
            format!(
                "R{} points to outside of jump table: [{},{}] max_entries {}\n",
                regno, min_index, max_index, map.max_entries
            ),
        );
        return Err(anyhow!("indirect_jump_min_max_index failed"));
    }

    *pmin_index = min_index;
    *pmax_index = max_index;
    Ok(0)
}
