//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_callee_state() -> Result<()> {
    let _ = Some(()).context("set_callee_state")?;
    Err(anyhow!("set_callee_state failed"))
}

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_find_vma_callback_state() -> Result<()> { Err(anyhow!("set_find_vma_callback_state failed")) }

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_kfunc_desc_imm() -> Result<()> { Err(anyhow!("set_kfunc_desc_imm failed")) }

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_loop_callback_state() -> Result<()> { Err(anyhow!("set_loop_callback_state failed")) }

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_map_elem_callback_state() -> Result<()> { Err(anyhow!("set_map_elem_callback_state failed")) }

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_rbtree_add_callback_state() -> Result<()> { Err(anyhow!("set_rbtree_add_callback_state failed")) }

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_sext32_default_val() -> Result<()> { Err(anyhow!("set_sext32_default_val failed")) }

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_sext64_default_val() -> Result<()> { Err(anyhow!("set_sext64_default_val failed")) }

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_task_work_schedule_callback_state() -> Result<()> { Err(anyhow!("set_task_work_schedule_callback_state failed")) }

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_timer_callback_state() -> Result<()> { Err(anyhow!("set_timer_callback_state failed")) }

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn set_user_ringbuf_callback_state() -> Result<()> { Err(anyhow!("set_user_ringbuf_callback_state failed")) }
