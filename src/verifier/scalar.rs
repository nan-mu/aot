//! Missing types: none

use anyhow::{anyhow, Context, Result};
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip_all)]
pub fn scalar_byte_swap() -> Result<()> {
    let _ = Some(()).context("scalar_byte_swap")?;
    Err(anyhow!("scalar_byte_swap failed"))
}

#[instrument(skip_all)]
pub fn scalar_min_max_add() -> Result<()> { Err(anyhow!("scalar_min_max_add failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_and() -> Result<()> { Err(anyhow!("scalar_min_max_and failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_arsh() -> Result<()> { Err(anyhow!("scalar_min_max_arsh failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_lsh() -> Result<()> { Err(anyhow!("scalar_min_max_lsh failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_mul() -> Result<()> { Err(anyhow!("scalar_min_max_mul failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_or() -> Result<()> { Err(anyhow!("scalar_min_max_or failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_rsh() -> Result<()> { Err(anyhow!("scalar_min_max_rsh failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_sdiv() -> Result<()> { Err(anyhow!("scalar_min_max_sdiv failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_smod() -> Result<()> { Err(anyhow!("scalar_min_max_smod failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_sub() -> Result<()> { Err(anyhow!("scalar_min_max_sub failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_udiv() -> Result<()> { Err(anyhow!("scalar_min_max_udiv failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_umod() -> Result<()> { Err(anyhow!("scalar_min_max_umod failed")) }
#[instrument(skip_all)]
pub fn scalar_min_max_xor() -> Result<()> { Err(anyhow!("scalar_min_max_xor failed")) }

#[instrument(skip_all)]
pub fn scalar_reg_for_stack() -> Result<()> { Err(anyhow!("scalar_reg_for_stack failed")) }

#[instrument(skip_all)]
pub fn inner_scalar32_min_max_lsh() -> Result<()> { Err(anyhow!("inner_scalar32_min_max_lsh failed")) }
#[instrument(skip_all)]
pub fn inner_scalar64_min_max_lsh() -> Result<()> { Err(anyhow!("inner_scalar64_min_max_lsh failed")) }

#[instrument(skip_all)]
pub fn scalar32_min_max_add() -> Result<()> { Err(anyhow!("scalar32_min_max_add failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_and() -> Result<()> { Err(anyhow!("scalar32_min_max_and failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_arsh() -> Result<()> { Err(anyhow!("scalar32_min_max_arsh failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_lsh() -> Result<()> { Err(anyhow!("scalar32_min_max_lsh failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_mul() -> Result<()> { Err(anyhow!("scalar32_min_max_mul failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_or() -> Result<()> { Err(anyhow!("scalar32_min_max_or failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_rsh() -> Result<()> { Err(anyhow!("scalar32_min_max_rsh failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_sdiv() -> Result<()> { Err(anyhow!("scalar32_min_max_sdiv failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_smod() -> Result<()> { Err(anyhow!("scalar32_min_max_smod failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_sub() -> Result<()> { Err(anyhow!("scalar32_min_max_sub failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_udiv() -> Result<()> { Err(anyhow!("scalar32_min_max_udiv failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_umod() -> Result<()> { Err(anyhow!("scalar32_min_max_umod failed")) }
#[instrument(skip_all)]
pub fn scalar32_min_max_xor() -> Result<()> { Err(anyhow!("scalar32_min_max_xor failed")) }

#[instrument(skip_all)]
pub fn scalars_exact_for_widen() -> Result<bool> { Err(anyhow!("scalars_exact_for_widen failed")) }
