//! Missing types: Bitmap64

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(buf))]
pub fn fmt_reg_mask(buf: &mut String, reg_mask: u32) -> Result<()> {
    let mut first = true;
    buf.clear();

    for i in 0..32u32 {
        if (reg_mask & (1u32 << i)) == 0 {
            continue;
        }
        if !first {
            buf.push(',');
        }
        first = false;
        buf.push_str(&format!("r{}", i));
    }

    Ok(())
}
