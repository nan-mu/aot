//! Missing types: BpfVerifierEnv, BpfSccCallchain

use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument(skip(env, callchain))]
pub fn format_callchain(env: &mut BpfVerifierEnv, callchain: &BpfSccCallchain) -> Result<&str> {
    let mut delta = 0usize;
    env.tmp_str_buf.clear();

    env.tmp_str_buf.push('(');
    delta += 1;

    for &cs in callchain.callsites.iter() {
        if cs == 0 {
            break;
        }
        let part = format!("{},", cs);
        if delta + part.len() >= TMP_STR_BUF_LEN as usize {
            break;
        }
        env.tmp_str_buf.push_str(&part);
        delta += part.len();
    }

    let tail = format!("{})", callchain.scc);
    if delta + tail.len() < TMP_STR_BUF_LEN as usize {
        env.tmp_str_buf.push_str(&tail);
    }

    Ok(env.tmp_str_buf.as_str())
}
