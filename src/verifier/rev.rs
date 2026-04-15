use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn rev_opcode(opcode: u8) -> Result<u8> {
    Ok(match opcode {
        BPF_JEQ => BPF_JNE,
        BPF_JNE => BPF_JEQ,
        /* JSET doesn't have its reverse opcode in BPF */
        BPF_JSET => BPF_JSET | BPF_X,
        x if x == (BPF_JSET | BPF_X) => BPF_JSET,
        BPF_JGE => BPF_JLT,
        BPF_JGT => BPF_JLE,
        BPF_JLE => BPF_JGT,
        BPF_JLT => BPF_JGE,
        BPF_JSGE => BPF_JSLT,
        BPF_JSGT => BPF_JSLE,
        BPF_JSLE => BPF_JSGT,
        BPF_JSLT => BPF_JSGE,
        _ => 0,
    })
}
