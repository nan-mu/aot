use anyhow::Result;
use tracing::instrument;

// Extracted from /Users/nan/bs/aot/src/verifier.c
#[instrument]
pub fn flip_opcode(opcode: u32) -> Result<u8> {
    /* How can we transform "a <op> b" into "b <op> a"? */
    let opcode_flip: [u8; 16] = [
        0,
        BPF_JEQ,
        BPF_JGT,
        BPF_JGE,
        BPF_JSET,
        BPF_JNE,
        BPF_JSGT,
        BPF_JSGE,
        0,
        BPF_JLT,
        BPF_JLE,
        BPF_JSLT,
        BPF_JSLE,
        0,
        0,
        0,
    ];
    Ok(opcode_flip[(opcode >> 4) as usize])
}
