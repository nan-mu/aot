use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Write};
use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use clap::Parser;
use object::{Object, ObjectSection};
use tracing::{debug, info, warn};

pub mod aot_rv32;
#[cfg(test)]
mod tests;

/// eBPF bytecode -> RV32 AOT compiler
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Output assembly file path (omit to print raw hex to stdout)
    output: Option<String>,
    /// Get object file from path instead of stdin
    input: Option<String>,
}

fn main() -> Result<()> {
    // Initialize tracing; RUST_LOG controls verbosity, default = info
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    run().context("Failed to run AOT compiler")
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // read bytes
    let bytes = match cli.input {
        Some(ref path) => {
            debug!("read eBPF bytes from file '{}'", path);
            read_from_file(path)?
        }
        None => {
            debug!("read eBPF bytes from stdin");
            read_from_stdin()?
        }
    };

    info!(bytes = bytes.len(), "eBPF bytecode read successfully");

    // AOT compile
    debug!("begin AOT compiling (eBPF -> RV32)...");
    let helpers: HashMap<u32, usize> = HashMap::new();
    let rv_machine_code = aot_rv32::bpf_to_rv32(&bytes, &helpers)
        .map_err(anyhow::Error::msg)
        .context("AOT compilation failed")?;
    info!(instructions = rv_machine_code.len(), "Compilation completed");

    // Output
    match cli.output {
        None => {
            // stdout: raw hex only, no decoration
            let stdout = io::stdout();
            let mut out = stdout.lock();
            for instr in &rv_machine_code {
                writeln!(out, "{:08x}", instr)?;
            }
        }
        Some(ref file_path) => {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(file_path)
                .with_context(|| format!("Failed to create file '{}'", file_path))?;

            writeln!(file, ".section .text.xdp_prog, \"ax\"")?;
            writeln!(file, ".global xdp_prog_main")?;
            writeln!(file, ".align 2")?;
            writeln!(file, "xdp_prog_main:")?;
            for instr in &rv_machine_code {
                writeln!(file, "    .word 0x{:08x}", instr)?;
            }

            warn!(path = %file_path, "Assembly file written");
            info!("Hint: Add this file to ESP-IDF's CMakeLists.txt to participate in linking.");
        }
    }

    Ok(())
}

#[tracing::instrument(name = "read_from_stdin")]
fn read_from_stdin() -> Result<Vec<u8>> {
    let mut ebpf_dump: Vec<u8> = Vec::new();
    for line in io::stdin().lock().lines() {
        let line = line.context("Failed to read from stdin")?;
        if line.trim().is_empty() {
            break;
        }
        let hex = line.trim();
        // Skip readelf offset labels
        if hex.len() == 8 {
            if let Ok(val) = u32::from_str_radix(hex, 16) {
                if val == ebpf_dump.len() as u32 {
                    debug!(offset = val, "Skipping readelf address label");
                    continue;
                }
            }
        }
        if hex.len() % 2 != 0 {
            bail!("The hexadecimal line length is not a multiple of 2: '{}'", hex);
        }
        for chunk in hex.as_bytes().chunks(2) {
            let hi = (chunk[0] as char)
                .to_digit(16)
                .with_context(|| format!("Invalid hexadecimal character: {}", chunk[0] as char))?  as u8;
            let lo = (chunk[1] as char)
                .to_digit(16)
                .with_context(|| format!("Invalid hexadecimal character: {}", chunk[1] as char))? as u8;
            ebpf_dump.push((hi << 4) | lo);
        }
    }

    if ebpf_dump.len() % 8 != 0 {
        bail!("The input is not a multiple of 8 bytes, actual length: {}", ebpf_dump.len());
    }

    Ok(ebpf_dump)
}

#[tracing::instrument(name = "read_from_file", skip(path))]
fn read_from_file(path: &str) -> Result<Vec<u8>> {
    debug!("Reading object file from '{}'", path);
    let file = fs::read(path)?;
    let object = object::File::parse(&*file)?;
    if let Some(section) = object.section_by_name("xdp") {
        let asm_bytes = section.data()?;
        debug!("Hex: {:02x?}", &asm_bytes[..asm_bytes.len().min(16)]);
        Ok(asm_bytes.to_vec())
    } else {
        bail!("Cannot find .xdp section in the object file");
    }
}