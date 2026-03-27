use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use clap::Parser;
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
}

fn main() {
    // Initialize tracing; RUST_LOG controls verbosity, default = info
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // ── Read hex bytes from stdin ────────────────────────────────────────────
    let mut ebpf_dump: Vec<u8> = Vec::new();
    // llvm-readelf -x inserts an 8-hex-char offset token at the start of every
    // group of 4 words (i.e. every 16 bytes).  We skip any line whose value
    // exactly equals the current byte offset so far.
    for line in io::stdin().lock().lines() {
        let line = line.context("读取 stdin 失败")?;
        if line.trim().is_empty() {
            break;
        }
        let hex = line.trim();
        // Skip readelf offset labels
        if hex.len() == 8 {
            if let Ok(val) = u32::from_str_radix(hex, 16) {
                if val == ebpf_dump.len() as u32 {
                    debug!(offset = val, "跳过 readelf 地址标签");
                    continue;
                }
            }
        }
        if hex.len() % 2 != 0 {
            bail!("十六进制行长度不是 2 的倍数：'{}'", hex);
        }
        for chunk in hex.as_bytes().chunks(2) {
            let hi = (chunk[0] as char)
                .to_digit(16)
                .with_context(|| format!("无效十六进制字符: {}", chunk[0] as char))?  as u8;
            let lo = (chunk[1] as char)
                .to_digit(16)
                .with_context(|| format!("无效十六进制字符: {}", chunk[1] as char))? as u8;
            ebpf_dump.push((hi << 4) | lo);
        }
    }

    if ebpf_dump.len() % 8 != 0 {
        bail!("输入字节数不是 8 的倍数，实际字节数：{}", ebpf_dump.len());
    }
    info!(bytes = ebpf_dump.len(), "读取 eBPF 字节完成");

    // ── AOT compile ──────────────────────────────────────────────────────────
    info!("开始 AOT 编译 (eBPF -> RV32)...");
    let helpers: HashMap<u32, usize> = HashMap::new();
    let rv_machine_code = aot_rv32::bpf_to_rv32(&ebpf_dump, &helpers)
        .map_err(anyhow::Error::msg)
        .context("AOT 编译失败")?;
    info!(instructions = rv_machine_code.len(), "编译完成");

    // ── Output ───────────────────────────────────────────────────────────────
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
                .with_context(|| format!("无法创建文件 '{}'", file_path))?;

            writeln!(file, ".section .text.xdp_prog, \"ax\"")?;
            writeln!(file, ".global xdp_prog_main")?;
            writeln!(file, ".align 2")?;
            writeln!(file, "xdp_prog_main:")?;
            for instr in &rv_machine_code {
                writeln!(file, "    .word 0x{:08x}", instr)?;
            }

            warn!(path = %file_path, "汇编文件已写入");
            info!("提示：在 ESP-IDF 的 CMakeLists.txt 中添加此文件即可参与链接。");
        }
    }

    Ok(())
}
