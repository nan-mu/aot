use std::env;
use std::fs::OpenOptions;
use std::process;
use std::io::{self, BufRead, Write};
use std::collections::HashMap;

pub mod aot_rv32;
#[cfg(test)]
mod tests;

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut ebpf_dump: Vec<u8> = Vec::new();
    // llvm-readelf -x inserts an 8-hex-char offset token at the start of every
    // group of 4 words (i.e. every 16 bytes).  We skip any line whose value
    // exactly equals the current byte offset so far, which is how those
    // address labels are formatted.
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() { break; }
        let hex = line.trim();
        // Skip lines that are the readelf offset label:
        // they are exactly 8 hex chars whose value == current byte offset.
        if hex.len() == 8 {
            if let Ok(val) = u32::from_str_radix(hex, 16) {
                if val == ebpf_dump.len() as u32 {
                    continue;
                }
            }
        }
        if hex.len() % 2 != 0 {
            eprintln!("❌ 致命错误：十六进制行长度不是2的倍数：'{}'", hex);
            process::exit(1);
        }
        for chunk in hex.as_bytes().chunks(2) {
            let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
            let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
            ebpf_dump.push((hi << 4) | lo);
        }
    }
    if ebpf_dump.len() % 8 != 0 {
        panic!("输入的字节数不是8的倍数！实际字节数：{}", ebpf_dump.len());
    }

    println!("开始 AOT 编译 (eBPF -> RV32)...");

    let helpers: HashMap<u32, usize> = HashMap::new();
    let rv_machine_code = match aot_rv32::bpf_to_rv32(&ebpf_dump, &helpers) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("❌ 编译错误：{}", e);
            process::exit(1);
        }
    };

    if args.len() == 1 {
        for instr in &rv_machine_code {
            let bytes = instr.to_le_bytes();
            println!("    0x{:02x}, 0x{:02x}, 0x{:02x}, 0x{:02x},",
                bytes[0], bytes[1], bytes[2], bytes[3]);
        }
        println!("}}");
        println!("size_t bin_size = sizeof(xdp_hot_update_bin);");

    } else if args.len() == 2 {
        let file_path = &args[1];

        let mut file = match OpenOptions::new().write(true).create_new(true).open(file_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("❌ 致命错误：无法创建文件 '{}'。原因: {}", file_path, e);
                process::exit(1);
            }
        };

        writeln!(file, ".section .text.xdp_prog, \"ax\"").unwrap();
        writeln!(file, ".global xdp_prog_main").unwrap();
        writeln!(file, ".align 2").unwrap();
        writeln!(file, "xdp_prog_main:").unwrap();

        for instr in &rv_machine_code {
            writeln!(file, "    .word 0x{:08x}", instr).unwrap();
        }

        println!("✅ AOT 编译成功！汇编文件已安全保存至: {}", file_path);
        println!("💡 提示：在 ESP-IDF 的 CMakeLists.txt 中添加此文件即可参与链接。");

    } else {
        eprintln!("❌ 错误：参数过多。");
        eprintln!("用法:");
        eprintln!("  {}                  (输出 C 语言数组到终端)", args[0]);
        eprintln!("  {} <output.S>       (生成 ESP-IDF 可链接的汇编文件)", args[0]);
        process::exit(1);
    }
}
