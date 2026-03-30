# AOT

## 概述

eBPF 字节码 → RV32 汇编的 AOT 编译器。读取 eBPF 十六进制字节，输出可直接汇编的 RISC-V 32 位指令序列。

## TODO

- [ ]: 其实这个是AOT模块，之后改一改。
- [ ]:

## 使用方法

### 编译 eBPF 程序

```shell
clang -O2 -target bpf -c xdp_hello.c -o xdp_hello.o
```

### AOT 编译（输出到标准输出）

```shell
llvm-readelf -x xdp xdp_hello.o | grep -oE '[0-9a-fA-F]{8}' | ./bpf2rv
```

### AOT 编译（输出汇编文件）

```shell
llvm-readelf -x xdp xdp_hello.o | grep -oE '[0-9a-fA-F]{8}' | ./bpf2rv tests/res
```

---

## RV32 QEMU 测试

将 AOT 编译输出在 QEMU 的 RV32 裸机环境中运行，验证生成代码的正确性。

### 前置依赖

| 工具 | 说明 | 安装方式 |
|------|------|---------|
| Rust target `riscv32imac-unknown-none-elf` | 交叉编译裸机目标 | 见下方步骤 |
| LLVM (`clang`) | 汇编器 | `brew install llvm` |
| `lld` | 链接器 | `brew install lld` |
| `qemu-system-riscv32` | RV32 仿真器 | `brew install qemu` |

### 一次性环境准备

安装 Rust riscv32 target（因系统 rustup 目录权限问题，需使用临时 RUSTUP_HOME）：

```shell
# 创建临时 rustup home 并复制现有工具链
mkdir -p /tmp/rustup_fresh
cp -r ~/.rustup/toolchains ~/.rustup/update-hashes ~/.rustup/settings.toml /tmp/rustup_fresh/

# 安装 riscv32 target
RUSTUP_HOME=/tmp/rustup_fresh rustup target add riscv32imac-unknown-none-elf
```

修复 homebrew locks 目录权限（如遇权限报错）：

```shell
sudo chown -R $(whoami) /opt/homebrew/var/homebrew/locks
```

安装 qemu：

```shell
brew install qemu
```

### 构建并运行测试

```shell
# 完整流程：重新生成 AOT 汇编 → 编译 → 链接 → 运行
bash tests/build_rv32.sh

# 跳过 AOT 重新生成（使用现有 tests/res）
bash tests/build_rv32.sh --no-regen

# 只构建 ELF，不启动 QEMU
bash tests/build_rv32.sh --build-only

# 启动 QEMU GDB server（端口 1234），用于调试
bash tests/build_rv32.sh --gdb
```

### 手动运行 ELF

```shell
qemu-system-riscv32 -machine virt -nographic -bios none \
    -kernel tests/build/rv32_test.elf
```

预期输出：

```
=== rv32 AOT test harness ===
Calling xdp_prog_main...
[helper 1: bpf_trace_printk called]
xdp_prog_main returned: 42 (hex: 0x0000002a)
action: 42 (expected from xdp_hello)
=== done ===
```

### 测试文件说明

| 文件 | 说明 |
|------|------|
| `tests/rv32_runner.rs` | no_std Rust 测试程序，包含 UART 输出、helper stub、XDP 上下文 |
| `tests/rv32.ld` | 链接脚本，RAM 起始 `0x8000_0000`，栈顶 `0x8010_0000` |
| `tests/build_rv32.sh` | 一键构建+运行脚本 |
| `tests/res` | AOT 编译器输出的 RV32 汇编（由 `bpf2rv` 生成） |
| `tests/build/rv32_test.elf` | 最终链接产物（构建后生成） |
