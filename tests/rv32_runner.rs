//! no_std RV32 test harness for the AOT-compiled xdp_prog_main.
//!
//! Build (bare-metal rv32imac, no OS):
//!   rustc --edition 2021 --target riscv32imac-unknown-none-elf \
//!         -C opt-level=2 -C panic=abort \
//!         --emit obj -o tests/build/rv32_runner.o tests/rv32_runner.rs
//!
//! Then assemble the AOT output and link:
//!   clang --target=riscv32 -march=rv32imac -mabi=ilp32 -x assembler \
//!         -c tests/res -o tests/build/xdp_prog.o
//!   ld.lld -T tests/rv32.ld tests/build/rv32_runner.o tests/build/xdp_prog.o \
//!         -o tests/build/rv32_test.elf
//!
//! Run under QEMU:
//!   qemu-system-riscv32 -machine virt -nographic -bios none \
//!       -kernel tests/build/rv32_test.elf

#![no_std]
#![no_main]

// ---------------------------------------------------------------------------
// Boot stub: must run before any Rust code.
// QEMU virt machine starts execution at 0x8000_0000 with sp=0.
// We initialize sp to _stack_top (defined in rv32.ld) then call rust_main.
// ---------------------------------------------------------------------------
core::arch::global_asm!(
    ".section .text._start",
    ".global _start",
    "_start:",
    "    la   sp, _stack_top",  // load stack top address from linker script
    "    call rust_main",       // jump to Rust entry
    "1:  j    1b",              // should never return; spin
);

// ---------------------------------------------------------------------------
// Minimal UART output (QEMU virt machine: 16550A UART at 0x1000_0000)
// ---------------------------------------------------------------------------

const UART0: *mut u8 = 0x1000_0000 as *mut u8;

#[inline(always)]
fn uart_putc(c: u8) {
    unsafe { UART0.write_volatile(c) }
}

fn uart_puts(s: &str) {
    for b in s.bytes() {
        uart_putc(b);
    }
}

/// Print a u32 as decimal.
fn uart_print_u32(mut n: u32) {
    if n == 0 {
        uart_putc(b'0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 10usize;
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    for &c in &buf[i..] {
        uart_putc(c);
    }
}

/// Print a u32 as lowercase hex with 0x prefix.
fn uart_print_hex(n: u32) {
    const HEX: &[u8] = b"0123456789abcdef";
    uart_puts("0x");
    for shift in (0..8).rev() {
        uart_putc(HEX[((n >> (shift * 4)) & 0xF) as usize]);
    }
}

// ---------------------------------------------------------------------------
// Helper stubs
//
// xdp_prog_main receives a2 = pointer to a table of function pointer slots.
// Helper id N is loaded from slot[N].  xdp_hello.c calls helper 1
// (bpf_trace_printk).  We provide a UART-printing stub.
// ---------------------------------------------------------------------------

extern "C" fn helper_trace_printk(
    _fmt: u32, _fmt_size: u32, _arg1: u32, _arg2: u32, _arg3: u32,
) -> u32 {
    uart_puts("[helper 1: bpf_trace_printk called]\n");
    0
}

extern "C" fn helper_stub(_: u32, _: u32, _: u32, _: u32, _: u32) -> u32 { 0 }

/// Function-pointer table indexed by eBPF helper id.
/// The AOT code does: lw t0, (id*4)(s1); jalr ra, t0, 0
static HELPER_TABLE: [unsafe extern "C" fn(u32, u32, u32, u32, u32) -> u32; 4] = [
    helper_stub,          // 0 - unused
    helper_trace_printk,  // 1 - bpf_trace_printk
    helper_stub,          // 2
    helper_stub,          // 3
];

// ---------------------------------------------------------------------------
// Fake XDP context
// ---------------------------------------------------------------------------

#[repr(C)]
struct XdpMd {
    data:             u32,
    data_end:         u32,
    data_meta:        u32,
    ingress_ifindex:  u32,
    rx_queue_index:   u32,
}

// ---------------------------------------------------------------------------
// External symbol: the AOT-compiled eBPF function (from tests/res)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// Calling convention (emit_prologue in aot_rv32.rs):
    ///   a0 = xdp_md ptr  (eBPF R1 lo)
    ///   a1 = 0           (eBPF R1 hi, zero for 32-bit pointers)
    ///   a2 = helper table ptr
    /// Returns in a0: XDP action code (u32)
    unsafe fn xdp_prog_main(ctx: *const XdpMd, ctx_hi: u32, helpers: *const ()) -> u32;
}

// ---------------------------------------------------------------------------
// Fake packet: Ethernet frame with EtherType=IPv4 (0x0800)
// ---------------------------------------------------------------------------

static PACKET: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // dst MAC
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // src MAC
    0x08, 0x00,                         // EtherType = IPv4
    0x00, 0x00,
];

// ---------------------------------------------------------------------------
// Entry point (_start)
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    uart_puts("=== rv32 AOT test harness ===\n");

    let ctx = XdpMd {
        data:            PACKET.as_ptr() as u32,
        data_end:        PACKET.as_ptr() as u32 + PACKET.len() as u32,
        data_meta:       PACKET.as_ptr() as u32,
        ingress_ifindex: 1,
        rx_queue_index:  0,
    };

    uart_puts("Calling xdp_prog_main...\n");

    let ret = unsafe { xdp_prog_main(&ctx as *const XdpMd, 0, HELPER_TABLE.as_ptr() as *const ()) };

    uart_puts("xdp_prog_main returned: ");
    uart_print_u32(ret);
    uart_puts(" (hex: ");
    uart_print_hex(ret);
    uart_puts(")\n");

    match ret {
        0  => uart_puts("action: XDP_ABORTED\n"),
        1  => uart_puts("action: XDP_PASS\n"),
        2  => uart_puts("action: XDP_DROP\n"),
        42 => uart_puts("action: 42 (expected from xdp_hello)\n"),
        _  => uart_puts("action: (unknown)\n"),
    }

    uart_puts("=== done ===\n");

    // Signal QEMU to exit cleanly via the test-finisher device (0x10_0000).
    // Writing 0x5555 causes QEMU to exit with code 0 (pass).
    const QEMU_TEST_FINISHER: *mut u32 = 0x0010_0000 as *mut u32;
    unsafe { QEMU_TEST_FINISHER.write_volatile(0x5555) };

    loop {}
}

// ---------------------------------------------------------------------------
// Panic handler (required for #![no_std], bare-metal targets only)
// ---------------------------------------------------------------------------

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    uart_puts("PANIC!\n");
    loop {}
}
