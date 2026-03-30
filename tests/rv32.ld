/* Linker script for QEMU virt machine (riscv32)
 * RAM starts at 0x8000_0000, 128 MB
 * UART0 at 0x1000_0000, QEMU test-finisher at 0x0010_0000
 */
OUTPUT_ARCH(riscv)
ENTRY(_start)

MEMORY {
    RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 128M
}

SECTIONS {
    . = 0x80000000;

    .text : {
        /* Entry first */
        KEEP(*(.text._start))
        *(.text .text.*)
    } > RAM

    .rodata : {
        *(.rodata .rodata.*)
    } > RAM

    .data : {
        *(.data .data.*)
    } > RAM

    .bss : {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    } > RAM

    /* Stack: 64 KB at top of a convenient region */
    _stack_top = 0x80100000;
}
