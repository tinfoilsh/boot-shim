.include "layout.inc"
.section .reset,"ax"

# Accept [lo, hi) as private memory.  Both bounds are layout symbols, or a
# marker the packager patches with a size-dependent address.
.macro accept lo, hi
    movabs $\lo, %r12
    movabs $\hi, %r13
    call accept_range
.endm

.code64
.global reset_start
reset_start:
    cli
    cld
    mov $PAGE_TABLES, %rax
    mov %rax, %cr3
    mov $0xb, %eax
    xor %ecx, %ecx
    cpuid
    shr $24, %edx
    test %edx, %edx
    jnz ap_wait

    mov $BSP_STACK_TOP, %rsp

    # Enter Linux on the measured GDT.  MRTD covers no vCPU state at all, so
    # without this the descriptors Linux runs on until it installs its own
    # table -- and the segment registers the 64-bit boot protocol requires --
    # would be whatever the loader happened to leave behind.  SNP gets the
    # same table from its measured VMSA and needs no equivalent here.
    mov $GDT_PTR, %rax
    lgdt (%rax)
    mov $BOOT_DS, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %ss
    mov %eax, %fs
    mov %eax, %gs
    push $BOOT_CS
    lea 1f(%rip), %rax
    push %rax
    lretq
1:

    # Accept usable low-memory ranges, skipping measured boot-data pages.
    accept 0, ZERO_PAGE
    accept ZERO_PAGE+PAGE, CMDLINE
    accept CMDLINE+PAGE, ACPI_BASE
    accept ACPI_BASE+PAGE, MAILBOX
    accept MAILBOX+PAGE, PAGE_TABLES
    accept PAGE_TABLES+PAGE_TABLE_SIZE, BSP_STACK
    accept BSP_STACK_TOP, SHIM_BASE

    # Accept every initially-unaccepted page below 1 GiB. Use 2-MiB
    # acceptance wherever alignment permits and 4-KiB pages at edges.  The
    # kernel and initramfs pages are already accepted and measured, so
    # acceptance resumes at their rounded ends.
    accept KERNEL_SETUP_END, KERNEL_BASE
    accept MARK_KERNEL_END, INITRAMFS_BASE
    accept MARK_INITRAMFS_END, RAM_SIZE
    jmp boot_kernel

accept_range:
    cmp %r13, %r12
    jae accept_done
    test $0x1fffff, %r12
    jnz accept_4k
    lea 0x200000(%r12), %r14
    cmp %r13, %r14
    ja accept_4k
    mov %r12, %rcx
    or $1, %rcx
    mov $6, %rax
    tdcall
    test %rax, %rax
    jnz halt
    add $0x200000, %r12
    jmp accept_range
accept_4k:
    mov %r12, %rcx
    mov $6, %rax
    tdcall
    test %rax, %rax
    jnz halt
    add $PAGE, %r12
    jmp accept_range
accept_done:
    ret

boot_kernel:
    mov $ZERO_PAGE, %rsi
entry_imm:
    movabs $MARK_ENTRY, %rax
    jmp *%rax

ap_wait:
    mov $MAILBOX, %rbx
ap_poll:
    mov (%rbx), %eax
    cmp $1, %eax
    jne ap_pause
    mov 4(%rbx), %eax
    cmp %edx, %eax
    jne ap_pause
    mov 8(%rbx), %rax
    test %rax, %rax
    jz halt
    movl $0, (%rbx)
    jmp *%rax
ap_pause:
    pause
    jmp ap_poll
halt:
    cli
    hlt
    jmp halt

    .org 0xff0
reset_vector:
    jmp reset_start
    .fill 0x1000-(.-reset_start),1,0
