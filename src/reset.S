.include "layout.inc"
.section .reset,"ax"

# Accept [lo, hi) as private memory.  Both bounds are layout symbols, or a
# marker the packager patches with a size-dependent address.
.macro accept lo, hi
    movabs $\lo, %r12
    movabs $\hi, %r13
    call accept_range
.endm

.code32
.global reset_start
reset_start:
    # TDH.VP.INIT starts every vCPU here in 32-bit protected mode with paging
    # off, ESI holding the vCPU index, CS based at 4 GiB - 64 KiB and the data
    # segments flat.  MRTD covers no vCPU state at all, so the first thing the
    # shim does is replace the descriptors it was handed with the measured
    # GDT; everything after this runs on a table the digest covers.
    cli
    cld
    mov $GDT_PTR, %eax
    lgdt (%eax)
    ljmp $BOOT_CS32, $(RESET_ALIAS + (flat32 - reset_start))
flat32:
    mov $BOOT_DS, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %ss
    mov %eax, %fs
    mov %eax, %gs
    # The TDX module leaves EFER.LME set and EFER unwritable, so enabling PAE
    # and paging is the whole transition to long mode.  Both control registers
    # are read-modify-written: the module fixes bits in each (CR0.NE, CR4.MCE)
    # and clearing one is a #GP.
    mov %cr4, %eax
    bts $5, %eax
    mov %eax, %cr4
    mov $PAGE_TABLES, %eax
    mov %eax, %cr3
    mov %cr0, %eax
    bts $31, %eax
    mov %eax, %cr0
    ljmp $BOOT_CS, $(RESET_ALIAS + (long_mode - reset_start))

.code64
long_mode:
    test %esi, %esi
    jnz ap_wait
    mov $BSP_STACK_TOP, %rsp

    # Accept every page the measured E820 map calls RAM.  Linux discovers
    # unaccepted memory only through EFI, which this boot path does not
    # provide.  The pages the loader added are already accepted and are
    # skipped: accepting one twice is how a page gets silently replaced.
    accept 0, ZERO_PAGE
    accept ZERO_PAGE+PAGE, CMDLINE
    accept CMDLINE+PAGE, VGA_HOLE
    # The VGA aperture is MMIO on a q35 machine and never guest RAM.  The rest
    # of the legacy region is memory Linux reads unconditionally -- the EBDA
    # and ROM scans -- so it is accepted around the measured ACPI tables, the
    # wakeup mailbox and the host's TD HOB.
    accept VGA_HOLE_END, ACPI_BASE
    accept ACPI_BASE+PAGE, MAILBOX
    accept TD_HOB+PAGE, PAGE_TABLES
    accept PAGE_TABLES+PAGE_TABLE_SIZE, BSP_STACK
    accept BSP_STACK_TOP, KERNEL_SETUP_BASE
    accept KERNEL_SETUP_END, KERNEL_BASE
    accept MARK_KERNEL_END, INITRAMFS_BASE
    accept MARK_INITRAMFS_END, RAM_SIZE

boot_kernel:
    mov $ZERO_PAGE, %rsi
entry_imm:
    movabs $MARK_ENTRY, %rax
    jmp *%rax

# Accept [%r12, %r13) as private memory, preferring 2-MiB pages.  A frame that
# already holds accepted pages reports TDX_PAGE_SIZE_MISMATCH and is retried
# 4 KiB at a time; every other non-zero status is fatal, including the
# already-accepted one that says this shim and its loader disagree about the
# layout the digest covers.
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
    jz accept_2m
    shr $32, %rax
    cmp $0xc0000b0b, %eax           # TDX_PAGE_SIZE_MISMATCH
    jne die
accept_4k:
    mov %r12, %rcx
    mov $6, %rax
    tdcall
    test %rax, %rax
    jnz die
    add $PAGE, %r12
    jmp accept_range
accept_2m:
    add $0x200000, %r12
    jmp accept_range
accept_done:
    ret

# APs land here and stay until the operating system claims them through the
# measured ACPI wakeup mailbox: a vCPU index is its APIC ID in the MADT this
# image authors, so nothing outside the digest decides which CPU answers.
ap_wait:
    mov $MAILBOX, %rbx
ap_poll:
    pause
    mov (%rbx), %eax
    cmp $1, %eax
    jne ap_poll
    mov 4(%rbx), %eax
    cmp %esi, %eax
    jne ap_poll
    mov 8(%rbx), %rax
    test %rax, %rax
    jz ap_poll
    movl $0, (%rbx)
    jmp *%rax

# Every reachable cause of this is a disagreement between the image and its
# loader about which pages the digest covers, and a TD has no channel to report
# it on that the boot path is allowed to depend on.
die:
    cli
    hlt
    jmp die

    .org 0xff0
reset_vector:
    jmp reset_start
    .fill 0x1000-(.-reset_start),1,0
