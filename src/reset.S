.include "layout.inc"
.section .reset,"ax"

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

    # Accept every page of guest RAM.  Linux discovers unaccepted memory only
    # through EFI, which this boot path does not provide.  The ranges come out
    # of the measured data block below, where the packager wrote the exact
    # complement of the regions it placed: the pages the loader added are
    # already accepted and are skipped, because accepting one twice is how a
    # page gets silently replaced.  There is no second copy of that map here
    # to fall out of step with the one the digest covers.
    lea shim_data(%rip), %rbp
    add $8, %rbp
accept_next:
    mov (%rbp), %r12
    mov 8(%rbp), %r13
    mov %r12, %rax
    or %r13, %rax
    jz boot_kernel
    add $16, %rbp
    call accept_range
    jmp accept_next

boot_kernel:
    mov $ZERO_PAGE, %rsi
    lea shim_data(%rip), %rax
    jmp *(%rax)

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
# loader about which pages the digest covers.  Report it through
# TDG.VP.VMCALL<ReportFatalError> -- the architectural channel for exactly
# this, and the only thing this shim ever says to the host -- so the failure
# reaches the operator instead of looking like a TD that hung.  R12 carries
# the offending address; the TD halts either way.
die:
    mov $0x1c00, %ecx               # expose R10, R11 and R12 to the host
    xor %r10d, %r10d                # standard GHCI
    mov $0x10003, %r11d             # ReportFatalError
    xor %eax, %eax                  # TDG.VP.VMCALL
    tdcall
fatal:
    cli
    hlt
    jmp fatal

    # The kernel entry point and the ranges to accept, written by the packager
    # into the measured page.  layout.rs pins the offset and the size.
    .org SHIM_DATA
shim_data:
    .fill SHIM_DATA_SIZE,1,0

    .org 0xff0
reset_vector:
    jmp reset_start
    .fill 0x1000-(.-reset_start),1,0
