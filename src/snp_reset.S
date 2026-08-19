.include "layout.inc"
.section .reset,"ax"

.code32
.global snp_reset_start
snp_reset_start:
    cli
    cld
    mov $BSP_STACK_TOP, %esp

    # The VMSA hands us 32-bit protected mode with paging off (CR0=0x31), so
    # the shim enters long mode itself.  A paged VMSA is possible -- KVM's
    # sev_post_set_cr3() writes CR3 into the save area on KVM_SET_SREGS
    # precisely so it reaches the VMSA -- but it would add CR0.PG, EFER.LME,
    # EFER.LMA, CR3 and a 64-bit CS to the fields that must survive the
    # loader's VMSA round-trip, and the build-time measurement depends on
    # every one of them.  Enabling paging here keeps that list short.
    mov $0xc0000080, %ecx
    rdmsr
    or $0x900, %eax                 # EFER.LME | EFER.NXE
    wrmsr
    mov $PAGE_TABLES, %eax
    mov %eax, %cr3
    mov %cr0, %eax
    bts $31, %eax
    mov %eax, %cr0
    call 1f
1:  pop %eax
    add $(snp_long_mode-1b), %eax
    push $BOOT_CS
    push %eax
    lret

.code64
snp_long_mode:
    mov $BOOT_DS, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %ss
    mov %eax, %fs
    mov %eax, %gs

    # Linux discovers unaccepted memory only through EFI, which this boot path
    # does not provide, so every page of guest RAM has to be validated here.
    # The ranges come out of the measured data block below, where the packager
    # wrote the exact complement of the regions it placed: the launch-updated
    # pages are already validated and are skipped, because revalidating them
    # is the hypervisor page-aliasing attack.  There is no second copy of that
    # map here to fall out of step with the one the digest covers.  No CPUID,
    # MSR, I/O, GHCB or exception dependency is permitted before Linux.
    lea shim_data(%rip), %rbp
    add $8, %rbp
validate_next:
    mov (%rbp), %r12
    mov 8(%rbp), %r13
    mov %r12, %rax
    or %r13, %rax
    jz snp_boot_kernel
    add $16, %rbp
    call validate_range
    jmp validate_next

snp_boot_kernel:
    mov $ZERO_PAGE, %rsi
    lea shim_data(%rip), %rax
    jmp *(%rax)

# Report an unexpected PVALIDATE outcome through the GHCB MSR termination
# request, the only host channel available before Linux installs a #VC
# handler.  The reason set carries the carry flag and status, the reason code
# the 2 MiB frame index of the offending GPA.
die:
    mov %r12, %rax
    shr $21, %rax
    and $0xff, %eax
    shl $16, %eax
    and $7, %r15d
    shl $3, %ebx
    or %r15d, %ebx
    and $0xf, %ebx
    shl $12, %ebx
    or %ebx, %eax
    or $0x100, %eax
    xor %edx, %edx
    mov $0xc0010130, %ecx
    wrmsr
    vmgexit
fatal:
    cli
    hlt
    jmp fatal

# Validate [%r12, %r13) as private memory, preferring 2 MiB pages.  PVALIDATE
# reports failure in EAX and sets CF for every one of them, so EAX has to be
# examined first; CF alone only means "RMP entry unchanged", which for a
# non-zero status is simply a restatement of the failure.
validate_range:
    cmp %r13, %r12
    jae validated
    test $0x1fffff, %r12
    jnz validate_4k
    lea 0x200000(%r12), %r14
    cmp %r13, %r14
    ja validate_4k
    mov %r12, %rax
    mov $1, %ecx
    mov $1, %edx
    pvalidate
    setc %bl
    mov %eax, %r15d
    test %eax, %eax
    jnz size_2m
    test %bl, %bl
    jnz die                         # double validation is never accepted
    jmp zero_2m
size_2m:
    cmp $6, %eax                    # FAIL_SIZEMISMATCH: retry as 4 KiB pages
    jne die
validate_4k:
    mov %r12, %rax
    xor %ecx, %ecx
    mov $1, %edx
    pvalidate
    setc %bl
    mov %eax, %r15d
    test %eax, %eax
    jnz die
    test %bl, %bl
    jnz die
    mov %r12, %rdi
    xor %eax, %eax
    mov $512, %ecx
    rep stosq
    add $PAGE, %r12
    jmp validate_range
zero_2m:
    mov %r12, %rdi
    xor %eax, %eax
    mov $0x40000, %ecx
    rep stosq
    add $0x200000, %r12
    jmp validate_range
validated:
    ret

    # The kernel entry point and the ranges to validate, written by the
    # packager into the measured page.  layout.rs pins the offset and size.
    .org SHIM_DATA
shim_data:
    .fill SHIM_DATA_SIZE,1,0

    .fill 0x1000-(.-snp_reset_start),1,0
