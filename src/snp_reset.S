.include "layout.inc"
.section .reset,"ax"

.code32
.global snp_reset_start
# Nothing before Linux may depend on CPUID, an MSR, I/O, the GHCB or an exception.
snp_reset_start:
    cli
    cld
    mov $BSP_STACK_TOP, %esp

    # The VMSA hands over 32-bit protected mode with paging off, so the shim enables it.
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

    # Linux finds unvalidated memory only through EFI, so guest RAM is validated here.
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

# The GHCB MSR termination request is the only host channel before Linux's #VC handler.
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

# Validate [%r12, %r13) as private memory, preferring 2 MiB; PVALIDATE reports status in EAX.
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

    # An application processor launches from its own measured VMSA in 32-bit
    # protected mode and parks here until Linux creates it for real through the
    # GHCB AP-creation call, which replaces this VMSA wholesale.
    #
    # The wait is an AP Reset Hold over the GHCB MSR protocol, not a HLT: under
    # SEV-ES a HLT is a non-automatic exit, so it would raise #VC into an AP that
    # has no IDT and triple-fault it. Reset Hold is the one park the hypervisor
    # can resume, and like the termination request below it needs no GHCB page.
    .code32
    .org SHIM_AP_PARK
.global snp_ap_park
snp_ap_park:
    cli
1:  mov $0xc0010130, %ecx
    xor %edx, %edx
    mov $6, %eax                    # GHCB MSR AP Reset Hold request
    wrmsr
    vmgexit
    jmp 1b                          # re-park if the host resumes us early

    # The kernel entry point and the ranges to validate, written here by the builder.
    .org SHIM_DATA
shim_data:
    .fill SHIM_DATA_SIZE,1,0

    .fill 0x1000-(.-snp_reset_start),1,0
