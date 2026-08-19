.section .reset,"ax"
.code32
.global snp_reset_start
snp_reset_start:
    cli
    cld
    mov $0x0010b000, %esp

    # KVM's SNP VMSA starts with paging disabled (CR0=0x31).  Enter long
    # mode in guest context instead of asking KVM to synthesize an already
    # paged VMSA, which results in an immediate shutdown on SNP hardware.
    mov $0xc0000080, %ecx
    rdmsr
    or $0x900, %eax                 # EFER.LME | EFER.NXE
    wrmsr
    mov $0x00100000, %eax
    mov %eax, %cr3
    mov %cr0, %eax
    bts $31, %eax
    mov %eax, %cr0
    call 1f
1:  pop %eax
    add $(snp_long_mode-1b), %eax
    push $0x10
    push %eax
    lret

.code64
snp_long_mode:
    mov $0x18, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %ss
    mov %eax, %fs
    mov %eax, %gs

    # Linux discovers unaccepted memory only through EFI, which this boot
    # path does not provide, so every page the E820 map calls RAM has to be
    # validated here.  The launch-updated pages are already validated and are
    # skipped: revalidating them is the hypervisor page-aliasing attack.  No
    # CPUID, MSR, I/O, GHCB or exception dependency is permitted before Linux.
    mov $0x00000000, %r12
    mov $0x00007000, %r13
    call validate_range
    mov $0x00008000, %r12
    mov $0x00020000, %r13
    call validate_range
    mov $0x00021000, %r12
    mov $0x000a0000, %r13
    call validate_range
    # 0xa0000..0xc0000 is the VGA aperture: real MMIO, never PVALIDATEd.  The
    # rest of the legacy region is RAM that Linux still reads unconditionally
    # (probe_roms, the EBDA and DMI scans), so it has to be validated around
    # the launch-updated ACPI, CPUID, Secrets and CC-blob pages.
    mov $0x000c0000, %r12
    mov $0x000e0000, %r13
    call validate_range
    mov $0x000e1000, %r12
    mov $0x000f0000, %r13
    call validate_range
    mov $0x000f3000, %r12
    mov $0x00100000, %r13
    call validate_range
    mov $0x00106000, %r12
    mov $0x00107000, %r13
    call validate_range
    mov $0x00117000, %r12
    mov $0x00120000, %r13
    call validate_range
    mov $0x00150000, %r12
    mov $0x01000000, %r13
    call validate_range
    movabs $0x1111111111111111, %r12    # end of the measured kernel payload
    mov $0x20000000, %r13
    call validate_range
    movabs $0x4444444444444444, %r12    # end of the measured initramfs
    mov $0x40000000, %r13
    call validate_range

snp_boot_kernel:
    mov $0x7000, %rsi
snp_entry:
    movabs $0x3333333333333333, %rax
    call *%rax

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
    add $0x1000, %r12
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


    .fill 0x1000-(.-snp_reset_start),1,0
