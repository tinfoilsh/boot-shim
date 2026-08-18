.section .reset,"ax"
.code64
.global reset_start
reset_start:
    cli
    cld
    mov $0x00100000, %rax
    mov %rax, %cr3
    mov $0xb, %eax
    xor %ecx, %ecx
    cpuid
    shr $24, %edx
    test %edx, %edx
    jnz ap_wait

    mov $0x0010b000, %rsp

    # Accept usable low-memory ranges, skipping measured boot-data pages.
    mov $0x00000000, %r12
    mov $0x00007000, %r13
    call accept_range
    mov $0x00008000, %r12
    mov $0x00020000, %r13
    call accept_range
    mov $0x00021000, %r12
    mov $0x000e0000, %r13
    call accept_range
    mov $0x000e1000, %r12
    mov $0x000f0000, %r13
    call accept_range
    mov $0x000f1000, %r12
    mov $0x00100000, %r13
    call accept_range
    mov $0x00106000, %r12
    mov $0x00107000, %r13
    call accept_range
    mov $0x00117000, %r12
    mov $0x00120000, %r13
    call accept_range

    # Accept every initially-unaccepted page below 1 GiB. Use 2-MiB
    # acceptance wherever alignment permits and 4-KiB pages at edges.
    mov $0x00150000, %r12
    mov $0x01000000, %r13
    call accept_range
    # Kernel end and initramfs pages are already accepted/measured. Their
    # rounded ends are patched into these immediate slots by the packager.
kernel_end_imm:
    movabs $0x1111111111111111, %r12
    mov $0x20000000, %r13
    call accept_range
initramfs_end_imm:
    movabs $0x2222222222222222, %r12
    mov $0x40000000, %r13
    call accept_range
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
    add $0x1000, %r12
    jmp accept_range
accept_done:
    ret

boot_kernel:
    mov $0x7000, %rsi
entry_imm:
    movabs $0x3333333333333333, %rax
    jmp *%rax

ap_wait:
    mov $0xf0000, %rbx
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
