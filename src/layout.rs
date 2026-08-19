// The fixed guest-physical layout.  Every constant here is measured, and both
// the packager and the reset shims consume it: build.rs `include!`s this file
// and re-emits the addresses as assembler `.set` directives, so a shim can
// never validate a different map from the one the packager measures.  Nothing
// in this file may reference the rest of the crate.

pub const PAGE: u64 = 4096;
pub const RAM_SIZE: u64 = 0x4000_0000;

pub const ZERO_PAGE: u64 = 0x0000_7000;
pub const CMDLINE: u64 = 0x0002_0000;
// The legacy VGA aperture is real MMIO on a q35 machine and never guest RAM.
pub const VGA_HOLE: u64 = 0x000a_0000;
pub const VGA_HOLE_END: u64 = 0x000c_0000;
pub const ACPI_BASE: u64 = 0x000e_0000;
pub const MAILBOX: u64 = 0x000f_0000;
pub const SNP_CPUID: u64 = 0x000f_0000;
pub const SNP_SECRETS: u64 = 0x000f_1000;
pub const SNP_CC_BLOB: u64 = 0x000f_2000;
pub const PAGE_TABLES: u64 = 0x0010_0000;
pub const PAGE_TABLE_SIZE: u64 = 6 * PAGE;
pub const BSP_STACK: u64 = 0x0010_7000;
pub const BSP_STACK_SIZE: u64 = 0x0001_0000;
pub const BSP_STACK_TOP: u64 = BSP_STACK + BSP_STACK_SIZE;
pub const SHIM_BASE: u64 = 0x0012_0000;
pub const SHIM_SIZE: u64 = PAGE;
pub const KERNEL_SETUP_BASE: u64 = 0x0012_1000;
pub const KERNEL_SETUP_AREA_SIZE: u64 = 0x0002_f000;
pub const KERNEL_SETUP_END: u64 = KERNEL_SETUP_BASE + KERNEL_SETUP_AREA_SIZE;
pub const KERNEL_BASE: u64 = 0x0100_0000;
pub const INITRAMFS_BASE: u64 = 0x2000_0000;
pub const RESET_ALIAS: u64 = 0xffff_f000;
pub const SNP_VMSA: u64 = 0xffff_ffff_f000;
pub const SHIM_LIMIT: usize = 256 * 1024;

// The shim-owned regions must tile in exactly the order the shims skip them.
// A shim validates the gaps between these, so a layout change that closed or
// reordered one would silently make it validate a launch-updated page.
const _: () = assert!(VGA_HOLE < VGA_HOLE_END && VGA_HOLE_END <= ACPI_BASE);
const _: () = assert!(SNP_CC_BLOB + PAGE <= PAGE_TABLES);
const _: () = assert!(PAGE_TABLES + PAGE_TABLE_SIZE <= BSP_STACK);
const _: () = assert!(BSP_STACK_TOP <= SHIM_BASE);
const _: () = assert!(SHIM_BASE + SHIM_SIZE == KERNEL_SETUP_BASE);
const _: () = assert!(KERNEL_SETUP_END <= KERNEL_BASE);

// Immediate slots the packager patches with the rounded ends of the measured
// kernel and initramfs, which depend on the input files.
pub const MARK_KERNEL_END: u64 = 0x1111_1111_1111_1111;
pub const MARK_INITRAMFS_END: u64 = 0x2222_2222_2222_2222;
pub const MARK_ENTRY: u64 = 0x3333_3333_3333_3333;

// Linux 64-bit boot protocol GDT selectors.  A selector is its own byte offset
// into the measured GDT, so these index the table the packager builds and name
// the selectors the reset shim loads.
pub const BOOT_CS32: u64 = 0x08;
pub const BOOT_CS: u64 = 0x10;
pub const BOOT_DS: u64 = 0x18;
// Four 8-byte entries: null, 32-bit code, 64-bit code, data.
pub const GDT_LIMIT: u64 = BOOT_DS + 7;
// The GDT sits at the base of the stack region, which grows down from the far
// end.  The 10-byte pseudo-descriptor follows it so a shim can `lgdt` without
// a stack.  SNP takes the same table through the measured VMSA's GDTR instead.
pub const GDT_PTR: u64 = BSP_STACK + GDT_LIMIT + 1;

pub const VCPU_COUNT: u32 = 4;
// SEV-SNP has no measured AP start mechanism here: the IGVM file carries one
// SnpVpContext and the MADT omits the multiprocessor wakeup structure, so the
// image must advertise exactly the one CPU it provisions.
pub const SNP_VCPU_COUNT: u32 = 1;
// The only CPU property that reaches the image.  It is 51 on every EPYC that
// supports SNP; the encrypted identity map is built around it.  Family, model
// and stepping deliberately appear nowhere: the IGVM file states the whole
// VMSA, including RDX, so no CPU signature enters the launch measurement.
pub const SNP_CBIT: u8 = 51;
// The VMSA's SEV_FEATURES.  QEMU forwards this to KVM_SEV_INIT2, so the file
// and not the host decides the feature set: SNPActive only, no DebugSwap.
pub const SNP_SEV_FEATURES: u64 = 1;

// SEV-SNP guest policy.  ABI 1.51 is a minimum firmware version, so a host
// running older SEV firmware refuses to launch this image.  MIGRATE_MA and
// DEBUG stay clear so no migration agent or debugger can attach.
//
// SMT and SINGLE_SOCKET cannot be expressed here.  KVM rejects
// SNP_LAUNCH_START with EINVAL for any policy that clears the SMT bit or sets
// SINGLE_SOCKET, so a policy asking for either is not a stricter image, it is
// an image that never launches.  Both facts are still attested -- SMT_EN and
// the socket count appear in the report's PLATFORM_INFO -- so they move to the
// verifier requirements the manifest publishes instead.
const POLICY_ABI_MINOR: u64 = 51;
const POLICY_ABI_MAJOR: u64 = 1 << 8;
const POLICY_SMT: u64 = 1 << 16;
const POLICY_RESERVED_ONE: u64 = 1 << 17;
pub const SNP_GUEST_POLICY: u64 =
    POLICY_ABI_MINOR | POLICY_ABI_MAJOR | POLICY_SMT | POLICY_RESERVED_ONE;

// This kernel is built without any 8250/earlycon driver, so naming a serial
// console here makes init fail to open /dev/console and panic.
pub const COMMAND_LINE: &str = "panic=-1 no5lvl";

pub fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}
