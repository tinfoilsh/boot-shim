pub const RAM_SIZE: u64 = 0x4000_0000;
pub const ZERO_PAGE: u64 = 0x0000_7000;
pub const CMDLINE: u64 = 0x0002_0000;
pub const ACPI_BASE: u64 = 0x000e_0000;
pub const MAILBOX: u64 = 0x000f_0000;
pub const SNP_CPUID: u64 = 0x000f_0000;
pub const SNP_SECRETS: u64 = 0x000f_1000;
pub const SNP_CC_BLOB: u64 = 0x000f_2000;
pub const PAGE_TABLES: u64 = 0x0010_0000;
pub const BSP_STACK: u64 = 0x0010_7000;
pub const SHIM_BASE: u64 = 0x0012_0000;
pub const KERNEL_SETUP_BASE: u64 = 0x0012_1000;
pub const KERNEL_SETUP_AREA_SIZE: usize = 0x2f000;
pub const KERNEL_BASE: u64 = 0x0100_0000;
pub const INITRAMFS_BASE: u64 = 0x2000_0000;
pub const RESET_ALIAS: u64 = 0xffff_f000;
pub const SNP_VMSA: u64 = 0xffff_ffff_f000;
pub const PAGE: u64 = 4096;
pub const SHIM_LIMIT: usize = 256 * 1024;
pub const VCPU_COUNT: u32 = 4;
// SEV-SNP has no measured AP start mechanism here: the IGVM file carries one
// SnpVpContext and the MADT omits the multiprocessor wakeup structure, so the
// image must advertise exactly the one CPU it provisions.
pub const SNP_VCPU_COUNT: u32 = 1;
pub const SNP_CBIT: u8 = 51;
pub const SNP_PHYS_BITS: u8 = 46;
pub const SNP_CPU_FAMILY: u8 = 26;
pub const SNP_CPU_MODEL: u8 = 2;
pub const SNP_CPU_STEPPING: u8 = 1;
pub const SNP_SEV_FEATURES: u64 = 1;
// ABI 1.51, reserved-must-be-one and single-socket; SMT/MA/debug are clear.
pub const SNP_GUEST_POLICY: u64 = 0x0000_0000_0012_0133;
// This kernel is built without any 8250/earlycon driver, so naming a serial
// console here makes init fail to open /dev/console and panic.
pub const COMMAND_LINE: &str = "panic=-1 no5lvl";

pub fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}
