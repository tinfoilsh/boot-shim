pub const RAM_SIZE: u64 = 0x4000_0000;
pub const ZERO_PAGE: u64 = 0x0000_7000;
pub const CMDLINE: u64 = 0x0002_0000;
pub const ACPI_BASE: u64 = 0x000e_0000;
pub const MAILBOX: u64 = 0x000f_0000;
pub const PAGE_TABLES: u64 = 0x0010_0000;
pub const BSP_STACK: u64 = 0x0010_7000;
pub const SHIM_BASE: u64 = 0x0012_0000;
pub const KERNEL_SETUP_BASE: u64 = 0x0012_1000;
pub const KERNEL_SETUP_AREA_SIZE: usize = 0x2f000;
pub const KERNEL_BASE: u64 = 0x0100_0000;
pub const INITRAMFS_BASE: u64 = 0x2000_0000;
pub const RESET_ALIAS: u64 = 0xffff_f000;
pub const PAGE: u64 = 4096;
pub const SHIM_LIMIT: usize = 256 * 1024;
pub const VCPU_COUNT: u32 = 4;
pub const COMMAND_LINE: &str = "console=ttyS0 panic=-1 no5lvl earlyprintk=ttyS0";

pub fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}
