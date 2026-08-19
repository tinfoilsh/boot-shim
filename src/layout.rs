// The fixed guest-physical layout.  Every constant here is measured, and both
// the packager and the reset shims consume it: build.rs `include!`s this file
// and re-emits the addresses as assembler `.set` directives, so a shim can
// never validate a different map from the one the packager measures.  Nothing
// in this file may reference the rest of the crate.

// One definition site for every address.  The macro emits the constants and
// the table build.rs re-emits as assembler symbols, so there is no separate
// export list to fall out of step with the constants themselves.
macro_rules! layout {
    ($($(#[$attr:meta])* $name:ident = $value:expr;)*) => {
        $($(#[$attr])* pub const $name: u64 = $value;)*
        // Consumed by build.rs, which `include!`s this file; the crate
        // itself only ever uses the constants.
        #[allow(dead_code)]
        pub const SYMBOLS: &[(&str, u64)] = &[$((stringify!($name), $name)),*];
    };
}

layout! {
    PAGE = 4096;

    ZERO_PAGE = 0x0000_7000;
    CMDLINE = 0x0002_0000;
    ACPI_BASE = 0x000e_0000;
    MAILBOX = 0x000f_0000;
    // The one page the host fills in: QEMU writes its own memory map there as
    // a TD HOB.  Nothing here reads it -- the E820 map Linux uses is measured
    // -- but a loader refuses an image that does not say where it goes.
    TD_HOB = 0x000f_1000;
    SNP_CPUID = 0x000f_0000;
    SNP_SECRETS = 0x000f_1000;
    SNP_CC_BLOB = 0x000f_2000;
    PAGE_TABLES = 0x0010_0000;
    // One PML4 page and one PDPT page of 1-GiB pages.  See MAP_LIMIT.
    PAGE_TABLE_SIZE = 2 * PAGE;
    BSP_STACK = 0x0010_7000;
    BSP_STACK_SIZE = 0x0001_0000;
    BSP_STACK_TOP = BSP_STACK + BSP_STACK_SIZE;
    SHIM_BASE = 0x0012_0000;
    SHIM_SIZE = PAGE;
    KERNEL_SETUP_BASE = 0x0012_1000;
    KERNEL_SETUP_AREA_SIZE = 0x0002_f000;
    KERNEL_SETUP_END = KERNEL_SETUP_BASE + KERNEL_SETUP_AREA_SIZE;
    KERNEL_BASE = 0x0100_0000;
    INITRAMFS_BASE = 0x2000_0000;
    RESET_ALIAS = 0xffff_f000;
    SNP_VMSA = 0xffff_ffff_f000;

    // Linux 64-bit boot protocol GDT selectors.  A selector is its own byte
    // offset into the measured GDT, so these index the table the packager
    // builds and name the selectors the reset shim loads.
    BOOT_CS32 = 0x08;
    BOOT_CS = 0x10;
    BOOT_DS = 0x18;
    // Four 8-byte entries: null, 32-bit code, 64-bit code, data.
    GDT_LIMIT = BOOT_DS + 7;
    // The GDT sits at the base of the stack region, which grows down from the
    // far end.  The 10-byte pseudo-descriptor follows it so a shim can `lgdt`
    // without a stack.  SNP takes the same table through the VMSA's GDTR.
    GDT_PTR = BSP_STACK + GDT_LIMIT + 1;

    // Where each shim finds its own data block inside its measured page: the
    // kernel entry point, then the ranges to accept.  Both are derived from
    // the section list the packager measures, so the addresses a shim acts on
    // and the addresses the digest covers are the same list.
    SHIM_DATA = 0x0000_0c00;
    // Bounded by the GUIDed table the TDX image carries at the end of the
    // page; tdvf.rs asserts the two do not meet.
    SHIM_DATA_SIZE = 0x0000_03b8;
}

pub const SHIM_LIMIT: usize = 256 * 1024;

// The identity map both shims run on is one PML4 page and one PDPT page of
// 1-GiB pages, so it covers exactly this much guest-physical space and no
// more.  It is a bound on --memory and not just on the map: the SNP shim
// PVALIDATEs and zeroes through this table, so a guest whose accept list ran
// past the map would page-fault with no IDT installed.  The TDX shim needs it
// to reach RESET_ALIAS, where it is itself executing.
pub const GIB: u64 = 0x4000_0000;
pub const MAP_LIMIT: u64 = 512 * GIB;
const _: () = assert!(PAGE_TABLE_SIZE == 2 * PAGE);
const _: () = assert!(RESET_ALIAS < MAP_LIMIT);

// The shim-owned regions must tile in exactly the order the shims skip them.
// A shim accepts the gaps between these, so a layout change that closed or
// reordered one would silently make it accept a launch-updated page.
const _: () = assert!(MAILBOX + PAGE == TD_HOB && TD_HOB + PAGE <= PAGE_TABLES);
const _: () = assert!(SNP_CPUID + PAGE == SNP_SECRETS && SNP_SECRETS + PAGE == SNP_CC_BLOB);
const _: () = assert!(SNP_CC_BLOB + PAGE <= PAGE_TABLES);
const _: () = assert!(PAGE_TABLES + PAGE_TABLE_SIZE <= BSP_STACK);
const _: () = assert!(GDT_PTR + 10 <= BSP_STACK_TOP);
const _: () = assert!(BSP_STACK_TOP <= SHIM_BASE);
const _: () = assert!(SHIM_BASE + SHIM_SIZE == KERNEL_SETUP_BASE);
const _: () = assert!(KERNEL_SETUP_END <= KERNEL_BASE);
const _: () = assert!(KERNEL_BASE < INITRAMFS_BASE);
const _: () = assert!(SHIM_DATA + SHIM_DATA_SIZE <= SHIM_SIZE);
// A TD fetches its first instruction from the top of the 32-bit address space.
const _: () = assert!(RESET_ALIAS + PAGE == 0x1_0000_0000);

// Offsets of the four tables inside the single measured ACPI page.  They are
// laid out by hand, so the page has to be checked for overlap here rather than
// discovered by a corrupt table at boot.
pub const ACPI_XSDT: u64 = 0x100;
pub const ACPI_FADT: u64 = 0x200;
pub const ACPI_DSDT: u64 = 0x400;
pub const ACPI_MADT: u64 = 0x500;
const _: () = assert!(36 <= ACPI_XSDT);
const _: () = assert!(ACPI_XSDT + 52 <= ACPI_FADT);
const _: () = assert!(ACPI_FADT + 276 <= ACPI_DSDT);
const _: () = assert!(ACPI_DSDT + 36 <= ACPI_MADT);
// One Local APIC entry per vCPU plus the wakeup structure, all inside the page.
pub const MAX_VCPUS: u32 = ((PAGE - ACPI_MADT - 44 - 16) / 8) as u32;

// SEV-SNP has no measured AP start mechanism here: the IGVM file carries one
// SnpVpContext and the MADT omits the multiprocessor wakeup structure, so the
// image must advertise exactly the one CPU it provisions.
pub const SNP_VCPU_COUNT: u32 = 1;
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

// Defaults for the parameters below.  They are defaults, not facts about the
// world: each one is a measured build input a deployer can override.
pub const DEFAULT_MEMORY: u64 = 0x4000_0000;
pub const DEFAULT_VCPUS: u32 = 4;
pub const DEFAULT_CMDLINE: &str = "panic=-1";
// The C-bit position is the one CPU property that reaches the image: the
// encrypted identity map is built around it.  It is 51 on the EPYC parts this
// has been run on, but nothing here can check that, so it is a stated build
// input rather than a constant.  Family, model and stepping deliberately
// appear nowhere: the IGVM file states the whole VMSA, including RDX, so no
// CPU signature enters the launch measurement.
pub const DEFAULT_CBIT: u8 = 51;

// The measured page tables are four-level.  A kernel that switched to five
// would be running on tables no measurement covers, so this is a property of
// the image rather than a preference, and it is appended to whatever command
// line the deployer asks for.
const REQUIRED_CMDLINE: &str = "no5lvl";

/// Everything about the image a deployer chooses at build time.  All of it is
/// measured -- the command line and E820 map are measured pages, the vCPU
/// count reaches the measured MADT -- so these are build inputs and not
/// runtime ones, but none of them is a property of the machine.
pub struct Params {
    pub memory: u64,
    pub vcpus: u32,
    pub cmdline: String,
    pub cbit: u8,
    /// Platform MMIO apertures the deployer declares.  Nothing is loaded
    /// there, the shim never accepts it and E820 reserves it.  Empty by
    /// default: the image describes a flat span of guest RAM and makes no
    /// assumption about any particular VMM's legacy memory map.  A platform
    /// that really does carve out an aperture has to say so, and the
    /// declaration is then measured and published like everything else.
    pub mmio: Vec<(u64, u64)>,
}

impl Params {
    pub fn new(
        memory: u64,
        vcpus: u32,
        cmdline: Option<&str>,
        cbit: u8,
        mmio: Vec<(u64, u64)>,
    ) -> Result<Self, String> {
        if !memory.is_multiple_of(PAGE) || memory <= INITRAMFS_BASE || memory > MAP_LIMIT {
            return Err(format!(
                "--memory must be page-aligned, larger than {INITRAMFS_BASE:#x} \
                 and at most {MAP_LIMIT:#x}"
            ));
        }
        if vcpus == 0 || vcpus > MAX_VCPUS {
            return Err(format!("--vcpus must be between 1 and {MAX_VCPUS}"));
        }
        if !(32..=63).contains(&cbit) {
            return Err("--cbit must name a bit in the physical address width".into());
        }
        let cmdline = match cmdline.map(str::trim).filter(|c| !c.is_empty()) {
            None => format!("{DEFAULT_CMDLINE} {REQUIRED_CMDLINE}"),
            Some(c) if c.split_whitespace().any(|w| w == REQUIRED_CMDLINE) => c.to_string(),
            Some(c) => format!("{c} {REQUIRED_CMDLINE}"),
        };
        if cmdline.bytes().any(|b| b == 0 || !b.is_ascii()) {
            return Err("--cmdline must be printable ASCII".into());
        }
        for (base, size) in &mmio {
            if !base.is_multiple_of(PAGE) || !size.is_multiple_of(PAGE) || *size == 0 {
                return Err("--mmio-hole must be a non-empty page-aligned range".into());
            }
            if base + size > memory {
                return Err("--mmio-hole lies outside the memory the image describes".into());
            }
        }
        Ok(Params {
            memory,
            vcpus,
            cmdline,
            cbit,
            mmio,
        })
    }
}

pub fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}
