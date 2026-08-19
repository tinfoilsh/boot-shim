use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

// The layout is defined once, in Rust, and re-emitted here as assembler
// symbols.  The shims address memory through these names only, so a shim
// cannot drift from the map the packager measures.
#[allow(dead_code)]
mod layout {
    include!("src/layout.rs");
}
use layout::*;

fn run(command: &mut Command) {
    let status = command.status().expect("failed to execute assembler tool");
    assert!(status.success(), "assembler tool failed");
}

fn write_layout(path: &Path) {
    let mut out = String::from("# Generated from src/layout.rs by build.rs.\n");
    macro_rules! export {
        ($($name:ident),* $(,)?) => {$(
            out.push_str(&format!(".set {}, {:#x}\n", stringify!($name), $name));
        )*};
    }
    export!(
        PAGE,
        RAM_SIZE,
        ZERO_PAGE,
        CMDLINE,
        VGA_HOLE,
        VGA_HOLE_END,
        ACPI_BASE,
        MAILBOX,
        TD_HOB,
        SNP_CPUID,
        SNP_CC_BLOB,
        PAGE_TABLES,
        PAGE_TABLE_SIZE,
        BSP_STACK,
        BSP_STACK_SIZE,
        BSP_STACK_TOP,
        SHIM_BASE,
        KERNEL_SETUP_BASE,
        KERNEL_SETUP_END,
        KERNEL_BASE,
        INITRAMFS_BASE,
        RESET_ALIAS,
        MARK_KERNEL_END,
        MARK_INITRAMFS_END,
        MARK_ENTRY,
        GDT_PTR,
        BOOT_CS32,
        BOOT_CS,
        BOOT_DS,
    );
    fs::write(path, out).expect("write layout.inc");
}

fn assemble(out: &Path, name: &str) {
    let object = out.join(format!("{name}.o"));
    let binary = out.join(format!("{name}.bin"));
    run(Command::new("as")
        .args(["--64", "-I"])
        .arg(out)
        .arg("-o")
        .arg(&object)
        .arg(format!("src/{name}.S")));
    run(Command::new("objcopy")
        .args(["-O", "binary", "-j", ".reset"])
        .arg(&object)
        .arg(&binary));
}

fn main() {
    println!("cargo:rerun-if-changed=src/reset.S");
    println!("cargo:rerun-if-changed=src/snp_reset.S");
    println!("cargo:rerun-if-changed=src/layout.rs");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    write_layout(&out.join("layout.inc"));
    assemble(&out, "reset");
    assemble(&out, "snp_reset");
}
