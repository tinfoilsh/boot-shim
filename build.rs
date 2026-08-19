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
#[allow(unused_imports)]
use layout::*;

fn run(command: &mut Command) {
    let status = command.status().expect("failed to execute assembler tool");
    assert!(status.success(), "assembler tool failed");
}

fn write_layout(path: &Path) {
    let mut out = String::from("# Generated from src/layout.rs by build.rs.\n");
    for (name, value) in layout::SYMBOLS {
        out.push_str(&format!(".set {name}, {value:#x}\n"));
    }
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
