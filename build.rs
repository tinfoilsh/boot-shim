use std::{env, path::PathBuf, process::Command};

fn run(command: &mut Command) {
    let status = command.status().expect("failed to execute assembler tool");
    assert!(status.success(), "assembler tool failed");
}

fn main() {
    println!("cargo:rerun-if-changed=src/reset.S");
    println!("cargo:rerun-if-changed=src/snp_reset.S");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let object = out.join("reset.o");
    let binary = out.join("reset.bin");
    run(Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg("src/reset.S"));
    run(Command::new("objcopy")
        .args(["-O", "binary", "-j", ".reset"])
        .arg(&object)
        .arg(&binary));
    let snp_object = out.join("snp_reset.o");
    let snp_binary = out.join("snp_reset.bin");
    run(Command::new("as")
        .args(["--64", "-o"])
        .arg(&snp_object)
        .arg("src/snp_reset.S"));
    run(Command::new("objcopy")
        .args(["-O", "binary", "-j", ".reset"])
        .arg(&snp_object)
        .arg(&snp_binary));
}
