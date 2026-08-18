use std::{env, path::PathBuf, process::Command};

fn run(command: &mut Command) {
    let status = command.status().expect("failed to execute assembler tool");
    assert!(status.success(), "assembler tool failed");
}

fn main() {
    println!("cargo:rerun-if-changed=src/reset.S");
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
}
