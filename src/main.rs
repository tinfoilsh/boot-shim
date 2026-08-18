mod acpi;
mod boot;
mod image;
mod layout;
mod mrtd;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "tdx-shim",
    about = "Build a deterministic TDX Linux IGVM image"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Build {
        #[arg(long)]
        kernel: PathBuf,
        #[arg(long)]
        initramfs: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}
fn main() {
    let result = match Cli::parse().command {
        Command::Build {
            kernel,
            initramfs,
            output,
        } => image::build(&kernel, &initramfs, &output),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
