mod acpi;
mod boot;
mod image;
mod layout;
mod mrtd;
mod snp;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "tdx-shim",
    about = "Build deterministic TDX or AMD SEV-SNP Linux IGVM images"
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
    /// Build an AMD SEV-SNP image for the pinned Turin profile.
    BuildSnp {
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
        Command::BuildSnp {
            kernel,
            initramfs,
            output,
        } => snp::build(&kernel, &initramfs, &output),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
