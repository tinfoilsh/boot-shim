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
        /// Deployment-specific value the host must pass as MRCONFIGID, 48
        /// hex-encoded bytes.  Recorded in the manifest for the verifier.
        #[arg(long)]
        config_hash: Option<String>,
    },
    /// Build an AMD SEV-SNP image for the pinned Turin profile.
    BuildSnp {
        #[arg(long)]
        kernel: PathBuf,
        #[arg(long)]
        initramfs: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Deployment-specific value the host must pass as HOST_DATA, 32
        /// hex-encoded bytes.  Recorded in the manifest for the verifier.
        #[arg(long)]
        config_hash: Option<String>,
        /// PKCS#8 PEM P-384 key that signs the ID block.  Without one the
        /// firmware enforces neither the launch digest nor the guest policy.
        #[arg(long)]
        id_key: Option<PathBuf>,
        /// Anti-rollback version placed in the signed ID block.
        #[arg(long, default_value_t = 0)]
        guest_svn: u32,
    },
}
fn main() {
    let result = match Cli::parse().command {
        Command::Build {
            kernel,
            initramfs,
            output,
            config_hash,
        } => image::build(&kernel, &initramfs, &output, config_hash.as_deref()),
        Command::BuildSnp {
            kernel,
            initramfs,
            output,
            config_hash,
            id_key,
            guest_svn,
        } => snp::build(
            &kernel,
            &initramfs,
            &output,
            config_hash.as_deref(),
            id_key.as_deref(),
            guest_svn,
        ),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
