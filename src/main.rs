mod acpi;
mod boot;
mod image;
mod layout;
mod mrtd;
mod snp;
use clap::{Args, Parser, Subcommand};
use layout::{Params, DEFAULT_CBIT, DEFAULT_RAM, DEFAULT_VCPUS};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "boot-shim",
    about = "Build deterministic TDX or AMD SEV-SNP Linux IGVM images"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The measured description of the guest, chosen at build time.
#[derive(Args)]
struct Common {
    #[arg(long)]
    kernel: PathBuf,
    #[arg(long)]
    initramfs: PathBuf,
    #[arg(long)]
    output: PathBuf,
    /// Guest RAM the host must match, in 0x hex or with a K/M/G suffix.
    #[arg(long, default_value_t = DEFAULT_RAM, value_parser = parse_size)]
    ram: u64,
    /// Linux command line, measured whole. The PCI options an IGVM guest needs
    /// replace any the caller passed, and `no5lvl` is always appended.
    #[arg(long, default_value = "", hide_default_value = true)]
    cmdline: String,
    /// Processor count, which the measured MADT advertises. SNP additionally
    /// measures one VMSA per processor, so this changes the launch digest.
    #[arg(long, default_value_t = DEFAULT_VCPUS)]
    vcpus: u32,
    /// A further MMIO aperture besides the machine's own, as BASE:SIZE, repeatable.
    #[arg(long, value_name = "BASE:SIZE", value_parser = parse_hole)]
    mmio_hole: Vec<(u64, u64)>,
}

#[derive(Subcommand)]
enum Command {
    /// Build an Intel TDX image.
    BuildTdx {
        #[command(flatten)]
        common: Common,
        /// MRCONFIGID the host must pass, 48 hex-encoded bytes.
        #[arg(long)]
        config_hash: Option<String>,
    },
    /// Build an AMD SEV-SNP image.
    BuildSnp {
        #[command(flatten)]
        common: Common,
        /// HOST_DATA the host must pass, 32 hex-encoded bytes.
        #[arg(long)]
        config_hash: Option<String>,
        /// Encryption bit the identity map is built around, published in the manifest.
        #[arg(long, default_value_t = DEFAULT_CBIT)]
        cbit: u8,
        /// PKCS#8 PEM P-384 key that signs the ID block the firmware enforces.
        #[arg(long)]
        id_key: Option<PathBuf>,
        /// Anti-rollback version placed in the signed ID block.
        #[arg(long, default_value_t = 0)]
        guest_svn: u32,
    },
}

fn parse_size(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (digits, scale) = match text.as_bytes().last() {
        Some(b'K' | b'k') => (&text[..text.len() - 1], 1 << 10),
        Some(b'M' | b'm') => (&text[..text.len() - 1], 1 << 20),
        Some(b'G' | b'g') => (&text[..text.len() - 1], 1 << 30),
        _ => (text, 1),
    };
    let value = match digits.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => digits.parse(),
    };
    value
        .map_err(|e| e.to_string())?
        .checked_mul(scale)
        .ok_or_else(|| "size overflows".to_string())
}

fn parse_hole(text: &str) -> Result<(u64, u64), String> {
    let (base, size) = text.split_once(':').ok_or("expected BASE:SIZE")?;
    Ok((parse_size(base)?, parse_size(size)?))
}

fn run() -> Result<(), String> {
    match Cli::parse().command {
        Command::BuildTdx {
            common,
            config_hash,
        } => {
            let params = Params::tdx(common.ram, common.vcpus, &common.cmdline, common.mmio_hole)?;
            image::build(
                &common.kernel,
                &common.initramfs,
                &common.output,
                &params,
                config_hash.as_deref(),
            )
        }
        Command::BuildSnp {
            common,
            config_hash,
            cbit,
            id_key,
            guest_svn,
        } => {
            let params = Params::snp(
                common.ram,
                common.vcpus,
                cbit,
                &common.cmdline,
                common.mmio_hole,
            )?;
            snp::build(
                &common.kernel,
                &common.initramfs,
                &common.output,
                &params,
                config_hash.as_deref(),
                id_key.as_deref(),
                guest_svn,
            )
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
