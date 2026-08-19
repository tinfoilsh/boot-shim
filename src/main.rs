mod acpi;
mod boot;
mod image;
mod layout;
mod mrtd;
mod snp;
mod tdvf;
use clap::{Args, Parser, Subcommand};
use layout::{Params, DEFAULT_CBIT, DEFAULT_MEMORY, DEFAULT_VCPUS};
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

/// The measured description of the guest, chosen at build time.  None of it is
/// a property of the machine: every field lands in a measured page, so a
/// change here is a change to the digest a verifier checks.
#[derive(Args)]
struct Common {
    #[arg(long)]
    kernel: PathBuf,
    #[arg(long)]
    initramfs: PathBuf,
    #[arg(long)]
    output: PathBuf,
    /// Guest memory the measured E820 map describes.  Accepts 0x hex and
    /// K/M/G suffixes.
    #[arg(long, default_value_t = DEFAULT_MEMORY, value_parser = parse_size)]
    memory: u64,
    /// Kernel command line.  Measured whole; `no5lvl` is appended whatever is
    /// given, because the measured page tables are four-level.
    #[arg(long)]
    cmdline: Option<String>,
    /// A platform MMIO aperture, as BASE:SIZE.  Repeatable.  Nothing is loaded
    /// there, the shim never accepts it and E820 reserves it.  There is no
    /// default: by default the image describes a flat span of guest RAM and
    /// assumes nothing about any particular VMM's legacy memory map.
    #[arg(long, value_name = "BASE:SIZE", value_parser = parse_hole)]
    mmio_hole: Vec<(u64, u64)>,
}

#[derive(Subcommand)]
enum Command {
    Build {
        #[command(flatten)]
        common: Common,
        /// vCPUs the measured MADT advertises.
        #[arg(long, default_value_t = DEFAULT_VCPUS)]
        vcpus: u32,
        /// Deployment-specific value the host must pass as MRCONFIGID, 48
        /// hex-encoded bytes.  Recorded in the manifest for the verifier.
        #[arg(long)]
        config_hash: Option<String>,
    },
    /// Build an AMD SEV-SNP image.
    BuildSnp {
        #[command(flatten)]
        common: Common,
        /// Deployment-specific value the host must pass as HOST_DATA, 32
        /// hex-encoded bytes.  Recorded in the manifest for the verifier.
        #[arg(long)]
        config_hash: Option<String>,
        /// C-bit position the encrypted identity map is built around.  The
        /// only CPU property that reaches the image, and nothing before Linux
        /// may take a CPUID dependency to discover it, so it is stated here
        /// and published in the manifest.
        #[arg(long, default_value_t = DEFAULT_CBIT)]
        cbit: u8,
        /// PKCS#8 PEM P-384 key that signs the ID block.  Without one the
        /// firmware enforces neither the launch digest nor the guest policy.
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

fn main() {
    let result = match Cli::parse().command {
        Command::Build {
            common,
            vcpus,
            config_hash,
        } => Params::new(
            common.memory,
            vcpus,
            common.cmdline.as_deref(),
            DEFAULT_CBIT,
            common.mmio_hole,
        )
        .and_then(|params| {
            image::build(
                &common.kernel,
                &common.initramfs,
                &common.output,
                &params,
                config_hash.as_deref(),
            )
        }),
        Command::BuildSnp {
            common,
            config_hash,
            cbit,
            id_key,
            guest_svn,
        } => Params::new(
            common.memory,
            layout::SNP_VCPU_COUNT,
            common.cmdline.as_deref(),
            cbit,
            common.mmio_hole,
        )
        .and_then(|params| {
            snp::build(
                &common.kernel,
                &common.initramfs,
                &common.output,
                &params,
                config_hash.as_deref(),
                id_key.as_deref(),
                guest_svn,
            )
        }),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
