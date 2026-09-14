# A reproducible build of the builder.
#
# `cargo build` pins only rustc. The binary it produces still depends on the
# machine: rustc hands the final link to cc, so a different gcc, ld or glibc
# yields a different binary from identical source.
# Two hosts running the same pinned rustc produced different boot-shim
# binaries for exactly that reason -- gcc 15.2 vs 13.3, binutils 2.46 vs 2.42,
# glibc 2.43 vs 2.39.
#
# The nixpkgs revision below pins all of them together, and is the same
# revision the guest image builds against, so the two agree on a toolchain.
#
#   nix-build            # -> result/bin/boot-shim
#
# This matters because the output of this binary is a measurement. Anyone
# asked to trust an expected_mrtd should be able to rebuild the thing that
# computed it and get the same bytes.
#
# The build is static, because the binary is published for other machines to
# run. A dynamically linked one names an interpreter inside this store and will
# not start anywhere else, which would leave the artifact people download
# different from the artifact this file builds and tests.
{
  system ? "x86_64-linux",
}:

assert system == "x86_64-linux";

let
  nixpkgsLock = builtins.fromJSON (builtins.readFile ./nixpkgs.lock.json);
  nixpkgs = builtins.fetchTarball {
    inherit (nixpkgsLock) url sha256;
  };
  pkgs = import nixpkgs {
    inherit system;
    config = { };
    overlays = [ ];
  };
  # One file states the compiler version. rustup reads it for a local cargo
  # build and CI passes it to the toolchain action; the assert below makes a
  # mismatch a build failure rather than two "pinned" builds quietly using
  # different compilers, which is what happened before it existed.
  toolchain = builtins.replaceStrings [ "\n" ] [ "" ] (builtins.readFile ./rust-toolchain);
  cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
in
assert pkgs.lib.assertMsg (pkgs.rustc.version == toolchain)
  "rust-toolchain pins ${toolchain} but this nixpkgs provides rustc ${pkgs.rustc.version}";
pkgs.pkgsStatic.rustPlatform.buildRustPackage {
  pname = "boot-shim";
  # Read from the manifest rather than repeated here: a second copy would let a
  # release name one version and build a store path called another.
  inherit (cargoToml.package) version;

  # Keep build outputs out of the source hash, or every local cargo build
  # invalidates the derivation.
  src = builtins.path {
    path = ./.;
    name = "boot-shim-src";
    filter =
      path: type:
      let
        base = baseNameOf path;
      in
      !(builtins.elem base [
        "target"
        "target_c"
        ".git"
        "result"
      ]);
  };

  # Exact versions come from the committed lock; Cargo.toml pins them with `=`
  # as well, so there is nothing left to resolve.
  cargoLock.lockFile = ./Cargo.lock;

  # Stable cargo has no profile-level trim-paths (it is still nightly-only),
  # so remap by hand what would otherwise be baked into the binary: the source
  # root and the vendored registry. Under nix both are already deterministic
  # paths, but a remapped binary does not depend on them at all.
  env.RUSTFLAGS = "--remap-path-prefix=/build/boot-shim-src=/boot-shim --remap-path-prefix=/build/cargo-vendor-dir=/cargo";

  # build.rs assembles src/reset.S and src/snp_reset.S with GNU as and
  # objcopy. Those bytes land in the measured shim page, so the assembler is
  # part of the measurement and has to be pinned like everything else. These
  # run on the build machine, so they come from the native package set rather
  # than the static one.
  nativeBuildInputs = [ pkgs.binutils ];

  # The suite covers image determinism (byte-identical IGVM output) and the
  # ACPI tables, so it is worth running where the toolchain is pinned.
  doCheck = true;

  meta = {
    description = "Deterministic IGVM images that boot Linux on Intel TDX and AMD SEV-SNP";
    license = pkgs.lib.licenses.bsd2Patent;
    platforms = [ "x86_64-linux" ];
  };
}
