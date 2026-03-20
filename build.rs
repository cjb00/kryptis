/// Build script for the Kryptis host crate.
///
/// Calls `risc0_build::embed_methods()` to compile the `kryptis-guest` zkVM
/// program and embed the resulting ELF binary + image ID into the host binary.
///
/// The `risc0` rustup toolchain must be installed (via rzup) for RISC-V
/// cross-compilation.  Run once:
///   curl -L https://risczero.com/install | bash && rzup install
///
/// For development and testing use `RISC0_DEV_MODE=1` to get the mock prover.
/// The guest is still compiled to RISC-V (for a valid ELF), but proofs are
/// generated and verified instantly without real ZK computation.
fn main() {
    risc0_build::embed_methods();
}
