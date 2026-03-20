/// Settlement layer integration points for Phase 3.
///
/// This module defines the data structures and traits that the base chain
/// uses to verify ZK validity proofs submitted by the execution domain
/// (Layer 2).  All verification logic is stubbed for Phase 1+2.
///
/// TODO Phase 3: Replace `StubVerifier` with a real ZK proof verifier.
/// The verifier will use PLONK/Halo2 or a VM-based proving system such
/// as Risc0 or SP1.  It must:
///   - Decode `proof_bytes` into the circuit's proof format.
///   - Verify that `old_state_root` transitions to `new_state_root`
///     under the execution domain's state transition function.
///   - Confirm that `da_commitment` matches published blobs on Layer 1.
///   - Reject proofs for unknown `domain_id` values.
use serde::{Deserialize, Serialize};

use crate::core::{
    crypto::{Address, Hash},
    error::{KryptisError, KryptisResult},
};

/// A ZK validity proof submitted from the execution domain (Layer 2)
/// to the settlement layer (Layer 3) to finalise a batch of payments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementProof {
    /// Identifier of the execution domain that generated this proof.
    pub domain_id: u64,
    /// State root of the domain *before* this batch was applied.
    pub old_state_root: Hash,
    /// State root of the domain *after* this batch was applied.
    pub new_state_root: Hash,
    /// Commitment to the data availability layer blobs for this batch.
    ///
    /// TODO Phase 4: This will be a KZG commitment once the DA layer
    /// (Layer 1) is operational.
    pub da_commitment: Hash,
    /// Number of payment transactions in this batch.
    pub batch_size: u64,
    /// Raw ZK proof bytes.  Empty for Phase 1+2.
    pub proof_bytes: Vec<u8>,
}

/// The on-chain record tracking the current state of an execution domain.
///
/// One `DomainState` entry is maintained per registered domain.
/// It is updated every time a valid `SettlementProof` is processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainState {
    /// The execution domain's unique identifier.
    pub domain_id: u64,
    /// The most recently confirmed state root for this domain.
    pub state_root: Hash,
    /// Height of the settlement block that last updated this domain.
    pub last_settled_height: u64,
    /// KRS1 address of the current sequencer for this domain.
    ///
    /// TODO Phase 3: The sequencer address will be provided by the
    /// shared sequencer network rather than set at registration time.
    pub sequencer_address: Address,
}

/// Interface for verifying ZK validity proofs from the execution domain.
///
/// # Phase 3 Replacement
/// Implement this trait with a real ZK verifier.  The implementation
/// must be `Send + Sync` so it can be shared across async tasks.
/// Constraints:
///   - Must not block the async executor; offload heavy computation to
///     `tokio::task::spawn_blocking`.
///   - Must return `Err(ConsensusError(...))` for any invalid proof.
///   - Should cache verification keys per `domain_id` to avoid
///     re-loading them for every proof.
pub trait ProofVerifier: Send + Sync {
    /// Verify that `proof` is a valid state transition for `domain`.
    ///
    /// Returns `Ok(())` if the proof is valid, otherwise an error
    /// describing the failure mode.
    fn verify(&self, proof: &SettlementProof, domain: &DomainState) -> KryptisResult<()>;
}

/// A no-op verifier used during Phase 1+2.
///
/// Always returns `Ok(())` regardless of input.  This allows the rest
/// of the settlement flow to be exercised end-to-end without a real
/// ZK backend.
///
/// TODO Phase 3: Remove this stub and inject a real `ProofVerifier`
/// implementation via dependency injection in `ConsensusEngine::new`.
pub struct StubVerifier;

impl ProofVerifier for StubVerifier {
    fn verify(&self, _proof: &SettlementProof, _domain: &DomainState) -> KryptisResult<()> {
        // TODO Phase 3: Replace with real ZK proof verification.
        // Use PLONK/Halo2 or Risc0/SP1 proving system.
        Ok(())
    }
}

/// A Risc0-backed ZK proof verifier.
///
/// Deserializes the `proof_bytes` field of `SettlementProof` as a
/// `risc0_zkvm::Receipt`, verifies the receipt against the compiled
/// guest image ID, then checks that the committed state transition
/// matches the on-chain `DomainState`.
///
/// In `RISC0_DEV_MODE=1` the mock prover produces receipts that pass
/// `receipt.verify()` without real ZK computation, so this verifier
/// works identically in dev and production — only the proving cost differs.
pub struct Risc0Verifier;

impl ProofVerifier for Risc0Verifier {
    fn verify(&self, proof: &SettlementProof, domain: &DomainState) -> KryptisResult<()> {
        use crate::settlement::prover::KRYPTIS_GUEST_ID;

        let receipt: risc0_zkvm::Receipt =
            bincode::deserialize(&proof.proof_bytes).map_err(|e| {
                KryptisError::ProofVerificationFailed(format!("receipt decode: {e}"))
            })?;

        receipt.verify(KRYPTIS_GUEST_ID).map_err(|e| {
            KryptisError::ProofVerificationFailed(format!("receipt verify: {e}"))
        })?;

        let output: kryptis_types::BatchOutput = receipt.journal.decode().map_err(|e| {
            KryptisError::ProofVerificationFailed(format!("journal decode: {e}"))
        })?;

        // old state root must match what's registered on-chain
        if hex::encode(output.old_state_root) != domain.state_root {
            return Err(KryptisError::StateMismatch);
        }

        // new state root must match what the proof claims
        if hex::encode(output.new_state_root) != proof.new_state_root {
            return Err(KryptisError::StateMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_hash() -> Hash {
        "a".repeat(64)
    }

    fn dummy_proof() -> SettlementProof {
        SettlementProof {
            domain_id: 1,
            old_state_root: dummy_hash(),
            new_state_root: dummy_hash(),
            da_commitment: dummy_hash(),
            batch_size: 100,
            proof_bytes: vec![],
        }
    }

    fn dummy_domain() -> DomainState {
        DomainState {
            domain_id: 1,
            state_root: dummy_hash(),
            last_settled_height: 0,
            sequencer_address: "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        }
    }

    #[test]
    fn stub_verifier_always_ok() {
        let verifier = StubVerifier;
        let proof = dummy_proof();
        let domain = dummy_domain();
        assert!(verifier.verify(&proof, &domain).is_ok());
    }

    #[test]
    fn settlement_proof_serialization_roundtrip() {
        let proof = dummy_proof();
        let json = serde_json::to_string(&proof).expect("serialize");
        let decoded: SettlementProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.domain_id, proof.domain_id);
        assert_eq!(decoded.batch_size, proof.batch_size);
    }
}
