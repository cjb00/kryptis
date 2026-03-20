//! Shared types between the Kryptis host and the Risc0 zkVM guest program.
//!
//! These types must be serializable via serde (used by risc0_zkvm::guest::env::read/commit)
//! and must produce identical results on both sides of the host/guest boundary.
//!
//! # State root consistency
//! `compute_state_root` is the single canonical implementation used by:
//! - `UtxoSet::state_root()` on the host (via conversion to `SerializableUtxo`)
//! - The guest program directly
//!
//! Both sides must produce the same bytes for the same UTXO set state.

use sha2::{Digest, Sha256};

/// A UTXO snapshotted for transmission to the zkVM guest.
///
/// Uses fixed-size byte arrays instead of hex strings for efficient
/// serialization inside the zkVM environment.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerializableUtxo {
    /// SHA-256 UTXO identifier as raw bytes.
    pub id: [u8; 32],
    /// KRS1 owner address.
    pub owner: String,
    /// Balance in base units.
    pub amount: u64,
}

/// A payment transaction in a form safe to pass into the zkVM guest.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerializablePayment {
    /// Input UTXO ids being consumed.
    pub inputs: Vec<[u8; 32]>,
    /// Output (owner address, amount) pairs being created.
    pub outputs: Vec<(String, u64)>,
    /// Transaction fee in base units.
    pub fee: u64,
    /// Ed25519 signature hex over the signable bytes.
    pub signature: String,
    /// Signer's public key hex (64 chars).
    pub public_key: String,
}

/// Input to the zkVM guest program: the entire UTXO set state plus payments.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BatchInput {
    /// State root of the UTXO set before applying this batch.
    pub old_state_root: [u8; 32],
    /// Payments to execute in this batch.
    pub payments: Vec<SerializablePayment>,
    /// All currently unspent UTXOs (used to reconstruct state + verify root).
    pub utxo_snapshots: Vec<SerializableUtxo>,
}

/// Output committed by the zkVM guest program and written to the receipt journal.
///
/// The settlement verifier reads this from the receipt to confirm the
/// state transition claimed in `SettlementProof`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BatchOutput {
    /// State root before the batch — must match the registered domain state.
    pub old_state_root: [u8; 32],
    /// State root after applying all payments — becomes the new domain state.
    pub new_state_root: [u8; 32],
    /// Number of payments successfully processed.
    pub payments_processed: u64,
    /// Total fees collected across all payments.
    pub total_fees: u64,
}

/// Compute a deterministic state root over a set of unspent UTXOs.
///
/// Algorithm:
/// 1. Sort UTXOs by id (byte-lexicographic order) for determinism.
/// 2. SHA-256 over the concatenation of (id || owner_bytes || amount_le).
///
/// This function is called identically on both the host (in `UtxoSet::state_root()`)
/// and inside the zkVM guest, ensuring the state root is consistent.
pub fn compute_state_root(utxos: &[SerializableUtxo]) -> [u8; 32] {
    let mut sorted = utxos.to_vec();
    sorted.sort_by_key(|u| u.id);

    let mut hasher = Sha256::new();
    for u in &sorted {
        hasher.update(u.id);
        hasher.update(u.owner.as_bytes());
        hasher.update(u.amount.to_le_bytes());
    }
    hasher.finalize().into()
}

/// Derive a deterministic UTXO output id from parent input and output index.
///
/// `id = SHA-256(parent_id || owner_bytes || amount_le || index_le)`
pub fn compute_output_id(parent_id: &[u8; 32], owner: &str, amount: u64, index: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(parent_id);
    h.update(owner.as_bytes());
    h.update(amount.to_le_bytes());
    h.update(index.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_root_deterministic() {
        let utxos = vec![
            SerializableUtxo { id: [1u8; 32], owner: "KRS1alice".to_string(), amount: 100 },
            SerializableUtxo { id: [2u8; 32], owner: "KRS1bob".to_string(), amount: 50 },
        ];
        let root1 = compute_state_root(&utxos);
        // Reversed order — same result because we sort internally
        let utxos_rev = vec![utxos[1].clone(), utxos[0].clone()];
        let root2 = compute_state_root(&utxos_rev);
        assert_eq!(root1, root2, "state root must be order-independent");
    }

    #[test]
    fn state_root_changes_with_content() {
        let utxos_a = vec![SerializableUtxo { id: [1u8; 32], owner: "KRS1a".to_string(), amount: 100 }];
        let utxos_b = vec![SerializableUtxo { id: [1u8; 32], owner: "KRS1a".to_string(), amount: 200 }];
        assert_ne!(compute_state_root(&utxos_a), compute_state_root(&utxos_b));
    }

    #[test]
    fn empty_utxo_set_has_consistent_root() {
        let r1 = compute_state_root(&[]);
        let r2 = compute_state_root(&[]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn output_id_deterministic() {
        let id = compute_output_id(&[0u8; 32], "KRS1alice", 1000, 0);
        let id2 = compute_output_id(&[0u8; 32], "KRS1alice", 1000, 0);
        assert_eq!(id, id2);
    }
}
