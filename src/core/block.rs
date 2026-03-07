/// Block structure, header, and Merkle tree computation for Kryptis.
///
/// Blocks are the primary unit of finality.  Each block references
/// the hash of its predecessor, forming the chain.  The Merkle root
/// over transaction IDs is included in the header so that individual
/// transactions can be proven without transmitting the entire block.
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::core::{
    crypto::{double_sha256, sha256, Address, Hash},
    error::{KryptisError, KryptisResult},
    transaction::Transaction,
};

/// The fixed-size header committed to by a block's hash.
///
/// Changing any header field changes the block hash, making
/// retrospective tampering detectable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Position in the chain (genesis = 0).
    pub height: u64,
    /// Hash of the immediately preceding block.
    pub previous_hash: Hash,
    /// Root of the binary Merkle tree over all transaction IDs.
    pub merkle_root: Hash,
    /// Wall-clock time in Unix milliseconds when the block was proposed.
    pub timestamp: i64,
    /// KRS1 address of the validator that proposed this block.
    pub proposer: Address,
    /// The epoch number at the time of proposal (epoch = height / BLOCKS_PER_EPOCH).
    pub epoch: u64,
}

impl BlockHeader {
    /// Compute the canonical block hash from the header fields.
    ///
    /// Uses double-SHA-256 to make length-extension attacks impractical.
    pub fn hash(&self) -> Hash {
        let repr = format!(
            "{}:{}:{}:{}:{}:{}",
            self.height,
            self.previous_hash,
            self.merkle_root,
            self.timestamp,
            self.proposer,
            self.epoch,
        );
        double_sha256(repr.as_bytes())
    }
}

/// A validator's cryptographic attestation that a block is valid.
///
/// Validators sign the block's *vote bytes* rather than the raw block
/// so that votes are compact and unambiguous.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// KRS1 address of the signing validator.
    pub validator_address: Address,
    /// Hex-encoded ed25519 public key.
    pub public_key: String,
    /// Hex-encoded ed25519 signature over the block's vote bytes.
    pub signature: String,
}

/// A finalised block in the Kryptis chain.
///
/// A block is considered finalised when it accumulates signatures from
/// validators representing ≥ 2/3 of total voting power.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// The fixed header whose hash is this block's ID.
    pub header: BlockHeader,
    /// The computed hash of `header`, stored for O(1) access.
    pub hash: Hash,
    /// Ordered list of transactions included in this block.
    pub transactions: Vec<Transaction>,
    /// Collected validator signatures (grows during the Precommit phase).
    pub validator_signatures: Vec<ValidatorSignature>,
}

impl Block {
    /// Construct the genesis block (height 0, no transactions).
    ///
    /// The genesis block has a zeroed previous hash and an empty Merkle
    /// root, and is the only block that carries no real signatures.
    pub fn genesis() -> Self {
        // Timestamp is fixed at zero so the genesis hash is deterministic
        // across restarts — this is required for chain state restoration to work,
        // since all subsequent blocks commit `previous_hash = genesis.hash`.
        let header = BlockHeader {
            height: 0,
            previous_hash: "0".repeat(64),
            merkle_root: compute_merkle_root(&[]),
            timestamp: 0,
            proposer: "KRS1genesis00000000000000000000000000000000".to_string(),
            epoch: 0,
        };
        let hash = header.hash();
        Self {
            header,
            hash,
            transactions: vec![],
            validator_signatures: vec![],
        }
    }

    /// Construct a new block for the given height.
    ///
    /// The `hash` field is computed immediately from the header so it
    /// is always consistent with `header`.
    pub fn new(
        height: u64,
        previous_hash: Hash,
        transactions: Vec<Transaction>,
        proposer: Address,
        epoch: u64,
    ) -> Self {
        let merkle_root = compute_merkle_root(&transactions);
        let header = BlockHeader {
            height,
            previous_hash,
            merkle_root,
            timestamp: Utc::now().timestamp_millis(),
            proposer,
            epoch,
        };
        let hash = header.hash();
        Self {
            header,
            hash,
            transactions,
            validator_signatures: vec![],
        }
    }

    /// Attach a validator's precommit signature to this block.
    pub fn add_validator_signature(&mut self, sig: ValidatorSignature) {
        self.validator_signatures.push(sig);
    }

    /// Validate the block against its expected predecessor hash.
    ///
    /// Checks:
    /// 1. The stored `hash` matches a fresh computation from `header`.
    /// 2. The `previous_hash` field equals `expected_previous_hash`.
    /// 3. The `merkle_root` matches the transactions in the block.
    /// 4. Every included transaction passes its own [`Transaction::validate`].
    pub fn validate(&self, expected_previous_hash: &str) -> KryptisResult<()> {
        // 1. Hash consistency
        let computed = self.header.hash();
        if computed != self.hash {
            return Err(KryptisError::InvalidBlock(format!(
                "stored hash {} does not match computed hash {}",
                self.hash, computed
            )));
        }
        // 2. Chain linkage
        if self.header.previous_hash != expected_previous_hash {
            return Err(KryptisError::InvalidBlock(format!(
                "previous_hash mismatch: expected {}, got {}",
                expected_previous_hash, self.header.previous_hash
            )));
        }
        // 3. Merkle root
        let expected_root = compute_merkle_root(&self.transactions);
        if self.header.merkle_root != expected_root {
            return Err(KryptisError::InvalidBlock(format!(
                "merkle root mismatch: expected {}, got {}",
                expected_root, self.header.merkle_root
            )));
        }
        // 4. Individual transaction validity (genesis block has none)
        for tx in &self.transactions {
            tx.validate().map_err(|e| {
                KryptisError::InvalidBlock(format!("invalid transaction {}: {}", tx.id, e))
            })?;
        }
        Ok(())
    }

    /// Return the canonical bytes that validators sign to cast a vote.
    ///
    /// Format: `"VOTE:{height}:{hash}"` as UTF-8 bytes.
    pub fn vote_bytes(&self) -> Vec<u8> {
        format!("VOTE:{}:{}", self.header.height, self.hash).into_bytes()
    }
}

/// Compute the binary Merkle root over the transaction IDs.
///
/// Each leaf is `sha256(tx.id)`.  When the number of leaves is odd the
/// last leaf is duplicated, which is standard in Bitcoin-style Merkle trees.
/// An empty transaction list produces a fixed "empty" sentinel hash.
pub fn compute_merkle_root(transactions: &[Transaction]) -> Hash {
    if transactions.is_empty() {
        return sha256(b"empty");
    }

    // Build leaf layer
    let mut layer: Vec<String> = transactions
        .iter()
        .map(|tx| sha256(tx.id.as_bytes()))
        .collect();

    // Reduce pairwise until one node remains
    while layer.len() > 1 {
        if !layer.len().is_multiple_of(2) {
            let last = layer.last().expect("non-empty").clone();
            layer.push(last);
        }
        layer = layer
            .chunks(2)
            .map(|pair| {
                let combined = format!("{}{}", pair[0], pair[1]);
                sha256(combined.as_bytes())
            })
            .collect();
    }

    layer.remove(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{crypto::Keypair, transaction::TransactionType};

    fn make_signed_tx(kp: &Keypair) -> Transaction {
        use crate::core::transaction::Transaction;
        let to = "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            kp.address(),
            to,
            1_000_000,
            100,
            kp.public_key_hex(),
            None,
        );
        let sig = kp.sign(&tx.signable_bytes());
        tx.attach_signature(sig);
        tx
    }

    #[test]
    fn genesis_block_is_valid() {
        let genesis = Block::genesis();
        // Genesis validates against its own previous_hash sentinel
        assert!(genesis.validate(&genesis.header.previous_hash).is_ok());
    }

    #[test]
    fn block_hash_is_deterministic() {
        let genesis = Block::genesis();
        assert_eq!(genesis.hash, genesis.header.hash());
    }

    #[test]
    fn chain_linkage_validation() {
        let genesis = Block::genesis();
        let block1 = Block::new(
            1,
            genesis.hash.clone(),
            vec![],
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            0,
        );
        assert!(block1.validate(&genesis.hash).is_ok());
    }

    #[test]
    fn invalid_linkage_rejected() {
        let block = Block::new(
            1,
            "wrong_hash".to_string(),
            vec![],
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            0,
        );
        assert!(block.validate("correct_hash").is_err());
    }

    #[test]
    fn merkle_root_empty_is_deterministic() {
        let r1 = compute_merkle_root(&[]);
        let r2 = compute_merkle_root(&[]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn merkle_root_changes_with_transactions() {
        let kp = Keypair::generate();
        let tx = make_signed_tx(&kp);
        let root_empty = compute_merkle_root(&[]);
        let root_one = compute_merkle_root(&[tx]);
        assert_ne!(root_empty, root_one);
    }

    #[test]
    fn merkle_root_deterministic_for_same_txs() {
        let kp = Keypair::generate();
        let tx1 = make_signed_tx(&kp);
        let tx2 = make_signed_tx(&kp);
        let r1 = compute_merkle_root(&[tx1.clone(), tx2.clone()]);
        let r2 = compute_merkle_root(&[tx1, tx2]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn block_vote_bytes_format() {
        let genesis = Block::genesis();
        let vb = String::from_utf8(genesis.vote_bytes()).expect("utf8");
        assert!(vb.starts_with("VOTE:0:"));
    }
}
