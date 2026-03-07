/// Transaction types and validation for the Kryptis blockchain.
///
/// Transactions are the atomic unit of state change.  All transactions
/// carry an ed25519 signature from the sender so that validators can
/// independently verify authenticity before inclusion in a block.
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::core::{
    crypto::{sha256, verify_signature, Address, Hash},
    error::{KryptisError, KryptisResult},
};

/// Differentiates the semantics of a [`Transaction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionType {
    /// Move tokens from one account to another.
    Transfer,
    /// Lock tokens in the staking pool.
    Stake,
    /// Unlock tokens from the staking pool.
    ///
    /// TODO Phase 3: Enforce a 21-day unbonding period before funds
    /// become spendable again, matching production PoS economics.
    Unstake,
    /// Mint new tokens as a block reward (no sender debit).
    Reward,
}

/// A single signed state-transition request.
///
/// The `id` is the SHA-256 of the serialisable fields *excluding* the
/// signature, so the ID can be computed before signing and remains stable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique identifier — SHA-256 of the transaction's signable bytes.
    pub id: Hash,
    /// The semantic type of this transaction.
    pub tx_type: TransactionType,
    /// The sender's KRS1 address.
    pub from: Address,
    /// The recipient's KRS1 address.
    pub to: Address,
    /// Transfer amount in base units (1 KRS = 1_000_000 base units).
    pub amount: u64,
    /// Fee paid to the block proposer, in base units.
    pub fee: u64,
    /// Unix timestamp in milliseconds when the transaction was created.
    pub timestamp: i64,
    /// Hex-encoded ed25519 public key of the sender.
    pub public_key: String,
    /// Hex-encoded ed25519 signature over [`signable_bytes`].
    pub signature: Option<String>,
    /// Optional human-readable memo (max 256 bytes recommended).
    pub memo: Option<String>,
}

impl Transaction {
    /// Construct a new unsigned transaction.
    ///
    /// The `id` is computed immediately from the provided fields so
    /// that callers can reference it before signing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tx_type: TransactionType,
        from: Address,
        to: Address,
        amount: u64,
        fee: u64,
        public_key: String,
        memo: Option<String>,
    ) -> Self {
        let timestamp = Utc::now().timestamp_millis();
        let mut tx = Self {
            id: String::new(),
            tx_type,
            from,
            to,
            amount,
            fee,
            timestamp,
            public_key,
            signature: None,
            memo,
        };
        tx.id = sha256(&tx.signable_bytes());
        tx
    }

    /// Bytes that are hashed to produce the transaction ID and that
    /// the sender signs.  The signature itself is excluded.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let repr = format!(
            "{:?}:{}:{}:{}:{}:{}:{}",
            self.tx_type,
            self.from,
            self.to,
            self.amount,
            self.fee,
            self.timestamp,
            self.memo.as_deref().unwrap_or("")
        );
        repr.into_bytes()
    }

    /// Attach a hex-encoded ed25519 signature to this transaction.
    pub fn attach_signature(&mut self, sig: String) {
        self.signature = Some(sig);
    }

    /// Verify that the attached signature is valid.
    ///
    /// Returns `Err(InvalidTransaction)` if no signature is present, or
    /// `Err(InvalidSignature)` if the signature does not verify.
    pub fn verify_signature(&self) -> KryptisResult<()> {
        let sig = self
            .signature
            .as_deref()
            .ok_or_else(|| KryptisError::InvalidTransaction("transaction is unsigned".into()))?;
        verify_signature(&self.public_key, &self.signable_bytes(), sig)
    }

    /// Validate the transaction according to protocol rules.
    ///
    /// Rules enforced:
    /// - Transfer amount must be > 0
    /// - `from` must not equal `to`
    /// - Both addresses must start with "KRS1"
    /// - The signature must be present and valid
    pub fn validate(&self) -> KryptisResult<()> {
        if self.tx_type == TransactionType::Transfer && self.amount == 0 {
            return Err(KryptisError::InvalidTransaction(
                "transfer amount must be greater than zero".into(),
            ));
        }
        if self.from == self.to && self.tx_type == TransactionType::Transfer {
            return Err(KryptisError::InvalidTransaction(
                "sender and recipient must differ".into(),
            ));
        }
        if !self.from.starts_with("KRS1") {
            return Err(KryptisError::InvalidTransaction(format!(
                "invalid from address: {}",
                self.from
            )));
        }
        if !self.to.starts_with("KRS1") && self.tx_type != TransactionType::Reward {
            return Err(KryptisError::InvalidTransaction(format!(
                "invalid to address: {}",
                self.to
            )));
        }
        self.verify_signature()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::Keypair;

    fn make_signed_transfer(kp: &Keypair, to: &str, amount: u64) -> Transaction {
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            kp.address(),
            to.to_string(),
            amount,
            100,
            kp.public_key_hex(),
            None,
        );
        let sig = kp.sign(&tx.signable_bytes());
        tx.attach_signature(sig);
        tx
    }

    fn dummy_krs1_address() -> String {
        // KRS1 + 40 hex chars = 44
        "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
    }

    #[test]
    fn valid_transfer_validates() {
        let kp = Keypair::generate();
        let to = dummy_krs1_address();
        let tx = make_signed_transfer(&kp, &to, 1_000_000);
        assert!(tx.validate().is_ok());
    }

    #[test]
    fn unsigned_transaction_fails_validation() {
        let kp = Keypair::generate();
        let tx = Transaction::new(
            TransactionType::Transfer,
            kp.address(),
            dummy_krs1_address(),
            1_000_000,
            100,
            kp.public_key_hex(),
            None,
        );
        assert!(tx.validate().is_err());
    }

    #[test]
    fn zero_amount_transfer_fails() {
        let kp = Keypair::generate();
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            kp.address(),
            dummy_krs1_address(),
            0,
            100,
            kp.public_key_hex(),
            None,
        );
        let sig = kp.sign(&tx.signable_bytes());
        tx.attach_signature(sig);
        assert!(tx.validate().is_err());
    }

    #[test]
    fn self_transfer_fails() {
        let kp = Keypair::generate();
        let addr = kp.address();
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            addr.clone(),
            addr,
            1_000_000,
            100,
            kp.public_key_hex(),
            None,
        );
        let sig = kp.sign(&tx.signable_bytes());
        tx.attach_signature(sig);
        assert!(tx.validate().is_err());
    }

    #[test]
    fn bad_address_format_fails() {
        let kp = Keypair::generate();
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            kp.address(),
            "INVALID_ADDRESS".to_string(),
            1_000_000,
            100,
            kp.public_key_hex(),
            None,
        );
        let sig = kp.sign(&tx.signable_bytes());
        tx.attach_signature(sig);
        assert!(tx.validate().is_err());
    }

    #[test]
    fn transaction_id_is_deterministic() {
        let kp = Keypair::generate();
        let tx = Transaction::new(
            TransactionType::Transfer,
            kp.address(),
            dummy_krs1_address(),
            1_000_000,
            100,
            kp.public_key_hex(),
            None,
        );
        // ID is set in constructor from signable_bytes
        let expected_id = sha256(&tx.signable_bytes());
        assert_eq!(tx.id, expected_id);
    }
}
