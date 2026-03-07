/// Unified error types for the Kryptis blockchain.
///
/// All public-facing functions return `KryptisResult<T>` to ensure
/// errors propagate cleanly without panics.
use thiserror::Error;

/// The canonical error type for the Kryptis blockchain.
#[derive(Debug, Error)]
pub enum KryptisError {
    /// A block failed structural or linkage validation.
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    /// A transaction failed validation (bad amount, signature, etc.).
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// A block was requested by hash/height but does not exist.
    #[error("Block not found: {0}")]
    BlockNotFound(String),

    /// An operation requires the chain to have at least one block.
    #[error("Chain is empty")]
    EmptyChain,

    /// Validator registration or operation failed.
    #[error("Invalid validator: {0}")]
    InvalidValidator(String),

    /// A stake operation cannot proceed because the amount is too low.
    #[error("Insufficient stake: required {required}, found {found}")]
    InsufficientStake { required: u64, found: u64 },

    /// Attempted to register a validator that already exists.
    #[error("Validator already exists: {0}")]
    ValidatorAlreadyExists(String),

    /// An operation requires the address to be a validator but it is not.
    #[error("Not a validator: {0}")]
    NotAValidator(String),

    /// An ed25519 signature did not verify.
    #[error("Invalid signature")]
    InvalidSignature,

    /// Key generation or derivation failed.
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// A public key hex string could not be decoded.
    #[error("Invalid public key")]
    InvalidPublicKey,

    /// A storage read or write operation failed.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// A network operation failed.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// JSON serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// The consensus engine encountered an unrecoverable state.
    #[error("Consensus error: {0}")]
    ConsensusError(String),

    /// The sequencer could not fulfil a request.
    #[error("Sequencer error: {0}")]
    SequencerError(String),
}

/// Convenience alias used throughout the codebase.
pub type KryptisResult<T> = Result<T, KryptisError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_invalid_block() {
        let e = KryptisError::InvalidBlock("bad hash".into());
        assert!(e.to_string().contains("bad hash"));
    }

    #[test]
    fn error_display_insufficient_stake() {
        let e = KryptisError::InsufficientStake {
            required: 10_000,
            found: 5_000,
        };
        let s = e.to_string();
        assert!(s.contains("10000"));
        assert!(s.contains("5000"));
    }

    #[test]
    fn result_propagation() {
        fn inner() -> KryptisResult<u64> {
            Err(KryptisError::EmptyChain)
        }
        fn outer() -> KryptisResult<u64> {
            let v = inner()?;
            Ok(v + 1)
        }
        assert!(outer().is_err());
    }
}
