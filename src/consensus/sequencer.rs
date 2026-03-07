/// Sequencer rotation and the Sequencer trait.
///
/// In Phase 1+2 the sequencer is the validator selected as block proposer
/// for the current epoch.  In Phase 3 this will be replaced by a
/// decentralised shared sequencer network (e.g. Espresso Systems)
/// without changing any consensus code — only a new `impl Sequencer`.
///
/// TODO Phase 3: Replace `RotatingSequencer` with a `SharedSequencer`
/// that:
///   - Connects to the external sequencer network's API.
///   - Returns the network-selected sequencer for each height.
///   - Submits `PaymentBatch`es to the sequencer network for ordering.
///   - Must respect the same `Sequencer` trait interface so `ConsensusEngine`
///     requires no changes.
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::{
    consensus::validator::ValidatorSet,
    core::{
        crypto::Address,
        error::KryptisResult,
        transaction::Transaction,
    },
};

/// A stub batch of payment transactions, to be processed by the
/// ZK execution domain in Phase 3.
///
/// TODO Phase 3: Expand this struct to include ZK-friendly encodings
/// of each payment and the domain's current state root.
#[derive(Debug, Clone)]
pub struct PaymentBatch {
    /// The execution domain this batch targets.
    pub domain_id: u64,
    /// The individual payment transactions in this batch.
    pub transactions: Vec<Transaction>,
    /// A unique identifier for this batch.
    pub batch_id: crate::core::crypto::Hash,
}

/// Interface for sequencer discovery and batch submission.
///
/// Implementors must be `Send + Sync` to be shared across async tasks
/// behind `Arc<dyn Sequencer>`.
pub trait Sequencer: Send + Sync {
    /// Return the KRS1 address of the current sequencer for `height`.
    fn current_sequencer(&self, height: u64) -> KryptisResult<Address>;

    /// Return true if `local_address` is the sequencer at `height`.
    fn is_local_sequencer(&self, height: u64, local_address: &str) -> bool;

    /// Submit a payment batch to the execution domain.
    ///
    /// In Phase 1+2 this logs the batch and returns `Ok(())`.
    /// In Phase 3 this will forward the batch to the shared sequencer.
    fn submit_batch(&self, batch: PaymentBatch) -> KryptisResult<()>;
}

/// A sequencer that rotates by delegating to [`ValidatorSet::select_proposer`].
///
/// The sequencer for a given block height is the same validator that
/// would propose a block at that height — this gives sequencer duties
/// to the validator with the most accumulated stake-weighted turns.
pub struct RotatingSequencer {
    /// The current validator set, shared with the consensus engine.
    validator_set: Arc<RwLock<ValidatorSet>>,
}

impl RotatingSequencer {
    /// Construct a `RotatingSequencer` backed by `validator_set`.
    pub fn new(validator_set: Arc<RwLock<ValidatorSet>>) -> Self {
        Self { validator_set }
    }
}

impl Sequencer for RotatingSequencer {
    fn current_sequencer(&self, height: u64) -> KryptisResult<Address> {
        // `block_in_place` moves the current worker thread out of the async
        // executor so that `blocking_read()` is safe to call even when this
        // method is invoked from inside a tokio runtime.
        let vs = tokio::task::block_in_place(|| self.validator_set.blocking_read());
        let proposer = vs.select_proposer(height)?;
        debug!(height, sequencer = %proposer.address, "Sequencer resolved");
        Ok(proposer.address.clone())
    }

    fn is_local_sequencer(&self, height: u64, local_address: &str) -> bool {
        match self.current_sequencer(height) {
            Ok(addr) => addr == local_address,
            Err(_) => false,
        }
    }

    fn submit_batch(&self, batch: PaymentBatch) -> KryptisResult<()> {
        // TODO Phase 3: Submit batch to the ZK execution domain via the
        // shared sequencer network's API.  The batch must be ordered and
        // committed before a settlement proof can be generated.
        info!(
            domain_id = batch.domain_id,
            batch_id = %batch.batch_id,
            tx_count = batch.transactions.len(),
            "Payment batch received (stub — not forwarded in Phase 1+2)"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator::{Validator, ValidatorSet, MIN_VALIDATOR_STAKE};

    fn make_validator_set_with_two() -> Arc<RwLock<ValidatorSet>> {
        let mut vs = ValidatorSet::new();
        vs.register(
            Validator::new(
                "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                "00".repeat(32),
                MIN_VALIDATOR_STAKE,
                500,
                None,
            )
            .expect("validator a"),
        )
        .expect("register a");
        vs.register(
            Validator::new(
                "KRS1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
                "00".repeat(32),
                MIN_VALIDATOR_STAKE * 2,
                500,
                None,
            )
            .expect("validator b"),
        )
        .expect("register b");
        vs.transition_epoch();
        Arc::new(RwLock::new(vs))
    }

    #[test]
    fn sequencer_selection_is_deterministic() {
        let vs = make_validator_set_with_two();
        let seq = RotatingSequencer::new(vs);
        let s1 = seq.current_sequencer(42).expect("seq");
        let s2 = seq.current_sequencer(42).expect("seq");
        assert_eq!(s1, s2);
    }

    #[test]
    fn sequencer_rotates_across_heights() {
        let vs = make_validator_set_with_two();
        let seq = RotatingSequencer::new(vs);
        let mut seen = std::collections::HashSet::new();
        for h in 0..50 {
            seen.insert(seq.current_sequencer(h).expect("seq"));
        }
        assert_eq!(seen.len(), 2, "Both validators should take sequencer turns");
    }

    #[test]
    fn is_local_sequencer_correct() {
        let vs = make_validator_set_with_two();
        let seq = RotatingSequencer::new(vs);
        // Find which validator is sequencer at height 0
        let current = seq.current_sequencer(0).expect("seq");
        assert!(seq.is_local_sequencer(0, &current));
        // The other address should not be local sequencer at the same height
        let other = if current == "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
            "KRS1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        } else {
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        };
        assert!(!seq.is_local_sequencer(0, other));
    }

    #[test]
    fn submit_batch_returns_ok() {
        let vs = make_validator_set_with_two();
        let seq = RotatingSequencer::new(vs);
        let batch = PaymentBatch {
            domain_id: 1,
            transactions: vec![],
            batch_id: "abc".to_string(),
        };
        assert!(seq.submit_batch(batch).is_ok());
    }
}
