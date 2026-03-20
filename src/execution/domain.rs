/// The UTXO execution domain (Layer 2).
///
/// `ExecutionDomain` is the central coordinator for Layer 2 activity:
/// - Accepts payment submissions into its mempool.
/// - Batches payments into `PaymentBatch`es ordered by fee.
/// - Tracks the UTXO set state and produces state roots for settlement.
use crate::core::{
    crypto::{Address, Hash},
    error::{KryptisError, KryptisResult},
};

use super::{
    batch::PaymentBatch,
    utxo::{Payment, Utxo, UtxoSet},
};

/// A UTXO-based execution domain.
///
/// One domain represents an independent Layer 2 payment channel whose state
/// transitions are proven by the zkVM guest and settled on the base chain.
pub struct ExecutionDomain {
    /// Unique domain identifier (matches `DomainState.domain_id` on chain).
    pub id: u64,
    /// Current UTXO set state.
    pub utxo_set: UtxoSet,
    /// Pending payments waiting to be included in the next batch.
    pub pending_payments: Vec<Payment>,
    /// All batches that have been committed (for audit / DA submission).
    pub committed_batches: Vec<PaymentBatch>,
    /// Address of this domain's sequencer.
    pub sequencer_address: Address,
    /// Monotonic nonce for genesis UTXO id uniqueness.
    genesis_nonce: u64,
}

impl ExecutionDomain {
    /// Create a new, empty execution domain.
    pub fn new(id: u64, sequencer_address: Address) -> Self {
        Self {
            id,
            utxo_set: UtxoSet::new(),
            pending_payments: Vec::new(),
            committed_batches: Vec::new(),
            sequencer_address,
            genesis_nonce: 0,
        }
    }

    /// Credit `amount` base units to `owner` as a genesis UTXO.
    ///
    /// Used to bootstrap wallet balances before real payments exist.
    /// Each call creates a distinct UTXO with a unique id derived from
    /// owner, amount, and a monotonic nonce.
    pub fn credit_genesis(&mut self, owner: Address, amount: u64) {
        let id = Utxo::genesis_id(&owner, amount, self.genesis_nonce);
        self.genesis_nonce += 1;
        let utxo = Utxo { id, owner, amount, spent: false };
        self.utxo_set.add(utxo).expect("genesis credit cannot fail");
    }

    /// Validate and add a payment to the mempool.
    ///
    /// Returns the payment id on success.
    pub fn submit_payment(&mut self, payment: Payment) -> KryptisResult<Hash> {
        payment.validate(&self.utxo_set)?;
        // Deduplicate by id
        if self.pending_payments.iter().any(|p| p.id == payment.id) {
            return Ok(payment.id);
        }
        let id = payment.id.clone();
        self.pending_payments.push(payment);
        Ok(id)
    }

    /// Select up to `max_payments` from the mempool (highest fee first),
    /// execute them atomically, and return the committed batch.
    ///
    /// Selected payments are removed from the mempool.  If execution of any
    /// payment fails within the batch, the entire batch is aborted and the
    /// UTXO set is unchanged.
    pub fn produce_batch(&mut self, max_payments: usize) -> KryptisResult<PaymentBatch> {
        if self.pending_payments.is_empty() {
            return Err(KryptisError::ExecutionError(
                "no pending payments to batch".into(),
            ));
        }

        // Sort by fee descending (highest fee first = fee-priority ordering)
        self.pending_payments
            .sort_by(|a, b| b.fee.cmp(&a.fee));

        let take = max_payments.min(self.pending_payments.len());
        let selected: Vec<Payment> = self.pending_payments.drain(..take).collect();

        let old_root = self.utxo_set.state_root();
        let mut batch = PaymentBatch::new(
            self.id,
            selected,
            old_root,
            self.sequencer_address.clone(),
        );

        let new_root = batch.execute(&mut self.utxo_set)?;
        batch.new_state_root = new_root;
        self.committed_batches.push(batch.clone());

        Ok(batch)
    }

    /// Current UTXO state root.
    pub fn state_root(&self) -> Hash {
        self.utxo_set.state_root()
    }

    /// Spendable balance of `address` in base units.
    pub fn balance_of(&self, address: &Address) -> u64 {
        self.utxo_set.balance_of(address)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::crypto::Keypair,
        execution::utxo::{Payment, PaymentOutput},
    };

    const SEQ: &str = "KRS1sequencer00000000000000000000000000000000";

    fn new_domain() -> ExecutionDomain {
        ExecutionDomain::new(1, SEQ.to_string())
    }

    #[test]
    fn genesis_credit_creates_spendable_utxo() {
        let mut domain = new_domain();
        let alice = "KRS1alice".to_string();
        domain.credit_genesis(alice.clone(), 1_000_000);
        assert_eq!(domain.balance_of(&alice), 1_000_000);
    }

    #[test]
    fn submit_payment_accepted() {
        let kp = Keypair::generate();
        let mut domain = new_domain();
        domain.credit_genesis(kp.address(), 1_000);

        let utxo_id = domain.utxo_set.utxos.values().next().unwrap().id.clone();
        let mut p = Payment::new(
            vec![utxo_id],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 900 }],
            100,
            kp.public_key_hex(),
        );
        p.attach_signature(kp.sign(&p.signable_bytes()));

        domain.submit_payment(p).expect("submit");
        assert_eq!(domain.pending_payments.len(), 1);
    }

    #[test]
    fn invalid_payment_rejected() {
        let mut domain = new_domain();
        // No genesis credit — UTXO doesn't exist
        let p = Payment::new(
            vec!["0".repeat(64)],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 100 }],
            0,
            "00".repeat(32),
        );
        assert!(domain.submit_payment(p).is_err());
    }

    #[test]
    fn produce_batch_fee_priority() {
        let kp = Keypair::generate();
        let mut domain = new_domain();
        // Two UTXOs — look them up by amount so test is hash-order-independent
        domain.credit_genesis(kp.address(), 1_000);
        domain.credit_genesis(kp.address(), 2_000);
        let id_1000 = domain
            .utxo_set
            .utxos
            .values()
            .find(|u| u.amount == 1_000)
            .unwrap()
            .id
            .clone();
        let id_2000 = domain
            .utxo_set
            .utxos
            .values()
            .find(|u| u.amount == 2_000)
            .unwrap()
            .id
            .clone();

        // Low-fee payment spends the 1_000 UTXO (output 900 + fee 100 = 1_000)
        let mut p_low = Payment::new(
            vec![id_1000],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 900 }],
            100, // low fee
            kp.public_key_hex(),
        );
        p_low.attach_signature(kp.sign(&p_low.signable_bytes()));

        // High-fee payment spends the 2_000 UTXO (output 1_500 + fee 500 = 2_000)
        let mut p_high = Payment::new(
            vec![id_2000],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 1_500 }],
            500, // high fee
            kp.public_key_hex(),
        );
        p_high.attach_signature(kp.sign(&p_high.signable_bytes()));

        domain.submit_payment(p_low).unwrap();
        domain.submit_payment(p_high).unwrap();

        // Produce batch of 1 — should pick high-fee payment
        let batch = domain.produce_batch(1).expect("batch");
        assert_eq!(batch.payments.len(), 1);
        assert_eq!(batch.payments[0].fee, 500);
    }

    #[test]
    fn produce_batch_updates_state_root() {
        let kp = Keypair::generate();
        let mut domain = new_domain();
        domain.credit_genesis(kp.address(), 1_000);
        let old_root = domain.state_root();

        let utxo_id = domain.utxo_set.utxos.values().next().unwrap().id.clone();
        let mut p = Payment::new(
            vec![utxo_id],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 900 }],
            100,
            kp.public_key_hex(),
        );
        p.attach_signature(kp.sign(&p.signable_bytes()));
        domain.submit_payment(p).unwrap();
        domain.produce_batch(10).unwrap();

        assert_ne!(domain.state_root(), old_root);
    }

    #[test]
    fn double_spend_prevented_in_mempool() {
        let kp = Keypair::generate();
        let mut domain = new_domain();
        domain.credit_genesis(kp.address(), 1_000);
        let utxo_id = domain.utxo_set.utxos.values().next().unwrap().id.clone();

        // First payment spends the UTXO
        let mut p1 = Payment::new(
            vec![utxo_id.clone()],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 900 }],
            100,
            kp.public_key_hex(),
        );
        p1.attach_signature(kp.sign(&p1.signable_bytes()));
        domain.submit_payment(p1).unwrap();

        // Execute the batch — UTXO is now spent
        domain.produce_batch(10).unwrap();

        // Second payment tries to spend the same UTXO
        let mut p2 = Payment::new(
            vec![utxo_id],
            vec![PaymentOutput { owner: "KRS1carol".to_string(), amount: 900 }],
            100,
            kp.public_key_hex(),
        );
        p2.attach_signature(kp.sign(&p2.signable_bytes()));
        assert!(domain.submit_payment(p2).is_err(), "double spend must be rejected");
    }
}
