/// Payment batch: atomic execution of multiple UTXO payments.
///
/// A `PaymentBatch` collects payments from the mempool and executes them
/// atomically against the UTXO set.  If any payment fails, the entire batch
/// is rolled back so the UTXO set remains consistent.  After successful
/// execution, the batch records the old and new state roots which are used
/// to construct the `SettlementProof` submitted to the base chain.
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::core::{
    crypto::{sha256, Address, Hash},
    error::{KryptisError, KryptisResult},
};

use super::utxo::{Payment, Utxo, UtxoSet};

/// An ordered, immutable collection of payments executed against a UTXO set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentBatch {
    /// Unique batch identifier.
    pub id: Hash,
    /// Execution domain this batch belongs to.
    pub domain_id: u64,
    /// Payments included in this batch, in execution order.
    pub payments: Vec<Payment>,
    /// UTXO state root before executing any payment in this batch.
    pub old_state_root: Hash,
    /// UTXO state root after executing all payments in this batch.
    pub new_state_root: Hash,
    /// Address of the sequencer that produced this batch.
    pub sequencer: Address,
    /// Unix timestamp (milliseconds) when the batch was produced.
    pub timestamp: i64,
}

impl PaymentBatch {
    /// Create a new batch (with `new_state_root` not yet computed).
    ///
    /// Call [`execute`] to apply the payments and fill in `new_state_root`.
    pub fn new(
        domain_id: u64,
        payments: Vec<Payment>,
        old_state_root: Hash,
        sequencer: Address,
    ) -> Self {
        let id = Self::compute_id(domain_id, &payments, &old_state_root);
        Self {
            id,
            domain_id,
            payments,
            old_state_root,
            new_state_root: String::new(),
            sequencer,
            timestamp: Utc::now().timestamp_millis(),
        }
    }

    fn compute_id(domain_id: u64, payments: &[Payment], old_root: &str) -> Hash {
        let mut data = domain_id.to_le_bytes().to_vec();
        for p in payments {
            data.extend_from_slice(p.id.as_bytes());
        }
        data.extend_from_slice(old_root.as_bytes());
        sha256(&data)
    }

    /// Atomically execute all payments against `utxo_set`.
    ///
    /// Applies each payment in order:
    /// 1. Validates the payment against current UTXO state.
    /// 2. Spends each input UTXO.
    /// 3. Creates each output UTXO.
    ///
    /// If any payment fails, the UTXO set is restored to its pre-batch state
    /// (snapshot-and-rollback semantics) and an error is returned.
    ///
    /// Returns the new state root on success.
    pub fn execute(&self, utxo_set: &mut UtxoSet) -> KryptisResult<Hash> {
        // Snapshot for rollback
        let snapshot = utxo_set.clone();

        for payment in &self.payments {
            if let Err(e) = apply_payment(utxo_set, payment) {
                // Atomic: any failure rolls back the entire batch
                *utxo_set = snapshot;
                return Err(e);
            }
        }

        Ok(utxo_set.state_root())
    }

    /// Verify that value is conserved across the entire batch.
    ///
    /// Total input value == total output value + total fees.
    /// Must hold before any payment is applied (uses the pre-execution UTXO set).
    pub fn verify_conservation(&self, utxo_set: &UtxoSet) -> bool {
        let mut total_in: u64 = 0;
        let mut total_out: u64 = 0;
        let mut total_fees: u64 = 0;

        for payment in &self.payments {
            for id in &payment.inputs {
                if let Some(utxo) = utxo_set.get(id) {
                    total_in = total_in.saturating_add(utxo.amount);
                }
            }
            for output in &payment.outputs {
                total_out = total_out.saturating_add(output.amount);
            }
            total_fees = total_fees.saturating_add(payment.fee);
        }

        total_in == total_out.saturating_add(total_fees)
    }
}

/// Apply a single payment to the UTXO set.
///
/// Validates, spends inputs, and creates outputs.  Does NOT clone for rollback
/// — the caller (`execute`) is responsible for snapshotting.
pub(crate) fn apply_payment(utxo_set: &mut UtxoSet, payment: &Payment) -> KryptisResult<()> {
    // Validate against current state (checks existence, no double-spend, sig, conservation)
    payment.validate(utxo_set)?;

    // Spend all inputs
    let first_input_id = payment.inputs[0].clone();
    for id in &payment.inputs {
        utxo_set.spend(id)?;
    }

    // Create output UTXOs
    for (idx, output) in payment.outputs.iter().enumerate() {
        let id = Utxo::output_id(&first_input_id, &output.owner, output.amount, idx as u32);
        let utxo = Utxo {
            id: id.clone(),
            owner: output.owner.clone(),
            amount: output.amount,
            spent: false,
        };
        utxo_set.add(utxo).map_err(|e| {
            KryptisError::ExecutionError(format!("failed to create output UTXO: {}", e))
        })?;
    }

    Ok(())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::crypto::Keypair,
        execution::utxo::{Payment, PaymentOutput, Utxo, UtxoSet},
    };

    fn make_funded_set(owner: &str, amount: u64) -> (UtxoSet, Hash) {
        let mut set = UtxoSet::new();
        let id = Utxo::genesis_id(owner, amount, 0);
        let utxo = Utxo { id: id.clone(), owner: owner.to_string(), amount, spent: false };
        set.add(utxo).unwrap();
        (set, id)
    }

    fn make_signed_payment(kp: &Keypair, input: Hash, to: &str, amount: u64, fee: u64) -> Payment {
        let mut p = Payment::new(
            vec![input],
            vec![PaymentOutput { owner: to.to_string(), amount }],
            fee,
            kp.public_key_hex(),
        );
        p.attach_signature(kp.sign(&p.signable_bytes()));
        p
    }

    #[test]
    fn batch_executes_atomically() {
        let kp = Keypair::generate();
        let (mut set, utxo_id) = make_funded_set(&kp.address(), 1_000);
        let payment = make_signed_payment(&kp, utxo_id, "KRS1bob", 900, 100);
        let old_root = set.state_root();

        let batch = PaymentBatch::new(1, vec![payment], old_root, "KRS1seq".to_string());
        let new_root = batch.execute(&mut set).expect("execute");

        assert_ne!(batch.old_state_root, new_root);
        assert_eq!(set.balance_of(&"KRS1bob".to_string()), 900);
    }

    #[test]
    fn batch_rollback_on_invalid_payment() {
        let kp = Keypair::generate();
        let (mut set, utxo_id) = make_funded_set(&kp.address(), 100);
        let root_before = set.state_root();

        // Payment spends more than available — should fail and roll back
        let bad_payment = Payment::new(
            vec![utxo_id],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 200 }],
            0,
            kp.public_key_hex(),
        );
        let batch = PaymentBatch::new(1, vec![bad_payment], root_before.clone(), "KRS1seq".to_string());
        assert!(batch.execute(&mut set).is_err());
        // UTXO set must be unchanged
        assert_eq!(set.state_root(), root_before);
    }

    #[test]
    fn verify_conservation_correct() {
        let kp = Keypair::generate();
        let (set, utxo_id) = make_funded_set(&kp.address(), 1_000);
        let payment = make_signed_payment(&kp, utxo_id, "KRS1bob", 900, 100);
        let old_root = set.state_root();
        let batch = PaymentBatch::new(1, vec![payment], old_root, "KRS1seq".to_string());
        assert!(batch.verify_conservation(&set));
    }

    #[test]
    fn state_root_changes_after_batch() {
        let kp = Keypair::generate();
        let (mut set, utxo_id) = make_funded_set(&kp.address(), 500);
        let payment = make_signed_payment(&kp, utxo_id, "KRS1bob", 400, 100);
        let old_root = set.state_root();
        let batch = PaymentBatch::new(1, vec![payment], old_root.clone(), "KRS1seq".to_string());
        let new_root = batch.execute(&mut set).unwrap();
        assert_ne!(old_root, new_root);
    }
}
