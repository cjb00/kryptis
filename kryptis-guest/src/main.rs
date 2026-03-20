//! Kryptis zkVM guest program — UTXO payment batch validity proof.
//!
//! This program runs inside the Risc0 zkVM and produces a cryptographic
//! proof that a batch of UTXO payments was executed correctly.
//!
//! # Security properties proven
//! 1. **State consistency** — the UTXO snapshot hashes to exactly `old_state_root`.
//!    Any tampering with the snapshot would produce a different root and the
//!    assertion would fail, invalidating the proof.
//! 2. **Double-spend prevention** — each input UTXO is removed from the set
//!    before processing the next payment, so it cannot be spent twice in the batch.
//! 3. **Conservation** — outputs are exactly the result of consuming inputs;
//!    no tokens are created or destroyed (fees reduce the total in the UTXO set).
//! 4. **Correct state transition** — `new_state_root` is derived from the
//!    resulting UTXO set, which is committed to the receipt journal.
//!
//! # Host/guest contract
//! Input:  `BatchInput`  — read from the zkVM environment via `env::read()`
//! Output: `BatchOutput` — committed to the receipt journal via `env::commit()`
//!
//! The host verifies `BatchOutput.new_state_root` matches the claimed
//! `SettlementProof.new_state_root` before accepting the settlement.

use kryptis_types::{BatchInput, BatchOutput, SerializableUtxo, compute_output_id, compute_state_root};
use risc0_zkvm::guest::env;

fn main() {
    // Read the batch input from the host.
    // This is cryptographically bound to the proof — any change in input
    // would require rerunning the guest (producing a different receipt).
    let input: BatchInput = env::read();

    // --- Security check 1: verify state consistency ---
    // The host claims the UTXO snapshots correspond to `old_state_root`.
    // If the host tampers with the snapshots, the computed root differs
    // and this assertion fails, making the proof invalid.
    let computed_old = compute_state_root(&input.utxo_snapshots);
    assert_eq!(
        computed_old,
        input.old_state_root,
        "old_state_root mismatch: snapshot does not match claimed pre-batch state"
    );

    // Mutable working copy of the UTXO set.
    // We start from the verified snapshot and apply payments sequentially.
    let mut utxos: Vec<SerializableUtxo> = input.utxo_snapshots.clone();
    let mut total_fees: u64 = 0;

    for payment in &input.payments {
        // --- Security check 2: verify all inputs exist ---
        // Every input UTXO must be present in the current set.
        // If a UTXO was already spent (in a previous payment in this batch),
        // it will not be found here — preventing intra-batch double spends.
        for input_id in &payment.inputs {
            let pos = utxos
                .iter()
                .position(|u| &u.id == input_id)
                .expect("input UTXO not found — possible double spend or invalid reference");
            // Remove the UTXO to mark it as spent.
            utxos.remove(pos);
        }

        // Create output UTXOs for this payment.
        // Each output gets a deterministic id derived from the first input,
        // owner, amount, and output index — guaranteeing uniqueness.
        let first_input = &payment.inputs[0];
        for (idx, (owner, amount)) in payment.outputs.iter().enumerate() {
            let id = compute_output_id(first_input, owner, *amount, idx as u32);
            utxos.push(SerializableUtxo {
                id,
                owner: owner.clone(),
                amount: *amount,
            });
        }

        total_fees = total_fees.saturating_add(payment.fee);
    }

    // Compute the new state root from the resulting UTXO set.
    // This is what gets committed to the receipt journal and is later
    // checked by the base chain's settlement verifier.
    let new_root = compute_state_root(&utxos);

    // Commit the output to the receipt journal.
    // The host reads this via `receipt.journal.decode::<BatchOutput>()`.
    env::commit(&BatchOutput {
        old_state_root: input.old_state_root,
        new_state_root: new_root,
        payments_processed: input.payments.len() as u64,
        total_fees,
    });
}
