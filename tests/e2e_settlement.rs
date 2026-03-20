//! End-to-end ZK settlement tests.
//!
//! These tests exercise the full Phase 3 flow:
//!   ExecutionDomain → PaymentBatch → Risc0 proof → Risc0Verifier → Chain
//!
//! All tests must be run with `RISC0_DEV_MODE=1` (the mock prover):
//!   `RISC0_DEV_MODE=1 cargo test --test e2e_settlement`
//!
//! The mock prover generates receipts instantly and verifies them with the
//! same code path as production — only the proving cost differs.

use kryptis_lib::{
    core::{chain::Chain, crypto::Keypair},
    execution::{
        domain::ExecutionDomain,
        utxo::{Payment, PaymentOutput},
    },
    settlement::{
        proof::{DomainState, ProofVerifier, Risc0Verifier, SettlementProof},
        prover::Prover,
    },
};

const DOMAIN_ID: u64 = 1;
const SEQ: &str = "KRS1sequencer00000000000000000000000000000000";

/// Build a signed payment with explicit outputs.
fn make_payment_multi_output(
    kp: &Keypair,
    input_utxo_id: String,
    outputs: Vec<PaymentOutput>,
    fee: u64,
) -> Payment {
    let mut p = Payment::new(vec![input_utxo_id], outputs, fee, kp.public_key_hex());
    p.attach_signature(kp.sign(&p.signable_bytes()));
    p
}

/// Build a simple one-input, one-output payment (no change) signed by `kp`.
fn make_payment(kp: &Keypair, input_utxo_id: String, recipient: &str, amount: u64, fee: u64) -> Payment {
    make_payment_multi_output(
        kp,
        input_utxo_id,
        vec![PaymentOutput { owner: recipient.to_string(), amount }],
        fee,
    )
}

// ─── Test 1: full settlement cycle ──────────────────────────────────────────

/// Full flow: genesis → payment with change → prove → Risc0Verifier::verify → chain update.
///
/// Requires `RISC0_DEV_MODE=1`.
#[test]
fn full_settlement_cycle() {
    std::env::set_var("RISC0_DEV_MODE", "1");

    let alice_kp = Keypair::generate();
    let alice = alice_kp.address();
    let bob = "KRS1bob0000000000000000000000000000000000000".to_string();

    // ── Execution domain setup ──
    let mut domain = ExecutionDomain::new(DOMAIN_ID, SEQ.to_string());
    domain.credit_genesis(alice.clone(), 100_000_000);

    let utxo_id = domain.utxo_set.utxos.values().next().unwrap().id.clone();

    // Payment: send 10M to Bob, 89M change to Alice, 1M fee
    // inputs: 100M = outputs(10M + 89M) + fee(1M) → exact conservation
    let payment = make_payment_multi_output(
        &alice_kp,
        utxo_id,
        vec![
            PaymentOutput { owner: bob.clone(), amount: 10_000_000 },
            PaymentOutput { owner: alice.clone(), amount: 89_000_000 },
        ],
        1_000_000,
    );
    domain.submit_payment(payment).expect("submit payment");

    // Capture pre-batch snapshots before produce_batch mutates the UTXO set
    let pre_snapshots = domain.utxo_set.to_snapshots();
    let batch = domain.produce_batch(100).expect("produce batch");

    // ── Generate ZK proof ──
    let receipt = Prover::prove_batch(&batch, pre_snapshots).expect("prove batch");
    let proof_bytes = bincode::serialize(&receipt).expect("serialize receipt");

    // ── On-chain domain registration ──
    // The domain's old_state_root is the state AFTER genesis credits.
    // We register the domain with this root so the verifier can check consistency.
    let old_root = batch.old_state_root.clone();
    let domain_state = DomainState {
        domain_id: DOMAIN_ID,
        state_root: old_root.clone(),
        last_settled_height: 0,
        sequencer_address: SEQ.to_string(),
    };

    let proof = SettlementProof {
        domain_id: DOMAIN_ID,
        old_state_root: old_root,
        new_state_root: batch.new_state_root.clone(),
        da_commitment: "0".repeat(64),
        batch_size: batch.payments.len() as u64,
        proof_bytes,
    };

    // ── Verify with Risc0Verifier ──
    Risc0Verifier
        .verify(&proof, &domain_state)
        .expect("Risc0Verifier must accept valid proof");

    // ── Update chain state ──
    let mut chain = Chain::new();
    chain.register_domain(DOMAIN_ID, SEQ.to_string()).expect("register domain");
    // Align the registered state root to the pre-batch execution domain state.
    chain.domain_states.get_mut(&DOMAIN_ID).unwrap().state_root = proof.old_state_root.clone();
    chain.update_domain_state(&proof).expect("update domain state");

    // ── Assertions ──
    assert_eq!(
        chain.domain_states[&DOMAIN_ID].state_root,
        domain.state_root(),
        "on-chain state root must match execution domain's new state root"
    );

    // Alice: genesis 100M spent, change 89M received back
    assert_eq!(domain.balance_of(&alice), 89_000_000);
    // Bob: received 10M
    assert_eq!(domain.balance_of(&bob), 10_000_000);
}

// ─── Test 2: tampered proof rejected ────────────────────────────────────────

/// A receipt with a tampered new_state_root must be rejected with StateMismatch.
#[test]
fn tampered_proof_rejected() {
    std::env::set_var("RISC0_DEV_MODE", "1");

    let alice_kp = Keypair::generate();
    let alice = alice_kp.address();
    let bob = "KRS1bob0000000000000000000000000000000000000".to_string();

    let mut domain = ExecutionDomain::new(DOMAIN_ID, SEQ.to_string());
    domain.credit_genesis(alice.clone(), 10_000_000);

    let utxo_id = domain.utxo_set.utxos.values().next().unwrap().id.clone();
    let payment = make_payment(&alice_kp, utxo_id, &bob, 9_500_000, 500_000);
    domain.submit_payment(payment).expect("submit");

    let pre_snapshots = domain.utxo_set.to_snapshots();
    let batch = domain.produce_batch(100).expect("batch");

    let receipt = Prover::prove_batch(&batch, pre_snapshots).expect("prove");
    let proof_bytes = bincode::serialize(&receipt).expect("serialize");

    let domain_state = DomainState {
        domain_id: DOMAIN_ID,
        state_root: batch.old_state_root.clone(),
        last_settled_height: 0,
        sequencer_address: SEQ.to_string(),
    };

    // Tamper: substitute a wrong new_state_root
    let proof = SettlementProof {
        domain_id: DOMAIN_ID,
        old_state_root: batch.old_state_root.clone(),
        new_state_root: "deadbeef".repeat(8), // 64 chars, wrong value
        da_commitment: "0".repeat(64),
        batch_size: 1,
        proof_bytes,
    };

    let result = Risc0Verifier.verify(&proof, &domain_state);
    assert!(result.is_err(), "tampered new_state_root must be rejected; got Ok");
}

// ─── Test 3: double spend prevented ─────────────────────────────────────────

/// Two payments spending the same UTXO — only the first makes it into the batch.
#[test]
fn double_spend_in_domain_prevented() {
    let alice_kp = Keypair::generate();
    let alice = alice_kp.address();

    let mut domain = ExecutionDomain::new(DOMAIN_ID, SEQ.to_string());
    domain.credit_genesis(alice.clone(), 10_000_000);

    let utxo_id = domain.utxo_set.utxos.values().next().unwrap().id.clone();

    let p1 = make_payment(&alice_kp, utxo_id.clone(), "KRS1bob", 9_000_000, 1_000_000);
    domain.submit_payment(p1).expect("first payment submitted");

    // Execute p1 into a batch — UTXO is now spent
    domain.produce_batch(100).expect("first batch");

    // Try to submit a second payment spending the same (now-spent) UTXO
    let p2 = make_payment(&alice_kp, utxo_id, "KRS1carol", 9_000_000, 1_000_000);
    let result = domain.submit_payment(p2);

    assert!(
        result.is_err(),
        "double spend against a spent UTXO must be rejected at mempool ingress"
    );
}
