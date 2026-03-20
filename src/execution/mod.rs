/// UTXO execution domain — Layer 2 payment processing.
///
/// Organises the three layers of execution:
/// - `utxo` — UTXO data model, `UtxoSet`, `Payment` validation
/// - `batch` — atomic `PaymentBatch` execution with rollback
/// - `domain` — `ExecutionDomain` coordinator (mempool, fee ordering, state)
pub mod batch;
pub mod domain;
pub mod utxo;
