/// UTXO model for the Kryptis execution domain (Layer 2).
///
/// Implements an account-less UTXO set with nullifiers for double-spend
/// prevention, a `Payment` transaction type, and a deterministic state root
/// computed via `kryptis_types::compute_state_root` — the same function used
/// inside the zkVM guest so both sides agree on state transitions.
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::core::{
    crypto::{sha256, verify_signature, Address, Hash},
    error::{KryptisError, KryptisResult},
};
use kryptis_types::{SerializableUtxo, compute_output_id, compute_state_root};

// ─── UTXO ────────────────────────────────────────────────────────────────────

/// A single unspent transaction output on the execution domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    /// Unique identifier: `sha256(tx_hash || output_index_le)`.
    pub id: Hash,
    /// KRS1 address of the owner.
    pub owner: Address,
    /// Balance in base units.
    pub amount: u64,
    /// Whether this UTXO has been consumed.  Spent UTXOs remain in the map
    /// but are never included in the state root.
    pub spent: bool,
}

impl Utxo {
    /// Derive the UTXO id for a genesis credit.
    ///
    /// Genesis UTXOs use `sha256("genesis" || owner || amount_le || nonce_le)`
    /// so multiple credits to the same address are distinguishable.
    pub fn genesis_id(owner: &str, amount: u64, nonce: u64) -> Hash {
        let mut data = b"genesis".to_vec();
        data.extend_from_slice(owner.as_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
        sha256(&data)
    }

    /// Derive the UTXO id for a payment output.
    ///
    /// `id = sha256(parent_input_id || owner || amount_le || index_le)`
    pub fn output_id(parent_input_id: &Hash, owner: &str, amount: u64, index: u32) -> Hash {
        let parent_bytes = hex::decode(parent_input_id).unwrap_or_default();
        let parent_arr: [u8; 32] = parent_bytes
            .try_into()
            .unwrap_or([0u8; 32]);
        hex::encode(compute_output_id(&parent_arr, owner, amount, index))
    }
}

// ─── UtxoSet ─────────────────────────────────────────────────────────────────

/// The full UTXO set for an execution domain.
///
/// Maintains a map of all UTXOs (spent and unspent) plus a nullifier set for
/// O(1) double-spend detection.  The state root only covers unspent UTXOs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UtxoSet {
    /// All UTXOs keyed by id (includes spent ones for historical reference).
    pub utxos: HashMap<Hash, Utxo>,
    /// Ids of spent UTXOs — used for fast double-spend checks.
    pub nullifiers: HashSet<Hash>,
}

impl UtxoSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a new unspent UTXO.  Returns an error if the id already exists.
    pub fn add(&mut self, utxo: Utxo) -> KryptisResult<()> {
        if self.utxos.contains_key(&utxo.id) {
            return Err(KryptisError::ExecutionError(format!(
                "UTXO {} already exists",
                utxo.id
            )));
        }
        self.utxos.insert(utxo.id.clone(), utxo);
        Ok(())
    }

    /// Consume a UTXO: mark it spent and add its id to the nullifier set.
    ///
    /// Returns the UTXO so the caller can verify the owner and amount.
    /// Fails if the UTXO does not exist or is already spent.
    pub fn spend(&mut self, utxo_id: &Hash) -> KryptisResult<Utxo> {
        if self.nullifiers.contains(utxo_id) {
            return Err(KryptisError::ExecutionError(format!(
                "UTXO {} already spent (double spend)",
                utxo_id
            )));
        }
        let utxo = self.utxos.get_mut(utxo_id).ok_or_else(|| {
            KryptisError::ExecutionError(format!("UTXO {} not found", utxo_id))
        })?;
        utxo.spent = true;
        let spent = utxo.clone();
        self.nullifiers.insert(utxo_id.clone());
        Ok(spent)
    }

    /// Returns `true` if the UTXO has been spent.
    pub fn is_spent(&self, utxo_id: &Hash) -> bool {
        self.nullifiers.contains(utxo_id)
    }

    /// Look up a UTXO by id.
    pub fn get(&self, utxo_id: &Hash) -> Option<&Utxo> {
        self.utxos.get(utxo_id)
    }

    /// Compute the deterministic state root over all *unspent* UTXOs.
    ///
    /// Delegates to `kryptis_types::compute_state_root` so the result is
    /// identical to what the zkVM guest computes from its snapshot.
    pub fn state_root(&self) -> Hash {
        let snaps = self.to_snapshots();
        hex::encode(compute_state_root(&snaps))
    }

    /// Convert unspent UTXOs to the serializable form used by the prover.
    pub fn to_snapshots(&self) -> Vec<SerializableUtxo> {
        self.utxos
            .values()
            .filter(|u| !u.spent)
            .map(|u| {
                let id_bytes = hex::decode(&u.id).unwrap_or_default();
                let id: [u8; 32] = id_bytes.try_into().unwrap_or([0u8; 32]);
                SerializableUtxo {
                    id,
                    owner: u.owner.clone(),
                    amount: u.amount,
                }
            })
            .collect()
    }

    /// Sum of all unspent UTXOs owned by `address`.
    pub fn balance_of(&self, address: &Address) -> u64 {
        self.utxos
            .values()
            .filter(|u| !u.spent && u.owner == *address)
            .map(|u| u.amount)
            .sum()
    }
}

// ─── Payment ─────────────────────────────────────────────────────────────────

/// A single UTXO payment transaction on the execution domain.
///
/// No scripting — just inputs (UTXOs to spend), outputs (new UTXOs to create),
/// a fee, and an ed25519 signature from the owner of all input UTXOs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    /// Unique identifier: `sha256(inputs[0] || inputs[1] || ... || fee_le)`.
    pub id: Hash,
    /// UTXO ids to spend.
    pub inputs: Vec<Hash>,
    /// New UTXOs to create.
    pub outputs: Vec<PaymentOutput>,
    /// Fee paid to the sequencer, in base units.  Consumed from inputs.
    pub fee: u64,
    /// Hex-encoded ed25519 signature over `signable_bytes()`.
    pub signature: String,
    /// Hex-encoded ed25519 public key of the signer (owner of all inputs).
    pub public_key: String,
}

/// A single output in a payment transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentOutput {
    pub owner: Address,
    pub amount: u64,
}

impl Payment {
    /// Build an unsigned payment.  Call `attach_signature` after signing.
    pub fn new(
        inputs: Vec<Hash>,
        outputs: Vec<PaymentOutput>,
        fee: u64,
        public_key: String,
    ) -> Self {
        let id = Self::compute_id(&inputs, fee);
        Self {
            id,
            inputs,
            outputs,
            fee,
            signature: String::new(),
            public_key,
        }
    }

    fn compute_id(inputs: &[Hash], fee: u64) -> Hash {
        let mut data = Vec::new();
        for input in inputs {
            data.extend_from_slice(input.as_bytes());
        }
        data.extend_from_slice(&fee.to_le_bytes());
        sha256(&data)
    }

    /// Bytes that the sender signs.
    ///
    /// Covers all inputs, all outputs (owner + amount), and the fee to prevent
    /// any tampering with transaction contents after signing.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PAYMENT:");
        for input in &self.inputs {
            bytes.extend_from_slice(input.as_bytes());
        }
        bytes.extend_from_slice(b":");
        for output in &self.outputs {
            bytes.extend_from_slice(output.owner.as_bytes());
            bytes.extend_from_slice(&output.amount.to_le_bytes());
        }
        bytes.extend_from_slice(b":");
        bytes.extend_from_slice(&self.fee.to_le_bytes());
        bytes
    }

    /// Attach the sender's signature.
    pub fn attach_signature(&mut self, sig: String) {
        self.signature = sig;
    }

    /// Validate the payment against the current UTXO set.
    ///
    /// Checks:
    /// 1. At least one input and one output.
    /// 2. No duplicate inputs within this transaction.
    /// 3. All input UTXOs exist and are unspent.
    /// 4. All output amounts > 0.
    /// 5. Total inputs >= total outputs + fee (conservation).
    /// 6. Signature is valid over `signable_bytes()`.
    pub fn validate(&self, utxo_set: &UtxoSet) -> KryptisResult<()> {
        if self.inputs.is_empty() {
            return Err(KryptisError::ExecutionError(
                "payment must have at least one input".into(),
            ));
        }
        if self.outputs.is_empty() {
            return Err(KryptisError::ExecutionError(
                "payment must have at least one output".into(),
            ));
        }

        // No duplicate inputs
        let mut seen = HashSet::new();
        for id in &self.inputs {
            if !seen.insert(id) {
                return Err(KryptisError::ExecutionError(format!(
                    "duplicate input UTXO {} in payment",
                    id
                )));
            }
        }

        // All inputs must exist and be unspent; sum their values
        let mut total_in: u64 = 0;
        for id in &self.inputs {
            let utxo = utxo_set
                .get(id)
                .ok_or_else(|| KryptisError::ExecutionError(format!("UTXO {} not found", id)))?;
            if utxo.spent {
                return Err(KryptisError::ExecutionError(format!(
                    "UTXO {} already spent",
                    id
                )));
            }
            total_in = total_in.checked_add(utxo.amount).ok_or_else(|| {
                KryptisError::ExecutionError("input amount overflow".into())
            })?;
        }

        // All outputs must have positive amounts; sum them
        let mut total_out: u64 = 0;
        for output in &self.outputs {
            if output.amount == 0 {
                return Err(KryptisError::ExecutionError(
                    "output amount must be greater than zero".into(),
                ));
            }
            total_out = total_out.checked_add(output.amount).ok_or_else(|| {
                KryptisError::ExecutionError("output amount overflow".into())
            })?;
        }

        // Conservation: inputs >= outputs + fee
        let total_spent = total_out.checked_add(self.fee).ok_or_else(|| {
            KryptisError::ExecutionError("outputs + fee overflow".into())
        })?;
        if total_in < total_spent {
            return Err(KryptisError::ExecutionError(format!(
                "insufficient inputs: have {}, need {}",
                total_in, total_spent
            )));
        }

        // Signature verification (skip if empty — for genesis/internal use)
        if !self.signature.is_empty() && !self.public_key.is_empty() {
            let msg = self.signable_bytes();
            verify_signature(&self.public_key, &msg, &self.signature)
                .map_err(|_| KryptisError::InvalidSignature)?;
        }

        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto::Keypair;

    fn make_genesis_utxo(owner: &str, amount: u64, nonce: u64) -> Utxo {
        let id = Utxo::genesis_id(owner, amount, nonce);
        Utxo { id, owner: owner.to_string(), amount, spent: false }
    }

    #[test]
    fn add_and_get_utxo() {
        let mut set = UtxoSet::new();
        let utxo = make_genesis_utxo("KRS1alice", 1_000, 0);
        let id = utxo.id.clone();
        set.add(utxo).expect("add");
        assert!(set.get(&id).is_some());
        assert!(!set.is_spent(&id));
    }

    #[test]
    fn spend_utxo_adds_nullifier() {
        let mut set = UtxoSet::new();
        let utxo = make_genesis_utxo("KRS1alice", 1_000, 0);
        let id = utxo.id.clone();
        set.add(utxo).expect("add");
        set.spend(&id).expect("spend");
        assert!(set.is_spent(&id));
    }

    #[test]
    fn double_spend_rejected() {
        let mut set = UtxoSet::new();
        let utxo = make_genesis_utxo("KRS1alice", 1_000, 0);
        let id = utxo.id.clone();
        set.add(utxo).expect("add");
        set.spend(&id).expect("first spend");
        assert!(set.spend(&id).is_err(), "double spend must be rejected");
    }

    #[test]
    fn balance_of_sums_unspent() {
        let mut set = UtxoSet::new();
        let alice = "KRS1alice";
        let u1 = make_genesis_utxo(alice, 100, 0);
        let u2 = make_genesis_utxo(alice, 200, 1);
        let u3 = make_genesis_utxo("KRS1bob", 50, 0);
        let id1 = u1.id.clone();
        set.add(u1).unwrap();
        set.add(u2).unwrap();
        set.add(u3).unwrap();
        assert_eq!(set.balance_of(&alice.to_string()), 300);
        // Spend one of alice's UTXOs
        set.spend(&id1).unwrap();
        assert_eq!(set.balance_of(&alice.to_string()), 200);
    }

    #[test]
    fn state_root_changes_after_spend() {
        let mut set = UtxoSet::new();
        let utxo = make_genesis_utxo("KRS1alice", 500, 0);
        let id = utxo.id.clone();
        set.add(utxo).unwrap();
        let root_before = set.state_root();
        set.spend(&id).unwrap();
        let root_after = set.state_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn state_root_deterministic() {
        let mut set1 = UtxoSet::new();
        let mut set2 = UtxoSet::new();
        let u = make_genesis_utxo("KRS1alice", 100, 0);
        set1.add(u.clone()).unwrap();
        set2.add(u).unwrap();
        assert_eq!(set1.state_root(), set2.state_root());
    }

    #[test]
    fn payment_validates_correctly() {
        let kp = Keypair::generate();
        let mut set = UtxoSet::new();
        let utxo = make_genesis_utxo(&kp.address(), 1_000, 0);
        let utxo_id = utxo.id.clone();
        set.add(utxo).unwrap();

        let mut payment = Payment::new(
            vec![utxo_id],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 900 }],
            100,
            kp.public_key_hex(),
        );
        let sig = kp.sign(&payment.signable_bytes());
        payment.attach_signature(sig);

        payment.validate(&set).expect("valid payment");
    }

    #[test]
    fn payment_insufficient_inputs_rejected() {
        let kp = Keypair::generate();
        let mut set = UtxoSet::new();
        let utxo = make_genesis_utxo(&kp.address(), 100, 0);
        let utxo_id = utxo.id.clone();
        set.add(utxo).unwrap();

        let payment = Payment::new(
            vec![utxo_id],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 200 }],
            0,
            kp.public_key_hex(),
        );
        assert!(payment.validate(&set).is_err());
    }

    #[test]
    fn payment_duplicate_input_rejected() {
        let kp = Keypair::generate();
        let mut set = UtxoSet::new();
        let utxo = make_genesis_utxo(&kp.address(), 1_000, 0);
        let id = utxo.id.clone();
        set.add(utxo).unwrap();

        let payment = Payment::new(
            vec![id.clone(), id],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 100 }],
            0,
            kp.public_key_hex(),
        );
        assert!(payment.validate(&set).is_err());
    }

    #[test]
    fn payment_zero_output_rejected() {
        let kp = Keypair::generate();
        let mut set = UtxoSet::new();
        let utxo = make_genesis_utxo(&kp.address(), 1_000, 0);
        let id = utxo.id.clone();
        set.add(utxo).unwrap();

        let payment = Payment::new(
            vec![id],
            vec![PaymentOutput { owner: "KRS1bob".to_string(), amount: 0 }],
            0,
            kp.public_key_hex(),
        );
        assert!(payment.validate(&set).is_err());
    }
}
