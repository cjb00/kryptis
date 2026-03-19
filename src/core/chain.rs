/// Blockchain state: account model, mempool, block commitment.
///
/// `Chain` is the authoritative in-memory state of the Kryptis base chain.
/// It is wrapped in `Arc<RwLock<Chain>>` when shared across async tasks so
/// that concurrent reads do not block each other.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::{
    core::{
        block::Block,
        crypto::Address,
        error::{KryptisError, KryptisResult},
        transaction::{Transaction, TransactionType},
    },
    settlement::proof::{DomainState, SettlementProof},
};

/// Per-account state tracked by the base chain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountState {
    /// Spendable token balance in base units.
    pub balance: u64,
    /// Tokens locked in the staking pool, in base units.
    pub staked: u64,
    /// Monotonically increasing counter for replay protection.
    pub nonce: u64,
}

/// The in-memory representation of the Kryptis base chain.
///
/// Holds all committed blocks, per-account balances, the pending
/// transaction mempool, and the registered execution domain states
/// (Phase 3 hook — populated via `register_domain` and
/// `update_domain_state`).
pub struct Chain {
    /// All committed blocks in height order; index 0 is genesis.
    pub blocks: Vec<Block>,
    /// Current account balances and staking state, keyed by KRS1 address.
    pub accounts: HashMap<Address, AccountState>,
    /// Pending transactions waiting to be included in a block.
    pub mempool: Vec<Transaction>,
    /// On-chain record of each registered execution domain.
    ///
    /// TODO Phase 3: Populated by settlement proofs submitted from Layer 2.
    pub domain_states: HashMap<u64, DomainState>,
}

impl Chain {
    /// Initialise a new chain with only the genesis block.
    pub fn new() -> Self {
        let genesis = Block::genesis();
        info!(height = 0, hash = %genesis.hash, "Genesis block created");
        Self {
            blocks: vec![genesis],
            accounts: HashMap::new(),
            mempool: Vec::new(),
            domain_states: HashMap::new(),
        }
    }

    /// Return the most recent committed block.
    pub fn tip(&self) -> &Block {
        // Safety: `blocks` always contains at least the genesis block.
        self.blocks.last().expect("chain always has genesis block")
    }

    /// Return the height of the most recent committed block.
    pub fn height(&self) -> u64 {
        self.tip().header.height
    }

    /// Return the hash of the most recent committed block.
    pub fn tip_hash(&self) -> &str {
        &self.tip().hash
    }

    /// Look up a block by height.
    pub fn get_block(&self, height: u64) -> Option<&Block> {
        self.blocks.get(height as usize)
    }

    /// Look up a block by its hash.
    pub fn get_block_by_hash(&self, hash: &str) -> Option<&Block> {
        self.blocks.iter().find(|b| b.hash == hash)
    }

    /// Validate and commit a block to the chain.
    ///
    /// Validation requirements:
    /// - Block height must be exactly `tip().height + 1`.
    /// - `previous_hash` must equal the current tip hash.
    /// - All structural checks in [`Block::validate`] must pass.
    ///
    /// After passing validation every transaction is applied to
    /// account state and the block is appended to `self.blocks`.
    pub fn commit_block(&mut self, block: Block) -> KryptisResult<()> {
        let expected_height = self.height() + 1;
        if block.header.height != expected_height {
            return Err(KryptisError::InvalidBlock(format!(
                "expected height {}, got {}",
                expected_height, block.header.height
            )));
        }
        block.validate(self.tip_hash())?;

        for tx in &block.transactions {
            self.apply_transaction(tx)?;
        }

        // Remove committed transactions from the mempool
        let committed_ids: std::collections::HashSet<&str> =
            block.transactions.iter().map(|t| t.id.as_str()).collect();
        self.mempool.retain(|t| !committed_ids.contains(t.id.as_str()));

        info!(
            height = block.header.height,
            hash = %block.hash,
            tx_count = block.transactions.len(),
            "Block committed"
        );
        self.blocks.push(block);
        Ok(())
    }

    /// Apply a single transaction to account state.
    ///
    /// Transaction semantics:
    /// - **Transfer**: debit `from` by `amount + fee`, credit `to` by `amount`.
    /// - **Stake**: move `amount` from `from.balance` to `from.staked`.
    /// - **Unstake**: move `amount` from `from.staked` to `from.balance`.
    ///   TODO Phase 3: Enforce a 21-day unbonding period.  Track pending
    ///   unstakes in a queue keyed by `(address, unlock_height)` and only
    ///   move funds to `balance` once `current_height >= unlock_height`.
    /// - **Reward**: mint `amount` directly to `to.balance` (no sender debit).
    pub fn apply_transaction(&mut self, tx: &Transaction) -> KryptisResult<()> {
        debug!(tx_id = %tx.id, tx_type = ?tx.tx_type, "Applying transaction");

        match tx.tx_type {
            TransactionType::Transfer => {
                let total_cost = tx.amount.checked_add(tx.fee).ok_or_else(|| {
                    KryptisError::InvalidTransaction("amount + fee overflow".into())
                })?;
                let from_acc = self.accounts.entry(tx.from.clone()).or_default();
                if from_acc.balance < total_cost {
                    return Err(KryptisError::InvalidTransaction(format!(
                        "insufficient balance: need {}, have {}",
                        total_cost, from_acc.balance
                    )));
                }
                from_acc.balance -= total_cost;
                from_acc.nonce += 1;

                let to_acc = self.accounts.entry(tx.to.clone()).or_default();
                to_acc.balance += tx.amount;
            }
            TransactionType::Stake => {
                let from_acc = self.accounts.entry(tx.from.clone()).or_default();
                if from_acc.balance < tx.amount {
                    return Err(KryptisError::InvalidTransaction(format!(
                        "insufficient balance for staking: need {}, have {}",
                        tx.amount, from_acc.balance
                    )));
                }
                from_acc.balance -= tx.amount;
                from_acc.staked += tx.amount;
                from_acc.nonce += 1;
            }
            TransactionType::Unstake => {
                // TODO Phase 3: Enforce a 21-day unbonding period before
                // returning funds to balance.  Queue the unstake at
                // (address, current_height + UNBONDING_BLOCKS) and apply
                // it lazily when the chain reaches unlock height.
                let from_acc = self.accounts.entry(tx.from.clone()).or_default();
                if from_acc.staked < tx.amount {
                    return Err(KryptisError::InvalidTransaction(format!(
                        "insufficient staked balance: need {}, have {}",
                        tx.amount, from_acc.staked
                    )));
                }
                from_acc.staked -= tx.amount;
                from_acc.balance += tx.amount;
                from_acc.nonce += 1;
            }
            TransactionType::Reward => {
                // Reward mints new tokens — no sender debit.
                let to_acc = self.accounts.entry(tx.to.clone()).or_default();
                to_acc.balance += tx.amount;
            }
        }
        Ok(())
    }

    /// Add a transaction to the mempool if it is not already present.
    pub fn add_to_mempool(&mut self, tx: Transaction) -> KryptisResult<()> {
        if self.mempool.iter().any(|t| t.id == tx.id) {
            warn!(tx_id = %tx.id, "Duplicate transaction ignored");
            return Ok(());
        }
        debug!(tx_id = %tx.id, "Transaction added to mempool");
        self.mempool.push(tx);
        Ok(())
    }

    /// Select up to `max` transactions from the mempool, ordered by fee descending.
    ///
    /// Higher-fee transactions are prioritised so that block proposers
    /// maximise their fee revenue, aligning their incentives with fast
    /// inclusion of high-value transactions.
    pub fn select_transactions(&self, max: usize) -> Vec<Transaction> {
        let mut sorted = self.mempool.clone();
        sorted.sort_by(|a, b| b.fee.cmp(&a.fee));
        sorted.truncate(max);
        sorted
    }

    /// Return the spendable balance of `address` in base units.
    pub fn balance_of(&self, address: &str) -> u64 {
        self.accounts.get(address).map_or(0, |a| a.balance)
    }

    /// Return the staked balance of `address` in base units.
    pub fn staked_of(&self, address: &str) -> u64 {
        self.accounts.get(address).map_or(0, |a| a.staked)
    }

    /// Return the transaction nonce of `address`.
    pub fn nonce_of(&self, address: &str) -> u64 {
        self.accounts.get(address).map_or(0, |a| a.nonce)
    }

    /// Credit `amount` base units to `address` without a corresponding debit.
    ///
    /// Used during genesis setup to bootstrap initial balances.
    pub fn credit_genesis(&mut self, address: &str, amount: u64) {
        let acc = self.accounts.entry(address.to_string()).or_default();
        acc.balance += amount;
        info!(address, amount, "Genesis credit applied");
    }

    /// Register a new execution domain on the settlement layer.
    ///
    /// TODO Phase 3: Require a registration bond from `sequencer` to
    /// prevent spam.  The bond is slashed if the domain goes offline.
    pub fn register_domain(
        &mut self,
        domain_id: u64,
        sequencer: Address,
    ) -> KryptisResult<()> {
        if self.domain_states.contains_key(&domain_id) {
            return Err(KryptisError::ConsensusError(format!(
                "domain {} already registered",
                domain_id
            )));
        }
        let state = DomainState {
            domain_id,
            state_root: "0".repeat(64),
            last_settled_height: 0,
            sequencer_address: sequencer,
        };
        self.domain_states.insert(domain_id, state);
        info!(domain_id, "Execution domain registered");
        Ok(())
    }

    /// Update the on-chain state for an execution domain from a settlement proof.
    ///
    /// The proof is accepted unconditionally for Phase 1+2 (the `StubVerifier`
    /// always returns `Ok(())`).  In Phase 3 this path will call the real
    /// `ProofVerifier` before updating `DomainState`.
    pub fn update_domain_state(&mut self, proof: &SettlementProof) -> KryptisResult<()> {
        // Capture height before the mutable borrow of domain_states.
        let current_height = self.height();
        let domain = self.domain_states.get_mut(&proof.domain_id).ok_or_else(|| {
            KryptisError::ConsensusError(format!("domain {} not registered", proof.domain_id))
        })?;
        // TODO Phase 3: Call ProofVerifier::verify(proof, domain) here instead
        // of accepting unconditionally.
        domain.state_root = proof.new_state_root.clone();
        domain.last_settled_height = current_height;
        info!(
            domain_id = proof.domain_id,
            new_state_root = %proof.new_state_root,
            "Domain state updated"
        );
        Ok(())
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{
        block::Block,
        crypto::Keypair,
        transaction::{Transaction, TransactionType},
    };

    fn make_reward(to: &str, amount: u64) -> Transaction {
        Transaction::new(
            TransactionType::Reward,
            "KRS1genesis00000000000000000000000000000000".to_string(),
            to.to_string(),
            amount,
            0,
            "00".repeat(32),
            None,
        )
    }

    #[test]
    fn new_chain_has_genesis() {
        let chain = Chain::new();
        assert_eq!(chain.height(), 0);
        assert!(!chain.tip_hash().is_empty());
    }

    #[test]
    fn credit_genesis_updates_balance() {
        let mut chain = Chain::new();
        let addr = "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        chain.credit_genesis(addr, 1_000_000);
        assert_eq!(chain.balance_of(addr), 1_000_000);
    }

    #[test]
    fn commit_empty_block_advances_height() {
        let mut chain = Chain::new();
        let tip_hash = chain.tip_hash().to_string();
        let block = Block::new(
            1,
            tip_hash,
            vec![],
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            0,
        );
        chain.commit_block(block).expect("commit");
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn invalid_height_rejected() {
        let mut chain = Chain::new();
        let block = Block::new(
            5, // wrong height
            chain.tip_hash().to_string(),
            vec![],
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            0,
        );
        assert!(chain.commit_block(block).is_err());
    }

    #[test]
    fn reward_transaction_mints_tokens() {
        let mut chain = Chain::new();
        let addr = "KRS1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let reward = make_reward(addr, 2_000_000);
        chain.apply_transaction(&reward).expect("apply reward");
        assert_eq!(chain.balance_of(addr), 2_000_000);
    }

    #[test]
    fn transfer_updates_balances() {
        let mut chain = Chain::new();
        let kp = Keypair::generate();
        let addr = kp.address();
        let recipient = "KRS1cccccccccccccccccccccccccccccccccccccccc";
        chain.credit_genesis(&addr, 10_000_000);

        let mut tx = Transaction::new(
            TransactionType::Transfer,
            addr.clone(),
            recipient.to_string(),
            5_000_000,
            100,
            kp.public_key_hex(),
            None,
        );
        let sig = kp.sign(&tx.signable_bytes());
        tx.attach_signature(sig);

        chain.apply_transaction(&tx).expect("apply transfer");
        assert_eq!(chain.balance_of(&addr), 4_999_900); // 10M - 5M - 100 fee
        assert_eq!(chain.balance_of(recipient), 5_000_000);
    }

    #[test]
    fn mempool_deduplication() {
        let mut chain = Chain::new();
        let kp = Keypair::generate();
        let tx = Transaction::new(
            TransactionType::Reward,
            "KRS1genesis00000000000000000000000000000000".to_string(),
            kp.address(),
            100,
            0,
            "00".repeat(32),
            None,
        );
        chain.add_to_mempool(tx.clone()).expect("first add");
        chain.add_to_mempool(tx).expect("duplicate — should be ignored");
        assert_eq!(chain.mempool.len(), 1);
    }

    #[test]
    fn select_transactions_fee_priority() {
        let mut chain = Chain::new();
        for fee in [10u64, 100, 50] {
            let tx = Transaction::new(
                TransactionType::Reward,
                "KRS1genesis00000000000000000000000000000000".to_string(),
                "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                1,
                fee,
                "00".repeat(32),
                None,
            );
            chain.add_to_mempool(tx).expect("add");
        }
        let selected = chain.select_transactions(2);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].fee, 100);
        assert_eq!(selected[1].fee, 50);
    }
}
