/// Persistent storage abstraction for the Kryptis blockchain.
///
/// The `Storage` trait decouples the consensus and chain logic from any
/// specific database engine.  The current implementation uses RocksDB,
/// but swapping in a different backend (e.g. sled, LMDB, or a remote
/// store for testing) only requires a new `impl Storage` without
/// touching consensus code.
use crate::{
    consensus::validator::ValidatorSet,
    core::{
        block::Block,
        chain::AccountState,
        error::KryptisResult,
    },
};

pub mod rocksdb;

/// Persistent storage interface for the Kryptis base chain.
///
/// All methods are synchronous (RocksDB is synchronous internally).
/// Implementations must be `Send + Sync` to be shared across async tasks.
pub trait Storage: Send + Sync {
    /// Persist a block, indexing it by both height and hash.
    fn save_block(&self, block: &Block) -> KryptisResult<()>;

    /// Retrieve a block by its chain height.
    fn get_block_by_height(&self, height: u64) -> KryptisResult<Option<Block>>;

    /// Retrieve a block by its hash.
    fn get_block_by_hash(&self, hash: &str) -> KryptisResult<Option<Block>>;

    /// Update the stored chain tip pointer.
    fn save_chain_tip(&self, height: u64, hash: &str) -> KryptisResult<()>;

    /// Return `(height, hash)` of the last persisted tip, or `None` if empty.
    fn get_chain_tip(&self) -> KryptisResult<Option<(u64, String)>>;

    /// Persist the complete validator set.
    fn save_validator_set(&self, set: &ValidatorSet) -> KryptisResult<()>;

    /// Retrieve the last persisted validator set.
    fn get_validator_set(&self) -> KryptisResult<Option<ValidatorSet>>;

    /// Persist account state for a single address.
    fn save_account(&self, address: &str, state: &AccountState) -> KryptisResult<()>;

    /// Retrieve account state for an address.
    fn get_account(&self, address: &str) -> KryptisResult<Option<AccountState>>;
}
