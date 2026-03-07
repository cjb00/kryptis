/// RocksDB-backed implementation of the `Storage` trait.
///
/// Key schema:
/// - `"b:h:{height}"` → JSON-encoded `Block`
/// - `"b:x:{hash}"`   → JSON-encoded `Block`
/// - `"tip"`          → JSON-encoded `(u64, String)` — current tip
/// - `"vs"`           → JSON-encoded `ValidatorSet`
/// - `"a:{address}"`  → JSON-encoded `AccountState`
use std::sync::Arc;

use rocksdb::{Options, DB};

use crate::{
    consensus::validator::ValidatorSet,
    core::{
        block::Block,
        chain::AccountState,
        error::{KryptisError, KryptisResult},
    },
    storage::Storage,
};

/// RocksDB-backed storage engine.
pub struct RocksStorage {
    db: Arc<DB>,
}

impl RocksStorage {
    /// Open (or create) a RocksDB database at `path`.
    pub fn open(path: &str) -> KryptisResult<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, path)
            .map_err(|e| KryptisError::StorageError(e.to_string()))?;
        Ok(Self { db: Arc::new(db) })
    }

    fn put(&self, key: &str, value: &str) -> KryptisResult<()> {
        self.db
            .put(key.as_bytes(), value.as_bytes())
            .map_err(|e| KryptisError::StorageError(e.to_string()))
    }

    fn get(&self, key: &str) -> KryptisResult<Option<String>> {
        match self.db.get(key.as_bytes()) {
            Ok(Some(bytes)) => {
                let s = String::from_utf8(bytes)
                    .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
                Ok(Some(s))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(KryptisError::StorageError(e.to_string())),
        }
    }
}

impl Storage for RocksStorage {
    fn save_block(&self, block: &Block) -> KryptisResult<()> {
        let json = serde_json::to_string(block)
            .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
        // Index by height
        self.put(&format!("b:h:{}", block.header.height), &json)?;
        // Index by hash
        self.put(&format!("b:x:{}", block.hash), &json)?;
        Ok(())
    }

    fn get_block_by_height(&self, height: u64) -> KryptisResult<Option<Block>> {
        match self.get(&format!("b:h:{}", height))? {
            Some(json) => {
                let block: Block = serde_json::from_str(&json)
                    .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    fn get_block_by_hash(&self, hash: &str) -> KryptisResult<Option<Block>> {
        match self.get(&format!("b:x:{}", hash))? {
            Some(json) => {
                let block: Block = serde_json::from_str(&json)
                    .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    fn save_chain_tip(&self, height: u64, hash: &str) -> KryptisResult<()> {
        let tip = (height, hash.to_string());
        let json = serde_json::to_string(&tip)
            .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
        self.put("tip", &json)
    }

    fn get_chain_tip(&self) -> KryptisResult<Option<(u64, String)>> {
        match self.get("tip")? {
            Some(json) => {
                let tip: (u64, String) = serde_json::from_str(&json)
                    .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
                Ok(Some(tip))
            }
            None => Ok(None),
        }
    }

    fn save_validator_set(&self, set: &ValidatorSet) -> KryptisResult<()> {
        let json = serde_json::to_string(set)
            .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
        self.put("vs", &json)
    }

    fn get_validator_set(&self) -> KryptisResult<Option<ValidatorSet>> {
        match self.get("vs")? {
            Some(json) => {
                let vs: ValidatorSet = serde_json::from_str(&json)
                    .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
                Ok(Some(vs))
            }
            None => Ok(None),
        }
    }

    fn save_account(&self, address: &str, state: &AccountState) -> KryptisResult<()> {
        let json = serde_json::to_string(state)
            .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
        self.put(&format!("a:{}", address), &json)
    }

    fn get_account(&self, address: &str) -> KryptisResult<Option<AccountState>> {
        match self.get(&format!("a:{}", address))? {
            Some(json) => {
                let state: AccountState = serde_json::from_str(&json)
                    .map_err(|e| KryptisError::SerializationError(e.to_string()))?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::validator::{Validator, ValidatorSet, MIN_VALIDATOR_STAKE},
        core::{block::Block, chain::AccountState},
    };
    use tempfile::TempDir;

    fn open_temp_db() -> (RocksStorage, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let storage = RocksStorage::open(dir.path().to_str().expect("path")).expect("open db");
        (storage, dir)
    }

    #[test]
    fn save_and_get_block_by_height() {
        let (storage, _dir) = open_temp_db();
        let genesis = Block::genesis();
        storage.save_block(&genesis).expect("save");
        let loaded = storage.get_block_by_height(0).expect("get").expect("some");
        assert_eq!(loaded.hash, genesis.hash);
    }

    #[test]
    fn save_and_get_block_by_hash() {
        let (storage, _dir) = open_temp_db();
        let genesis = Block::genesis();
        let hash = genesis.hash.clone();
        storage.save_block(&genesis).expect("save");
        let loaded = storage.get_block_by_hash(&hash).expect("get").expect("some");
        assert_eq!(loaded.header.height, 0);
    }

    #[test]
    fn get_missing_block_returns_none() {
        let (storage, _dir) = open_temp_db();
        let result = storage.get_block_by_height(999).expect("get");
        assert!(result.is_none());
    }

    #[test]
    fn save_and_get_validator_set() {
        let (storage, _dir) = open_temp_db();
        let mut vs = ValidatorSet::new();
        let v = Validator::new(
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "00".repeat(32),
            MIN_VALIDATOR_STAKE,
            500,
            None,
        )
        .expect("validator");
        vs.register(v).expect("register");
        storage.save_validator_set(&vs).expect("save");

        let loaded = storage.get_validator_set().expect("get").expect("some");
        assert_eq!(loaded.validators.len(), 1);
        assert_eq!(loaded.epoch, 0);
    }

    #[test]
    fn save_and_get_account() {
        let (storage, _dir) = open_temp_db();
        let state = AccountState {
            balance: 500_000,
            staked: 100_000,
            nonce: 3,
        };
        storage
            .save_account("KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &state)
            .expect("save");
        let loaded = storage
            .get_account("KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("get")
            .expect("some");
        assert_eq!(loaded.balance, 500_000);
        assert_eq!(loaded.staked, 100_000);
        assert_eq!(loaded.nonce, 3);
    }

    #[test]
    fn chain_tip_persistence() {
        let (storage, _dir) = open_temp_db();
        assert!(storage.get_chain_tip().expect("get").is_none());
        storage.save_chain_tip(5, "abc123").expect("save");
        let (height, hash) = storage.get_chain_tip().expect("get").expect("some");
        assert_eq!(height, 5);
        assert_eq!(hash, "abc123");
    }
}
