/// Wallet management: keypair storage, transaction signing, and creation.
///
/// A `Wallet` is the user-facing interface for creating and signing
/// transactions.  It manages a single keypair stored on disk and
/// provides helpers for the common transaction types.
use std::path::PathBuf;

use crate::core::{
    crypto::{Address, Keypair},
    error::{KryptisError, KryptisResult},
    transaction::{Transaction, TransactionType},
};

/// The filename used to store the keypair within the data directory.
const WALLET_FILE: &str = "wallet.json";

/// A user wallet backed by a single ed25519 keypair on disk.
///
/// The wallet is created once via [`Wallet::new`] and thereafter
/// loaded via [`Wallet::load`].  Transactions are signed in-memory
/// and the signed transaction bytes are ready for broadcast.
pub struct Wallet {
    /// The node's signing keypair.
    pub keypair: Keypair,
    /// Directory where `wallet.json` is stored.
    pub data_dir: PathBuf,
}

impl Wallet {
    /// Generate a new keypair and persist it to `data_dir/wallet.json`.
    ///
    /// Returns an error if the directory cannot be created or the file
    /// cannot be written.
    pub fn new(data_dir: PathBuf) -> KryptisResult<Self> {
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| KryptisError::StorageError(e.to_string()))?;
        let keypair = Keypair::generate();
        let path = data_dir.join(WALLET_FILE);
        keypair.save_to_file(&path)?;
        Ok(Self { keypair, data_dir })
    }

    /// Load an existing wallet from `data_dir/wallet.json`.
    ///
    /// Returns an error if the file does not exist or is malformed.
    pub fn load(data_dir: PathBuf) -> KryptisResult<Self> {
        let path = data_dir.join(WALLET_FILE);
        let keypair = Keypair::load_from_file(&path)?;
        Ok(Self { keypair, data_dir })
    }

    /// Return the KRS1 address of this wallet's keypair.
    pub fn address(&self) -> Address {
        self.keypair.address()
    }

    /// Sign a transaction in-place using this wallet's keypair.
    pub fn sign_transaction(&self, tx: &mut Transaction) -> KryptisResult<()> {
        let sig = self.keypair.sign(&tx.signable_bytes());
        tx.attach_signature(sig);
        Ok(())
    }

    /// Create and sign a transfer transaction.
    pub fn create_transfer(
        &self,
        to: Address,
        amount: u64,
        fee: u64,
    ) -> KryptisResult<Transaction> {
        let mut tx = Transaction::new(
            TransactionType::Transfer,
            self.address(),
            to,
            amount,
            fee,
            self.keypair.public_key_hex(),
            None,
        );
        self.sign_transaction(&mut tx)?;
        Ok(tx)
    }

    /// Create and sign a stake transaction.
    pub fn create_stake(&self, amount: u64) -> KryptisResult<Transaction> {
        // Stake destination is the same address (staking from self)
        let mut tx = Transaction::new(
            TransactionType::Stake,
            self.address(),
            self.address(),
            amount,
            0,
            self.keypair.public_key_hex(),
            None,
        );
        self.sign_transaction(&mut tx)?;
        Ok(tx)
    }

    /// Create and sign an unstake transaction.
    pub fn create_unstake(&self, amount: u64) -> KryptisResult<Transaction> {
        let mut tx = Transaction::new(
            TransactionType::Unstake,
            self.address(),
            self.address(),
            amount,
            0,
            self.keypair.public_key_hex(),
            None,
        );
        self.sign_transaction(&mut tx)?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_wallet() -> (Wallet, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let wallet = Wallet::new(dir.path().to_path_buf()).expect("new wallet");
        (wallet, dir)
    }

    #[test]
    fn new_wallet_creates_file() {
        let dir = TempDir::new().expect("tempdir");
        let _wallet = Wallet::new(dir.path().to_path_buf()).expect("new");
        assert!(dir.path().join("wallet.json").exists());
    }

    #[test]
    fn load_wallet_roundtrip() {
        let dir = TempDir::new().expect("tempdir");
        let wallet = Wallet::new(dir.path().to_path_buf()).expect("new");
        let original_addr = wallet.address();
        let loaded = Wallet::load(dir.path().to_path_buf()).expect("load");
        assert_eq!(loaded.address(), original_addr);
    }

    #[test]
    fn address_format() {
        let (wallet, _dir) = tmp_wallet();
        let addr = wallet.address();
        assert!(addr.starts_with("KRS1"));
        assert_eq!(addr.len(), 44);
    }

    #[test]
    fn create_transfer_is_signed() {
        let (wallet, _dir) = tmp_wallet();
        let recipient = "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let tx = wallet
            .create_transfer(recipient, 1_000_000, 100)
            .expect("transfer");
        assert!(tx.signature.is_some());
        assert!(tx.verify_signature().is_ok());
    }

    #[test]
    fn create_stake_is_signed() {
        let (wallet, _dir) = tmp_wallet();
        let tx = wallet.create_stake(5_000_000).expect("stake");
        assert!(tx.signature.is_some());
        assert_eq!(tx.tx_type, TransactionType::Stake);
    }

    #[test]
    fn create_unstake_is_signed() {
        let (wallet, _dir) = tmp_wallet();
        let tx = wallet.create_unstake(1_000_000).expect("unstake");
        assert!(tx.signature.is_some());
        assert_eq!(tx.tx_type, TransactionType::Unstake);
    }
}
