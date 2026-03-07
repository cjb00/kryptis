/// Command-line interface for the Kryptis blockchain node.
///
/// Uses `clap` 4.0 with derive macros for ergonomic argument parsing.
/// All node, wallet, transaction, validator, and chain commands are
/// implemented here.
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::core::error::{KryptisError, KryptisResult};

// ─── Top-level CLI ─────────────────────────────────────────────────────────

/// Kryptis ($KRS) — Modular Proof of Stake blockchain CLI.
#[derive(Parser)]
#[command(name = "kryptis", version, about)]
pub struct Cli {
    /// The command to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Top-level command groups.
#[derive(Subcommand)]
pub enum Commands {
    /// Node management commands.
    Node {
        #[command(subcommand)]
        subcommand: NodeCommands,
    },
    /// Wallet management commands.
    Wallet {
        #[command(subcommand)]
        subcommand: WalletCommands,
    },
    /// Transaction commands.
    Tx {
        #[command(subcommand)]
        subcommand: TxCommands,
    },
    /// Validator commands.
    Validator {
        #[command(subcommand)]
        subcommand: ValidatorCommands,
    },
    /// Chain information commands.
    Chain {
        #[command(subcommand)]
        subcommand: ChainCommands,
    },
}

// ─── Node commands ──────────────────────────────────────────────────────────

/// Commands for managing the P2P node.
#[derive(Subcommand)]
pub enum NodeCommands {
    /// Start the Kryptis node.
    Start {
        /// Directory for storing blockchain data.
        #[arg(long, default_value = "~/.kryptis")]
        data_dir: PathBuf,
        /// libp2p multiaddr to listen on (e.g. /ip4/0.0.0.0/tcp/30333).
        #[arg(long, default_value = "/ip4/0.0.0.0/tcp/30333")]
        listen_addr: String,
        /// Bootstrap peer multiaddrs. May be repeated: --peers ADDR --peers ADDR2
        #[arg(long, num_args(1..))]
        peers: Vec<String>,
        /// Run as a validator node (participates in block production).
        #[arg(long)]
        validator: bool,
    },
}

// ─── Wallet commands ────────────────────────────────────────────────────────

/// Commands for managing wallets.
#[derive(Subcommand)]
pub enum WalletCommands {
    /// Generate a new wallet keypair.
    New {
        /// Directory to store the wallet file.
        #[arg(long, default_value = "~/.kryptis")]
        data_dir: PathBuf,
    },
    /// Print the KRS1 address of the wallet in --data-dir.
    Address {
        /// Wallet data directory.
        #[arg(long, default_value = "~/.kryptis")]
        data_dir: PathBuf,
    },
    /// Query the balance of an address.
    Balance {
        /// The KRS1 address to query.
        #[arg(long)]
        address: String,
        /// Node RPC URL.
        #[arg(long, default_value = "http://localhost:8080")]
        node: String,
    },
}

// ─── Transaction commands ───────────────────────────────────────────────────

/// Commands for creating and broadcasting transactions.
#[derive(Subcommand)]
pub enum TxCommands {
    /// Send a transfer transaction.
    Send {
        /// Recipient KRS1 address.
        #[arg(long)]
        to: String,
        /// Amount in base units (1 KRS = 1,000,000 base units).
        #[arg(long)]
        amount: u64,
        /// Transaction fee in base units.
        #[arg(long)]
        fee: u64,
        /// Wallet data directory.
        #[arg(long, default_value = "~/.kryptis")]
        data_dir: PathBuf,
    },
    /// Stake tokens to become (or increase stake as) a validator.
    Stake {
        /// Amount to stake in base units.
        #[arg(long)]
        amount: u64,
        /// Wallet data directory.
        #[arg(long, default_value = "~/.kryptis")]
        data_dir: PathBuf,
    },
    /// Unstake (unbond) tokens from the staking pool.
    Unstake {
        /// Amount to unstake in base units.
        #[arg(long)]
        amount: u64,
        /// Wallet data directory.
        #[arg(long, default_value = "~/.kryptis")]
        data_dir: PathBuf,
    },
}

// ─── Validator commands ─────────────────────────────────────────────────────

/// Commands for validator management.
#[derive(Subcommand)]
pub enum ValidatorCommands {
    /// Register as a validator.
    Register {
        /// Amount to stake (must be ≥ 10,000 KRS).
        #[arg(long)]
        stake: u64,
        /// Commission rate in basis points (e.g. 500 = 5%).
        #[arg(long)]
        commission: u16,
        /// Human-readable validator name.
        #[arg(long)]
        moniker: String,
        /// Wallet data directory.
        #[arg(long, default_value = "~/.kryptis")]
        data_dir: PathBuf,
    },
    /// List all active validators.
    List,
    /// Show details for a specific validator.
    Info {
        /// The KRS1 address of the validator.
        #[arg(long)]
        address: String,
    },
}

// ─── Chain commands ─────────────────────────────────────────────────────────

/// Commands for querying chain state.
#[derive(Subcommand)]
pub enum ChainCommands {
    /// Print current chain info (height, tip hash, validator count, etc.).
    Info,
    /// Print details for a specific block.
    Block {
        /// The block height to query.
        #[arg(long)]
        height: u64,
    },
}

// ─── Command handlers ───────────────────────────────────────────────────────

/// Execute a node subcommand.
///
/// The `start` command initialises all subsystems and runs the node
/// indefinitely.  This is handled in `main.rs` rather than here to
/// keep the CLI module free of async runtime logic.
pub fn handle_node_command(cmd: NodeCommands) -> KryptisResult<()> {
    match cmd {
        NodeCommands::Start {
            data_dir,
            listen_addr,
            peers,
            validator,
        } => {
            println!("Starting Kryptis node...");
            println!("  Data dir:    {}", data_dir.display());
            println!("  Listen addr: {}", listen_addr);
            println!("  Peers:       {:?}", peers);
            println!("  Validator:   {}", validator);
            // Actual startup is handled asynchronously in main.rs.
            Err(KryptisError::ConsensusError(
                "Node start must be invoked from main.rs async context".into(),
            ))
        }
    }
}

/// Execute a wallet subcommand.
pub fn handle_wallet_command(cmd: WalletCommands) -> KryptisResult<()> {
    use crate::wallet::Wallet;

    match cmd {
        WalletCommands::New { data_dir } => {
            let dir = expand_tilde(data_dir);
            let wallet = Wallet::new(dir)?;
            println!("New wallet created:");
            println!("  Address:    {}", wallet.address());
            println!("  Public key: {}", wallet.keypair.public_key_hex());
        }
        WalletCommands::Address { data_dir } => {
            let dir = expand_tilde(data_dir);
            let wallet = Wallet::load(dir)?;
            println!("{}", wallet.address());
        }
        WalletCommands::Balance { address, node } => {
            // TODO Phase 2: Make an HTTP request to the node's RPC endpoint.
            // For now, read from the local storage if available.
            println!("Querying balance of {} from {}", address, node);
            println!("  (HTTP RPC not yet implemented — run a node with --validator to check)");
        }
    }
    Ok(())
}

/// Execute a transaction subcommand.
pub fn handle_tx_command(cmd: TxCommands) -> KryptisResult<()> {
    use crate::wallet::Wallet;

    match cmd {
        TxCommands::Send {
            to,
            amount,
            fee,
            data_dir,
        } => {
            let dir = expand_tilde(data_dir);
            let wallet = Wallet::load(dir)?;
            let tx = wallet.create_transfer(to, amount, fee)?;
            println!("Transaction created (broadcast via running node):");
            println!("  ID:     {}", tx.id);
            println!("  From:   {}", tx.from);
            println!("  To:     {}", tx.to);
            println!("  Amount: {} base units", tx.amount);
            println!("  Fee:    {} base units", tx.fee);
            // TODO: Submit to node via RPC
        }
        TxCommands::Stake { amount, data_dir } => {
            let dir = expand_tilde(data_dir);
            let wallet = Wallet::load(dir)?;
            let tx = wallet.create_stake(amount)?;
            println!("Stake transaction created:");
            println!("  ID:     {}", tx.id);
            println!("  Amount: {} base units", tx.amount);
        }
        TxCommands::Unstake { amount, data_dir } => {
            let dir = expand_tilde(data_dir);
            let wallet = Wallet::load(dir)?;
            let tx = wallet.create_unstake(amount)?;
            println!("Unstake transaction created:");
            println!("  ID:     {}", tx.id);
            println!("  Amount: {} base units", tx.amount);
        }
    }
    Ok(())
}

/// Execute a validator subcommand.
pub fn handle_validator_command(cmd: ValidatorCommands) -> KryptisResult<()> {
    use crate::{
        consensus::validator::{Validator, ValidatorSet},
        wallet::Wallet,
    };

    match cmd {
        ValidatorCommands::Register {
            stake,
            commission,
            moniker,
            data_dir,
        } => {
            let dir = expand_tilde(data_dir);
            let wallet = Wallet::load(dir)?;
            let v = Validator::new(
                wallet.address(),
                wallet.keypair.public_key_hex(),
                stake,
                commission as u64,
                Some(moniker),
            )?;
            println!("Validator registered (submit stake transaction to activate):");
            println!("  Address:    {}", v.address);
            println!("  Stake:      {} base units", v.stake);
            println!("  Commission: {} bps", v.commission_bps);
            // TODO: Submit to node via RPC
        }
        ValidatorCommands::List => {
            // TODO Phase 2: Query from node RPC.
            println!("Active validators:");
            println!("  (requires a running node with --validator flag)");
            let vs = ValidatorSet::new();
            if vs.active_validators().is_empty() {
                println!("  No active validators found in local state.");
            }
        }
        ValidatorCommands::Info { address } => {
            println!("Validator info for {}:", address);
            println!("  (requires a running node — RPC not yet implemented)");
        }
    }
    Ok(())
}

/// Execute a chain subcommand.
pub fn handle_chain_command(cmd: ChainCommands) -> KryptisResult<()> {
    match cmd {
        ChainCommands::Info => {
            println!("Chain info:");
            println!("  (requires a running node — reading from local storage)");
            // TODO Phase 2: Read from local RocksDB or node RPC.
        }
        ChainCommands::Block { height } => {
            println!("Block at height {}:", height);
            println!("  (requires a running node — RPC not yet implemented)");
        }
    }
    Ok(())
}

/// Expand a leading `~` in a path to the user's home directory.
fn expand_tilde(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix("~/") {
        let home = std::env::var("HOME").unwrap_or_default();
        PathBuf::from(format!("{}/{}", home, stripped))
    } else if s == "~" {
        PathBuf::from(std::env::var("HOME").unwrap_or_default())
    } else {
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_wallet_new() {
        use clap::Parser;
        let cli = Cli::parse_from(["kryptis", "wallet", "new", "--data-dir", "/tmp/test"]);
        if let Commands::Wallet {
            subcommand: WalletCommands::New { data_dir },
        } = cli.command
        {
            assert_eq!(data_dir, PathBuf::from("/tmp/test"));
        } else {
            panic!("wrong command");
        }
    }

    #[test]
    fn cli_parses_chain_info() {
        use clap::Parser;
        let cli = Cli::parse_from(["kryptis", "chain", "info"]);
        assert!(matches!(
            cli.command,
            Commands::Chain {
                subcommand: ChainCommands::Info
            }
        ));
    }

    #[test]
    fn cli_parses_tx_send() {
        use clap::Parser;
        let cli = Cli::parse_from([
            "kryptis",
            "tx",
            "send",
            "--to",
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--amount",
            "1000000",
            "--fee",
            "100",
        ]);
        if let Commands::Tx {
            subcommand: TxCommands::Send { to, amount, fee, .. },
        } = cli.command
        {
            assert_eq!(to, "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            assert_eq!(amount, 1_000_000);
            assert_eq!(fee, 100);
        } else {
            panic!("wrong command");
        }
    }

    #[test]
    fn expand_tilde_works() {
        let home = std::env::var("HOME").unwrap_or_default();
        let result = expand_tilde(PathBuf::from("~/.kryptis"));
        assert_eq!(result, PathBuf::from(format!("{}/.kryptis", home)));
    }
}
