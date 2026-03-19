/// Kryptis ($KRS) — Modular Proof of Stake blockchain node entry point.
///
/// Parses CLI arguments, initialises `tracing-subscriber` with an
/// `env-filter` (set `RUST_LOG=kryptis=info` to control verbosity),
/// and dispatches to the appropriate command handler.
///
/// For `node start`, all subsystems are initialised and run as concurrent
/// tokio tasks:
///  - Consensus engine (Tendermint BFT)
///  - P2P node (libp2p GossipSub + mDNS)
///  - (Future) RPC server
use std::{io::IsTerminal as _, path::PathBuf, sync::Arc};

use clap::Parser;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info};

use kryptis_lib::{
    cli::{
        handle_chain_command, handle_tx_command, handle_validator_command,
        handle_wallet_command, Cli, Commands, NodeCommands,
    },
    consensus::{
        engine::ConsensusEngine,
        sequencer::RotatingSequencer,
        validator::{ValidatorSet, MIN_VALIDATOR_STAKE},
    },
    core::{
        chain::Chain,
        crypto::Keypair,
    },
    network::{messages::NetworkMessage, node::{NodeConfig, P2PNode}},
    rpc::RpcState,
    storage::{rocksdb::RocksStorage, Storage},
    wallet::Wallet,
};

#[tokio::main]
async fn main() {
    // Initialise structured logging.  Use RUST_LOG to control verbosity.
    // Disable ANSI colour codes when stderr is not a real terminal (e.g. when
    // redirected to a log file in the testnet script).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kryptis=info".parse().expect("valid filter")),
        )
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let cli = Cli::parse();

    let result = dispatch(cli).await;
    if let Err(e) = result {
        error!(error = %e, "Command failed");
        std::process::exit(1);
    }
}

/// Dispatch a parsed CLI command to the appropriate handler.
async fn dispatch(cli: Cli) -> kryptis_lib::core::error::KryptisResult<()> {
    match cli.command {
        Commands::Node { subcommand } => match subcommand {
            NodeCommands::Start {
                data_dir,
                listen_addr,
                peers,
                validator,
            } => {
                start_node(data_dir, listen_addr, peers, validator).await?;
            }
        },
        Commands::Wallet { subcommand } => {
            handle_wallet_command(subcommand)?;
        }
        Commands::Tx { subcommand } => {
            handle_tx_command(subcommand)?;
        }
        Commands::Validator { subcommand } => {
            handle_validator_command(subcommand)?;
        }
        Commands::Chain { subcommand } => {
            handle_chain_command(subcommand)?;
        }
    }
    Ok(())
}

/// Start a full Kryptis node with all subsystems.
///
/// Initialises:
/// 1. Persistent storage (RocksDB)
/// 2. In-memory chain state (restored from storage if available)
/// 3. Validator set (restored from storage if available)
/// 4. Wallet / node keypair
/// 5. Consensus engine (Tendermint BFT)
/// 6. P2P node (libp2p)
///
/// All components are wired together via tokio channels and spawned as
/// concurrent tasks.
async fn start_node(
    data_dir: PathBuf,
    listen_addr: String,
    bootstrap_peers: Vec<String>,
    is_validator: bool,
) -> kryptis_lib::core::error::KryptisResult<()> {
    info!(
        data_dir = %data_dir.display(),
        listen_addr = %listen_addr,
        is_validator,
        "Starting Kryptis node"
    );

    // Expand tilde in data_dir
    let data_dir = expand_tilde(data_dir);

    // Ensure data directory exists
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| kryptis_lib::core::error::KryptisError::StorageError(e.to_string()))?;

    // 1. Storage
    let storage_path = data_dir.join("chain.db");
    let storage = Arc::new(
        RocksStorage::open(storage_path.to_str().unwrap_or("chain.db"))?,
    );

    // 2. Chain state
    let chain = Arc::new(RwLock::new(Chain::new()));

    // Restore from storage if available
    if let Some((tip_height, _tip_hash)) = storage.get_chain_tip()? {
        let mut chain_write = chain.write().await;
        let mut restored = 0u64;
        for h in 1..=tip_height {
            if let Some(block) = storage.get_block_by_height(h)? {
                if chain_write.commit_block(block).is_ok() {
                    restored += 1;
                } else {
                    tracing::warn!(height = h, "Block failed validation during restore — stopping early");
                    break;
                }
            }
        }
        let actual_height = chain_write.height();
        if restored == tip_height {
            info!(height = actual_height, "Chain restored from storage");
        } else {
            tracing::warn!(
                stored_tip = tip_height,
                restored,
                actual_height,
                "Chain restore incomplete — stored data may be incompatible with this binary"
            );
        }
    }

    // 3. Validator set
    let validator_set = if let Some(vs) = storage.get_validator_set()? {
        info!(epoch = vs.epoch, "Validator set restored from storage");
        Arc::new(RwLock::new(vs))
    } else {
        Arc::new(RwLock::new(ValidatorSet::new()))
    };

    // 4. Wallet / node keypair
    let wallet = if data_dir.join("wallet.json").exists() {
        Wallet::load(data_dir.clone())?
    } else {
        info!("No wallet found — generating new keypair");
        Wallet::new(data_dir.clone())?
    };
    let node_keypair = Arc::new(Keypair::load_from_file(&data_dir.join("wallet.json"))?);

    info!(address = %wallet.address(), "Node identity loaded");

    if is_validator {
        let mut vs: tokio::sync::RwLockWriteGuard<ValidatorSet> = validator_set.write().await;

        // If the restored validator set has active validators but none of them
        // is our current key (e.g. wallet was regenerated), the old set is
        // permanently stale — reset it so this node can produce blocks solo.
        let has_active = !vs.active_validators().is_empty();
        let we_are_in = vs.get_validator(&wallet.address()).is_some();
        if has_active && !we_are_in {
            tracing::warn!(
                "Restored validator set does not contain our address \
                 (wallet may have been regenerated) — resetting to current key only"
            );
            *vs = ValidatorSet::new();
        }

        // Register validator in the set if not already present
        if vs.get_validator(&wallet.address()).is_none() {
            let v = kryptis_lib::consensus::validator::Validator::new(
                wallet.address(),
                wallet.keypair.public_key_hex(),
                MIN_VALIDATOR_STAKE,
                500,
                Some("local-validator".to_string()),
            );
            match v {
                Ok(validator) => {
                    vs.register(validator).ok();
                    vs.transition_epoch();
                    storage.save_validator_set(&vs)?;
                    info!("Registered as validator");
                }
                Err(e) => {
                    info!(error = %e, "Could not auto-register as validator (insufficient stake)");
                }
            }
        }
    }

    // 5. Sequencer
    let sequencer = Arc::new(RotatingSequencer::new(validator_set.clone()));

    // 6. Message channels
    let (consensus_tx, consensus_rx) = mpsc::channel::<NetworkMessage>(1024);

    // 7. Consensus engine
    let mut engine = ConsensusEngine::new(
        chain.clone(),
        validator_set.clone(),
        storage.clone() as Arc<dyn kryptis_lib::storage::Storage>,
        node_keypair.clone(),
        sequencer,
    );

    // 8. P2P node
    let p2p_config = NodeConfig {
        listen_addr,
        bootstrap_peers,
        max_peers: 50,
        data_dir: data_dir.clone(),
    };

    let p2p_node = P2PNode::new(&wallet.keypair, p2p_config).await?;
    let outbound_tx = p2p_node.outbound_sender();
    let peer_count = p2p_node.peer_count_handle();

    // Wire consensus engine to broadcast via P2P
    engine.set_msg_out(outbound_tx.clone());

    // 9. Initial ValidatorAnnounce — broadcast 2 s after startup so peers
    //    have time to connect before the first announcement.
    if is_validator {
        let local_validator = {
            let vs = validator_set.read().await;
            vs.get_validator(&wallet.address()).cloned()
        };
        if let Some(v) = local_validator {
            let announce_tx = outbound_tx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                announce_tx.send(NetworkMessage::ValidatorAnnounce(v)).await.ok();
            });
        }
    }

    // 10. HTTP RPC server (port 8080)
    let rpc_state = Arc::new(RpcState {
        chain: chain.clone(),
        validator_set: validator_set.clone(),
        storage: storage.clone() as Arc<dyn kryptis_lib::storage::Storage>,
        peer_count,
    });
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
            .await
            .expect("RPC listener bind failed");
        info!("HTTP RPC server listening on http://0.0.0.0:8080");
        axum::serve(listener, kryptis_lib::rpc::router(rpc_state))
            .await
            .expect("RPC server error");
    });

    // 11. Spawn P2P and consensus tasks
    let consensus_tx_clone = consensus_tx.clone();
    let p2p_handle = tokio::spawn(async move {
        p2p_node.start(consensus_tx_clone).await;
    });

    let consensus_handle = tokio::spawn(async move {
        engine.run(consensus_rx).await;
    });

    info!("All subsystems started. Node is running.");
    println!("Kryptis node is running");
    println!("Node address:  {}", wallet.address());
    println!("RPC endpoint:  http://localhost:8080");
    println!("Press Ctrl+C to stop.");

    // Wait for shutdown
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| kryptis_lib::core::error::KryptisError::NetworkError(e.to_string()))?;

    info!("Shutdown signal received");
    p2p_handle.abort();
    consensus_handle.abort();

    Ok(())
}

/// Expand a leading `~` to the user's home directory.
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
