/// HTTP JSON-RPC server for the Kryptis blockchain node.
///
/// Provides four read/write endpoints over plain HTTP on port 8080.
/// The server runs as a separate tokio task alongside the consensus
/// engine and P2P node; all state access goes through the shared
/// `Arc<RwLock<…>>` handles.
///
/// Endpoints:
/// - `GET  /status`           → chain height, tip hash, validator count, peer count
/// - `GET  /block/:height`    → full block JSON (404 if not found)
/// - `GET  /balance/:address` → balance, staked, and nonce for a KRS1 address
/// - `POST /tx`               → accept a signed Transaction into the mempool
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::{
    consensus::validator::ValidatorSet,
    core::{chain::Chain, transaction::Transaction},
    storage::Storage,
};

// ─── Shared state ────────────────────────────────────────────────────────────

/// State shared between all RPC handler functions.
pub struct RpcState {
    /// In-memory chain state (read for balance/nonce, write for mempool).
    pub chain: Arc<RwLock<Chain>>,
    /// Current validator set (read for active validator count).
    pub validator_set: Arc<RwLock<ValidatorSet>>,
    /// Persistent storage (read for block queries).
    pub storage: Arc<dyn Storage>,
    /// Live count of connected P2P peers, updated by the P2P event loop.
    pub peer_count: Arc<AtomicUsize>,
}

// ─── Response types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct StatusResponse {
    chain_id: &'static str,
    height: u64,
    tip_hash: String,
    validator_count: usize,
    peer_count: usize,
}

#[derive(Serialize)]
struct BalanceResponse {
    address: String,
    balance: u64,
    staked: u64,
    nonce: u64,
}

#[derive(Serialize)]
struct TxResponse {
    tx_id: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ─── Router ───────────────────────────────────────────────────────────────────

/// Build the axum Router for the RPC server.
pub fn router(state: Arc<RpcState>) -> Router {
    Router::new()
        .route("/status", get(get_status))
        .route("/block/:height", get(get_block))
        .route("/balance/:address", get(get_balance))
        .route("/tx", post(post_tx))
        .with_state(state)
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

/// `GET /status` — chain height, tip hash, validator count, peer count.
async fn get_status(State(state): State<Arc<RpcState>>) -> impl IntoResponse {
    let chain = state.chain.read().await;
    let vs = state.validator_set.read().await;

    let resp = StatusResponse {
        chain_id: "kryptis-1",
        height: chain.height(),
        tip_hash: chain.tip_hash().to_string(),
        validator_count: vs.active_validators().len(),
        peer_count: state.peer_count.load(Ordering::Relaxed),
    };
    Json(resp)
}

/// `GET /block/:height` — full Block JSON or 404.
async fn get_block(
    State(state): State<Arc<RpcState>>,
    Path(height): Path<u64>,
) -> impl IntoResponse {
    match state.storage.get_block_by_height(height) {
        Ok(Some(block)) => Json(block).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("block at height {} not found", height),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}

/// `GET /balance/:address` — spendable balance, staked, and nonce.
async fn get_balance(
    State(state): State<Arc<RpcState>>,
    Path(address): Path<String>,
) -> impl IntoResponse {
    let chain = state.chain.read().await;
    Json(BalanceResponse {
        balance: chain.balance_of(&address),
        staked: chain.staked_of(&address),
        nonce: chain.nonce_of(&address),
        address,
    })
}

/// `POST /tx` — add a signed transaction to the mempool.
///
/// Expects a JSON body matching the `Transaction` struct.
/// Returns `{"tx_id": "…"}` on success or a 400 error body.
async fn post_tx(
    State(state): State<Arc<RpcState>>,
    Json(tx): Json<Transaction>,
) -> impl IntoResponse {
    let tx_id = tx.id.clone();
    let mut chain = state.chain.write().await;
    match chain.add_to_mempool(tx) {
        Ok(()) => Json(TxResponse { tx_id }).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
            .into_response(),
    }
}
