/// HTTP JSON-RPC server for the Kryptis blockchain node.
///
/// Provides five read/write endpoints over plain HTTP on port 8080.
/// The server runs as a separate tokio task alongside the consensus
/// engine and P2P node; all state access goes through the shared
/// `Arc<RwLock<…>>` handles.
///
/// Endpoints:
/// - `GET  /status`           → chain height, tip hash, validator count, peer count
/// - `GET  /block/:height`    → full block JSON (404 if not found)
/// - `GET  /balance/:address` → balance, staked, and nonce for a KRS1 address
/// - `POST /tx`               → accept a signed Transaction into the mempool
/// - `POST /settlement`       → submit a ZK settlement proof for an execution domain
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
    settlement::proof::{ProofVerifier, SettlementProof},
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
    /// ZK proof verifier — `StubVerifier` in Phase 1/2, `Risc0Verifier` in Phase 3+.
    pub verifier: Arc<dyn ProofVerifier>,
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
struct SettlementResponse {
    domain_id: u64,
    new_state_root: String,
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
        .route("/settlement", post(post_settlement))
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

/// `POST /settlement` — submit a ZK settlement proof for an execution domain.
///
/// 1. Looks up the current `DomainState` for `proof.domain_id`.
/// 2. Verifies the proof via the injected `ProofVerifier`.
/// 3. Updates the on-chain `DomainState` to `proof.new_state_root`.
///
/// Returns 400 if the domain is not registered or the proof is invalid.
/// Returns 200 with the updated domain info on success.
async fn post_settlement(
    State(state): State<Arc<RpcState>>,
    Json(proof): Json<SettlementProof>,
) -> impl IntoResponse {
    let domain = {
        let chain = state.chain.read().await;
        match chain.domain_states.get(&proof.domain_id) {
            Some(d) => d.clone(),
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse {
                        error: format!("domain {} not registered", proof.domain_id),
                    }),
                )
                    .into_response();
            }
        }
    };

    if let Err(e) = state.verifier.verify(&proof, &domain) {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("proof verification failed: {e}"),
            }),
        )
            .into_response();
    }

    let mut chain = state.chain.write().await;
    match chain.update_domain_state(&proof) {
        Ok(()) => Json(SettlementResponse {
            domain_id: proof.domain_id,
            new_state_root: proof.new_state_root,
        })
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
