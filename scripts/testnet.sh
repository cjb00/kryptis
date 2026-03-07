#!/usr/bin/env bash
# ============================================================
# Kryptis ($KRS) — 4-node local testnet launcher
#
# Spins up four validator nodes on localhost, each in its own
# data directory, waits 15 seconds, then checks that every
# node has produced at least one block (height > 0).
#
# Usage:
#   ./scripts/testnet.sh           # run and wait for output
#   KRYPTIS_BIN=./kryptis ./scripts/testnet.sh  # custom binary
#
# Requirements:
#   - cargo build --release (or set KRYPTIS_BIN)
#   - jq (optional – used for pretty-printing status)
# ============================================================

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KRYPTIS_BIN="${KRYPTIS_BIN:-${REPO_ROOT}/target/release/kryptis}"
TESTNET_DIR="${TMPDIR:-/tmp}/kryptis-testnet-$$"
NODE_COUNT=4
BASE_PORT=30330          # nodes listen on 30330, 30331, 30332, 30333
RPC_BASE_PORT=9330       # RPC ports 9330–9333
WAIT_SECS=15
LOG_LEVEL="${RUST_LOG:-info}"

# Colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

pids=()          # child PIDs for cleanup

# ─── Helpers ──────────────────────────────────────────────────
log()  { echo -e "${CYAN}[testnet]${RESET} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${RESET} $*"; }
fail() { echo -e "${RED}[ FAIL ]${RESET} $*" >&2; }
warn() { echo -e "${YELLOW}[ WARN ]${RESET} $*"; }

cleanup() {
    log "Shutting down ${#pids[@]} nodes…"
    for pid in "${pids[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    log "Removing testnet data at ${TESTNET_DIR}"
    rm -rf "${TESTNET_DIR}"
    log "Done."
}
trap cleanup EXIT INT TERM

# ─── Pre-flight checks ────────────────────────────────────────
if [[ ! -x "${KRYPTIS_BIN}" ]]; then
    fail "Binary not found: ${KRYPTIS_BIN}"
    echo  "    Run:  cargo build --release"
    exit 1
fi

log "Binary : ${KRYPTIS_BIN}"
log "Testnet: ${TESTNET_DIR}"
mkdir -p "${TESTNET_DIR}"

# ─── Generate wallets and collect addresses ───────────────────
log "Generating ${NODE_COUNT} validator wallets…"
addresses=()
for i in $(seq 0 $((NODE_COUNT - 1))); do
    NODE_DIR="${TESTNET_DIR}/node${i}"
    mkdir -p "${NODE_DIR}"

    # Generate keypair (kryptis wallet new writes to --data-dir/wallet.json)
    "${KRYPTIS_BIN}" wallet new --data-dir "${NODE_DIR}" \
        2>/dev/null || true

    # Read address from the generated wallet
    addr=$("${KRYPTIS_BIN}" wallet address --data-dir "${NODE_DIR}" \
        2>/dev/null || echo "UNKNOWN")
    addresses+=("${addr}")
    log "  node${i}: ${addr}"
done

# ─── Build bootstrap peer list ────────────────────────────────
# Node 0 is the bootstrap node; all others dial it.
BOOTSTRAP_ADDR="/ip4/127.0.0.1/tcp/${BASE_PORT}"

# ─── Launch nodes ─────────────────────────────────────────────
log "Starting ${NODE_COUNT} nodes…"
for i in $(seq 0 $((NODE_COUNT - 1))); do
    NODE_DIR="${TESTNET_DIR}/node${i}"
    PORT=$((BASE_PORT + i))
    LOG_FILE="${NODE_DIR}/node.log"

    PEERS=""
    if [[ "${i}" -gt 0 ]]; then
        PEERS="--peers ${BOOTSTRAP_ADDR}"
    fi

    RUST_LOG="${LOG_LEVEL}" "${KRYPTIS_BIN}" node start \
        --data-dir    "${NODE_DIR}"          \
        --listen-addr "/ip4/0.0.0.0/tcp/${PORT}" \
        --validator                          \
        ${PEERS}                             \
        > "${LOG_FILE}" 2>&1 &

    pid=$!
    pids+=("${pid}")
    ok "node${i} started (PID ${pid}, port ${PORT})"
done

# ─── Wait for consensus ───────────────────────────────────────
log "Waiting ${WAIT_SECS}s for nodes to produce blocks…"
for s in $(seq "${WAIT_SECS}" -1 1); do
    printf "\r${YELLOW}  %2ds remaining…${RESET}" "${s}"
    sleep 1
done
echo ""

# ─── Verify height > 0 on every node ─────────────────────────
log "Checking block heights…"
all_ok=true
for i in $(seq 0 $((NODE_COUNT - 1))); do
    NODE_DIR="${TESTNET_DIR}/node${i}"
    LOG_FILE="${NODE_DIR}/node.log"

    # Parse the highest "height=" value seen in the log.
    # Uses -oE (extended regex) which works on both macOS and Linux.
    height=$(grep -oE 'height=[0-9]+' "${LOG_FILE}" 2>/dev/null \
             | sed 's/height=//' | sort -n | tail -1 || true)
    height="${height:-0}"

    if [[ "${height}" -gt 0 ]]; then
        ok "node${i}: height=${height}"
    else
        fail "node${i}: height=0 — no blocks produced"
        all_ok=false
        # Print last 20 lines of log for debugging
        warn "=== node${i} log (last 20 lines) ==="
        tail -20 "${LOG_FILE}" >&2 || true
    fi
done

# ─── Final verdict ────────────────────────────────────────────
echo ""
if "${all_ok}"; then
    echo -e "${BOLD}${GREEN}✓ Testnet healthy — all ${NODE_COUNT} nodes produced blocks.${RESET}"
    exit 0
else
    echo -e "${BOLD}${RED}✗ Testnet check failed — one or more nodes did not produce blocks.${RESET}"
    exit 1
fi
