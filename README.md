# Kryptis ($KRS)

A modular, from-scratch **Proof of Stake blockchain** written in Rust.

Kryptis implements a structurally correct **Tendermint BFT** consensus protocol with a rotating stake-weighted sequencer, ed25519 cryptography, RocksDB persistence, and a libp2p peer-to-peer network — all in a single self-contained binary (~11 MB release build).

---

## Features

| Area | Detail |
|---|---|
| **Consensus** | Tendermint BFT — Propose → Prevote → Precommit → Commit |
| **Validator selection** | Stake-weighted round-robin, GCD-normalised, deterministic |
| **Cryptography** | ed25519 (dalek) · SHA-256 · double-SHA-256 block headers |
| **Address format** | `KRS1` + hex(SHA-256(pubkey)[0..20]) — 44 chars total |
| **Transactions** | Transfer · Stake · Unstake · Reward (block reward) |
| **Storage** | RocksDB — blocks, chain state, validator set survive restarts |
| **Networking** | libp2p · GossipSub message propagation · mDNS peer discovery · Noise encryption · Yamux multiplexing |
| **Epochs** | 100-block epochs; 2 KRS block reward per committed block |
| **Slashing** | Double-sign 5% · Downtime 1% (basis points) |

---

## Architecture

```
kryptis/
├── src/
│   ├── main.rs                  # Entry point, CLI dispatch, node bootstrap
│   ├── lib.rs                   # Library crate root
│   │
│   ├── core/
│   │   ├── block.rs             # BlockHeader, Block, binary Merkle tree
│   │   ├── chain.rs             # Chain — append, validate, restore from DB
│   │   ├── crypto.rs            # ed25519 Keypair, SHA-256, KRS1 addresses
│   │   ├── error.rs             # KryptisError, KryptisResult
│   │   └── transaction.rs       # Transaction types, signing, verification
│   │
│   ├── consensus/
│   │   ├── engine.rs            # Tendermint BFT state machine
│   │   ├── sequencer.rs         # RotatingSequencer — selects proposer per height
│   │   └── validator.rs         # ValidatorSet, staking, slashing, proposer selection
│   │
│   ├── network/
│   │   ├── node.rs              # libp2p SwarmBuilder, GossipSub, mDNS
│   │   └── messages.rs          # NetworkMessage (block · vote · tx · peer)
│   │
│   ├── storage/
│   │   ├── mod.rs               # Storage trait
│   │   └── rocksdb.rs           # RocksDB implementation
│   │
│   ├── wallet/
│   │   └── mod.rs               # Wallet — load/save, create_transfer/stake/unstake
│   │
│   ├── settlement/              # Phase 3 stub — ZK settlement proof verifier
│   ├── availability/            # Phase 4 stub — data availability layer
│   │
│   └── cli/
│       └── mod.rs               # clap 4 CLI definitions and command handlers
│
└── scripts/
    └── testnet.sh               # 4-node local testnet launcher
```

### Consensus Flow

Each block height runs one or more **rounds**. A round has four steps:

```
┌──────────┐  propose  ┌──────────┐  ≥⅔ prevotes  ┌────────────┐  ≥⅔ precommits  ┌────────┐
│  Propose │ ─────────►│ Prevote  │ ──────────────►│ Precommit  │ ───────────────►│ Commit │
└──────────┘           └──────────┘                └────────────┘                 └────────┘
     │                      │                            │
     └── timeout 3s ────────┴── timeout 2s ─────────────┴── timeout 2s → next round
```

- A **supermajority** is ≥ 2/3 of total weighted voting power.
- A solo validator commits a block every ~3 s via the propose-timeout path.
- The **proposer** is selected by `height % Σ(stake / gcd)` — stakes are normalised so a 2× stake validator is chosen exactly 2× as often.
- The genesis block uses `timestamp = 0` to ensure a stable, deterministic hash across restarts (required for RocksDB chain restoration).

### Storage Layout (RocksDB)

| Key | Value |
|---|---|
| `block:{height}` | JSON-serialised `Block` (header + transactions) |
| `chain:tip` | Current tip height as `u64` |
| `validator_set` | JSON-serialised `ValidatorSet` |

---

## Requirements

- **Rust 1.70+** (`std::io::IsTerminal` is used for TTY-aware log colours)
- **macOS or Linux** (RocksDB links automatically via the `rocksdb` crate)

Install Rust via [rustup](https://rustup.rs):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

---

## Building

```sh
git clone https://github.com/yourname/kryptis
cd kryptis

# Development build
cargo build

# Optimised release build (LTO, single codegen unit — ~11 MB)
cargo build --release
```

Binary: `./target/release/kryptis`

---

## Quick Start — Single Validator Node

```sh
# 1. Generate a wallet (creates ~/.kryptis/wallet.json)
./target/release/kryptis wallet new --data-dir ~/.kryptis

# 2. Start the validator node
./target/release/kryptis node start \
  --data-dir ~/.kryptis \
  --listen-addr /ip4/0.0.0.0/tcp/30333 \
  --validator
```

Expected log output:

```
INFO kryptis_lib::consensus::engine: Proposing block height=1
INFO kryptis_lib::core::chain:       Block committed height=1 hash=4dc864… tx_count=0
INFO kryptis_lib::consensus::engine: Block committed height=1 hash=4dc864… proposer=KRS1a1b2…
INFO kryptis_lib::consensus::engine: Proposing block height=2
…
```

Blocks commit continuously. The node restores its chain from RocksDB on restart, picking up exactly where it left off.

---

## Quick Start — 4-Node Local Testnet

```sh
cargo build --release
bash scripts/testnet.sh
```

The script:
1. Creates isolated data directories under `$TMPDIR/kryptis-testnet-*/`
2. Generates a fresh ed25519 wallet per node
3. Starts 4 validator nodes on ports 30330–30333 (node0 is the bootstrap)
4. Waits 15 seconds for block production
5. Verifies every node has advanced past height 0
6. Cleans up all processes and temp data on exit

Expected output:

```
[testnet] Generating 4 validator wallets…
[testnet]   node0: KRS141e380acb9e2632e55c45edfc6a7fa7fd222f3f6
[testnet]   node1: KRS120cd4df46e63e0922c9ed901ac50089b7c00aff2
[  OK  ] node0 started (PID 1234, port 30330)
[  OK  ] node1 started (PID 1235, port 30331)
[  OK  ] node2 started (PID 1236, port 30332)
[  OK  ] node3 started (PID 1237, port 30333)
[testnet] Waiting 15s for nodes to produce blocks…
[  OK  ] node0: height=685
[  OK  ] node1: height=2965
[  OK  ] node2: height=3327
[  OK  ] node3: height=976
✓ Testnet healthy — all 4 nodes produced blocks.
```

---

## CLI Reference

### `node start`

```sh
kryptis node start [OPTIONS]

Options:
  --data-dir <DIR>          Data directory [default: ~/.kryptis]
  --listen-addr <MULTIADDR> libp2p listen address [default: /ip4/0.0.0.0/tcp/30333]
  --peers <MULTIADDR>...    Bootstrap peer multiaddrs (repeatable)
  --validator               Participate in block production
```

Connect to an existing node:

```sh
kryptis node start \
  --data-dir ~/.kryptis-2 \
  --listen-addr /ip4/0.0.0.0/tcp/30334 \
  --validator \
  --peers /ip4/127.0.0.1/tcp/30333
```

### `wallet`

```sh
# Generate a new ed25519 keypair and save to --data-dir/wallet.json
kryptis wallet new --data-dir ~/.kryptis

# Print the KRS1 address of the wallet in --data-dir
kryptis wallet address --data-dir ~/.kryptis

# Query balance (HTTP RPC — Phase 2)
kryptis wallet balance --address KRS1… --node http://localhost:8080
```

### `tx`

> All amounts are in **base units**. 1 KRS = 1,000,000 base units.

```sh
# Transfer KRS tokens to another address
kryptis tx send \
  --to KRS1recipient… \
  --amount 1000000 \
  --fee 1000 \
  --data-dir ~/.kryptis

# Stake tokens to activate (or increase stake) as a validator
kryptis tx stake --amount 10000000000 --data-dir ~/.kryptis

# Unstake (unbond) tokens from the staking pool
kryptis tx unstake --amount 10000000000 --data-dir ~/.kryptis
```

### `validator`

```sh
# Register as a validator (minimum stake: 10,000 KRS)
kryptis validator register \
  --stake 10000000000 \
  --commission 500 \       # 500 bps = 5%
  --moniker "my-node" \
  --data-dir ~/.kryptis

# List active validators
kryptis validator list

# Show details for a specific validator address
kryptis validator info --address KRS1…
```

### `chain`

```sh
# Print chain tip info
kryptis chain info

# Print block at a specific height
kryptis chain block --height 42
```

---

## Token Economics

| Parameter | Value |
|---|---|
| Ticker | `$KRS` |
| Decimals | 6 (1 KRS = 1,000,000 base units) |
| Address format | `KRS1` + 40 hex chars |
| Block reward | 2 KRS per committed block |
| Epoch length | 100 blocks |
| Minimum validator stake | 10,000 KRS |
| Maximum active validators | 100 |
| Double-sign slash | 5% of stake |
| Downtime slash | 1% of stake |

---

## Development

```sh
# Run all 78 tests
cargo test --all

# Run tests with log output visible
RUST_LOG=debug cargo test --all -- --nocapture

# Lint (zero warnings enforced)
cargo clippy --all-targets -- -D warnings

# Check without building
cargo check
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `RUST_LOG` | `kryptis=info` | Log verbosity — `trace` · `debug` · `info` · `warn` · `error` |
| `KRYPTIS_BIN` | `./target/release/kryptis` | Override binary path in `testnet.sh` |

---

## Roadmap

| Phase | Status | Scope |
|---|---|---|
| **Phase 1** | ✅ Complete | Core chain, Tendermint BFT, RocksDB, P2P networking, CLI |
| **Phase 2** | 🔧 Next | HTTP/JSON-RPC server, mempool, transaction broadcasting, balance queries |
| **Phase 3** | 📋 Planned | Unbonding period (21-day), delegation, governance, ZK settlement proofs |
| **Phase 4** | 📋 Planned | Distributed data availability layer, light clients, IBC bridge |

---

## License

MIT
