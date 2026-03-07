//! Kryptis ($KRS) — Modular Proof of Stake blockchain library.
//!
//! This crate provides all the components of the Kryptis base chain:
//!
//! - [`core`] — fundamental data structures (blocks, transactions, crypto)
//! - [`consensus`] — Tendermint BFT engine, validator set, sequencer
//! - [`storage`] — persistent storage trait and RocksDB implementation
//! - [`network`] — libp2p P2P networking
//! - [`settlement`] — ZK proof verification stubs (Phase 3)
//! - [`availability`] — data availability layer stubs (Phase 4)
//! - [`wallet`] — keypair management and transaction signing
//! - [`cli`] — command-line interface

pub mod availability;
pub mod cli;
pub mod consensus;
pub mod core;
pub mod network;
pub mod settlement;
pub mod storage;
pub mod wallet;
