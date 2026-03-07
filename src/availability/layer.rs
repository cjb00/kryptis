/// Data availability layer integration points for Phase 4.
///
/// This module defines the `DataAvailability` trait that will be
/// implemented by the DAG-based Layer 1 in Phase 4.  For now, an
/// in-memory stub implementation is provided so that the rest of the
/// codebase can compile and test against the interface.
///
/// TODO Phase 4: Replace `InMemoryDA` with a real DAG-based DA layer.
/// The implementation must:
///   - Publish blobs to a peer-to-peer DAG network.
///   - Generate KZG commitments for efficient availability proofs.
///   - Allow validators to verify that data is available without
///     downloading the full blob (data availability sampling).
///   - Interface with the settlement layer to provide `da_commitment`
///     values for `SettlementProof` construction.
use std::{collections::HashMap, sync::Arc};

use chrono::Utc;
use tokio::sync::RwLock;

use crate::core::{
    crypto::{sha256, Address, Hash},
    error::KryptisResult,
};

/// A raw data blob published to the data availability layer.
#[derive(Debug, Clone)]
pub struct DataBlob {
    /// Unique identifier for this blob, derived from its content.
    pub id: Hash,
    /// The raw bytes of the blob.
    pub data: Vec<u8>,
    /// KRS1 address of the node that produced this blob.
    pub producer: Address,
    /// Unix timestamp in milliseconds when the blob was created.
    pub timestamp: i64,
}

/// A commitment proving that a blob has been published to the DA layer.
///
/// In Phase 4 this will be a KZG polynomial commitment that allows
/// light clients to verify availability without downloading the full blob.
#[derive(Debug, Clone)]
pub struct AvailabilityCommitment {
    /// The ID of the blob this commitment covers.
    pub blob_id: Hash,
    /// KZG commitment placeholder.
    ///
    /// TODO Phase 4: Replace with a real KZG commitment computed using
    /// the BLS12-381 curve.  The commitment must allow proofs that any
    /// chunk of the blob is available.
    pub commitment: Hash,
}

/// Interface for the data availability layer (Layer 1).
///
/// # Phase 4 Replacement
/// Implement this trait with the real DAG-based DA layer.  Constraints:
///   - `publish` must be non-blocking; data propagation happens async.
///   - `verify_availability` must use data availability sampling,
///     not full download.
///   - The implementation must handle partial node failures gracefully.
///   - Must be `Send + Sync` for use behind `Arc`.
pub trait DataAvailability: Send + Sync {
    /// Publish a blob to the DA network and return a commitment.
    fn publish(&self, blob: DataBlob) -> KryptisResult<AvailabilityCommitment>;

    /// Retrieve a blob by its ID if it is locally available.
    fn retrieve(&self, blob_id: &Hash) -> KryptisResult<Option<DataBlob>>;

    /// Verify that a blob is available on the network without downloading it.
    fn verify_availability(&self, commitment: &AvailabilityCommitment) -> KryptisResult<bool>;
}

/// In-memory stub implementation of the data availability layer.
///
/// Stores all published blobs in a `HashMap` guarded by a `RwLock`.
/// Used for unit tests and Phase 1+2 integration tests.
pub struct InMemoryDA {
    blobs: Arc<RwLock<HashMap<Hash, DataBlob>>>,
}

impl InMemoryDA {
    /// Create an empty in-memory DA store.
    pub fn new() -> Self {
        Self {
            blobs: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryDA {
    fn default() -> Self {
        Self::new()
    }
}

impl DataAvailability for InMemoryDA {
    fn publish(&self, blob: DataBlob) -> KryptisResult<AvailabilityCommitment> {
        let blob_id = blob.id.clone();
        // Derive a deterministic commitment from the blob contents.
        let commitment = sha256(&blob.data);

        // Use blocking_write for the sync trait method.
        self.blobs.blocking_write().insert(blob_id.clone(), blob);

        Ok(AvailabilityCommitment {
            blob_id,
            commitment,
        })
    }

    fn retrieve(&self, blob_id: &Hash) -> KryptisResult<Option<DataBlob>> {
        Ok(self.blobs.blocking_read().get(blob_id).cloned())
    }

    fn verify_availability(&self, commitment: &AvailabilityCommitment) -> KryptisResult<bool> {
        // Stub: verify by checking if the blob is locally stored.
        // TODO Phase 4: Replace with data availability sampling.
        match self.retrieve(&commitment.blob_id)? {
            Some(blob) => {
                let expected = sha256(&blob.data);
                Ok(expected == commitment.commitment)
            }
            None => Ok(false),
        }
    }
}

/// Construct a `DataBlob` from raw bytes, computing its ID automatically.
pub fn make_blob(data: Vec<u8>, producer: Address) -> DataBlob {
    let id = sha256(&data);
    DataBlob {
        id,
        data,
        producer,
        timestamp: Utc::now().timestamp_millis(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn producer() -> Address {
        "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
    }

    #[test]
    fn publish_and_retrieve() {
        let da = InMemoryDA::new();
        let blob = make_blob(b"hello kryptis".to_vec(), producer());
        let blob_id = blob.id.clone();
        da.publish(blob).expect("publish");
        let retrieved = da.retrieve(&blob_id).expect("retrieve").expect("some");
        assert_eq!(retrieved.data, b"hello kryptis");
    }

    #[test]
    fn retrieve_missing_returns_none() {
        let da = InMemoryDA::new();
        let result = da.retrieve(&"nonexistent".to_string()).expect("ok");
        assert!(result.is_none());
    }

    #[test]
    fn verify_availability_published_blob() {
        let da = InMemoryDA::new();
        let blob = make_blob(b"data".to_vec(), producer());
        let commitment = da.publish(blob).expect("publish");
        assert!(da.verify_availability(&commitment).expect("verify"));
    }

    #[test]
    fn verify_availability_missing_blob() {
        let da = InMemoryDA::new();
        let commitment = AvailabilityCommitment {
            blob_id: "ghost".to_string(),
            commitment: "abc".to_string(),
        };
        assert!(!da.verify_availability(&commitment).expect("verify"));
    }
}
