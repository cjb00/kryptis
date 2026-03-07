/// Network message types for the Kryptis P2P protocol.
///
/// All variants must be serialisable so they can be transmitted over the
/// libp2p GossipSub transport as JSON-encoded bytes.
use serde::{Deserialize, Serialize};

use crate::{
    consensus::engine::Vote,
    core::{block::Block, transaction::Transaction},
};

/// The union of all message types that can traverse the Kryptis P2P network.
///
/// Each variant maps to a GossipSub topic:
/// - `NewBlock`, `ResponseBlock` → `kryptis/blocks`
/// - `NewTransaction`            → `kryptis/transactions`
/// - `Prevote`, `Precommit`      → `kryptis/votes`
/// - `PeerHello`, `RequestBlock` → any topic (typically `kryptis/blocks`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// A newly proposed or committed block.
    NewBlock(Block),

    /// A pending transaction that should be added to the mempool.
    NewTransaction(Transaction),

    /// A validator's prevote for a block at a given height/round.
    Prevote(Vote),

    /// A validator's precommit for a block at a given height/round.
    Precommit(Vote),

    /// Initial greeting sent when a peer connection is established.
    PeerHello {
        /// The libp2p PeerId string of the greeting node.
        peer_id: String,
        /// The KRS1 address of the node's validator or wallet.
        address: String,
    },

    /// Request a specific block by height from a peer.
    RequestBlock {
        /// The height of the block being requested.
        height: u64,
    },

    /// Response to a `RequestBlock` (may be `None` if not found).
    ResponseBlock(Option<Block>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::block::Block;

    #[test]
    fn serialize_new_block() {
        let block = Block::genesis();
        let msg = NetworkMessage::NewBlock(block.clone());
        let json = serde_json::to_string(&msg).expect("serialize");
        let decoded: NetworkMessage = serde_json::from_str(&json).expect("deserialize");
        if let NetworkMessage::NewBlock(b) = decoded {
            assert_eq!(b.hash, block.hash);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn serialize_peer_hello() {
        let msg = NetworkMessage::PeerHello {
            peer_id: "QmFoo".into(),
            address: "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        };
        let json = serde_json::to_string(&msg).expect("serialize");
        assert!(json.contains("PeerHello"));
    }

    #[test]
    fn serialize_request_block() {
        let msg = NetworkMessage::RequestBlock { height: 42 };
        let json = serde_json::to_string(&msg).expect("serialize");
        let decoded: NetworkMessage = serde_json::from_str(&json).expect("deserialize");
        if let NetworkMessage::RequestBlock { height } = decoded {
            assert_eq!(height, 42);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn serialize_response_block_none() {
        let msg = NetworkMessage::ResponseBlock(None);
        let json = serde_json::to_string(&msg).expect("serialize");
        let decoded: NetworkMessage = serde_json::from_str(&json).expect("deserialize");
        if let NetworkMessage::ResponseBlock(b) = decoded {
            assert!(b.is_none());
        } else {
            panic!("wrong variant");
        }
    }
}
