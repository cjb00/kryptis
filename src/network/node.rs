/// libp2p P2P node for the Kryptis blockchain network.
///
/// Uses TCP + Noise encryption + Yamux multiplexing for transport,
/// GossipSub for message propagation, and mDNS for local peer discovery.
///
/// Design note: gossipsub and mDNS behaviours are pre-built before the
/// `SwarmBuilder::with_behaviour` call (which requires an infallible
/// closure in libp2p 0.52+) so that errors can be propagated via
/// `KryptisResult` before the swarm is constructed.
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use futures::StreamExt;
use libp2p::{
    gossipsub, identity, mdns, noise, tcp, yamux, Multiaddr, Swarm, SwarmBuilder,
};
use libp2p::swarm::NetworkBehaviour;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::{
    core::{
        crypto::Keypair,
        error::{KryptisError, KryptisResult},
    },
    network::messages::NetworkMessage,
};

/// Configuration for the P2P node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Multiaddr to listen on (e.g. `/ip4/0.0.0.0/tcp/30333`).
    pub listen_addr: String,
    /// Bootstrap peer multiaddrs to dial on startup.
    pub bootstrap_peers: Vec<String>,
    /// Maximum number of connected peers.
    pub max_peers: usize,
    /// Directory for storing peer data.
    pub data_dir: PathBuf,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/30333".to_string(),
            bootstrap_peers: vec![],
            max_peers: 50,
            data_dir: PathBuf::from(
                std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()),
            )
            .join(".kryptis"),
        }
    }
}

/// The combined libp2p behaviour for Kryptis.
///
/// `#[derive(NetworkBehaviour)]` auto-generates `KryptisBehaviourEvent`
/// with one variant per field.
#[derive(NetworkBehaviour)]
struct KryptisBehaviour {
    /// GossipSub for pub/sub message propagation.
    gossipsub: gossipsub::Behaviour,
    /// mDNS for automatic local network peer discovery.
    mdns: mdns::tokio::Behaviour,
}

/// The Kryptis P2P node.
///
/// Call [`outbound_sender`] to get a broadcast handle before calling
/// [`start`] (which consumes the node).
pub struct P2PNode {
    /// The libp2p swarm.
    swarm: Swarm<KryptisBehaviour>,
    /// Sender for pushing messages to the broadcast queue.
    outbound_tx: mpsc::Sender<NetworkMessage>,
    /// Receiver used inside the event loop.
    outbound_rx: mpsc::Receiver<NetworkMessage>,
    /// GossipSub topic for block messages.
    blocks_topic: gossipsub::IdentTopic,
    /// GossipSub topic for transaction messages.
    txs_topic: gossipsub::IdentTopic,
    /// GossipSub topic for consensus vote messages.
    votes_topic: gossipsub::IdentTopic,
    /// GossipSub topic for validator announcements.
    validators_topic: gossipsub::IdentTopic,
    /// Live count of connected peers, shared with the RPC layer.
    peer_count: Arc<AtomicUsize>,
}

impl P2PNode {
    /// Construct a new P2P node from the given keypair and configuration.
    pub async fn new(keypair: &Keypair, config: NodeConfig) -> KryptisResult<Self> {
        // Derive a libp2p identity key from our ed25519 signing key.
        let mut secret_bytes = keypair.signing_key.to_bytes();
        let secret = identity::ed25519::SecretKey::try_from_bytes(&mut secret_bytes)
            .map_err(|e| KryptisError::KeyGenerationFailed(e.to_string()))?;
        let ed25519_kp = identity::ed25519::Keypair::from(secret);
        let libp2p_kp = identity::Keypair::from(ed25519_kp);

        // Define GossipSub topics.
        let blocks_topic = gossipsub::IdentTopic::new("kryptis/blocks");
        let txs_topic = gossipsub::IdentTopic::new("kryptis/transactions");
        let votes_topic = gossipsub::IdentTopic::new("kryptis/votes");
        let validators_topic = gossipsub::IdentTopic::new("kryptis/validators");

        // Pre-build gossipsub (infallible closure required by libp2p 0.52+).
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(1))
            .build()
            .map_err(|e| KryptisError::NetworkError(e.to_string()))?;

        let gossipsub_kp = libp2p_kp.clone();
        let mut gossipsub_behaviour = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(gossipsub_kp),
            gossipsub_config,
        )
        .map_err(|e| KryptisError::NetworkError(e.to_string()))?;

        // Subscribe before the swarm is built.
        gossipsub_behaviour
            .subscribe(&blocks_topic)
            .map_err(|e| KryptisError::NetworkError(e.to_string()))?;
        gossipsub_behaviour
            .subscribe(&txs_topic)
            .map_err(|e| KryptisError::NetworkError(e.to_string()))?;
        gossipsub_behaviour
            .subscribe(&votes_topic)
            .map_err(|e| KryptisError::NetworkError(e.to_string()))?;
        gossipsub_behaviour
            .subscribe(&validators_topic)
            .map_err(|e| KryptisError::NetworkError(e.to_string()))?;

        // Pre-build mDNS.
        let local_peer_id = libp2p_kp.public().to_peer_id();
        let mdns_behaviour = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
            .map_err(|e| KryptisError::NetworkError(e.to_string()))?;

        let behaviour = KryptisBehaviour {
            gossipsub: gossipsub_behaviour,
            mdns: mdns_behaviour,
        };

        // Build the swarm with an infallible closure (libp2p 0.52+ requirement).
        let mut swarm = SwarmBuilder::with_existing_identity(libp2p_kp)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| KryptisError::NetworkError(e.to_string()))?
            .with_behaviour(|_key| behaviour)
            .expect("infallible: KryptisBehaviour construction cannot fail")
            .build();

        // Start listening.
        let listen_addr: Multiaddr = config
            .listen_addr
            .parse()
            .map_err(|e: libp2p::multiaddr::Error| {
                KryptisError::NetworkError(format!("invalid listen addr: {}", e))
            })?;
        swarm
            .listen_on(listen_addr)
            .map_err(|e| KryptisError::NetworkError(e.to_string()))?;

        // Dial bootstrap peers.
        for peer_addr in &config.bootstrap_peers {
            match peer_addr.parse::<Multiaddr>() {
                Ok(addr) => {
                    if let Err(e) = swarm.dial(addr) {
                        warn!(addr = %peer_addr, error = %e, "Failed to dial bootstrap peer");
                    }
                }
                Err(e) => {
                    warn!(addr = %peer_addr, error = %e, "Invalid bootstrap peer address");
                }
            }
        }

        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        Ok(Self {
            swarm,
            outbound_tx,
            outbound_rx,
            blocks_topic,
            txs_topic,
            votes_topic,
            validators_topic,
            peer_count: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Return a sender for pushing messages out to the P2P network.
    ///
    /// Must be called before [`start`] since `start` consumes `self`.
    pub fn outbound_sender(&self) -> mpsc::Sender<NetworkMessage> {
        self.outbound_tx.clone()
    }

    /// Return a shared handle to the live peer count (updated by the event loop).
    pub fn peer_count_handle(&self) -> Arc<AtomicUsize> {
        self.peer_count.clone()
    }

    /// Connect to a peer by multiaddr.
    pub fn connect_peer(&mut self, addr: &str) -> KryptisResult<()> {
        let multiaddr: Multiaddr =
            addr.parse()
                .map_err(|e: libp2p::multiaddr::Error| {
                    KryptisError::NetworkError(format!("invalid multiaddr: {}", e))
                })?;
        self.swarm
            .dial(multiaddr)
            .map_err(|e| KryptisError::NetworkError(e.to_string()))
    }

    /// Start the P2P event loop (consumes the node).
    ///
    /// Incoming network messages are routed to `inbound_tx` for the
    /// consensus engine.  Outbound messages are sent via the channel
    /// returned by [`outbound_sender`].
    pub async fn start(mut self, inbound_tx: mpsc::Sender<NetworkMessage>) {
        info!("P2P node event loop started");

        let blocks_topic = self.blocks_topic.clone();
        let txs_topic = self.txs_topic.clone();
        let votes_topic = self.votes_topic.clone();
        let validators_topic = self.validators_topic.clone();
        let peer_count = self.peer_count.clone();

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    match event {
                        libp2p::swarm::SwarmEvent::Behaviour(KryptisBehaviourEvent::Gossipsub(
                            gossipsub::Event::Message {
                                propagation_source: _,
                                message_id: _,
                                message,
                            },
                        )) => {
                            match serde_json::from_slice::<NetworkMessage>(&message.data) {
                                Ok(msg) => {
                                    debug!("Received network message");
                                    if inbound_tx.send(msg).await.is_err() {
                                        error!("Inbound message channel closed");
                                        break;
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "Failed to deserialise network message");
                                }
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(KryptisBehaviourEvent::Mdns(
                            mdns::Event::Discovered(peers),
                        )) => {
                            for (peer_id, addr) in peers {
                                info!(peer = %peer_id, addr = %addr, "mDNS: peer discovered");
                                self.swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .add_explicit_peer(&peer_id);
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(KryptisBehaviourEvent::Mdns(
                            mdns::Event::Expired(expired),
                        )) => {
                            for (peer_id, _addr) in expired {
                                debug!(peer = %peer_id, "mDNS: peer expired");
                                self.swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .remove_explicit_peer(&peer_id);
                            }
                        }
                        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                            info!(addr = %address, "P2P node listening");
                        }
                        libp2p::swarm::SwarmEvent::ConnectionEstablished {
                            peer_id, ..
                        } => {
                            info!(peer = %peer_id, "Peer connected");
                            // Add to GossipSub mesh so messages flow to this peer.
                            // (mDNS peers go through add_explicit_peer in the mDNS
                            // Discovered handler; bootstrap peers dialled via --peers
                            // only trigger ConnectionEstablished, not mDNS.)
                            self.swarm
                                .behaviour_mut()
                                .gossipsub
                                .add_explicit_peer(&peer_id);
                            peer_count.fetch_add(1, Ordering::Relaxed);
                        }
                        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, .. } => {
                            debug!(peer = %peer_id, "Peer disconnected");
                            peer_count.fetch_sub(1, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }

                Some(msg) = self.outbound_rx.recv() => {
                    let topic = match &msg {
                        NetworkMessage::NewBlock(_)
                        | NetworkMessage::ResponseBlock(_)
                        | NetworkMessage::RequestBlock { .. } => blocks_topic.clone(),
                        NetworkMessage::NewTransaction(_) => txs_topic.clone(),
                        NetworkMessage::Prevote(_)
                        | NetworkMessage::Precommit(_) => votes_topic.clone(),
                        NetworkMessage::ValidatorAnnounce(_)
                        | NetworkMessage::PeerHello { .. } => validators_topic.clone(),
                    };

                    match serde_json::to_vec(&msg) {
                        Ok(data) => {
                            if let Err(e) =
                                self.swarm.behaviour_mut().gossipsub.publish(topic, data)
                            {
                                debug!(error = %e, "GossipSub publish (may be no peers yet)");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to serialise outbound message");
                        }
                    }
                }
            }
        }
    }

    /// Broadcast a message via the internal channel.
    pub async fn broadcast(&self, message: NetworkMessage) -> KryptisResult<()> {
        self.outbound_tx
            .send(message)
            .await
            .map_err(|e| KryptisError::NetworkError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_config_defaults() {
        let config = NodeConfig::default();
        assert_eq!(config.listen_addr, "/ip4/0.0.0.0/tcp/30333");
        assert_eq!(config.max_peers, 50);
        assert!(config.bootstrap_peers.is_empty());
    }

    #[test]
    fn network_message_serialization_roundtrip() {
        use crate::core::block::Block;
        let block = Block::genesis();
        let msg = NetworkMessage::NewBlock(block.clone());
        let json = serde_json::to_vec(&msg).expect("serialize");
        let decoded: NetworkMessage = serde_json::from_slice(&json).expect("deserialize");
        if let NetworkMessage::NewBlock(b) = decoded {
            assert_eq!(b.hash, block.hash);
        } else {
            panic!("wrong variant");
        }
    }
}
