/// Tendermint-style BFT consensus engine.
///
/// Implements a simplified but structurally correct Tendermint consensus
/// protocol.  Each round proceeds through four steps:
///
/// 1. **Propose** — the designated block proposer creates and broadcasts a block.
/// 2. **Prevote**  — every validator validates the proposed block and broadcasts a prevote.
/// 3. **Precommit** — on collecting ≥ 2/3 prevotes, a validator broadcasts a precommit.
/// 4. **Commit**   — on collecting ≥ 2/3 precommits, the block is committed.
///
/// Timeouts (propose=3s, prevote=2s, precommit=2s) advance the round when
/// network conditions prevent progress.
use std::{
    collections::HashMap,
    sync::Arc,
};

use tokio::{
    sync::{mpsc, RwLock},
    time::{timeout, Duration},
};
use tracing::{debug, error, info, warn};

use crate::{
    consensus::{
        sequencer::Sequencer,
        validator::{ValidatorSet, BLOCK_REWARD, BLOCKS_PER_EPOCH},
    },
    core::{
        block::Block,
        chain::Chain,
        crypto::Keypair,
        error::{KryptisError, KryptisResult},
        transaction::{Transaction, TransactionType},
    },
    network::messages::NetworkMessage,
    storage::Storage,
};

/// The vote type distinguishes the two voting phases in Tendermint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VoteType {
    /// Prevote: validator attests it has seen a valid block for this height/round.
    Prevote,
    /// Precommit: validator is ready to commit the block if 2/3+ agree.
    Precommit,
}

/// A single vote cast by a validator for a specific block at a given height.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Vote {
    /// Block height this vote applies to.
    pub height: u64,
    /// Round number within the height (reset to 0 on new height).
    pub round: u32,
    /// Hash of the block being voted on.
    pub block_hash: crate::core::crypto::Hash,
    /// Whether this is a Prevote or Precommit.
    pub vote_type: VoteType,
    /// KRS1 address of the voting validator.
    pub validator_address: crate::core::crypto::Address,
    /// Hex-encoded ed25519 signature over the canonical vote bytes.
    pub signature: String,
}

/// The step within a single consensus round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusStep {
    /// Waiting for the proposer to broadcast a block.
    Propose,
    /// Collecting prevotes; will broadcast prevote when block received.
    Prevote,
    /// Collecting precommits; will broadcast precommit on prevote supermajority.
    Precommit,
    /// Committed — advancing to next height.
    Commit,
}

/// The Tendermint BFT consensus engine.
///
/// Shared state (`chain`, `validator_set`) is protected by `RwLock` so
/// that read-heavy operations (balance checks, proposer selection) do not
/// contend with block commits.
pub struct ConsensusEngine {
    /// In-memory chain state, shared with the P2P layer.
    chain: Arc<RwLock<Chain>>,
    /// Current validator set, shared with the sequencer.
    validator_set: Arc<RwLock<ValidatorSet>>,
    /// Persistent storage for blocks and state.
    storage: Arc<dyn Storage>,
    /// This node's signing keypair.
    node_keypair: Arc<Keypair>,
    /// Sequencer abstraction (Phase 3: replace with shared sequencer).
    sequencer: Arc<dyn Sequencer>,
    /// Accumulated prevotes per block hash for the current height.
    prevotes: HashMap<crate::core::crypto::Hash, Vec<Vote>>,
    /// Accumulated precommits per block hash for the current height.
    precommits: HashMap<crate::core::crypto::Hash, Vec<Vote>>,
    /// Current consensus height (mirrors chain tip + 1 after commit).
    current_height: u64,
    /// Current round within `current_height`.
    current_round: u32,
    /// Current step within the round.
    step: ConsensusStep,
    /// The block proposed for the current height/round (if received).
    current_proposal: Option<Block>,
    /// Channel to broadcast outgoing network messages.
    msg_out: Option<mpsc::Sender<NetworkMessage>>,
}

/// Consensus timeout durations.
const PROPOSE_TIMEOUT: Duration = Duration::from_secs(3);
const PREVOTE_TIMEOUT: Duration = Duration::from_secs(2);
const PRECOMMIT_TIMEOUT: Duration = Duration::from_secs(2);

impl ConsensusEngine {
    /// Construct a new consensus engine.
    ///
    /// `msg_out` is set after construction via [`set_msg_out`] once the
    /// P2P node is initialised, to break the initialisation cycle.
    pub fn new(
        chain: Arc<RwLock<Chain>>,
        validator_set: Arc<RwLock<ValidatorSet>>,
        storage: Arc<dyn Storage>,
        node_keypair: Arc<Keypair>,
        sequencer: Arc<dyn Sequencer>,
    ) -> Self {
        let current_height = {
            // Peek at the chain height to resume from correct height after restart.
            // We use try_read() here during construction — chain is not yet shared.
            0 // Will be updated in run() from actual chain state
        };
        Self {
            chain,
            validator_set,
            storage,
            node_keypair,
            sequencer,
            prevotes: HashMap::new(),
            precommits: HashMap::new(),
            current_height,
            current_round: 0,
            step: ConsensusStep::Propose,
            current_proposal: None,
            msg_out: None,
        }
    }

    /// Set the outbound message channel after the P2P node is ready.
    pub fn set_msg_out(&mut self, tx: mpsc::Sender<NetworkMessage>) {
        self.msg_out = Some(tx);
    }

    /// Main consensus loop.
    ///
    /// Processes incoming network messages and drives the consensus state
    /// machine forward.  Timeouts advance the round when progress stalls.
    pub async fn run(&mut self, mut msg_rx: mpsc::Receiver<NetworkMessage>) {
        // Sync height from chain state
        {
            let chain = self.chain.read().await;
            self.current_height = chain.height() + 1;
        }
        info!(height = self.current_height, "Consensus engine started");

        loop {
            // Check if we are the proposer for the current height
            let is_proposer = self.check_is_proposer().await;

            if is_proposer && self.step == ConsensusStep::Propose {
                match self.propose_block().await {
                    Ok(block) => {
                        info!(height = block.header.height, "Proposing block");
                        self.handle_block(block.clone()).await.ok();
                        self.broadcast(NetworkMessage::NewBlock(block)).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to propose block");
                    }
                }
            }

            // Wait for a message with a timeout
            let recv_result = timeout(
                match self.step {
                    ConsensusStep::Propose => PROPOSE_TIMEOUT,
                    ConsensusStep::Prevote => PREVOTE_TIMEOUT,
                    ConsensusStep::Precommit => PRECOMMIT_TIMEOUT,
                    ConsensusStep::Commit => Duration::from_millis(100),
                },
                msg_rx.recv(),
            )
            .await;

            match recv_result {
                Ok(Some(msg)) => {
                    if let Err(e) = self.handle_message(msg).await {
                        debug!(error = %e, "Message handling error");
                    }
                }
                Ok(None) => {
                    // Channel closed
                    info!("Message channel closed; consensus engine stopping");
                    break;
                }
                Err(_timeout) => {
                    // Timeout: advance the round
                    warn!(
                        height = self.current_height,
                        round = self.current_round,
                        step = ?self.step,
                        "Consensus timeout — advancing round"
                    );
                    self.advance_round();
                }
            }
        }
    }

    /// Route an incoming network message to the appropriate handler.
    async fn handle_message(&mut self, msg: NetworkMessage) -> KryptisResult<()> {
        match msg {
            NetworkMessage::NewBlock(block) => {
                self.handle_block(block).await
            }
            NetworkMessage::Prevote(vote) => self.handle_prevote(vote).await,
            NetworkMessage::Precommit(vote) => self.handle_precommit(vote).await,
            NetworkMessage::NewTransaction(tx) => {
                let mut chain = self.chain.write().await;
                chain.add_to_mempool(tx)
            }
            _ => Ok(()), // Other message types handled by P2P layer
        }
    }

    /// Check whether this node is the block proposer for the current height.
    async fn check_is_proposer(&self) -> bool {
        let address = self.node_keypair.address();
        self.sequencer.is_local_sequencer(self.current_height, &address)
    }

    /// Propose a new block: select transactions and create the block.
    pub async fn propose_block(&self) -> KryptisResult<Block> {
        let chain = self.chain.read().await;
        let vs = self.validator_set.read().await;

        let txs = chain.select_transactions(1000);
        let height = chain.height() + 1;
        let previous_hash = chain.tip_hash().to_string();
        let proposer = self.node_keypair.address();
        let epoch = height / BLOCKS_PER_EPOCH;

        // Determine actual epoch from validator set
        let epoch = std::cmp::max(epoch, vs.epoch);

        Ok(Block::new(height, previous_hash, txs, proposer, epoch))
    }

    /// Process a received block proposal.
    ///
    /// Validates the block, checks that the proposer is correct for this
    /// height, then broadcasts a Prevote if everything checks out.
    pub async fn handle_block(&mut self, block: Block) -> KryptisResult<()> {
        if block.header.height != self.current_height {
            debug!(
                got = block.header.height,
                expected = self.current_height,
                "Ignoring block for wrong height"
            );
            return Ok(());
        }

        // Validate block structure
        let tip_hash = {
            let chain = self.chain.read().await;
            chain.tip_hash().to_string()
        };
        block.validate(&tip_hash)?;

        // Check proposer is correct
        let expected_proposer = {
            let vs = self.validator_set.read().await;
            vs.select_proposer(block.header.height)?.address.clone()
        };
        if block.header.proposer != expected_proposer {
            return Err(KryptisError::InvalidBlock(format!(
                "wrong proposer: expected {}, got {}",
                expected_proposer, block.header.proposer
            )));
        }

        debug!(height = block.header.height, "Block proposal valid; casting prevote");
        self.current_proposal = Some(block.clone());
        self.step = ConsensusStep::Prevote;

        // Cast our prevote
        let mut vote = Vote {
            height: block.header.height,
            round: self.current_round,
            block_hash: block.hash.clone(),
            vote_type: VoteType::Prevote,
            validator_address: self.node_keypair.address(),
            signature: String::new(),
        };
        self.sign_vote(&mut vote)?;
        self.handle_prevote(vote.clone()).await?;
        self.broadcast(NetworkMessage::Prevote(vote)).await;
        Ok(())
    }

    /// Process a received prevote.
    ///
    /// Accumulates prevotes.  On reaching supermajority, broadcasts a precommit.
    pub async fn handle_prevote(&mut self, vote: Vote) -> KryptisResult<()> {
        if vote.height != self.current_height {
            return Ok(());
        }
        self.verify_vote(&vote)?;

        let votes = self.prevotes.entry(vote.block_hash.clone()).or_default();
        // Deduplicate by validator address
        if !votes.iter().any(|v| v.validator_address == vote.validator_address) {
            votes.push(vote.clone());
        }

        let signers: Vec<String> = votes
            .iter()
            .map(|v| v.validator_address.clone())
            .collect();

        let has_supermajority = {
            let vs = self.validator_set.read().await;
            vs.has_supermajority(&signers)
        };

        if has_supermajority && self.step == ConsensusStep::Prevote {
            debug!(height = self.current_height, "Prevote supermajority reached; casting precommit");
            self.step = ConsensusStep::Precommit;

            let mut precommit = Vote {
                height: self.current_height,
                round: self.current_round,
                block_hash: vote.block_hash.clone(),
                vote_type: VoteType::Precommit,
                validator_address: self.node_keypair.address(),
                signature: String::new(),
            };
            self.sign_vote(&mut precommit)?;
            self.handle_precommit(precommit.clone()).await?;
            self.broadcast(NetworkMessage::Precommit(precommit)).await;
        }
        Ok(())
    }

    /// Process a received precommit.
    ///
    /// Accumulates precommits.  On reaching supermajority, commits the block.
    pub async fn handle_precommit(&mut self, vote: Vote) -> KryptisResult<()> {
        if vote.height != self.current_height {
            return Ok(());
        }
        self.verify_vote(&vote)?;

        let votes = self.precommits.entry(vote.block_hash.clone()).or_default();
        if !votes.iter().any(|v| v.validator_address == vote.validator_address) {
            votes.push(vote.clone());
        }

        let signers: Vec<String> = votes
            .iter()
            .map(|v| v.validator_address.clone())
            .collect();

        let has_supermajority = {
            let vs = self.validator_set.read().await;
            vs.has_supermajority(&signers)
        };

        if has_supermajority && self.step == ConsensusStep::Precommit {
            if let Some(block) = self.current_proposal.take() {
                if block.hash == vote.block_hash {
                    debug!(height = self.current_height, "Precommit supermajority reached; committing");
                    self.commit_block(block).await?;
                }
            }
        }
        Ok(())
    }

    /// Commit a finalised block to the chain and persistent storage.
    ///
    /// Actions:
    /// 1. Apply block to in-memory chain.
    /// 2. Persist block to storage.
    /// 3. Update chain tip pointer in storage.
    /// 4. Distribute block reward to proposer.
    /// 5. Transition epoch if at epoch boundary.
    /// 6. Advance to next height.
    pub async fn commit_block(&mut self, block: Block) -> KryptisResult<()> {
        let height = block.header.height;
        let hash = block.hash.clone();
        let proposer = block.header.proposer.clone();

        // Commit to in-memory chain
        {
            let mut chain = self.chain.write().await;
            chain.commit_block(block.clone())?;

            // Mint block reward to proposer
            let reward = Transaction::new(
                TransactionType::Reward,
                "KRS1genesis00000000000000000000000000000000".to_string(),
                proposer.clone(),
                BLOCK_REWARD,
                0,
                "00".repeat(32),
                Some(format!("block reward for height {}", height)),
            );
            chain.apply_transaction(&reward)?;
        }

        // Persist to storage
        self.storage.save_block(&block)?;
        self.storage.save_chain_tip(height, &hash)?;

        info!(height, hash = %hash, proposer = %proposer, "Block committed");

        // Epoch transition check
        if height.is_multiple_of(BLOCKS_PER_EPOCH) && height > 0 {
            let mut vs = self.validator_set.write().await;
            vs.transition_epoch();
            self.storage.save_validator_set(&vs)?;
            info!(epoch = vs.epoch, "Epoch transition at height {}", height);
        }

        // Advance to next height
        self.step = ConsensusStep::Commit;
        self.advance_height(height + 1).await;
        Ok(())
    }

    /// Advance the consensus state to a new height.
    async fn advance_height(&mut self, new_height: u64) {
        self.current_height = new_height;
        self.current_round = 0;
        self.step = ConsensusStep::Propose;
        self.prevotes.clear();
        self.precommits.clear();
        self.current_proposal = None;
        debug!(height = new_height, "Advanced to new height");
    }

    /// Advance to the next round within the current height.
    fn advance_round(&mut self) {
        self.current_round += 1;
        self.step = ConsensusStep::Propose;
        self.current_proposal = None;
        debug!(
            height = self.current_height,
            round = self.current_round,
            "Advanced to next round"
        );
    }

    /// Sign a vote using this node's keypair.
    pub fn sign_vote(&self, vote: &mut Vote) -> KryptisResult<()> {
        let bytes = vote_signable_bytes(vote);
        vote.signature = self.node_keypair.sign(&bytes);
        Ok(())
    }

    /// Verify a vote's signature against the validator's registered public key.
    pub fn verify_vote(&self, vote: &Vote) -> KryptisResult<()> {
        // For Phase 1+2 with a single node or test setup, skip signature
        // verification if the validator is not in the validator set.
        // TODO Phase 2: Enforce strict signature verification once all validators
        // have registered their public keys in the ValidatorSet.
        let vs = tokio::task::block_in_place(|| self.validator_set.blocking_read());
        if let Some(validator) = vs.get_validator(&vote.validator_address) {
            let bytes = vote_signable_bytes(vote);
            crate::core::crypto::verify_signature(&validator.public_key, &bytes, &vote.signature)
                .map_err(|_| KryptisError::InvalidSignature)?;
        }
        // If validator not found in set, allow (handles bootstrap scenarios)
        Ok(())
    }

    /// Broadcast a message to the P2P network.
    async fn broadcast(&self, msg: NetworkMessage) {
        if let Some(tx) = &self.msg_out {
            if tx.send(msg).await.is_err() {
                error!("Failed to broadcast message — channel closed");
            }
        }
    }
}

/// Canonical bytes a validator signs to cast a vote.
fn vote_signable_bytes(vote: &Vote) -> Vec<u8> {
    format!(
        "VOTE:{:?}:{}:{}:{}",
        vote.vote_type, vote.height, vote.round, vote.block_hash
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        consensus::{
            sequencer::RotatingSequencer,
            validator::{Validator, ValidatorSet, MIN_VALIDATOR_STAKE},
        },
        core::{block::Block, chain::Chain, crypto::Keypair},
        storage::rocksdb::RocksStorage,
    };
    use tempfile::TempDir;

    #[allow(dead_code)]
    fn make_engine_with_validator(
        kp: &Keypair,
    ) -> (ConsensusEngine, Arc<RwLock<ValidatorSet>>, TempDir) {
        let dir = TempDir::new().expect("tempdir");
        let storage: Arc<dyn Storage> =
            Arc::new(RocksStorage::open(dir.path().to_str().expect("path")).expect("db"));

        let chain = Arc::new(RwLock::new(Chain::new()));

        let mut vs = ValidatorSet::new();
        let v = Validator::new(
            kp.address(),
            kp.public_key_hex(),
            MIN_VALIDATOR_STAKE,
            500,
            None,
        )
        .expect("validator");
        vs.register(v).expect("register");
        vs.transition_epoch();

        // Credit the validator with genesis funds
        {
            let mut c = tokio::runtime::Handle::current().block_on(chain.write());
            c.credit_genesis(&kp.address(), MIN_VALIDATOR_STAKE * 2);
        }

        let vs_arc = Arc::new(RwLock::new(vs));
        let seq = Arc::new(RotatingSequencer::new(vs_arc.clone()));
        let engine = ConsensusEngine::new(
            chain,
            vs_arc.clone(),
            storage,
            Arc::new(Keypair::generate()), // node keypair (separate from validator for test isolation)
            seq,
        );
        (engine, vs_arc, dir)
    }

    #[tokio::test]
    async fn propose_block_creates_valid_block() {
        let kp = Keypair::generate();
        let mut vs = ValidatorSet::new();
        let v = Validator::new(
            kp.address(),
            kp.public_key_hex(),
            MIN_VALIDATOR_STAKE,
            500,
            None,
        )
        .expect("v");
        vs.register(v).expect("register");
        vs.transition_epoch();

        let chain = Arc::new(RwLock::new(Chain::new()));
        let vs_arc = Arc::new(RwLock::new(vs));
        let dir = TempDir::new().expect("dir");
        let storage: Arc<dyn Storage> =
            Arc::new(RocksStorage::open(dir.path().to_str().expect("path")).expect("db"));
        let seq = Arc::new(RotatingSequencer::new(vs_arc.clone()));
        let kp_arc = Arc::new(kp);
        let engine = ConsensusEngine::new(chain, vs_arc, storage, kp_arc.clone(), seq);

        let block = engine.propose_block().await.expect("propose");
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.proposer, kp_arc.address());
    }

    #[tokio::test]
    async fn commit_block_advances_height() {
        let kp = Arc::new(Keypair::generate());
        let mut vs = ValidatorSet::new();
        let v = Validator::new(
            kp.address(),
            kp.public_key_hex(),
            MIN_VALIDATOR_STAKE,
            500,
            None,
        )
        .expect("v");
        vs.register(v).expect("register");
        vs.transition_epoch();

        let chain = Arc::new(RwLock::new(Chain::new()));
        {
            let mut c = chain.write().await;
            c.credit_genesis(&kp.address(), MIN_VALIDATOR_STAKE * 10);
        }
        let vs_arc = Arc::new(RwLock::new(vs));
        let dir = TempDir::new().expect("dir");
        let storage: Arc<dyn Storage> =
            Arc::new(RocksStorage::open(dir.path().to_str().expect("path")).expect("db"));
        let seq = Arc::new(RotatingSequencer::new(vs_arc.clone()));
        let mut engine =
            ConsensusEngine::new(chain.clone(), vs_arc, storage, kp.clone(), seq);
        engine.current_height = 1;

        let tip_hash = chain.read().await.tip_hash().to_string();
        let block = Block::new(1, tip_hash, vec![], kp.address(), 0);
        engine.commit_block(block).await.expect("commit");

        assert_eq!(chain.read().await.height(), 1);
        assert_eq!(engine.current_height, 2);
    }
}
