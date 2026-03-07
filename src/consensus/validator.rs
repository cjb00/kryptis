/// Validator set management, staking, slashing, and proposer selection.
///
/// The `ValidatorSet` is the authoritative source of truth for which
/// validators are active in the current epoch, what their voting power is,
/// and who should propose the next block.
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::core::{
    crypto::Address,
    error::{KryptisError, KryptisResult},
};

/// Euclidean GCD used to normalise voting powers in proposer selection.
fn gcd(a: u64, b: u64) -> u64 {
    if b == 0 { a } else { gcd(b, a % b) }
}

/// Minimum stake (in base units) required to register as a validator.
/// 10,000 KRS × 1,000,000 base units per KRS.
pub const MIN_VALIDATOR_STAKE: u64 = 10_000 * 1_000_000;

/// Hard cap on the number of active validators per epoch.
pub const MAX_VALIDATORS: usize = 100;

/// Number of blocks in one epoch.  The sequencer rotates once per epoch.
pub const BLOCKS_PER_EPOCH: u64 = 100;

/// Block reward minted to the proposer of each committed block (in base units).
/// 2 KRS × 1,000,000 base units per KRS.
pub const BLOCK_REWARD: u64 = 2 * 1_000_000;

/// Slash amount in basis points for double-signing (5%).
pub const SLASH_DOUBLE_SIGN_BPS: u64 = 500;

/// Slash amount in basis points for extended downtime (1%).
pub const SLASH_DOWNTIME_BPS: u64 = 100;

/// Lifecycle state of a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Selected for the current epoch; participates in consensus.
    Active,
    /// Registered but not yet selected into the active set.
    Pending,
    /// Slashed for misbehaviour; excluded from active set.
    Jailed,
    /// Voluntarily deactivated or dropped from top-N at epoch transition.
    Inactive,
}

/// A single validator's identity, stake, and performance record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// KRS1 address of the validator operator.
    pub address: Address,
    /// Hex-encoded ed25519 public key used to verify block votes.
    pub public_key: String,
    /// Current stake in base units (may decrease via slashing).
    pub stake: u64,
    /// Lifecycle state.
    pub status: ValidatorStatus,
    /// Total blocks proposed by this validator across all epochs.
    pub blocks_proposed: u64,
    /// Commission rate in basis points (e.g. 500 = 5%).
    pub commission_bps: u64,
    /// Human-readable node name.
    pub moniker: Option<String>,
}

impl Validator {
    /// Register a new validator.
    ///
    /// Returns `Err(InsufficientStake)` if `stake` is below [`MIN_VALIDATOR_STAKE`].
    pub fn new(
        address: Address,
        public_key: String,
        stake: u64,
        commission_bps: u64,
        moniker: Option<String>,
    ) -> KryptisResult<Self> {
        if stake < MIN_VALIDATOR_STAKE {
            return Err(KryptisError::InsufficientStake {
                required: MIN_VALIDATOR_STAKE,
                found: stake,
            });
        }
        Ok(Self {
            address,
            public_key,
            stake,
            status: ValidatorStatus::Pending,
            blocks_proposed: 0,
            commission_bps,
            moniker,
        })
    }

    /// Voting power equals stake when Active, otherwise zero.
    ///
    /// This ensures that Jailed and Inactive validators cannot
    /// influence block finality even if their keys are still known.
    pub fn voting_power(&self) -> u64 {
        if self.status == ValidatorStatus::Active {
            self.stake
        } else {
            0
        }
    }
}

/// The set of all registered validators for the current epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// All known validators, keyed by KRS1 address.
    pub validators: HashMap<Address, Validator>,
    /// Current epoch number, incremented at each epoch transition.
    pub epoch: u64,
}

impl ValidatorSet {
    /// Create an empty validator set at epoch 0.
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
            epoch: 0,
        }
    }

    /// Register a new validator.
    ///
    /// Returns `Err(ValidatorAlreadyExists)` if the address is already known.
    pub fn register(&mut self, validator: Validator) -> KryptisResult<()> {
        if self.validators.contains_key(&validator.address) {
            return Err(KryptisError::ValidatorAlreadyExists(validator.address));
        }
        info!(
            address = %validator.address,
            stake = validator.stake,
            "Validator registered"
        );
        self.validators.insert(validator.address.clone(), validator);
        Ok(())
    }

    /// Perform an epoch transition.
    ///
    /// Steps:
    /// 1. Mark all current validators as `Inactive`.
    /// 2. Sort by stake descending.
    /// 3. Reactivate the top `MAX_VALIDATORS` non-Jailed validators.
    /// 4. Increment the epoch counter.
    pub fn transition_epoch(&mut self) {
        // Deactivate all
        for v in self.validators.values_mut() {
            if v.status == ValidatorStatus::Active {
                v.status = ValidatorStatus::Inactive;
            }
        }

        // Collect and sort non-jailed validators by stake descending
        let mut eligible: Vec<Address> = self
            .validators
            .values()
            .filter(|v| v.status != ValidatorStatus::Jailed)
            .map(|v| v.address.clone())
            .collect();
        eligible.sort_by(|a, b| {
            let sa = self.validators[a].stake;
            let sb = self.validators[b].stake;
            sb.cmp(&sa).then(a.cmp(b)) // tie-break alphabetically for determinism
        });

        // Activate top MAX_VALIDATORS
        for addr in eligible.iter().take(MAX_VALIDATORS) {
            if let Some(v) = self.validators.get_mut(addr) {
                v.status = ValidatorStatus::Active;
            }
        }

        self.epoch += 1;
        info!(epoch = self.epoch, "Epoch transition completed");
    }

    /// Select the block proposer for `block_height` using weighted round-robin.
    ///
    /// Algorithm:
    /// 1. Sort active validators by address for determinism.
    /// 2. Normalize voting powers by their GCD so the cycle length equals
    ///    the sum of reduced powers (e.g. two validators with 10K and 20K
    ///    stake normalise to 1 and 2, giving a cycle of 3).
    /// 3. Compute `seed = block_height % total_normalised`.
    /// 4. Walk the sorted list accumulating normalised power; the first
    ///    validator whose cumulative power exceeds `seed` is selected.
    pub fn select_proposer(&self, block_height: u64) -> KryptisResult<&Validator> {
        let total = self.total_voting_power();
        if total == 0 {
            return Err(KryptisError::ConsensusError(
                "no active validators with voting power".into(),
            ));
        }

        // Deterministic order: sort active validators by address
        let mut active: Vec<&Validator> = self
            .validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .collect();
        active.sort_by(|a, b| a.address.cmp(&b.address));

        // Normalise by GCD to keep cycle length manageable
        let gcd = active
            .iter()
            .fold(0u64, |acc, v| gcd(acc, v.voting_power()));
        let divisor = if gcd > 0 { gcd } else { 1 };
        let total_units: u64 = active.iter().map(|v| v.voting_power() / divisor).sum();

        let seed = block_height % total_units;
        let mut cumulative: u64 = 0;
        for v in &active {
            cumulative += v.voting_power() / divisor;
            if cumulative > seed {
                return Ok(v);
            }
        }

        // Fallback: return last (should not be reached with total > 0)
        active
            .last()
            .copied()
            .ok_or_else(|| KryptisError::ConsensusError("proposer selection failed".into()))
    }

    /// Return the sum of voting power across all active validators.
    pub fn total_voting_power(&self) -> u64 {
        self.validators.values().map(|v| v.voting_power()).sum()
    }

    /// Return true if the validators whose addresses are in `signer_addresses`
    /// collectively hold more than 2/3 of total voting power.
    ///
    /// Supermajority condition: `signed_power * 3 > total_power * 2`
    pub fn has_supermajority(&self, signer_addresses: &[String]) -> bool {
        let total = self.total_voting_power();
        if total == 0 {
            return false;
        }
        let signed: u64 = signer_addresses
            .iter()
            .filter_map(|addr| self.validators.get(addr))
            .map(|v| v.voting_power())
            .sum();
        signed * 3 > total * 2
    }

    /// Slash a validator's stake by `slash_bps` basis points and jail them.
    ///
    /// Returns the amount slashed.  The slashed tokens are burned (removed
    /// from the validator's stake without being credited anywhere).
    ///
    /// TODO Phase 3: Credit slashed tokens to the community pool or
    /// redistribute them to the validators who reported the misbehaviour.
    pub fn slash(&mut self, address: &str, slash_bps: u64) -> KryptisResult<u64> {
        let validator = self
            .validators
            .get_mut(address)
            .ok_or_else(|| KryptisError::NotAValidator(address.to_string()))?;

        let slash_amount = validator.stake * slash_bps / 10_000;
        validator.stake = validator.stake.saturating_sub(slash_amount);
        validator.status = ValidatorStatus::Jailed;

        warn!(
            address,
            slash_bps,
            slash_amount,
            remaining_stake = validator.stake,
            "Validator slashed and jailed"
        );
        Ok(slash_amount)
    }

    /// Return all validators with `Active` status.
    pub fn active_validators(&self) -> Vec<&Validator> {
        self.validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .collect()
    }

    /// Look up a validator by KRS1 address.
    pub fn get_validator(&self, address: &str) -> Option<&Validator> {
        self.validators.get(address)
    }
}

impl Default for ValidatorSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(addr: &str, stake: u64) -> Validator {
        Validator::new(
            addr.to_string(),
            "00".repeat(32),
            stake,
            500,
            Some(addr.to_string()),
        )
        .expect("valid validator")
    }

    fn active_validator_set() -> ValidatorSet {
        let mut vs = ValidatorSet::new();
        vs.register(make_validator(
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            MIN_VALIDATOR_STAKE,
        ))
        .expect("register a");
        vs.register(make_validator(
            "KRS1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            MIN_VALIDATOR_STAKE * 2,
        ))
        .expect("register b");
        vs.transition_epoch(); // Activate top validators
        vs
    }

    #[test]
    fn min_stake_enforced() {
        let result = Validator::new(
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "00".repeat(32),
            MIN_VALIDATOR_STAKE - 1,
            0,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn register_and_activate_via_epoch_transition() {
        let vs = active_validator_set();
        assert_eq!(vs.active_validators().len(), 2);
    }

    #[test]
    fn duplicate_registration_fails() {
        let mut vs = ValidatorSet::new();
        let v = make_validator(
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            MIN_VALIDATOR_STAKE,
        );
        vs.register(v.clone()).expect("first");
        assert!(vs.register(v).is_err());
    }

    #[test]
    fn supermajority_60_percent_not_enough() {
        let vs = active_validator_set();
        // Total power = 3 * MIN.  B has 2 * MIN (66.7%) — just barely not enough with integer math.
        // 2/3 check: signed * 3 > total * 2 → 2*MIN*3 > 3*MIN*2 → 6 > 6 → FALSE
        let signers = vec![
            "KRS1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ];
        // B has 2/3 exactly — boundary is exclusive so NOT supermajority
        assert!(!vs.has_supermajority(&signers));
    }

    #[test]
    fn supermajority_80_percent_passes() {
        let mut vs = ValidatorSet::new();
        vs.register(make_validator(
            "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            MIN_VALIDATOR_STAKE,
        ))
        .expect("a");
        vs.register(make_validator(
            "KRS1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            MIN_VALIDATOR_STAKE * 4,
        ))
        .expect("b");
        vs.transition_epoch();
        // B has 4/5 = 80% > 2/3
        let signers = vec![
            "KRS1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ];
        assert!(vs.has_supermajority(&signers));
    }

    #[test]
    fn slash_reduces_stake_and_jails() {
        let mut vs = active_validator_set();
        let addr = "KRS1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let original_stake = vs.get_validator(addr).expect("exists").stake;
        let slashed = vs.slash(addr, SLASH_DOUBLE_SIGN_BPS).expect("slash");
        let validator = vs.get_validator(addr).expect("exists");
        assert_eq!(validator.stake, original_stake - slashed);
        assert_eq!(validator.status, ValidatorStatus::Jailed);
    }

    #[test]
    fn proposer_selection_is_deterministic() {
        let vs = active_validator_set();
        let p1 = vs.select_proposer(42).expect("proposer").address.clone();
        let p2 = vs.select_proposer(42).expect("proposer").address.clone();
        assert_eq!(p1, p2);
    }

    #[test]
    fn proposer_selection_rotates() {
        let vs = active_validator_set();
        // With two validators and different heights we should see both selected
        let mut seen = std::collections::HashSet::new();
        for h in 0..50 {
            let addr = vs.select_proposer(h).expect("proposer").address.clone();
            seen.insert(addr);
        }
        assert_eq!(seen.len(), 2, "Both validators should be selected across 50 heights");
    }

    #[test]
    fn epoch_transition_activates_top_validators() {
        let mut vs = ValidatorSet::new();
        // Register MAX_VALIDATORS + 1 validators; the lowest-stake one should stay Inactive.
        let base_stake = MIN_VALIDATOR_STAKE;
        for i in 0..=(MAX_VALIDATORS as u64) {
            let addr = format!("KRS1{:040}", i);
            vs.register(make_validator(&addr, base_stake + i)).expect("register");
        }
        vs.transition_epoch();
        assert_eq!(vs.active_validators().len(), MAX_VALIDATORS);
    }
}
