//! Economic Incentives and Tokenomics Module for Symbios Network
//!
//! This module implements the economic model, token distribution, staking,
//! rewards, and incentive mechanisms for the Symbios blockchain network.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::types::{PublicKey, Transaction};

/// Native token of the Symbios network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SYMToken {
    pub total_supply: u64,
    pub circulating_supply: u64,
    pub burned_supply: u64,
    pub precision: u8, // Decimal places
}

/// Economic parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicParameters {
    pub block_reward: u64,           // SYM tokens per block
    pub transaction_fee: u64,        // Base fee per transaction
    pub staking_reward_rate: f64,    // Annual staking reward rate
    pub slashing_penalty: f64,       // Penalty for misbehavior
    pub inflation_rate: f64,         // Annual inflation rate
    pub max_supply: Option<u64>,     // Maximum token supply (deflationary if None)
}

/// Staking pool for validator incentives
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingPool {
    pub pool_id: String,
    pub validator: PublicKey,
    pub total_staked: u64,
    pub delegators: HashMap<PublicKey, u64>, // delegator -> amount
    pub rewards_accumulated: u64,
    pub commission_rate: f64, // Validator's commission (0.0 to 1.0)
    pub active: bool,
}

/// Tokenomics engine managing economic incentives
pub struct TokenomicsEngine {
    token: SYMToken,
    parameters: EconomicParameters,
    staking_pools: HashMap<PublicKey, StakingPool>,
    reward_distribution: RewardDistribution,
    inflation_schedule: Vec<InflationPeriod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDistribution {
    pub validator_rewards: u64,
    pub delegator_rewards: u64,
    pub community_fund: u64,
    pub development_fund: u64,
    pub burned_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InflationPeriod {
    pub start_block: u64,
    pub end_block: u64,
    pub inflation_rate: f64,
    pub target_supply: u64,
}

/// Validator performance metrics for reward calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    pub validator: PublicKey,
    pub blocks_proposed: u64,
    pub blocks_signed: u64,
    pub uptime_percentage: f64,
    pub response_time_ms: u64,
    pub slashing_events: u32,
    pub performance_score: f64, // 0.0 to 1.0
}

impl TokenomicsEngine {
    /// Create new tokenomics engine with default parameters
    pub fn new() -> Self {
        let token = SYMToken {
            total_supply: 1_000_000_000, // 1 billion SYM
            circulating_supply: 200_000_000, // 200 million initially
            burned_supply: 0,
            precision: 9, // 9 decimal places like nano-SYM
        };

        let parameters = EconomicParameters {
            block_reward: 100_000_000, // 100 SYM per block (with 9 decimals)
            transaction_fee: 1_000_000, // 0.001 SYM base fee
            staking_reward_rate: 0.08, // 8% annual staking reward
            slashing_penalty: 0.05, // 5% of stake slashed
            inflation_rate: 0.03, // 3% annual inflation
            max_supply: Some(2_000_000_000), // 2 billion max supply
        };

        let reward_distribution = RewardDistribution {
            validator_rewards: 60, // 60% to validators
            delegator_rewards: 30, // 30% to delegators
            community_fund: 5, // 5% to community
            development_fund: 4, // 4% to development
            burned_tokens: 1, // 1% burned
        };

        // Inflation schedule: reduce inflation every 4 years
        let inflation_schedule = vec![
            InflationPeriod {
                start_block: 0,
                end_block: 1_051_200, // ~4 years at 3s blocks
                inflation_rate: 0.08,
                target_supply: 1_200_000_000,
            },
            InflationPeriod {
                start_block: 1_051_201,
                end_block: 2_102_400, // ~8 years
                inflation_rate: 0.04,
                target_supply: 1_400_000_000,
            },
            InflationPeriod {
                start_block: 2_102_401,
                end_block: 3_153_600, // ~12 years
                inflation_rate: 0.02,
                target_supply: 1_600_000_000,
            },
        ];

        Self {
            token,
            parameters,
            staking_pools: HashMap::new(),
            reward_distribution,
            inflation_schedule,
        }
    }

    /// Calculate block reward for given block height
    pub fn calculate_block_reward(&self, block_height: u64) -> u64 {
        // Find applicable inflation period
        for period in &self.inflation_schedule {
            if block_height >= period.start_block && block_height <= period.end_block {
                return (self.parameters.block_reward as f64 * (1.0 + period.inflation_rate)) as u64;
            }
        }

        // Default to base reward if no period matches
        self.parameters.block_reward
    }

    /// Calculate validator rewards based on performance
    pub fn calculate_validator_rewards(&self, metrics: &ValidatorMetrics, block_height: u64) -> u64 {
        let base_reward = self.calculate_block_reward(block_height);
        let performance_multiplier = metrics.performance_score;

        // Apply slashing penalty
        let slashing_multiplier = if metrics.slashing_events > 0 {
            1.0 - self.parameters.slashing_penalty * metrics.slashing_events as f64
        } else {
            1.0
        };

        let validator_share = (base_reward as f64 * self.reward_distribution.validator_rewards as f64 / 100.0) as u64;

        (validator_share as f64 * performance_multiplier * slashing_multiplier) as u64
    }

    /// Calculate staking rewards for delegators
    pub fn calculate_staking_rewards(&self, stake_amount: u64, lock_period_days: u64) -> u64 {
        let base_annual_reward = (stake_amount as f64 * self.parameters.staking_reward_rate) as u64;

        // Bonus for longer lock periods
        let lock_bonus = match lock_period_days {
            0..=30 => 1.0,      // No bonus
            31..=90 => 1.1,     // 10% bonus
            91..=180 => 1.25,   // 25% bonus
            181..=365 => 1.5,   // 50% bonus
            _ => 2.0,            // 100% bonus for >1 year
        };

        (base_annual_reward as f64 * lock_bonus) as u64
    }

    /// Create new staking pool
    pub fn create_staking_pool(&mut self, validator: PublicKey, commission_rate: f64) -> Result<String, Box<dyn std::error::Error>> {
        if commission_rate < 0.0 || commission_rate > 1.0 {
            return Err("Commission rate must be between 0.0 and 1.0".into());
        }

        let pool_id = format!("pool_{}", validator.as_str());

        let pool = StakingPool {
            pool_id: pool_id.clone(),
            validator: validator.clone(),
            total_staked: 0,
            delegators: HashMap::new(),
            rewards_accumulated: 0,
            commission_rate,
            active: true,
        };

        self.staking_pools.insert(validator, pool);
        Ok(pool_id)
    }

    /// Delegate stake to validator
    pub fn delegate_stake(&mut self, delegator: PublicKey, validator: PublicKey, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(pool) = self.staking_pools.get_mut(&validator) {
            if !pool.active {
                return Err("Staking pool is not active".into());
            }

            *pool.delegators.entry(delegator).or_insert(0) += amount;
            pool.total_staked += amount;
            Ok(())
        } else {
            Err("Staking pool not found".into())
        }
    }

    /// Undelegate stake from validator
    pub fn undelegate_stake(&mut self, delegator: PublicKey, validator: PublicKey, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(pool) = self.staking_pools.get_mut(&validator) {
            if let Some(delegated) = pool.delegators.get_mut(&delegator) {
                if *delegated < amount {
                    return Err("Insufficient delegated stake".into());
                }

                *delegated -= amount;
                pool.total_staked -= amount;

                if *delegated == 0 {
                    pool.delegators.remove(&delegator);
                }

                Ok(())
            } else {
                Err("No stake found for this delegator".into())
            }
        } else {
            Err("Staking pool not found".into())
        }
    }

    /// Distribute rewards to validators and delegators
    pub fn distribute_rewards(&mut self, block_height: u64) -> Result<RewardDistribution, Box<dyn std::error::Error>> {
        let base_reward = self.calculate_block_reward(block_height);
        let mut total_distributed = 0u64;

        // Distribute to validators
        for (validator, pool) in &mut self.staking_pools {
            if pool.active {
                // Calculate validator's share
                let validator_reward = (base_reward as f64 * self.reward_distribution.validator_rewards as f64 / 100.0) as u64;
                let commission = (validator_reward as f64 * pool.commission_rate) as u64;
                let delegator_share = validator_reward - commission;

                // Distribute to delegators
                if pool.total_staked > 0 {
                    for (delegator, stake) in &pool.delegators {
                        let delegator_reward = (delegator_share as f64 * *stake as f64 / pool.total_staked as f64) as u64;
                        // In real implementation, this would create reward transactions
                        total_distributed += delegator_reward;
                    }
                }

                pool.rewards_accumulated += commission;
                total_distributed += commission;
            }
        }

        // Community and development funds
        let community_fund = (base_reward as f64 * self.reward_distribution.community_fund as f64 / 100.0) as u64;
        let development_fund = (base_reward as f64 * self.reward_distribution.development_fund as f64 / 100.0) as u64;
        let burned = (base_reward as f64 * self.reward_distribution.burned_tokens as f64 / 100.0) as u64;

        // Update token supply
        self.token.circulating_supply += total_distributed + community_fund + development_fund;
        self.token.burned_supply += burned;

        Ok(RewardDistribution {
            validator_rewards: total_distributed,
            delegator_rewards: 0, // Would be calculated separately
            community_fund,
            development_fund,
            burned_tokens: burned,
        })
    }

    /// Calculate total value locked (TVL)
    pub fn calculate_tvl(&self) -> u64 {
        self.staking_pools.values()
            .filter(|pool| pool.active)
            .map(|pool| pool.total_staked)
            .sum()
    }

    /// Get staking pool information
    pub fn get_staking_pool(&self, validator: &PublicKey) -> Option<&StakingPool> {
        self.staking_pools.get(validator)
    }

    /// Get all active staking pools
    pub fn get_active_pools(&self) -> Vec<&StakingPool> {
        self.staking_pools.values()
            .filter(|pool| pool.active)
            .collect()
    }

    /// Calculate market cap (simplified)
    pub fn calculate_market_cap(&self, token_price: f64) -> f64 {
        self.token.circulating_supply as f64 * token_price
    }

    /// Generate tokenomics report
    pub fn generate_tokenomics_report(&self) -> String {
        let mut report = String::new();
        report.push_str("# Symbios Network Tokenomics Report\n\n");

        report.push_str("## Token Supply\n\n");
        report.push_str(&format!("- Total Supply: {} SYM\n", self.token.total_supply));
        report.push_str(&format!("- Circulating Supply: {} SYM\n", self.token.circulating_supply));
        report.push_str(&format!("- Burned Supply: {} SYM\n", self.token.burned_supply));
        report.push_str(&format!("- Max Supply: {:?} SYM\n", self.parameters.max_supply));
        report.push_str(&format!("- Precision: {} decimal places\n\n", self.token.precision));

        report.push_str("## Economic Parameters\n\n");
        report.push_str(&format!("- Block Reward: {} SYM\n", self.parameters.block_reward));
        report.push_str(&format!("- Transaction Fee: {} SYM\n", self.parameters.transaction_fee));
        report.push_str(&format!("- Staking Reward Rate: {:.1}%\n", self.parameters.staking_reward_rate * 100.0));
        report.push_str(&format!("- Slashing Penalty: {:.1}%\n", self.parameters.slashing_penalty * 100.0));
        report.push_str(&format!("- Inflation Rate: {:.1}%\n\n", self.parameters.inflation_rate * 100.0));

        report.push_str("## Reward Distribution\n\n");
        report.push_str(&format!("- Validator Rewards: {}%\n", self.reward_distribution.validator_rewards));
        report.push_str(&format!("- Delegator Rewards: {}%\n", self.reward_distribution.delegator_rewards));
        report.push_str(&format!("- Community Fund: {}%\n", self.reward_distribution.community_fund));
        report.push_str(&format!("- Development Fund: {}%\n", self.reward_distribution.development_fund));
        report.push_str(&format!("- Burned Tokens: {}%\n\n", self.reward_distribution.burned_tokens));

        report.push_str("## Staking Pools\n\n");
        report.push_str(&format!("- Active Pools: {}\n", self.staking_pools.values().filter(|p| p.active).count()));
        report.push_str(&format!("- Total Value Locked: {} SYM\n", self.calculate_tvl()));

        for pool in self.get_active_pools() {
            report.push_str(&format!("\n### Pool: {}\n", pool.pool_id));
            report.push_str(&format!("- Validator: {}\n", pool.validator.as_str()));
            report.push_str(&format!("- Total Staked: {} SYM\n", pool.total_staked));
            report.push_str(&format!("- Delegators: {}\n", pool.delegators.len()));
            report.push_str(&format!("- Commission Rate: {:.1}%\n", pool.commission_rate * 100.0));
            report.push_str(&format!("- Accumulated Rewards: {} SYM\n", pool.rewards_accumulated));
        }

        report.push_str("\n## Inflation Schedule\n\n");
        for period in &self.inflation_schedule {
            report.push_str(&format!("- Blocks {}-{}: {:.1}% inflation, target supply: {} SYM\n",
                period.start_block, period.end_block,
                period.inflation_rate * 100.0, period.target_supply));
        }

        report
    }
}

/// Governance system for tokenomics parameters
pub struct GovernanceSystem {
    proposals: HashMap<String, GovernanceProposal>,
    voting_power: HashMap<PublicKey, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub proposer: PublicKey,
    pub changes: ParameterChanges,
    pub voting_start: u64,
    pub voting_end: u64,
    pub status: ProposalStatus,
    pub votes_for: u64,
    pub votes_against: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterChanges {
    UpdateBlockReward(u64),
    UpdateStakingReward(f64),
    UpdateInflationRate(f64),
    UpdateSlashingPenalty(f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalStatus {
    Active,
    Passed,
    Rejected,
    Executed,
}

impl GovernanceSystem {
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            voting_power: HashMap::new(),
        }
    }

    pub fn create_proposal(&mut self, proposal: GovernanceProposal) -> Result<String, Box<dyn std::error::Error>> {
        self.proposals.insert(proposal.id.clone(), proposal.clone());
        Ok(proposal.id)
    }

    pub fn vote(&mut self, proposal_id: &str, voter: PublicKey, approve: bool, voting_power: u64) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            if approve {
                proposal.votes_for += voting_power;
            } else {
                proposal.votes_against += voting_power;
            }
            Ok(())
        } else {
            Err("Proposal not found".into())
        }
    }

    pub fn execute_proposal(&mut self, proposal_id: &str, engine: &mut TokenomicsEngine) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(proposal) = self.proposals.get_mut(proposal_id) {
            if proposal.votes_for > proposal.votes_against {
                match &proposal.changes {
                    ParameterChanges::UpdateBlockReward(new_reward) => {
                        engine.parameters.block_reward = *new_reward;
                    }
                    ParameterChanges::UpdateStakingReward(new_rate) => {
                        engine.parameters.staking_reward_rate = *new_rate;
                    }
                    ParameterChanges::UpdateInflationRate(new_rate) => {
                        engine.parameters.inflation_rate = *new_rate;
                    }
                    ParameterChanges::UpdateSlashingPenalty(new_penalty) => {
                        engine.parameters.slashing_penalty = *new_penalty;
                    }
                }
                proposal.status = ProposalStatus::Executed;
                Ok(())
            } else {
                Err("Proposal did not pass".into())
            }
        } else {
            Err("Proposal not found".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenomics_engine_creation() {
        let engine = TokenomicsEngine::new();
        assert_eq!(engine.token.total_supply, 1_000_000_000);
        assert_eq!(engine.parameters.block_reward, 100_000_000);
    }

    #[test]
    fn test_block_reward_calculation() {
        let engine = TokenomicsEngine::new();

        // Test with first inflation period
        let reward = engine.calculate_block_reward(1000);
        assert!(reward > engine.parameters.block_reward); // Should have inflation bonus
    }

    #[test]
    fn test_staking_pool_creation() {
        let mut engine = TokenomicsEngine::new();
        let validator = crate::types::PublicKey::new("validator1".to_string());

        let result = engine.create_staking_pool(validator.clone(), 0.1);
        assert!(result.is_ok());

        let pool = engine.get_staking_pool(&validator).unwrap();
        assert_eq!(pool.commission_rate, 0.1);
    }

    #[test]
    fn test_stake_delegation() {
        let mut engine = TokenomicsEngine::new();
        let validator = crate::types::PublicKey::new("validator1".to_string());
        let delegator = crate::types::PublicKey::new("delegator1".to_string());

        engine.create_staking_pool(validator.clone(), 0.1).unwrap();
        engine.delegate_stake(delegator.clone(), validator.clone(), 1000).unwrap();

        let pool = engine.get_staking_pool(&validator).unwrap();
        assert_eq!(pool.total_staked, 1000);
        assert_eq!(*pool.delegators.get(&delegator).unwrap(), 1000);
    }

    #[test]
    fn test_staking_rewards_calculation() {
        let engine = TokenomicsEngine::new();

        let rewards_1_month = engine.calculate_staking_rewards(1000, 30);
        let rewards_1_year = engine.calculate_staking_rewards(1000, 365);

        assert!(rewards_1_year > rewards_1_month); // Longer lock = more rewards
    }

    #[test]
    fn test_validator_rewards_calculation() {
        let engine = TokenomicsEngine::new();

        let metrics = ValidatorMetrics {
            validator: crate::types::PublicKey::new("validator1".to_string()),
            blocks_proposed: 100,
            blocks_signed: 100,
            uptime_percentage: 0.99,
            response_time_ms: 500,
            slashing_events: 0,
            performance_score: 0.95,
        };

        let rewards = engine.calculate_validator_rewards(&metrics, 1000);
        assert!(rewards > 0);
    }

    #[test]
    fn test_governance_system() {
        let mut governance = GovernanceSystem::new();

        let proposal = GovernanceProposal {
            id: "test_proposal".to_string(),
            title: "Update Block Reward".to_string(),
            description: "Increase block reward".to_string(),
            proposer: crate::types::PublicKey::new("proposer".to_string()),
            changes: ParameterChanges::UpdateBlockReward(200_000_000),
            voting_start: 0,
            voting_end: 1000,
            status: ProposalStatus::Active,
            votes_for: 0,
            votes_against: 0,
        };

        governance.create_proposal(proposal).unwrap();

        // Vote for the proposal
        let voter = crate::types::PublicKey::new("voter".to_string());
        governance.vote("test_proposal", voter, true, 1000).unwrap();

        // Execute the proposal
        let mut engine = TokenomicsEngine::new();
        let old_reward = engine.parameters.block_reward;
        governance.execute_proposal("test_proposal", &mut engine).unwrap();

        assert!(engine.parameters.block_reward > old_reward);
    }

    #[test]
    fn test_tokenomics_report_generation() {
        let engine = TokenomicsEngine::new();
        let report = engine.generate_tokenomics_report();

        assert!(report.contains("Symbios Network Tokenomics Report"));
        assert!(report.contains("Total Supply"));
        assert!(report.contains("Staking Pools"));
    }
}
