use serde::{Deserialize, Serialize};
use shared::resource::ResourceType;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    #[default]
    Comment,
    ProfileField,
    LegacyProfileField,
}

impl From<ResourceType> for ChallengeType {
    fn from(value: ResourceType) -> Self {
        match value {
            ResourceType::Level => ChallengeType::Comment,
            ResourceType::ProfileField => ChallengeType::ProfileField,
            ResourceType::LegacyProfileField => ChallengeType::LegacyProfileField,
        }
    }
}

impl From<ChallengeType> for ResourceType {
    fn from(value: ChallengeType) -> ResourceType {
        match value {
            ChallengeType::Comment => ResourceType::Level,
            ChallengeType::ProfileField => ResourceType::ProfileField,
            ChallengeType::LegacyProfileField => ResourceType::LegacyProfileField,
        }
    }
}

#[derive(Serialize)]
pub struct ChallengeData {
    pub r#type: ChallengeType,
    /// ID of the target bot account / uploaded level for submitting challenge result
    pub resource_id: i32,
    pub challenge_id: u32,
    pub secret: u32,
}

#[derive(Serialize)]
pub struct CompletedChallengeData {}

// random fun math
fn solve_challenge(secret: u32) -> u32 {
    let mut secret = secret as u64;
    secret = secret.wrapping_mul(0x9e3779b97f4a7c15);
    secret ^= secret >> 27;
    secret = secret.wrapping_mul(0x9e3779b1);
    secret ^= secret >> 31;
    secret as u32
}

fn solve_challenge_legacy(secret: i32) -> i32 {
    secret ^ 0x5F3759DF
}

/// Returns a pair (secret, answer) for an auth challenge
pub fn compute_challenge_pair() -> (u32, u32) {
    let secret = rand::random();
    let answer = solve_challenge(secret);
    (secret, answer)
}

pub fn compute_challenge_pair_legacy() -> (u32, u32) {
    let secret: i32 = rand::random();
    let answer = solve_challenge_legacy(secret);
    (secret as u32, answer as u32)
}
