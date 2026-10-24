use serde::{Deserialize, Serialize};
use shared::resource::ResourceType;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeType {
    #[default]
    Comment,
    ProfileField,
}

impl From<ResourceType> for ChallengeType {
    fn from(value: ResourceType) -> Self {
        match value {
            ResourceType::Level => ChallengeType::Comment,
            ResourceType::ProfileField => ChallengeType::ProfileField,
        }
    }
}

impl From<ChallengeType> for ResourceType {
    fn from(value: ChallengeType) -> ResourceType {
        match value {
            ChallengeType::Comment => ResourceType::Level,
            ChallengeType::ProfileField => ResourceType::ProfileField,
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

/// Returns a pair (secret, answer) for an auth challenge
pub fn compute_challenge_pair() -> (u32, u32) {
    let secret = rand::random();
    let answer = solve_challenge(secret);
    (secret, answer)
}
