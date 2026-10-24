use serde::{Deserialize, Serialize};

use crate::resource::ResourceKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GDAccountData {
    pub account_id: i32,
    pub user_id: i32,
    pub username: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct UserChallenge {
    pub resource: ResourceKey,
    pub challenge_id: u32,
    pub account_id: i32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UserChallengeOutcome {
    Success,
    ResourceFailing,
    OtherError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserChallengeResult {
    pub account_id: i32,
    pub challenge_id: u32,
    pub answer: u32,
    pub outcome: UserChallengeOutcome,
    pub account_data: Option<GDAccountData>,
}

impl UserChallengeResult {
    pub fn new_failure(account_id: i32, challenge_id: u32, outcome: UserChallengeOutcome) -> Self {
        Self {
            account_id,
            challenge_id,
            answer: 0,
            outcome,
            account_data: None,
        }
    }

    pub fn new_success(account_id: i32, challenge_id: u32, answer: u32, account_data: GDAccountData) -> Self {
        Self {
            account_id,
            challenge_id,
            answer,
            outcome: UserChallengeOutcome::Success,
            account_data: Some(account_data),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArgonNodeMessage {
    Ping {
        time: u64,
    },
    Pong {
        time: u64,
    },

    Login {
        key: String,
    },

    LoginSuccess {
        resources: Vec<ResourceKey>,
    },

    Disconnect,

    Challenges {
        challenges: Vec<UserChallenge>,
        cleanups: Vec<u32>,
    },

    ChallengeResults {
        results: Vec<UserChallengeResult>,
    },
}

impl ArgonNodeMessage {
    pub fn decode(n: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(n)
    }

    pub fn encode(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_allocvec(self)
    }
}
