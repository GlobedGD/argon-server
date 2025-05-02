use int_enum::IntEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, IntEnum)]
#[repr(u16)]
pub enum MessageCode {
    // Universal messages
    Invalid = 0,
    Ping = 1,
    Pong = 2,
    Close = 3,
    CloseAck = 4,

    // Messages sent by the node
    NodeHandshake = 1000,      // data: NodeHandshakeData
    NodeStartup = 1001,        // data: password (string)
    NodeReportError = 1020,    // data: error message (string)
    NodeReportMessages = 1021, // data: Vec<WorkerAuthMessage>

    // Messages sent by the central server
    HandshakeResponse = 2000, // data: ServerHandshakeResponse
    StartupConfig = 2001,     // data: WorkerConfiguration
    StartupAbort = 2002,      // data: error message (string)
    RefreshConfig = 2010,     // data: WorkerConfiguration
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeHandshakeData {
    pub key: String, // public key of the node
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerHandshakeResponse {
    pub key: String, // public key of the server
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkerConfiguration {
    pub account_id: i32,
    pub account_gjp: String,
    pub base_url: String,
    pub msg_check_interval: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerError {
    pub message: String,
    pub fail_count: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerAuthMessage {
    #[serde(rename = "id")]
    pub message_id: i32,
    #[serde(rename = "a")]
    pub account_id: i32,
    #[serde(rename = "u")]
    pub user_id: i32,
    #[serde(rename = "n")]
    pub username: String,
    #[serde(rename = "c")]
    pub challenge_answer: i32,
}
