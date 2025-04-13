use int_enum::IntEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, IntEnum)]
#[repr(u16)]
pub enum MessageCode {
    // Universal messages
    Invalid = 0,
    Ping = 1,
    Pong = 2,
    Close = 3,
    CloseAck = 4,

    // Messages sent by the node
    NodeHandshake = 1000, // data: client's public key (string)
    NodeStartup = 1001,   // data: password (string)

    // Messages sent by the central server
    HandshakeResponse = 2000, // data: server's public key (string)
    StartupConfig = 2001,     // data: WorkerConfiguration
    StartupAbort = 2002,      // data: error message (string)
}

// #[derive(Debug, Serialize, Deserialize)]

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerConfiguration {
    pub account_id: i32,
    pub account_gjp: String,
    pub base_url: String,
    pub msg_check_interval: u32,
}
