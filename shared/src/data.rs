use int_enum::IntEnum;
use serde::{Deserialize, Serialize};
use serde_json;

#[derive(Debug, PartialEq, IntEnum)]
#[repr(u16)]
pub enum MessageCode {
    Invalid = 0,
    Ping = 1,
    Pong = 2,
}
