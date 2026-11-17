//! A resource is a Geometry Dash entity that can be used as an intermediate for account verification.
//! For example, a level is a valuable resource because users can post comments under them to verify their account.

use serde::{Deserialize, Serialize};
use strum::EnumIter;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Hash, PartialEq, Eq, EnumIter)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    Level,
    ProfileField,
    LegacyProfileField,
}

/// A resource key uniquely identifies a specific verification resource
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct ResourceKey {
    pub r#type: ResourceType,
    pub id: i32,
}
