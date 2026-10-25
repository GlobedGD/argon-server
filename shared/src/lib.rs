pub mod logging;
pub mod message;
pub mod resource;

pub use qunet;

#[cfg(feature = "docker")]
pub const DOCKER_CONFIG_BASE_NAME: &str = "/data/config.toml";
#[cfg(not(feature = "docker"))]
pub const DOCKER_CONFIG_BASE_NAME: &str = "config.toml";
