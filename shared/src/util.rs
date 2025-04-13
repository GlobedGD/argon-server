use log::LevelFilter as LogLevelFilter;

pub fn get_log_level(env_var: &str) -> Option<LogLevelFilter> {
    std::env::var(env_var).map_or_else(
        |_| {
            Some(if cfg!(debug_assertions) {
                LogLevelFilter::Trace
            } else {
                LogLevelFilter::Info
            })
        },
        |level| match &*level.to_lowercase() {
            "trace" => Some(LogLevelFilter::Trace),
            "debug" => Some(LogLevelFilter::Debug),
            "info" => Some(LogLevelFilter::Info),
            "warn" => Some(LogLevelFilter::Warn),
            "error" => Some(LogLevelFilter::Error),
            "off" => Some(LogLevelFilter::Off),
            _ => None,
        },
    )
}
