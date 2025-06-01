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

pub fn format_duration(dur: &Duration, long: bool) -> String {
    if dur.as_secs() > 60 * 60 * 24 {
        let days = dur.as_secs_f64() / 60.0 / 60.0 / 24.0;
        format!("{days:.1}{}", if long { " days" } else { "d" })
    } else if dur.as_secs() > 60 * 60 {
        let hrs = dur.as_secs_f64() / 60.0 / 60.0;
        format!("{hrs:.1}{}", if long { " hours" } else { "h" })
    } else if dur.as_secs() > 60 {
        let mins = dur.as_secs_f64() / 60.0;
        format!("{mins:.1}{}", if long { " minutes" } else { "m" })
    } else if dur.as_secs() > 0 {
        let secs = dur.as_secs_f64();
        format!("{secs:.3}{}", if long { " seconds" } else { "s" })
    } else {
        let ms = dur.as_millis_f64();
        format!("{ms:.3}{}", if long { " milliseconds" } else { "ms" })
    }
}
