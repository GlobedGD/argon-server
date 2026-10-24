use serde::Deserialize;
use validator::{Validate, ValidationError};

use std::path::PathBuf;

use tracing::{Level, level_filters::LevelFilter};
use tracing_appender::{
    non_blocking::{NonBlockingBuilder, WorkerGuard},
    rolling::{RollingFileAppender, Rotation},
};
use tracing_subscriber::{Layer as _, Registry, filter, fmt::Layer, layer::SubscriberExt};

#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub file_enabled: bool,
    pub log_directory: Option<String>,
    pub log_filename: String,
    #[validate(custom(function = "validate_log_level"))]
    pub console_level: String,
    #[validate(custom(function = "validate_log_level"))]
    pub file_level: String,
    pub rolling: bool,
    pub retention_days: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            file_enabled: false,
            log_directory: None,
            log_filename: "argon-node".to_owned(),
            console_level: "info".to_owned(),
            file_level: "debug".to_owned(),
            rolling: false,
            retention_days: 7,
        }
    }
}

fn validate_log_level(level: &str) -> Result<(), ValidationError> {
    match level.to_lowercase().as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
        _ => Err(ValidationError::new("invalid log level")),
    }
}

#[must_use]
pub struct LoggerGuard {
    _file: Option<WorkerGuard>,
    _stdout: WorkerGuard,
}

pub fn init(config: &LoggingConfig) -> LoggerGuard {
    let console_level = parse_filter(&config.console_level);
    let file_level = parse_filter(&config.file_level);

    // suppress some noisy ones
    let filter = filter::Targets::new()
        .with_target("tokio", Level::WARN)
        .with_target("runtime", Level::WARN)
        .with_target("h2", Level::WARN)
        .with_target("hyper", Level::WARN);

    // use either log directory from config, or `logs/` if rolling, or cwd if not rolling
    let directory = config.log_directory.as_ref().map(|dir| PathBuf::from(&dir)).unwrap_or_else(|| {
        let mut cwd = std::env::current_dir().unwrap();
        if config.rolling {
            cwd.push("logs");
        }
        cwd
    });

    // create stdout layer
    let (nb_stdout, stdout_guard) = NonBlockingBuilder::default()
        .lossy(false)
        .thread_name("Stdout writer thread")
        .buffered_lines_limit(1024)
        .finish(std::io::stdout());

    let stdout_layer =
        Layer::default().with_writer(nb_stdout).with_filter(filter.clone().with_default(console_level));

    let subscriber = Registry::default().with(stdout_layer);

    let file_guard = if config.file_enabled {
        // create appender
        let appender = RollingFileAppender::builder()
            .rotation(if config.rolling { Rotation::DAILY } else { Rotation::NEVER })
            .filename_prefix(&config.log_filename)
            .max_log_files(config.retention_days as usize)
            .build(&directory)
            .expect("failed to build appender");

        let (nb_file, guard) = NonBlockingBuilder::default()
            .lossy(false)
            .thread_name("Log writer thread")
            .buffered_lines_limit(2048)
            .finish(appender);

        let file_layer = Layer::default()
            .with_writer(nb_file)
            .with_ansi(false)
            .with_filter(filter.with_default(file_level));

        let subscriber = subscriber.with(file_layer);
        tracing::subscriber::set_global_default(subscriber).unwrap();

        Some(guard)
    } else {
        tracing::subscriber::set_global_default(subscriber).unwrap();
        None
    };

    LoggerGuard {
        _file: file_guard,
        _stdout: stdout_guard,
    }
}

fn parse_filter(level: &str) -> LevelFilter {
    match level.to_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        _ => LevelFilter::INFO,
    }
}
