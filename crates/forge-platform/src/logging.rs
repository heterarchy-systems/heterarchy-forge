use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::ParseError;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::{SubscriberInitExt, TryInitError};

use crate::AppPaths;

const DEFAULT_FILTER: &str = "info,forge_runtime=debug,forge_desktop=debug";

/// Guard that flushes the non-blocking log writer when dropped.
#[derive(Debug)]
pub struct LoggingGuard {
    _file_guard: WorkerGuard,
}

pub fn init_logging(paths: &AppPaths) -> Result<LoggingGuard, LoggingError> {
    let file_appender = tracing_appender::rolling::daily(paths.logs(), "forge.log");
    let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);

    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(_) => EnvFilter::try_new(DEFAULT_FILTER).map_err(LoggingError::InvalidDefaultFilter)?,
    };

    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_ansi(false)
        .with_target(true)
        .with_writer(file_writer);

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .try_init()
        .map_err(LoggingError::SubscriberInitialization)?;

    Ok(LoggingGuard {
        _file_guard: file_guard,
    })
}

#[derive(Debug, Error)]
pub enum LoggingError {
    #[error("invalid built-in tracing filter")]
    InvalidDefaultFilter(#[source] ParseError),
    #[error("failed to initialize tracing subscriber")]
    SubscriberInitialization(#[source] TryInitError),
}
