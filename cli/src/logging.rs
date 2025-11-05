use clap_verbosity_flag::Verbosity;
use env_logger::Builder;
use log::{Level, LevelFilter};

/// Initializes the logger
pub fn init_logger(verbosity: &Verbosity) {
    let level = verbosity
        .log_level()
        .map(level_to_filter)
        .unwrap_or(LevelFilter::Warn);

    Builder::new()
        .filter_level(level)
        .parse_default_env()
        .init();
}

fn level_to_filter(level: Level) -> LevelFilter {
    match level {
        Level::Error => LevelFilter::Error,
        Level::Warn  => LevelFilter::Warn,
        Level::Info  => LevelFilter::Info,
        Level::Debug => LevelFilter::Debug,
        Level::Trace => LevelFilter::Trace,
    }
}