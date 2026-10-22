use crate::LogLevel;
use log::{LevelFilter, debug};
use simplelog::{ColorChoice, CombinedLogger, Config, TermLogger, TerminalMode};

pub fn initialize_default_logger() {
    CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )])
    .unwrap();
    log::set_max_level(LevelFilter::Trace);
}

pub fn initialize_logger_by_loglevel(log_level: &LogLevel) {
    let level_filter = match log_level {
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };

    log::set_max_level(level_filter);
    debug!("Log level is set to {:?}.", log_level);
}
