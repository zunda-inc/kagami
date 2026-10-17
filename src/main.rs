use crate::libkagami::config_file_parser::parse_config_file;
use crate::libkagami::config_merger::merge_config;
use crate::libkagami::logger::{initialize_default_logger, initialize_logger_by_loglevel};
use crate::libkagami::{Config, KagamiCommands};
use clap::Parser;
use log::{error, info};
use std::process::ExitCode;

mod libkagami;

fn main() -> ExitCode {
    initialize_default_logger();
    let command = KagamiCommands::parse();
    let parsed_config_file = match parse_config_file(&command.config_file_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to load config file.");
            error!("{}", e.to_string());
            return ExitCode::FAILURE;
        }
    };
    let merged_config = merge_config(&parsed_config_file, &command);
    initialize_logger_by_loglevel(
        &merged_config
            .log_level
            .unwrap_or(Config::default().log_level.unwrap()),
    );
    info!("Config file successfully loaded from `{}`.", &command.config_file_path);

    println!("Hello, world!");
    ExitCode::SUCCESS
}
