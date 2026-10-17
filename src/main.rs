use clap::Parser;
use log::{error, info};
use std::process::ExitCode;
use kagami::config_file_parser::parse_config_file;
use kagami::config_merger::merge_config;
use kagami::{Config, KagamiCommands};
use kagami::github_client::init_octocrab;
use kagami::logger::{initialize_default_logger, initialize_logger_by_loglevel};

#[tokio::main]
async fn main() -> ExitCode {
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

    info!(
        "Config file successfully loaded from `{}`.",
        &command.config_file_path
    );

    info!("Validating config...");

    if let Err(e) = merged_config.validate() {
        error!("Config has validation error.");
        error!("{}", e.to_string());
        return ExitCode::FAILURE;
    }

    let octocrab = match init_octocrab().await {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to initialize GitHub client.");
            error!("{}", e.to_string());
            return ExitCode::FAILURE;
        }
    };

    println!("Hello, world!");
    ExitCode::SUCCESS
}
