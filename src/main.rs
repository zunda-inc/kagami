use clap::Parser;
use kagami::config_file_parser::parse_config_file;
use kagami::config_merger::merge_config;
use kagami::ghsa::find_vulnerabilities;
use kagami::github_client::init_octocrab;
use kagami::logger::{initialize_default_logger, initialize_logger_by_loglevel};
use kagami::output::output_to_stdout;
use kagami::{Config, KagamiCommands};
use log::{debug, error, info, trace};
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    initialize_default_logger();

    let command = KagamiCommands::parse();

    // Apply the log level given on the command line right away, so that the logs emitted while
    // loading the config honor it. The merged log level is applied again below.
    initialize_logger_by_loglevel(
        &command
            .log_level
            .unwrap_or(Config::default().log_level.unwrap()),
    );
    trace!("Command line options: {:?}.", command);

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
    trace!("Merged config: {:?}.", merged_config);

    info!(
        "Config file successfully loaded from `{}`.",
        &command.config_file_path
    );

    debug!("Validating config...");

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

    info!("Checking vulnerabilities based on the configuration.");

    let results = match find_vulnerabilities(&merged_config.targets, &octocrab).await {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to check the vulnerabilities.");
            error!("{}", e.to_string());
            return ExitCode::FAILURE;
        }
    };

    info!(
        "Retrieved {} advisories for {} targets.",
        results.iter().map(|r| r.advisories.len()).sum::<usize>(),
        results.len()
    );

    let output_format = match merged_config.output_format {
        Some(f) => f,
        None => {
            error!("Unexpected: `output_format` is not set.");
            return ExitCode::FAILURE;
        }
    };
    debug!("Output format is {:?}.", output_format);

    match output_to_stdout(&output_format, &results) {
        Err(e) => {
            error!("Failed to write the output.");
            error!("{}", e.to_string());
            return ExitCode::FAILURE;
        }
        _ => {}
    };

    ExitCode::SUCCESS
}
