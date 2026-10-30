use clap::Parser;
use kagami::config_file_parser::parse_config_file;
use kagami::config_merger::merge_config;
use kagami::fail_on_severity::should_fail_on_severity;
use kagami::ghsa::find_vulnerabilities;
use kagami::github_client::init_octocrab;
use kagami::logger::{initialize_default_logger, initialize_logger_by_loglevel};
use kagami::output::output_to_stdout;
use kagami::output_version::output_version;
use kagami::resolve_config_file::resolve_config_file_path;
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

    // version command
    if command.version {
        if let Err(e) = output_version(command.fancy) {
            error!("Failed to write the version.");
            error!("{}", e);
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }

    let config_file_path = match resolve_config_file_path(command.config_file_path.clone()) {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            return ExitCode::FAILURE;
        }
    };

    let parsed_config_file = match parse_config_file(&config_file_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to load config file from `{}`.", config_file_path);
            error!("{}", e);
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
        config_file_path
    );

    debug!("Validating config...");

    if let Err(e) = merged_config.validate() {
        error!("Config has validation error.");
        error!("{}", e);
        return ExitCode::FAILURE;
    }

    let octocrab = match init_octocrab().await {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to initialize GitHub client.");
            error!("{}", e);
            return ExitCode::FAILURE;
        }
    };

    info!("Checking vulnerabilities based on the configuration.");

    let results = match find_vulnerabilities(&merged_config.targets, &octocrab).await {
        Ok(o) => o,
        Err(e) => {
            error!("Failed to check the vulnerabilities.");
            error!("{}", e);
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

    if let Err(e) = output_to_stdout(&output_format, &results) {
        error!("Failed to write the output.");
        error!("{}", e);
        return ExitCode::FAILURE;
    };

    if should_fail_on_severity(&results, merged_config.fail_on_severity) {
        error!(
            "A vulnerability rated `{}` or higher, as specified in the settings, has been detected.",
            merged_config
                .fail_on_severity
                .map(|f| f.to_string())
                .unwrap_or("".to_string())
        );
        error!("Will exit with exit code 1.");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
