use crate::{Config, KagamiCommands};
use log::debug;

pub fn merge_config(file_config: &Config, command_line_options: &KagamiCommands) -> Config {
    let output_format = command_line_options
        .output_format
        .or(file_config.output_format);
    let log_level = command_line_options.log_level.or(file_config.log_level);
    let fail_on_severity = command_line_options
        .fail_on_severity
        .or(file_config.fail_on_severity);

    debug!(
        "Output format: command line {:?}, config file {:?}, using {:?}.",
        command_line_options.output_format, file_config.output_format, output_format
    );
    debug!(
        "Log level: command line {:?}, config file {:?}, using {:?}.",
        command_line_options.log_level, file_config.log_level, log_level
    );
    debug!(
        "Fail on severity: command line {:?}, config file {:?}, using {:?}",
        command_line_options.fail_on_severity, file_config.fail_on_severity, fail_on_severity
    );

    Config {
        targets: file_config.targets.clone(),
        output_format,
        log_level,
        fail_on_severity,
    }
}
