use crate::{Config, KagamiCommands};
use log::debug;

pub fn merge_config(file_config: &Config, command_line_options: &KagamiCommands) -> Config {
    let output_format = command_line_options
        .output_format
        .or(file_config.output_format);
    let log_level = command_line_options.log_level.or(file_config.log_level);

    debug!(
        "Output format: command line {:?}, config file {:?}, using {:?}.",
        command_line_options.output_format, file_config.output_format, output_format
    );
    debug!(
        "Log level: command line {:?}, config file {:?}, using {:?}.",
        command_line_options.log_level, file_config.log_level, log_level
    );

    Config {
        targets: file_config.targets.clone(),
        output_format,
        log_level,
    }
}
