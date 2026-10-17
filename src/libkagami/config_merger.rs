use crate::libkagami::{Config, KagamiCommands};

pub fn merge_config(file_config: &Config, command_line_options: &KagamiCommands) -> Config {
    Config {
        targets: file_config.targets.clone(),
        output_format: command_line_options
            .output_format
            .or(file_config.output_format),
        log_level: command_line_options.log_level.or(file_config.log_level),
    }
}
