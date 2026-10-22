// The output format and the log level come from the command line first, then the config file,
// then `Config::default()`. `-o` and `-l` must stay `None` when they are not given, otherwise the
// config file could never set them.
use clap::{CommandFactory, Parser};
use kagami::config_merger::merge_config;
use kagami::{Config, KagamiCommands, LogLevel, OutputFormat};

#[test]
fn flags_are_none_when_not_given() {
    let command = KagamiCommands::try_parse_from(["kagami"]).unwrap();

    assert_eq!(command.output_format, None);
    assert_eq!(command.log_level, None);
    assert_eq!(command.config_file_path, "kagami.yaml");
}

#[test]
fn config_file_is_used_without_flags() {
    let command = KagamiCommands::try_parse_from(["kagami"]).unwrap();
    let file_config = Config {
        targets: vec![],
        output_format: Some(OutputFormat::Json),
        log_level: Some(LogLevel::Info),
    };

    let merged = merge_config(&file_config, &command);

    assert_eq!(merged.output_format, Some(OutputFormat::Json));
    assert_eq!(merged.log_level, Some(LogLevel::Info));
}

#[test]
fn flags_override_config_file() {
    let command = KagamiCommands::try_parse_from(["kagami", "-o", "text", "-l", "debug"]).unwrap();
    let file_config = Config {
        targets: vec![],
        output_format: Some(OutputFormat::Json),
        log_level: Some(LogLevel::Info),
    };

    let merged = merge_config(&file_config, &command);

    assert_eq!(merged.output_format, Some(OutputFormat::Text));
    assert_eq!(merged.log_level, Some(LogLevel::Debug));
}

// A config file without `output_format` and `log_level` gets them from `Config::default()`
// through `#[serde(default)]`.
#[test]
fn defaults_are_used_when_config_file_omits_them() {
    let command = KagamiCommands::try_parse_from(["kagami"]).unwrap();
    let file_config: Config = yaml_serde::from_str("targets: []").unwrap();

    let merged = merge_config(&file_config, &command);

    assert_eq!(merged.output_format, Config::default().output_format);
    assert_eq!(merged.log_level, Config::default().log_level);
}

// `-o` and `-l` have no clap default, so their defaults are written by hand in the help text of
// `src/command_line.rs`. Update both when `Config::default()` changes.
#[test]
fn help_shows_the_defaults_of_config() {
    let help = KagamiCommands::command().render_help().to_string();

    assert_eq!(Config::default().output_format, Some(OutputFormat::Text));
    assert!(help.contains("[default: text]"), "{help}");
    assert_eq!(Config::default().log_level, Some(LogLevel::Warn));
    assert!(help.contains("[default: warn]"), "{help}");
}
