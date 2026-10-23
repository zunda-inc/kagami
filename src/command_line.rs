use crate::advisory::Severity;
use crate::{LogLevel, OutputFormat};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "kagami")]
#[command(version)]
#[command(
    about = "This simple tool checks whether there are any publicly disclosed vulnerabilities in a list of defined software.",
    long_about= None
)]
pub struct KagamiCommands {
    /// Sets an output format, overriding the one in the config file [default: text]
    #[arg(short, long, value_enum)]
    pub output_format: Option<OutputFormat>,
    /// Sets a log level, overriding the one in the config file [default: warn]
    #[arg(short, long, value_enum)]
    pub log_level: Option<LogLevel>,
    /// If a vulnerability of the specified severity or higher is detected, it will exit with an exit code of 1 to indicate failure.
    /// If no severity is specified, it will always exit with a code of 0 unless an error occurs.
    #[arg(short, long, value_enum)]
    pub fail_on_severity: Option<Severity>,
    /// Sets a path to the config file, relative to the current directory.
    #[arg(default_value = "kagami.yaml")]
    pub config_file_path: String,
}
