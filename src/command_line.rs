use clap::Parser;
use crate::{LogLevel, OutputFormat};

#[derive(Parser, Debug)]
#[command(name = "kagami")]
#[command(version = "1.0.0")]
#[command(
    about = "This simple tool checks whether there are any publicly disclosed vulnerabilities in a list of defined software.",
    long_about= None
)]
pub struct KagamiCommands {
    /// Sets an output format.
    #[arg(short, long, value_enum, default_value = "text")]
    pub output_format: Option<OutputFormat>,
    /// Sets a log level.
    #[arg(short, long, value_enum, default_value = "warn")]
    pub log_level: Option<LogLevel>,
    /// Sets a path to the config file. Default is `kagami.yaml` in the current directory.
    #[arg(default_value = "kagami.yaml")]
    pub config_file_path: String,
}
