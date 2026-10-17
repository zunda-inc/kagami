use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Config {
    targets: Vec<Target>,
    output_format: Option<OutputFormat>,
    log_level: Option<LogLevel>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            output_format: Some(OutputFormat::Text),
            log_level: Some(LogLevel::Info),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct Target {
    name: Option<String>,
    version: String,
    ecosystem: Option<String>,
    advisory_type: AdvisoryType,
    repository_path: Option<String>,
}

#[derive(Deserialize, Debug)]
enum AdvisoryType {
    Github,
    GithubRepository,
}

#[derive(Deserialize, Debug)]
enum OutputFormat {
    Json,
    Yaml,
    Text,
}

#[derive(Deserialize, Debug)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}
