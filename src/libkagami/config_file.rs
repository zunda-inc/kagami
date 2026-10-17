use clap::ValueEnum;
use serde::Deserialize;
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    pub targets: Vec<Target>,
    pub output_format: Option<OutputFormat>,
    pub log_level: Option<LogLevel>,
}

impl Config {
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        for target in &self.targets {
            let validate_result = target.validate();
            if let Err(e) = validate_result {
                return Err(e);
            };
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            output_format: Some(OutputFormat::Text),
            log_level: Some(LogLevel::Warn),
        }
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct Target {
    pub name: Option<String>,
    pub version: String,
    pub ecosystem: Option<String>,
    pub advisory_type: AdvisoryType,
    pub repository_path: Option<String>,
}

impl Target {
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.advisory_type == AdvisoryType::GithubRepository && self.repository_path.is_none() {
            return Err(Box::new(TargetParseError::RepositoryPathNotSpecified));
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum TargetParseError {
    RepositoryPathNotSpecified,
}

impl Display for TargetParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            TargetParseError::RepositoryPathNotSpecified => {
                "Please specify `repository_path` when the `advisory_type` is `github_repository`."
            }
        };
        write!(f, "{}", message)
    }
}

impl Error for TargetParseError {}

#[derive(PartialEq, Copy, Clone, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryType {
    Github,
    GithubRepository,
}

#[derive(PartialEq, Copy, Clone, Deserialize, ValueEnum, Debug)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    Json,
    Yaml,
    Text,
}

#[derive(PartialEq, Copy, Clone, Deserialize, ValueEnum, Debug)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}
