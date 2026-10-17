use clap::ValueEnum;
use serde::Deserialize;

#[derive(Clone, Deserialize, Debug)]
#[serde(default)]
pub struct Config {
    pub targets: Vec<Target>,
    pub output_format: Option<OutputFormat>,
    pub log_level: Option<LogLevel>,
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

#[derive(Copy, Clone, Deserialize, Debug)]
pub enum AdvisoryType {
    Github,
    GithubRepository,
}

#[derive(Copy, Clone, Deserialize, ValueEnum, Debug)]
pub enum OutputFormat {
    Json,
    Yaml,
    Text,
}

#[derive(Copy, Clone, Deserialize, ValueEnum, Debug)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}
