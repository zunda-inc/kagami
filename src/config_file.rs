use clap::ValueEnum;
use log::{debug, trace};
use semver::Version;
use serde::{Deserialize, Serialize};
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
        debug!("Validating {} targets.", self.targets.len());

        for target in &self.targets {
            trace!("Validating target {:?}.", target);

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
    pub fn extract_repository_path(&self) -> Result<Option<[&str; 2]>, Box<dyn Error>> {
        let path = match self
            .repository_path
            .as_ref()
            .and_then(|s| Some(s.split("/").collect::<Vec<&str>>()))
        {
            Some(s) => s,
            None => return Ok(None),
        };

        if path.len() != 2 {
            return Err(Box::new(TargetParseError::RepositoryPathInvalid));
        }

        Ok(Some([path[0], path[1]]))
    }

    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        if self.advisory_type == AdvisoryType::GithubRepository && self.repository_path.is_none() {
            return Err(Box::new(TargetParseError::RepositoryPathNotSpecified));
        }
        if self.advisory_type == AdvisoryType::Github && self.name.is_none() {
            return Err(Box::new(TargetParseError::TargetNameNotSpecified));
        }
        if Version::parse(&self.version).is_err() {
            return Err(Box::new(TargetParseError::VersionNotParsable));
        }
        if self.repository_path.is_some() {
            match self.extract_repository_path() {
                Ok(_) => {}
                Err(e) => return Err(e),
            };
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum TargetParseError {
    RepositoryPathNotSpecified,
    TargetNameNotSpecified,
    VersionNotParsable,
    RepositoryPathInvalid,
}

impl Display for TargetParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            TargetParseError::RepositoryPathNotSpecified => {
                "Please specify `repository_path` when the `advisory_type` is `github_repository`."
            }
            TargetParseError::TargetNameNotSpecified => {
                "Please specify `name` when the `advisory_type` is `github`."
            }
            TargetParseError::VersionNotParsable => "`version` is not valid semver.",
            TargetParseError::RepositoryPathInvalid => "`repository_path` is invalid.",
        };
        write!(f, "{}", message)
    }
}

impl Error for TargetParseError {}

#[derive(PartialEq, Copy, Clone, strum_macros::Display, Deserialize, Serialize, Debug)]
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
