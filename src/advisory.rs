use crate::AdvisoryType;
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct TargetWithAdvisory {
    pub name: Option<String>,
    pub version: String,
    pub ecosystem: Option<String>,
    pub advisory_type: AdvisoryType,
    pub repository_path: Option<String>,
    pub advisories: Vec<Advisory>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Advisory {
    pub ghsa_id: String,
    pub cve_id: Option<String>,
    pub summary: String,
    pub description: String,
    pub severity: Severity,
    pub cvss_severities: CvssSeverities,
    pub epss: Option<Epss>,
    pub html_url: String,
    pub published_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    ValueEnum,
    strum_macros::Display,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    // Sort order of the severities, the most severe first.
    pub const fn order(self) -> i32 {
        match self {
            Severity::Critical => 1,
            Severity::High => 2,
            Severity::Medium => 3,
            Severity::Low => 4,
            Severity::Unknown => 5,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Vulnerability {
    pub package: Package,
    pub vulnerable_version_range: String,
    pub patched_versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CvssSeverities {
    pub cvss_v3: CvssScore,
    pub cvss_v4: CvssScore,
}

#[derive(Debug, Clone, Serialize)]
pub struct CvssScore {
    pub vector_string: Option<String>,
    pub score: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Epss {
    pub percentage: f64,
    pub percentile: f64,
}
