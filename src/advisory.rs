use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub package: Package,
    pub vulnerable_version_range: String,
    pub patched_versions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Package {
    pub ecosystem: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct CvssSeverities {
    pub cvss_v3: CvssScore,
    pub cvss_v4: CvssScore,
}

#[derive(Debug, Clone)]
pub struct CvssScore {
    pub vector_string: Option<String>,
    pub score: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Epss {
    pub percentage: f64,
    pub percentile: f64,
}
