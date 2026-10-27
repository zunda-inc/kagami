// Patched version of https://github.com/XAMPPRocky/octocrab/blob/main/src/api/security_advisories.rs
// and https://github.com/XAMPPRocky/octocrab/blob/main/src/models/security_advisories.rs .
// We have to change the type of source_code_location from Option<Url> to Option<String> .
// Some of source_code_location contains non-url strings.

use chrono::{DateTime, Utc};
use octocrab::models::security_advisories::{
    CvssSeverities, Cwe, Epss, GlobalAdvisoryCredit, SecurityAdvisoryIdentifier, Vulnerability,
};
use octocrab::{Octocrab, Page, Result};
use serde::{Deserialize, Serialize};
use url::Url;

/// A GitHub Global Security Advisory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PatchedSecurityAdvisory {
    pub ghsa_id: String,
    pub cve_id: Option<String>,
    pub url: Url,
    pub html_url: Url,
    pub repository_advisory_url: Option<Url>,
    pub summary: String,
    pub description: Option<String>,
    pub r#type: String,
    pub severity: String,
    pub source_code_location: Option<String>,
    pub identifiers: Option<Vec<SecurityAdvisoryIdentifier>>,
    pub references: Option<Vec<String>>,
    pub published_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub github_reviewed_at: Option<DateTime<Utc>>,
    pub nvd_published_at: Option<DateTime<Utc>>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub vulnerabilities: Option<Vec<Vulnerability>>,
    pub cvss_severities: Option<CvssSeverities>,
    pub cwes: Option<Vec<Cwe>>,
    pub credits: Option<Vec<GlobalAdvisoryCredit>>,
    pub epss: Option<Epss>,
}

/// Handler for GitHub's Security Advisories API.
///
/// Created with [`Octocrab::security_advisories`].
pub struct PatchedSecurityAdvisoriesHandler<'octo> {
    crab: &'octo Octocrab,
}

impl<'octo> PatchedSecurityAdvisoriesHandler<'octo> {
    pub(crate) fn new(crab: &'octo Octocrab) -> Self {
        Self { crab }
    }

    /// List global security advisories.
    pub fn list_global_advisories(&self) -> PatchedListGlobalSecurityAdvisoriesBuilder<'octo, '_> {
        PatchedListGlobalSecurityAdvisoriesBuilder::new(self)
    }

    /// Shortcut for [`Self::list_global_advisories`].
    pub fn list(&self) -> PatchedListGlobalSecurityAdvisoriesBuilder<'octo, '_> {
        self.list_global_advisories()
    }
}

/// A builder pattern struct for listing global security advisories.
#[derive(serde::Serialize)]
pub struct PatchedListGlobalSecurityAdvisoriesBuilder<'octo, 'b> {
    #[serde(skip)]
    handler: &'b PatchedSecurityAdvisoriesHandler<'octo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ghsa_id: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cve_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ecosystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_withdrawn: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    affects: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    published: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epss_percentage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epss_percentile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    per_page: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sort: Option<String>,
}

impl<'octo, 'b> PatchedListGlobalSecurityAdvisoriesBuilder<'octo, 'b> {
    pub(crate) fn new(handler: &'b PatchedSecurityAdvisoriesHandler<'octo>) -> Self {
        Self {
            handler,
            ghsa_id: None,
            r#type: None,
            cve_id: None,
            ecosystem: None,
            severity: None,
            cwes: None,
            is_withdrawn: None,
            affects: None,
            published: None,
            updated: None,
            modified: None,
            epss_percentage: None,
            epss_percentile: None,
            before: None,
            after: None,
            direction: None,
            per_page: None,
            sort: None,
        }
    }

    /// If specified, only advisories with this GHSA identifier will be returned.
    pub fn ghsa_id(mut self, ghsa_id: impl Into<String>) -> Self {
        self.ghsa_id = Some(ghsa_id.into());
        self
    }

    /// If specified, only advisories of this type will be returned (e.g. "reviewed", "unreviewed", "malware").
    pub fn r#type(mut self, r#type: impl Into<String>) -> Self {
        self.r#type = Some(r#type.into());
        self
    }

    /// If specified, only advisories with this CVE identifier will be returned.
    pub fn cve_id(mut self, cve_id: impl Into<String>) -> Self {
        self.cve_id = Some(cve_id.into());
        self
    }

    /// If specified, only advisories for this ecosystem will be returned.
    pub fn ecosystem(mut self, ecosystem: impl Into<String>) -> Self {
        self.ecosystem = Some(ecosystem.into());
        self
    }

    /// If specified, only advisories with this severity will be returned.
    pub fn severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = Some(severity.into());
        self
    }

    /// If specified, only advisories with this Common Weakness Enumerator (CWE) identifier will be returned.
    pub fn cwes(mut self, cwes: impl Into<String>) -> Self {
        self.cwes = Some(cwes.into());
        self
    }

    /// Whether to only return advisories that have been withdrawn.
    pub fn is_withdrawn(mut self, is_withdrawn: bool) -> Self {
        self.is_withdrawn = Some(is_withdrawn);
        self
    }

    /// If specified, only advisories affecting this package will be returned.
    pub fn affects(mut self, affects: impl Into<String>) -> Self {
        self.affects = Some(affects.into());
        self
    }

    /// If specified, only advisories published on this date or date range will be returned.
    pub fn published(mut self, published: impl Into<String>) -> Self {
        self.published = Some(published.into());
        self
    }

    /// If specified, only advisories updated on this date or date range will be returned.
    pub fn updated(mut self, updated: impl Into<String>) -> Self {
        self.updated = Some(updated.into());
        self
    }

    /// If specified, only advisories modified on this date or date range will be returned.
    pub fn modified(mut self, modified: impl Into<String>) -> Self {
        self.modified = Some(modified.into());
        self
    }

    /// If specified, only advisories with this EPSS percentage will be returned.
    pub fn epss_percentage(mut self, epss_percentage: impl Into<String>) -> Self {
        self.epss_percentage = Some(epss_percentage.into());
        self
    }

    /// If specified, only advisories with this EPSS percentile will be returned.
    pub fn epss_percentile(mut self, epss_percentile: impl Into<String>) -> Self {
        self.epss_percentile = Some(epss_percentile.into());
        self
    }

    /// A cursor, as given in the Link header, used for pagination.
    pub fn before(mut self, before: impl Into<String>) -> Self {
        self.before = Some(before.into());
        self
    }

    /// A cursor, as given in the Link header, used for pagination.
    pub fn after(mut self, after: impl Into<String>) -> Self {
        self.after = Some(after.into());
        self
    }

    /// The direction to sort the results by.
    pub fn direction(mut self, direction: impl Into<String>) -> Self {
        self.direction = Some(direction.into());
        self
    }

    /// The number of results per page (max 100).
    pub fn per_page(mut self, per_page: impl Into<u8>) -> Self {
        self.per_page = Some(per_page.into());
        self
    }

    /// The property to sort the results by.
    pub fn sort(mut self, sort: impl Into<String>) -> Self {
        self.sort = Some(sort.into());
        self
    }

    /// Sends the request to list global security advisories.
    pub async fn send(&self) -> Result<Page<PatchedSecurityAdvisory>> {
        self.handler.crab.get("/advisories", Some(&self)).await
    }
}
