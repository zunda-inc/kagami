use crate::advisory::{
    Advisory, CvssScore, CvssSeverities, Epss, Package, Severity, TargetWithAdvisory, Vulnerability,
};
use crate::error::KagamiError;
use crate::{AdvisoryType, Target};
use itertools::Itertools;
use octocrab::Octocrab;
use octocrab::models::security_advisories as gh;
use semver::{Version, VersionReq};
use std::error::Error;

pub async fn find_vulnerabilities(
    targets: &Vec<Target>,
    octocrab: &Octocrab,
) -> Result<Vec<TargetWithAdvisory>, Box<dyn Error>> {
    let mut results: Vec<TargetWithAdvisory> = vec![];

    for target in targets {
        match target.advisory_type {
            AdvisoryType::Github => {
                // いい感じに
                let target_version = &target.version;
                let target_name = match &target.name {
                    Some(s) => format!("{s}@{target_version}"),
                    None => {
                        return Err(Box::new(KagamiError::OptionalGuard(
                            "target.name".to_string(),
                        )));
                    }
                };
                let security_advisories_query = octocrab.security_advisories();
                let mut query = security_advisories_query.list().affects(target_name);
                match &target.ecosystem {
                    Some(ecosystem) => query = query.ecosystem(ecosystem),
                    None => {}
                };
                query = query.per_page(100);
                let page_result = query.send().await?;
                let all_result = octocrab.all_pages(page_result).await?;
                let mapped_results = process_advisory_type_github_page(&target, &all_result)?;
                results.extend(mapped_results);
            }
            AdvisoryType::GithubRepository => {
                // いい感じに
            }
        }
    }

    Ok(results)
}

fn process_advisory_type_github_page(
    target: &Target,
    results: &Vec<gh::SecurityAdvisory>,
) -> Result<Vec<TargetWithAdvisory>, Box<dyn Error>> {
    let mut mapped_results: Vec<TargetWithAdvisory> = vec![];

    for advisory in results {
        let vulnerabilities = match &advisory.vulnerabilities {
            Some(v) => v,
            None => continue,
        };

        let is_target_versions: Vec<bool> = vulnerabilities
            .iter()
            .map(|v| {
                let vulnerable_version_range = match &v.vulnerable_version_range {
                    Some(r) => r,
                    None => return Ok(false),
                };
                version_is_in_target_range(&target.version, vulnerable_version_range)
            })
            .try_collect()?;

        if !is_target_versions.iter().any(|r| *r) {
            continue;
        }

        mapped_results.push(TargetWithAdvisory {
            name: target.name.clone(),
            version: target.version.clone(),
            ecosystem: target.ecosystem.clone(),
            advisory_type: target.advisory_type,
            repository_path: target.repository_path.clone(),
            advisories: vec![map_advisory(advisory)],
        });
    }

    Ok(mapped_results)
}

fn map_advisory(advisory: &gh::SecurityAdvisory) -> Advisory {
    let cvss = advisory.cvss_severities.as_ref();
    let map_score = |score: Option<&gh::CvssScore>| CvssScore {
        vector_string: score.and_then(|s| s.vector_string.clone()),
        score: score.and_then(|s| s.score),
    };

    Advisory {
        ghsa_id: advisory.ghsa_id.clone(),
        cve_id: advisory.cve_id.clone(),
        summary: advisory.summary.clone(),
        description: advisory.description.clone().unwrap_or_default(),
        severity: match advisory.severity.as_str() {
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => Severity::Unknown,
        },
        cvss_severities: CvssSeverities {
            cvss_v3: map_score(cvss.and_then(|c| c.cvss_v3.as_ref())),
            cvss_v4: map_score(cvss.and_then(|c| c.cvss_v4.as_ref())),
        },
        epss: advisory
            .epss
            .as_ref()
            .and_then(|e| e.percentage.zip(e.percentile))
            .map(|(percentage, percentile)| Epss {
                percentage,
                percentile,
            }),
        html_url: advisory.html_url.to_string(),
        published_at: advisory.published_at,
        updated_at: advisory.updated_at,
        withdrawn_at: advisory.withdrawn_at,
        vulnerabilities: advisory
            .vulnerabilities
            .iter()
            .flatten()
            .map(map_vulnerability)
            .collect(),
    }
}

fn map_vulnerability(vulnerability: &gh::Vulnerability) -> Vulnerability {
    let package = vulnerability.package.as_ref();

    Vulnerability {
        package: Package {
            ecosystem: package.map(|p| p.ecosystem.clone()).unwrap_or_default(),
            name: package.and_then(|p| p.name.clone()).unwrap_or_default(),
        },
        vulnerable_version_range: vulnerability
            .vulnerable_version_range
            .clone()
            .unwrap_or_default(),
        // Global advisories only fill `first_patched_version`, so fall back to it.
        patched_versions: match &vulnerability.patched_versions {
            Some(s) => s.split(',').map(|s| s.trim().to_string()).collect(),
            None => vulnerability
                .first_patched_version
                .iter()
                .cloned()
                .collect(),
        },
    }
}

fn version_is_in_target_range(
    version: impl Into<String>,
    target_range: impl Into<String>,
) -> Result<bool, Box<dyn Error>> {
    let parsed_version = match Version::parse(&version.into()) {
        Ok(v) => v,
        Err(e) => return Err(Box::new(e)),
    };
    let target_range = target_range.into();
    let target_ranges = target_range.split("||").map(|s| s.trim());

    for range in target_ranges {
        let req = match VersionReq::parse(&range) {
            Ok(v) => v,
            Err(e) => return Err(Box::new(e)),
        };

        if req.matches(&parsed_version) {
            return Ok(true);
        }
    }

    Ok(false)
}
