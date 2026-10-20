use crate::advisory::{
    Advisory, CvssScore, CvssSeverities, Epss, Package, Severity, TargetWithAdvisory,
    Vulnerability, make_severity_order,
};
use crate::error::KagamiError;
use crate::{AdvisoryType, Target};
use itertools::Itertools;
use log::{debug, info, trace};
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
                let target_version = &target.version;
                let target_name = match &target.name {
                    Some(s) => format!("{s}@{target_version}"),
                    None => {
                        return Err(Box::new(KagamiError::OptionalGuard(
                            "target.name".to_string(),
                        )));
                    }
                };

                info!(
                    "Checking `{}` in the GitHub advisory database (ecosystem: {}).",
                    target_name,
                    target.ecosystem.as_deref().unwrap_or("any")
                );

                let security_advisories_query = octocrab.security_advisories();
                let mut query = security_advisories_query
                    .list()
                    .affects(target_name.clone());
                match &target.ecosystem {
                    Some(ecosystem) => query = query.ecosystem(ecosystem),
                    None => {}
                };
                query = query.per_page(100);

                let page_result = query.send().await?;
                let all_result = octocrab.all_pages(page_result).await?;
                debug!(
                    "Fetched {} advisories for `{}`.",
                    all_result.len(),
                    target_name
                );

                let mapped_results = process_advisory_type_github(&target, &all_result)?;
                debug!(
                    "{} of them affect `{}`.",
                    mapped_results.advisories.len(),
                    target_name
                );

                results.push(mapped_results);
            }
            AdvisoryType::GithubRepository => {
                let repository_path = match target.extract_repository_path()? {
                    Some(s) => s,
                    None => {
                        return Err(Box::new(KagamiError::OptionalGuard(
                            "repository_path".to_string(),
                        )));
                    }
                };

                info!(
                    "Checking the advisories published in `{}/{}` for version `{}`.",
                    repository_path[0], repository_path[1], target.version
                );

                let repo_adv_page = octocrab
                    .repos(repository_path[0], repository_path[1])
                    .security_advisories()
                    .list()
                    .state("published")
                    .per_page(100)
                    .send()
                    .await?;
                let all_result = octocrab.all_pages(repo_adv_page).await?;
                debug!(
                    "Fetched {} published advisories from `{}/{}`.",
                    all_result.len(),
                    repository_path[0],
                    repository_path[1]
                );

                let mapped_results = process_advisory_type_github_repository(&target, &all_result)?;
                debug!(
                    "{} of them affect version `{}`.",
                    mapped_results.advisories.len(),
                    target.version
                );

                results.push(mapped_results);
            }
        }
    }

    Ok(results)
}

fn process_advisory_type_github(
    target: &Target,
    results: &Vec<gh::SecurityAdvisory>,
) -> Result<TargetWithAdvisory, Box<dyn Error>> {
    let mut mapped_advisories: Vec<Advisory> = vec![];

    for advisory in results {
        let vulnerabilities = match &advisory.vulnerabilities {
            Some(v) => v,
            None => {
                trace!(
                    "`{}` has no vulnerability entries, skipped.",
                    advisory.ghsa_id
                );
                continue;
            }
        };

        if !is_target_version_for_vulnerabilities(&target.version, &vulnerabilities)? {
            trace!(
                "`{}` does not affect version `{}`, skipped.",
                advisory.ghsa_id, target.version
            );
            continue;
        }

        trace!(
            "`{}` affects version `{}`.",
            advisory.ghsa_id, target.version
        );
        mapped_advisories.push(map_advisory(advisory));
    }

    let severity_order = make_severity_order();
    Ok(TargetWithAdvisory {
        name: target.name.clone(),
        version: target.version.clone(),
        ecosystem: target.ecosystem.clone(),
        advisory_type: target.advisory_type,
        repository_path: target.repository_path.clone(),
        advisories: mapped_advisories
            .iter()
            .sorted_by(|a, b| severity_order[&a.severity].cmp(&severity_order[&b.severity]))
            .map(|v| v.clone())
            .collect(),
    })
}

fn process_advisory_type_github_repository(
    target: &Target,
    results: &Vec<gh::RepositoryAdvisory>,
) -> Result<TargetWithAdvisory, Box<dyn Error>> {
    let mut mapped_advisories: Vec<Advisory> = vec![];

    for advisory in results {
        let vulnerabilities = match &advisory.vulnerabilities {
            Some(v) => v,
            None => {
                trace!(
                    "`{}` has no vulnerability entries, skipped.",
                    advisory.ghsa_id
                );
                continue;
            }
        };

        if !is_target_version_for_vulnerabilities(&target.version, &vulnerabilities)? {
            trace!(
                "`{}` does not affect version `{}`, skipped.",
                advisory.ghsa_id, target.version
            );
            continue;
        }

        trace!(
            "`{}` affects version `{}`.",
            advisory.ghsa_id, target.version
        );
        mapped_advisories.push(map_repository_advisory(advisory)?);
    }

    let severity_order = make_severity_order();
    Ok(TargetWithAdvisory {
        name: target.name.clone(),
        version: target.version.clone(),
        ecosystem: target.ecosystem.clone(),
        advisory_type: target.advisory_type,
        repository_path: target.repository_path.clone(),
        advisories: mapped_advisories
            .iter()
            .sorted_by(|a, b| severity_order[&a.severity].cmp(&severity_order[&b.severity]))
            .map(|v| v.clone())
            .collect(),
    })
}

fn is_target_version_for_vulnerabilities(
    target_version: impl Into<String>,
    vulnerabilities: &Vec<octocrab::models::security_advisories::Vulnerability>,
) -> Result<bool, Box<dyn Error>> {
    let target_version: String = target_version.into();
    let is_target_versions: Vec<bool> = vulnerabilities
        .iter()
        .map(|v| {
            let vulnerable_version_range = match &v.vulnerable_version_range {
                Some(r) => r,
                None => return Ok(false),
            };
            version_is_in_target_range(&target_version, vulnerable_version_range)
        })
        .try_collect()?;

    Ok(is_target_versions.iter().any(|r| *r))
}

fn map_advisory(advisory: &gh::SecurityAdvisory) -> Advisory {
    Advisory {
        ghsa_id: advisory.ghsa_id.clone(),
        cve_id: advisory.cve_id.clone(),
        summary: advisory.summary.clone(),
        description: advisory.description.clone().unwrap_or_default(),
        severity: map_severity(&advisory.severity),
        cvss_severities: map_cvss_severities(advisory.cvss_severities.as_ref()),
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

fn map_repository_advisory(advisory: &gh::RepositoryAdvisory) -> Result<Advisory, KagamiError> {
    let published_at = advisory
        .published_at
        .ok_or_else(|| KagamiError::OptionalGuard("advisory.published_at".to_string()))?;
    let updated_at = advisory
        .updated_at
        .ok_or_else(|| KagamiError::OptionalGuard("advisory.updated_at".to_string()))?;

    Ok(Advisory {
        ghsa_id: advisory.ghsa_id.clone(),
        cve_id: advisory.cve_id.clone(),
        summary: advisory.summary.clone(),
        description: advisory.description.clone().unwrap_or_default(),
        severity: map_severity(advisory.severity.as_deref().unwrap_or_default()),
        cvss_severities: map_cvss_severities(advisory.cvss_severities.as_ref()),
        // Repository advisories don't carry EPSS.
        epss: None,
        html_url: advisory.html_url.to_string(),
        published_at,
        updated_at,
        withdrawn_at: advisory.withdrawn_at,
        vulnerabilities: advisory
            .vulnerabilities
            .iter()
            .flatten()
            .map(map_vulnerability)
            .collect(),
    })
}

fn map_severity(severity: &str) -> Severity {
    match severity {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Unknown,
    }
}

fn map_cvss_severities(cvss: Option<&gh::CvssSeverities>) -> CvssSeverities {
    let map_score = |score: Option<&gh::CvssScore>| CvssScore {
        vector_string: score.and_then(|s| s.vector_string.clone()),
        score: score.and_then(|s| s.score),
    };

    CvssSeverities {
        cvss_v3: map_score(cvss.and_then(|c| c.cvss_v3.as_ref())),
        cvss_v4: map_score(cvss.and_then(|c| c.cvss_v4.as_ref())),
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
    let version: String = version.into();
    let parsed_version = match Version::parse(&version) {
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
            trace!("Version `{}` matches the range `{}`.", version, range);
            return Ok(true);
        }
    }

    trace!(
        "Version `{}` does not match the range `{}`.",
        version, target_range
    );
    Ok(false)
}
