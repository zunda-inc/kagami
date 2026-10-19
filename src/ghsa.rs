use crate::advisory::TargetWithAdvisory;
use crate::error::KagamiError;
use crate::{AdvisoryType, Target};
use itertools::Itertools;
use octocrab::Octocrab;
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
                let mapped_results =
                    process_advisory_type_github_page(&target, &all_result)?;
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
    results: &Vec<octocrab::models::security_advisories::SecurityAdvisory>,
) -> Result<Vec<TargetWithAdvisory>, Box<dyn Error>> {
    let mapped_results: Vec<TargetWithAdvisory> = vec![];

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

        // It's target version from here.
    }

    Ok(mapped_results)
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
