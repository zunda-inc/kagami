use crate::advisory::TargetWithAdvisory;
use crate::{AdvisoryType, Target};
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
            }
            AdvisoryType::GithubRepository => {
                // いい感じに
            }
        }
    }

    Ok(results)
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
