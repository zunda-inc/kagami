use crate::error::KagamiError;
use itertools::Itertools;
use regex::Regex;
use semver::{Comparator, Op, VersionReq};
use std::error::Error;

pub fn normalize_version_range(version_range: impl Into<String>) -> Result<String, Box<dyn Error>> {
    let mut version_range: String = version_range.into();

    // Check if it can parse at this point
    match VersionReq::parse(&version_range) {
        Ok(version_req) => {
            let is_branch_list = is_branch_list(&version_req);
            if is_branch_list {
                return Ok(version_req.comparators.iter().map(to_branch).join(" || "));
            }
            return Ok(version_range);
        }
        // If there is an error, it should do nothing here.
        Err(_) => {}
    };

    if version_range.trim() == "All" {
        return Ok("*".to_string());
    }
    if version_range.trim() == "All versions" {
        return Ok("*".to_string());
    }

    // Should not include v before the version.
    let front_v_regex = Regex::new(r"v(\d+)\.")?;
    version_range = front_v_regex
        .replace_all(version_range.as_str(), "$1")
        .to_string();

    // Check if it can parse at this point
    if VersionReq::parse(&version_range).is_ok() {
        return Ok(version_range);
    }

    // `version - version, version - version` pattern
    let comma_count = version_range.matches(",").count();
    let hyphen_count = version_range.matches(" - ").count();
    let is_hyphen_range_pattern =
        hyphen_count == if comma_count == 0 { 0 } else { comma_count + 1 } || hyphen_count == 1;
    if is_hyphen_range_pattern {
        let range_items = version_range
            .split(",")
            .map(|v| v.trim())
            .map(|v| {
                let versions = v.split(" - ").map(|s| s.trim()).collect::<Vec<_>>();
                if versions.len() != 2 {
                    return Err(KagamiError::VersionRangeInconsistent(version_range.clone()));
                }
                Ok(format!(">= {}, <= {}", versions[0], versions[1]))
            })
            .collect::<Result<Vec<_>, _>>()?;
        version_range = range_items.join(" || ");
    }

    Ok(version_range)
}

fn is_branch_list(requirement: &VersionReq) -> bool {
    let comparators = &requirement.comparators;
    let all_upper_bounds = comparators
        .iter()
        .all(|c| matches!(c.op, Op::Less | Op::LessEq));
    let all_full_versions = comparators
        .iter()
        .all(|c| c.minor.is_some() && c.patch.is_some() && c.pre.is_empty());
    let branch_count = comparators
        .iter()
        .map(|c| (c.major, c.minor))
        .unique()
        .count();

    comparators.len() >= 2
        && all_upper_bounds
        && all_full_versions
        && branch_count == comparators.len()
}

fn to_branch(comparator: &Comparator) -> String {
    let op = if comparator.op == Op::LessEq {
        "<="
    } else {
        "<"
    };
    let (major, minor) = (comparator.major, comparator.minor.unwrap());
    format!(
        ">= {major}.{minor}.0, {op} {major}.{minor}.{}",
        comparator.patch.unwrap()
    )
}
