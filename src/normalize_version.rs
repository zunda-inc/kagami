use crate::error::KagamiError;
use itertools::Itertools;
use regex::Regex;
use semver::{Comparator, Op, Version, VersionReq};
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
    let front_v_regex = Regex::new(r"\bv(\d+)\.")?;
    version_range = front_v_regex
        .replace_all(version_range.as_str(), "$1.")
        .to_string();

    // `version, version` pattern: a bare version is an exact version, and a list of them means OR.
    let bare_versions = version_range
        .split(",")
        .map(|v| Version::parse(v.trim()))
        .collect::<Result<Vec<_>, _>>();
    if let Ok(bare_versions) = bare_versions {
        version_range = bare_versions.iter().map(to_exact_version).join(" || ");
    }

    // Check if it can parse at this point
    if VersionReq::parse(&version_range).is_ok() {
        return Ok(version_range);
    }

    // `version - version, version - version` pattern
    let comma_count = version_range.matches(",").count();
    let hyphen_count = version_range.matches(" - ").count();
    let is_hyphen_range_pattern = hyphen_count >= 1 && hyphen_count == comma_count + 1;
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

    // Check if it can parse at this point
    if VersionReq::parse(&version_range).is_ok() {
        return Ok(version_range);
    }

    // `||` で正しく区切られてないパターンを捕捉する
    let compare_regex = Regex::new(r"(>=|<=|>|<|=)")?;
    let split_by_comma = version_range
        .split(",")
        .map(|v| v.trim())
        .collect::<Vec<_>>();
    let mut and_parts: Vec<String> = vec![];
    for part in split_by_comma {
        let split_result = regex_split_include_match(part, &compare_regex);
        let split_parts = split_result
            .iter()
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .collect::<Vec<_>>();
        if split_parts.len() == 4 {
            and_parts.push(format!(
                "{} {}, {} {}",
                split_parts[0], split_parts[1], split_parts[2], split_parts[3]
            ));
            continue;
        }
        if split_parts.len() == 2 {
            and_parts.push(format!("{} {}", split_parts[0], split_parts[1]));
            continue;
        }
    }
    let missing_or_pattern = and_parts.join(" || ");
    if !and_parts.is_empty() && and_parts.iter().all(|v| VersionReq::parse(v).is_ok()) {
        return Ok(missing_or_pattern);
    }

    // ただスペースで区切られているが、色々とおかしいやつ
    let split_by_space = version_range
        .split(" ")
        .map(|v| v.trim().to_string())
        .collect::<Vec<_>>();
    let mut split_by_space_elements: Vec<String> = vec![];
    for (idx, elem) in split_by_space.iter().enumerate() {
        if idx == split_by_space.len() - 1 {
            break;
        }

        if split_by_space.len() < idx + 2 {
            split_by_space_elements.push(elem.to_string());
            continue;
        }

        if idx % 2 != 0 {
            continue;
        }

        let next_elem = &split_by_space[idx + 1];
        let and_range = format!("{}, {}", elem, next_elem);

        split_by_space_elements.push(and_range);
    }
    let missing_commas_normalized = split_by_space_elements.join(" || ");
    if !split_by_space_elements.is_empty()
        && split_by_space_elements
            .iter()
            .all(|v| VersionReq::parse(v).is_ok())
    {
        return Ok(missing_commas_normalized);
    }

    Ok(version_range)
}

fn regex_split_include_match(s: impl Into<String>, re: &Regex) -> Vec<String> {
    let s = s.into();
    let s = s.as_str();

    let mut parts: Vec<String> = Vec::new();
    let mut last = 0;
    for m in re.find_iter(s) {
        parts.push((&s[last..m.start()]).to_string());
        parts.push(m.as_str().to_string());
        last = m.end();
    }

    parts.push((&s[last..]).to_string());
    parts
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

// `2.9.3+6eba5be` becomes `= 2.9.3`: the build metadata is dropped because a requirement cannot carry it.
fn to_exact_version(version: &Version) -> String {
    let mut exact_version = format!("= {}.{}.{}", version.major, version.minor, version.patch);
    if !version.pre.is_empty() {
        exact_version = format!("{exact_version}-{}", version.pre);
    }
    exact_version
}
