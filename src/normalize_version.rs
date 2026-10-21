use crate::error::KagamiError;
use regex::Regex;
use semver::VersionReq;
use std::error::Error;

pub fn normalize_version_range(version_range: impl Into<String>) -> Result<String, Box<dyn Error>> {
    let mut version_range: String = version_range.into();

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
    let is_hyphen_range_pattern =
        version_range.matches(" - ").count() == version_range.matches(",").count() - 1;
    if is_hyphen_range_pattern {
        let range_items = version_range
            .split(",")
            .map(|v| v.trim())
            .map(|v| {
                let versions = v.split(" - ").map(|s| s.trim()).collect::<Vec<_>>();
                if versions.len() != 2 {
                    return Err(KagamiError::VersionRangeInconsistent(version_range.clone()));
                }
                Ok(format!(">={}, <={}", versions[0], versions[1]))
            })
            .collect::<Result<Vec<_>, _>>()?;
        version_range = range_items.join(" || ");
    }

    // Check if it can parse at this point
    if VersionReq::parse(&version_range).is_ok() {
        return Ok(version_range);
    }

    Ok(version_range)
}
