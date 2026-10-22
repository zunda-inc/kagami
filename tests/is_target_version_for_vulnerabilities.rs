// `is_target_version_for_vulnerabilities` decides whether an advisory affects the target. An
// advisory has one vulnerability entry per affected package or release branch.
use kagami::ghsa::is_target_version_for_vulnerabilities;
use octocrab::models::security_advisories::Vulnerability;
use rstest::rstest;
use serde_json::json;

// 1. One matching entry is enough. php-src writes the fix of each branch as its own entry
// (GHSA-w8hw-w9fx-j79w).
#[rstest]
#[case::php_src_newest_branch(
    "8.5.9",
    vec![Some("< 8.2.35"), Some("< 8.3.36"), Some("< 8.4.27"), Some("< 8.5.12")],
    true
)]
#[case::php_src_patched(
    "8.5.12",
    vec![Some("< 8.2.35"), Some("< 8.3.36"), Some("< 8.4.27"), Some("< 8.5.12")],
    false
)]
fn matches_any_entry(
    #[case] version: &str,
    #[case] ranges: Vec<Option<&str>>,
    #[case] expected: bool,
) {
    let vulnerabilities: Vec<Vulnerability> = ranges
        .iter()
        .map(|range| serde_json::from_value(json!({ "vulnerable_version_range": range })).unwrap())
        .collect();

    assert_eq!(
        is_target_version_for_vulnerabilities("GHSA-0000-0000-0000", version, &vulnerabilities),
        expected
    );
}

// 2. An entry without a usable range does not affect the target. A range that cannot be read is
// skipped with a warning instead of stopping the whole run, and must not hide the other entries.
#[rstest]
#[case::kyverno_none("1.0.0", vec![Some("NONE")], false)]
#[case::none_next_to_a_match("1.9.0", vec![Some("NONE"), Some("< 1.9.1")], true)]
#[case::missing_range("1.0.0", vec![None], false)]
fn skips_entries_without_usable_range(
    #[case] version: &str,
    #[case] ranges: Vec<Option<&str>>,
    #[case] expected: bool,
) {
    let vulnerabilities: Vec<Vulnerability> = ranges
        .iter()
        .map(|range| serde_json::from_value(json!({ "vulnerable_version_range": range })).unwrap())
        .collect();

    assert_eq!(
        is_target_version_for_vulnerabilities("GHSA-0000-0000-0000", version, &vulnerabilities),
        expected
    );
}
