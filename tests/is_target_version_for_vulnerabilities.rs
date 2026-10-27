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
        is_target_version_for_vulnerabilities(
            "GHSA-0000-0000-0000",
            version,
            &None,
            &vulnerabilities
        ),
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
        is_target_version_for_vulnerabilities(
            "GHSA-0000-0000-0000",
            version,
            &None,
            &vulnerabilities
        ),
        expected
    );
}

// 3. With `packages`, only the entries of the listed packages count. Microsoft lists many packages
// in one advisory, with platforms and version schemes of their own. Names compare ignoring case,
// as NuGet does, and a `.*` in the name of an entry stands for any name after the dot. An entry
// without a package name still counts, and without `packages` every entry does.
#[rstest]
// GHSA-p3jp-9v83-76w9
#[case::listed_package(
    "10.0.13",
    Some(vec!["Microsoft.NETCore.App.Runtime.linux-x64"]),
    Some("Microsoft.NETCore.App.Runtime.linux-x64"),
    ">= 10.0.0, < 10.0.14",
    true
)]
// GHSA-4mpw-cpwj-hxxj only lists the Windows runtimes
#[case::other_platform(
    "10.0.13",
    Some(vec!["Microsoft.NETCore.App.Runtime.linux-x64"]),
    Some("Microsoft.NETCore.App.Runtime.win-x64"),
    ">= 10.0.0, < 10.0.14",
    false
)]
// GHSA-crgg-f857-pvc7: `<= 13.1.21296` alone would cover 10.0.14
#[case::other_version_scheme(
    "10.0.14",
    Some(vec!["Microsoft.AspNetCore.App.Runtime.linux-x64"]),
    Some("aspnetcorev2_inprocess.dll"),
    "16.0.21299.0, <= 15.0.21297.12, < = 13.1.21296.21",
    false
)]
#[case::without_package_name(
    "10.0.13",
    Some(vec!["Microsoft.NETCore.App.Runtime.linux-x64"]),
    None,
    ">= 10.0.0, < 10.0.14",
    true
)]
#[case::without_packages(
    "10.0.13",
    None,
    Some("Microsoft.NETCore.App.Runtime.win-x64"),
    ">= 10.0.0, < 10.0.14",
    true
)]
// GHSA-73j8-2gch-69rq writes `NetCore`
#[case::case_differs(
    "10.0.3",
    Some(vec!["Microsoft.NETCore.App.Runtime.linux-x64"]),
    Some("Microsoft.NetCore.App.Runtime.linux-x64"),
    ">= 9.0.0, <= 9.0.13 >= 10.0.0, <= 10.0.3",
    true
)]
// GHSA-3rq8-h3gj-r5c6 lists every runtime of ASP.NET Core as one entry
#[case::wildcard(
    "6.0.4",
    Some(vec!["Microsoft.AspNetCore.App.Runtime.linux-x64"]),
    Some("Microsoft.AspNetCore.App.Runtime.*"),
    ">=3.0.0,<=3.1.24 >=5.0.0,<=5.0.16 >=6.0.0,<=6.0.4",
    true
)]
#[case::wildcard_other_package(
    "6.0.4",
    Some(vec!["Microsoft.NETCore.App.Runtime.linux-x64"]),
    Some("Microsoft.AspNetCore.App.Runtime.*"),
    ">=3.0.0,<=3.1.24 >=5.0.0,<=5.0.16 >=6.0.0,<=6.0.4",
    false
)]
#[case::synthetic_wildcard_needs_the_dot(
    "6.0.4",
    Some(vec!["Microsoft.AspNetCore.App.RuntimeExtras"]),
    Some("Microsoft.AspNetCore.App.Runtime.*"),
    ">=3.0.0,<=3.1.24 >=5.0.0,<=5.0.16 >=6.0.0,<=6.0.4",
    false
)]
fn counts_only_listed_packages(
    #[case] version: &str,
    #[case] packages: Option<Vec<&str>>,
    #[case] package: Option<&str>,
    #[case] range: &str,
    #[case] expected: bool,
) {
    let packages = packages.map(|names| {
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>()
    });
    let vulnerabilities: Vec<Vulnerability> = vec![
        serde_json::from_value(json!({
            "package": package.map(|name| json!({ "ecosystem": "nuget", "name": name })),
            "vulnerable_version_range": range,
        }))
        .unwrap(),
    ];

    assert_eq!(
        is_target_version_for_vulnerabilities(
            "GHSA-0000-0000-0000",
            version,
            &packages,
            &vulnerabilities
        ),
        expected
    );
}
