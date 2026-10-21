// A range that already parses is returned unchanged. A range that has to be rebuilt uses one
// space between the operator and the version, `, ` between the comparators of one requirement
// and ` || ` between alternatives.
use kagami::normalize_version::normalize_version_range;
use rstest::rstest;

// 1. `v` in front of a version
#[rstest]
#[case::cilium(">= v1.19.0, < v1.19.6", ">= 1.19.0, < 1.19.6")]
#[case::traefik(">= v3.7.0-ea.1, <= v3.7.14", ">= 3.7.0-ea.1, <= 3.7.14")]
#[case::moby("< v2.0.0-beta.25", "< 2.0.0-beta.25")]
#[case::argo_cd("> v2.4", "> 2.4")]
#[case::v_inside_prerelease_tag(">= 1.0.0-dev1, < 2.0.0", ">= 1.0.0-dev1, < 2.0.0")]
fn strips_v_prefix(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input).unwrap(), expected);
}

// 2. `All`
#[rstest]
#[case::redis("All", "*")]
#[case::argo_cd("All versions", "*")]
fn all_means_every_version(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input).unwrap(), expected);
}

// 3. Hyphen ranges; comma-separated items are release branches, so they mean OR
#[rstest]
#[case::argo_cd("3.2.0 - 3.3.8", ">= 3.2.0, <= 3.3.8")]
#[case::grafana("6.3.0-beta1 - 9.3.1", ">= 6.3.0-beta1, <= 9.3.1")]
#[case::php_src(
    "7.3.27 - 7.3.33, 7.4.15 - 7.4.33, 8.0.2 - 8.0.30, 8.1.0 - 8.1.28",
    ">= 7.3.27, <= 7.3.33 || >= 7.4.15, <= 7.4.33 || >= 8.0.2, <= 8.0.30 || >= 8.1.0, <= 8.1.28"
)]
fn converts_hyphen_ranges(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input).unwrap(), expected);
}

// 4. Missing commas between comparators; each `>= a < b` pair is a release branch
#[rstest]
#[case::containerd(
    ">= 2.1.0 < 2.2.7,  >= 2.3.0 < 2.3.4",
    ">= 2.1.0, < 2.2.7 || >= 2.3.0, < 2.3.4"
)]
#[case::grafana(
    ">=9.2.0 <9.2.10 >=9.3.0 <9.3.4",
    ">= 9.2.0, < 9.2.10 || >= 9.3.0, < 9.3.4"
)]
fn inserts_missing_commas(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input).unwrap(), expected);
}

// 5. Bare versions are exact versions, and a list of them means OR
#[rstest]
#[case::argo_cd("v2.1.0", "= 2.1.0")]
#[case::argo_cd_build_metadata("v2.9.3+6eba5be", "= 2.9.3")]
#[case::cert_manager(
    "v1.18.0,v1.18.1,v1.19.0,v1.19.1",
    "= 1.18.0 || = 1.18.1 || = 1.19.0 || = 1.19.1"
)]
fn bare_versions_are_exact(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input).unwrap(), expected);
}

// Upper bounds of several branches in one entry mean OR, each with its own branch as lower bound
#[rstest]
#[case::envoy_gateway("< 1.8.4, < 1.9.1", ">= 1.8.0, < 1.8.4 || >= 1.9.0, < 1.9.1")]
#[case::php_src_single_upper_bound_stays("<8.4.26", "<8.4.26")]
fn splits_upper_bounds_into_branches(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input).unwrap(), expected);
}

// Valid ranges are returned unchanged
#[rstest]
#[case::minimist(">= 1.0.0, < 1.2.6", ">= 1.0.0, < 1.2.6")]
#[case::express_prerelease(">=5.0.0-alpha.1, <5.0.0", ">=5.0.0-alpha.1, <5.0.0")]
#[case::argo_cd_alternatives(
    ">= 3.0.0, < 3.3.15 || >= 3.4.0, < 3.4.10 || = 3.6.0-rc1",
    ">= 3.0.0, < 3.3.15 || >= 3.4.0, < 3.4.10 || = 3.6.0-rc1"
)]
fn keeps_valid_ranges(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input).unwrap(), expected);
}
