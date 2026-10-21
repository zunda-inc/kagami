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

// Regression: ranges that already parse must come back unchanged. Taken from real advisories.
#[rstest]
// GitHub's curated database
#[case::lodash_lower_and_upper(">= 4.0.0, <= 4.17.23")]
#[case::lodash_upper_inclusive("<= 4.17.23")]
#[case::lodash_upper_exclusive("< 4.17.21")]
#[case::minimist(">= 1.0.0, < 1.2.6")]
#[case::minimist_old_branch("< 0.2.4")]
#[case::kubernetes_single("< 1.32.10")]
#[case::kubernetes_prerelease_lower(">= 1.33.0-alpha.0, < 1.33.6")]
#[case::kubernetes_inclusive("<= 1.32.3")]
#[case::ingress_nginx(">= 1.14.0, < 1.14.3")]
#[case::runc_prerelease_both(">= 1.5.0-rc.1, <= 1.5.0-rc.2")]
#[case::runc_prerelease_without_dot(">= 1.0.0-rc3, <= 1.2.7")]
#[case::moby_two_digit_major("<= 28.5.2")]
#[case::moby_prerelease_upper("< 2.0.0-beta.14")]
#[case::containerd_exact("= 2.4.0")]
#[case::argo_cd_open_ended(">= 2.1.0")]
#[case::argo_cd_alternatives(
    ">= 3.0.0, < 3.3.15 || >= 3.4.0, < 3.4.10 || >= 3.5.0, < 3.5.4 || = 3.6.0-rc1"
)]
// Repository advisories that were already clean
#[case::express_no_spaces("<4.22.0")]
#[case::express_prerelease(">=5.0.0-alpha.1, <5.0.0")]
#[case::express_prerelease_both(">=5.0.0-alpha.1, <5.0.0-beta.3")]
#[case::elliptic_no_spaces("<=6.6.0")]
#[case::php_src_no_spaces("<8.2.34")]
#[case::php_src_with_space("< 8.2.32")]
#[case::cilium(">= 1.19.0, < 1.19.3")]
#[case::redis_open_ended(">= 7.0.0")]
#[case::redis_partial_version(">= 7.2")]
// Shapes semver accepts that no advisory happened to use
#[case::wildcard("*")]
#[case::caret("^1.2.3")]
#[case::tilde("~1.2")]
#[case::prerelease_tag_containing_v(">= 1.0.0-preview.1, < 1.0.0")]
// Upper bound pairs that are not branch lists
#[case::same_branch_twice("< 1.8.4, < 1.8.9")]
#[case::partial_version_upper_bounds("< 7.2, < 8.0.1")]
#[case::prerelease_upper_bounds("<= 1.4.0-rc.2, <= 1.3.5")]
fn keeps_valid_ranges(#[case] range: &str) {
    assert_eq!(normalize_version_range(range).unwrap(), range);
}
