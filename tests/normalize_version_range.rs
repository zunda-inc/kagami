// Output format: one space between the operator and the version, `, ` between the comparators
// of one requirement, ` || ` between alternatives.
use kagami::normalize_version::normalize_version_range;

// 1. `v` in front of a version
#[test]
fn strips_v_prefix() {
    assert_eq!(
        normalize_version_range(">= v1.19.0, < v1.19.6").unwrap(),
        ">= 1.19.0, < 1.19.6"
    ); // cilium
    assert_eq!(
        normalize_version_range(">= v3.7.0-ea.1, <= v3.7.14").unwrap(),
        ">= 3.7.0-ea.1, <= 3.7.14"
    ); // traefik
    assert_eq!(
        normalize_version_range("< v2.0.0-beta.25").unwrap(),
        "< 2.0.0-beta.25"
    ); // moby
    assert_eq!(normalize_version_range("> v2.4").unwrap(), "> 2.4"); // argo-cd
    // The `v` of `dev1` is part of the pre-release tag.
    assert_eq!(
        normalize_version_range(">= 1.0.0-dev1, < 2.0.0").unwrap(),
        ">= 1.0.0-dev1, < 2.0.0"
    );
}

// 2. `All`
#[test]
fn all_means_every_version() {
    assert_eq!(normalize_version_range("All").unwrap(), "*"); // redis
    assert_eq!(normalize_version_range("All versions").unwrap(), "*"); // argo-cd
}

// 3. Hyphen ranges
#[test]
fn converts_hyphen_ranges() {
    assert_eq!(
        normalize_version_range("3.2.0 - 3.3.8").unwrap(),
        ">= 3.2.0, <= 3.3.8"
    ); // argo-cd
    assert_eq!(
        normalize_version_range("6.3.0-beta1 - 9.3.1").unwrap(),
        ">= 6.3.0-beta1, <= 9.3.1"
    ); // grafana
    // php-src: every item is a release branch, so the commas mean OR.
    assert_eq!(
        normalize_version_range("7.3.27 - 7.3.33, 7.4.15 - 7.4.33, 8.0.2 - 8.0.30, 8.1.0 - 8.1.28")
            .unwrap(),
        ">= 7.3.27, <= 7.3.33 || >= 7.4.15, <= 7.4.33 || >= 8.0.2, <= 8.0.30 || >= 8.1.0, <= 8.1.28"
    );
}

// 4. Missing commas between comparators
#[test]
fn inserts_missing_commas() {
    // containerd: each `>= a < b` pair is a release branch.
    assert_eq!(
        normalize_version_range(">= 2.1.0 < 2.2.7,  >= 2.3.0 < 2.3.4").unwrap(),
        ">= 2.1.0, < 2.2.7 || >= 2.3.0, < 2.3.4"
    );
    // grafana: no commas at all.
    assert_eq!(
        normalize_version_range(">=9.2.0 <9.2.10 >=9.3.0 <9.3.4").unwrap(),
        ">= 9.2.0, < 9.2.10 || >= 9.3.0, < 9.3.4"
    );
}

// 5. Bare versions are exact versions, and a list of them means OR
#[test]
fn bare_versions_are_exact() {
    assert_eq!(normalize_version_range("v2.1.0").unwrap(), "= 2.1.0"); // argo-cd
    assert_eq!(
        normalize_version_range("v2.9.3+6eba5be").unwrap(),
        "= 2.9.3"
    ); // argo-cd, build metadata dropped
    // cert-manager
    assert_eq!(
        normalize_version_range("v1.18.0,v1.18.1,v1.19.0,v1.19.1").unwrap(),
        "= 1.18.0 || = 1.18.1 || = 1.19.0 || = 1.19.1"
    );
}

// Upper bounds of several branches in one entry mean OR, each with its own branch as lower bound
#[test]
fn splits_upper_bounds_into_branches() {
    assert_eq!(
        normalize_version_range("< 1.8.4, < 1.9.1").unwrap(),
        ">= 1.8.0, < 1.8.4 || >= 1.9.0, < 1.9.1"
    ); // envoy gateway
    // A single upper bound stays as it is.
    assert_eq!(normalize_version_range("<8.4.26").unwrap(), "< 8.4.26"); // php-src
}

// Valid ranges are returned in the output format
#[test]
fn keeps_valid_ranges() {
    assert_eq!(
        normalize_version_range(">= 1.0.0, < 1.2.6").unwrap(),
        ">= 1.0.0, < 1.2.6"
    );
    assert_eq!(
        normalize_version_range(">=5.0.0-alpha.1, <5.0.0").unwrap(),
        ">= 5.0.0-alpha.1, < 5.0.0"
    );
    assert_eq!(
        normalize_version_range(">= 3.0.0, < 3.3.15 || >= 3.4.0, < 3.4.10 || = 3.6.0-rc1").unwrap(),
        ">= 3.0.0, < 3.3.15 || >= 3.4.0, < 3.4.10 || = 3.6.0-rc1"
    );
}

// Prose has no safe interpretation and must be rejected
#[test]
fn rejects_prose() {
    assert!(normalize_version_range("All versions prior to 1.7.14 and 1.8.7").is_err()); // argo-cd
    assert!(normalize_version_range("3.2.0 through 3.2.11, 3.3.9, and 3.4.1").is_err()); // argo-cd
    assert!(normalize_version_range("6.2 or newer").is_err()); // redis
    assert!(normalize_version_range("N/A").is_err()); // moby
}
