// `version_is_in_target_range` answers whether the target version is inside one vulnerable
// version range. The range is normalized first, so these cases use raw ranges from real
// advisories and check the answer, not the normalized text.
use kagami::ghsa::version_is_in_target_range;
use rstest::rstest;

// 1. Upper and lower bounds
#[rstest]
#[case::kubernetes_below_upper_bound("1.32.9", "< 1.32.10", true)]
#[case::kubernetes_at_exclusive_upper_bound("1.32.10", "< 1.32.10", false)]
#[case::moby_at_inclusive_upper_bound("28.5.2", "<= 28.5.2", true)]
#[case::redis_partial_lower_bound("7.2.0", ">= 7.2", true)]
#[case::redis_below_partial_lower_bound("7.1.9", ">= 7.2", false)]
#[case::argo_cd_through_is_inclusive("1.8.7", "1.2.0 through 1.8.7", true)]
#[case::argo_cd_after_through("1.8.8", "1.2.0 through 1.8.7", false)]
#[case::libgit2_hyphen_without_spaces("1.9.3", "1.9.0-1.9.6", true)]
#[case::libgit2_after_hyphen_without_spaces("1.9.7", "1.9.0-1.9.6", false)]
fn checks_bounds(#[case] version: &str, #[case] range: &str, #[case] expected: bool) {
    assert_eq!(
        version_is_in_target_range(version, range).unwrap(),
        expected
    );
}

// 2. Alternatives: being inside one of them is enough
#[rstest]
#[case::containerd_first_branch("2.2.6", ">= 2.1.0 < 2.2.7,  >= 2.3.0 < 2.3.4", true)]
#[case::containerd_second_branch("2.3.0", ">= 2.1.0 < 2.2.7,  >= 2.3.0 < 2.3.4", true)]
#[case::containerd_patched("2.2.7", ">= 2.1.0 < 2.2.7,  >= 2.3.0 < 2.3.4", false)]
#[case::php_src_inside_a_hyphen_range(
    "7.4.33",
    "7.3.27 - 7.3.33, 7.4.15 - 7.4.33, 8.0.2 - 8.0.30, 8.1.0 - 8.1.28",
    true
)]
#[case::php_src_before_a_hyphen_range(
    "7.4.14",
    "7.3.27 - 7.3.33, 7.4.15 - 7.4.33, 8.0.2 - 8.0.30, 8.1.0 - 8.1.28",
    false
)]
#[case::cert_manager_listed("1.19.1", "v1.18.0,v1.18.1,v1.19.0,v1.19.1", true)]
#[case::cert_manager_not_listed("1.18.2", "v1.18.0,v1.18.1,v1.19.0,v1.19.1", false)]
#[case::dotnet_runtime_first_branch("9.0.13", ">= 9.0.0, <= 9.0.13 >= 10.0.0, <= 10.0.3", true)]
#[case::dotnet_runtime_second_branch("10.0.3", ">= 9.0.0, <= 9.0.13 >= 10.0.0, <= 10.0.3", true)]
#[case::dotnet_runtime_patched("10.0.14", ">= 9.0.0, <= 9.0.13 >= 10.0.0, <= 10.0.3", false)]
fn matches_any_alternative(#[case] version: &str, #[case] range: &str, #[case] expected: bool) {
    assert_eq!(
        version_is_in_target_range(version, range).unwrap(),
        expected
    );
}

// 3. Upper bounds of several release branches in one entry: each bound covers its own branch, so
// 1.9.0 is affected although it is not below 1.8.4. Branches before the lowest bound and the minor
// versions the list skips never got the fix, so they stay affected
#[rstest]
#[case::envoy_gateway_older_branch("1.8.3", "< 1.8.4, < 1.9.1", true)]
#[case::envoy_gateway_newer_branch("1.9.0", "< 1.8.4, < 1.9.1", true)]
#[case::envoy_gateway_older_branch_patched("1.8.4", "< 1.8.4, < 1.9.1", false)]
#[case::envoy_gateway_newer_branch_patched("1.9.1", "< 1.8.4, < 1.9.1", false)]
#[case::envoy_gateway_branch_without_fix("1.7.5", "< 1.8.4, < 1.9.1", true)]
#[case::argo_cd_branch_without_fix("1.6.2", "All versions prior to 1.7.12 and 1.8.4", true)]
#[case::quarkus_skipped_branch("3.25.1", "<3.20.6, <3.27.3, <3.33.1, <3.35.1", true)]
#[case::quarkus_lts_patched("3.27.3", "<3.20.6, <3.27.3, <3.33.1, <3.35.1", false)]
#[case::opensearch_new_major_before_its_fix("2.3.0", "<1.3.7; <2.4.0", true)]
#[case::opensearch_new_major_patched("2.4.0", "<1.3.7; <2.4.0", false)]
fn reads_upper_bounds_as_branches(
    #[case] version: &str,
    #[case] range: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        version_is_in_target_range(version, range).unwrap(),
        expected
    );
}

// 4. Exact versions and every version
#[rstest]
#[case::argo_cd_build_metadata("2.9.3", "v2.9.3+6eba5be", true)]
#[case::argo_cd_next_patch("2.9.4", "v2.9.3+6eba5be", false)]
#[case::aspnetcore_without_v("10.0.0-rc.1.25451.107", "10.0.0-rc.1.25451.107", true)]
#[case::aspnetcore_without_v_later_patch("10.0.14", "10.0.0-rc.1.25451.107", false)]
#[case::envoy_list_without_v_later_patch("1.39.1", "1.37.0,1.36.4,1.35.8,1.34.12", false)]
#[case::redis_all("8.2.1", "All", true)]
fn matches_exact_and_every_version(
    #[case] version: &str,
    #[case] range: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        version_is_in_target_range(version, range).unwrap(),
        expected
    );
}

// 5. Input that cannot be read is an error, so that the caller can warn about it
#[rstest]
#[case::kyverno_none("1.0.0", "NONE")]
#[case::caddy_note_only(
    "2.10.0",
    "(confirmed on main @ e0f8d9b2047af417d8faf354b675941f3dac9891)"
)]
#[case::v_prefixed_target_version("v1.0.0", "< 2.0.0")]
fn fails_on_unreadable_input(#[case] version: &str, #[case] range: &str) {
    assert!(version_is_in_target_range(version, range).is_err());
}

// 6. A pre-release target is judged as the release it leads to. `VersionReq` alone never puts
// `1.32.0-rc.2` inside `< 1.32.10` or `*`
#[rstest]
#[case::kubernetes_release_candidate("1.32.0-rc.2", "< 1.32.10", true)]
#[case::redis_all_release_candidate("8.2.0-rc1", "All", true)]
#[case::first_affected_release("1.33.0-rc.1", ">= 1.33.0, < 1.33.6", true)]
#[case::envoy_gateway_branch_start("1.9.0-rc.1", "< 1.8.4, < 1.9.1", true)]
#[case::argo_cd_exact_release("2.9.3-rc.1", "v2.9.3+6eba5be", true)]
#[case::fixed_release("2.0.0-rc.1", "< 2.0.0", false)]
#[case::after_the_range("1.33.0-rc.1", "< 1.32.10", false)]
fn judges_prerelease_as_its_release(
    #[case] version: &str,
    #[case] range: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        version_is_in_target_range(version, range).unwrap(),
        expected
    );
}

// 7. A range that names pre-releases is compared with the pre-release itself
#[rstest]
#[case::kubernetes_prerelease_lower_bound("1.33.0-rc.1", ">= 1.33.0-alpha.0, < 1.33.6", true)]
#[case::runc_named_prerelease("1.5.0-rc.1", ">= 1.5.0-rc.1, <= 1.5.0-rc.2", true)]
#[case::runc_after_named_prereleases("1.5.0-rc.3", ">= 1.5.0-rc.1, <= 1.5.0-rc.2", false)]
#[case::express_named_prerelease("5.0.0-beta.1", ">=5.0.0-alpha.1, <5.0.0-beta.3", true)]
fn compares_named_prereleases(#[case] version: &str, #[case] range: &str, #[case] expected: bool) {
    assert_eq!(
        version_is_in_target_range(version, range).unwrap(),
        expected
    );
}

// 8. A bare version next to a branch that misses an end is that end, so the branch does not reach
// every older or newer version
#[rstest]
#[case::metabase_inside("1.55.22", "1.55.0, < 1.55.23", true)]
#[case::metabase_older_branch("1.54.9", "1.55.0, < 1.55.23", false)]
#[case::aspnetcore_at_upper_end("6.0.0", ">=5.0.0,6.0.0, >=4.6.0, 4.7.0", true)]
#[case::aspnetcore_patched("6.0.1", ">=5.0.0,6.0.0, >=4.6.0, 4.7.0", false)]
#[case::aspnetcore_newer_major("10.0.14", ">=5.0.0,6.0.0, >=4.6.0, 4.7.0", false)]
fn reads_bare_versions_as_missing_ends(
    #[case] version: &str,
    #[case] range: &str,
    #[case] expected: bool,
) {
    assert_eq!(
        version_is_in_target_range(version, range).unwrap(),
        expected
    );
}
