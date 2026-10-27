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
    assert_eq!(normalize_version_range(input), expected);
}

// 2. `All`
#[rstest]
#[case::redis("All", "*")]
#[case::argo_cd("All versions", "*")]
fn all_means_every_version(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// 3. Hyphen ranges, also without spaces when a version with a dot follows the hyphen;
// comma-separated items are release branches, so they mean OR
#[rstest]
#[case::argo_cd("3.2.0 - 3.3.8", ">= 3.2.0, <= 3.3.8")]
#[case::grafana("6.3.0-beta1 - 9.3.1", ">= 6.3.0-beta1, <= 9.3.1")]
#[case::php_src(
    "7.3.27 - 7.3.33, 7.4.15 - 7.4.33, 8.0.2 - 8.0.30, 8.1.0 - 8.1.28",
    ">= 7.3.27, <= 7.3.33 || >= 7.4.15, <= 7.4.33 || >= 8.0.2, <= 8.0.30 || >= 8.1.0, <= 8.1.28"
)]
#[case::libgit2_without_spaces("1.9.0-1.9.6", ">= 1.9.0, <= 1.9.6")]
#[case::squid_without_spaces("5.0.3-5.9, 6.0-6.3", ">= 5.0.3, <= 5.9 || >= 6.0, <= 6.3")]
#[case::containerd_without_spaces("<= 1.5.17, 1.6.0-1.6.17", "<= 1.5.17 || >= 1.6.0, <= 1.6.17")]
#[case::jetty_qualifier_without_spaces(
    "7.2.2-9.4.38, 10.0.0.alpha0-10.0.1",
    ">= 7.2.2, <= 9.4.38 || >= 10.0.0-alpha0, <= 10.0.1"
)]
#[case::imagemagick_patch_level_stays("7.1.1-4,7.1.1-6 (Beta)", "= 7.1.1-4 || = 7.1.1-6")]
fn converts_hyphen_ranges(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// 4. Missing commas between comparators; a lower bound starts a release branch, also when the
// commas sit inside the branches
#[rstest]
#[case::containerd(
    ">= 2.1.0 < 2.2.7,  >= 2.3.0 < 2.3.4",
    ">= 2.1.0, < 2.2.7 || >= 2.3.0, < 2.3.4"
)]
#[case::grafana(
    ">=9.2.0 <9.2.10 >=9.3.0 <9.3.4",
    ">= 9.2.0, < 9.2.10 || >= 9.3.0, < 9.3.4"
)]
#[case::dotnet_runtime(
    ">= 9.0.0, <= 9.0.13 >= 10.0.0, <= 10.0.3",
    ">= 9.0.0, <= 9.0.13 || >= 10.0.0, <= 10.0.3"
)]
#[case::dotnet_runtime_empty_branch(
    ">= 9.0.0, < 9.0.0 >= 8.0.0, < 8.0.11",
    ">= 9.0.0, < 9.0.0 || >= 8.0.0, < 8.0.11"
)]
#[case::aspnetcore_no_spaces(
    ">=3.0.0,<=3.1.24 >=5.0.0,<=5.0.16 >=6.0.0,<=6.0.4",
    ">= 3.0.0, <= 3.1.24 || >= 5.0.0, <= 5.0.16 || >= 6.0.0, <= 6.0.4"
)]
fn inserts_missing_commas(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// 5. Bare versions are exact versions, and a list of them means OR. `semver` alone would read a
// bare version without `v` as `^`
#[rstest]
#[case::argo_cd("v2.1.0", "= 2.1.0")]
#[case::argo_cd_build_metadata("v2.9.3+6eba5be", "= 2.9.3")]
#[case::cert_manager(
    "v1.18.0,v1.18.1,v1.19.0,v1.19.1",
    "= 1.18.0 || = 1.18.1 || = 1.19.0 || = 1.19.1"
)]
#[case::aspnetcore_without_v("10.0.0-rc.1.25451.107", "= 10.0.0-rc.1.25451.107")]
#[case::envoy_without_v(
    "1.19.0, 1.18.3, 1.17.3, 1.16.4",
    "= 1.19.0 || = 1.18.3 || = 1.17.3 || = 1.16.4"
)]
#[case::envoy_without_v_or_spaces(
    "1.37.0,1.36.4,1.35.8,1.34.12",
    "= 1.37.0 || = 1.36.4 || = 1.35.8 || = 1.34.12"
)]
fn bare_versions_are_exact(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// Upper bounds of several branches in one entry mean OR. Each bound but the lowest leaves out the
// listed branches below it, while the versions before the lowest bound and the minor versions the
// list skips stay inside, as they never got the fix
#[rstest]
#[case::envoy_gateway("< 1.8.4, < 1.9.1", "< 1.8.4 || >= 1.9.0, < 1.9.1")]
#[case::quarkus_lts_branches(
    "<3.20.6, <3.27.3, <3.33.1, <3.35.1",
    "< 3.20.6 || >= 3.21.0, < 3.27.3 || >= 3.28.0, < 3.33.1 || >= 3.34.0, < 3.35.1"
)]
#[case::opensearch_new_major("<1.3.7; <2.4.0", "< 1.3.7 || >= 2.0.0, < 2.4.0")]
#[case::php_src_single_upper_bound_stays("<8.4.26", "<8.4.26")]
fn splits_upper_bounds_into_branches(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
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
    assert_eq!(normalize_version_range(range), range);
}

// 6. Qualifiers after the patch number (Maven, Discourse, PEP 440)
#[rstest]
#[case::netty_final(">=4.2.0.Final, <=4.2.14.Final", ">= 4.2.0, <= 4.2.14")]
#[case::netty_two_branches("<=4.2.12.Final, <=4.1.132.Final", ">= 4.2.0, <= 4.2.12 || <= 4.1.132")]
#[case::jetty_alpha_beta(">=12.1.0.alpha0, <=12.1.0.beta2", ">= 12.1.0-alpha0, <= 12.1.0-beta2")]
#[case::vllm_pep440(">= 0.23.0rc2, < 0.30.0", ">= 0.23.0-0rc2, < 0.30.0")]
#[case::clickhouse_fourth_number("< 24.3.18.6", "< 24.3.18")]
#[case::jetty_build_stamp("<= 9.4.32.v20200930, <= 10.0.0.beta2", "<= 9.4.32, <= 10.0.0-beta2")]
#[case::dotnet_four_part_versions(
    "16.0.21299.0, <= 15.0.21297.12, < = 13.1.21296.21",
    "= 16.0.21299 || >= 15.0.0, <= 15.0.21297 || <= 13.1.21296"
)]
fn fixes_version_qualifiers(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// 7. Labels in front of comparators, `;` between them
#[rstest]
#[case::discourse(
    "stable <= 2.8.13; beta <= 3.0.0.beta15; tests-passed <= 3.0.0.beta15",
    "<= 2.8.13, <= 3.0.0-beta15, <= 3.0.0-beta15"
)]
#[case::jaeger("jaeger-ui < v1.31.0", "< 1.31.0")]
#[case::woodpecker_semicolon(">= 1.0.0; < 1.0.2", ">= 1.0.0, < 1.0.2")]
fn drops_labels_and_semicolons(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// 8. Bounds written in English
#[rstest]
#[case::envoy_and_earlier("1.20.1 and earlier", "<= 1.20.1")]
#[case::envoy_capital_v("V1.21.0 and earlier", "<= 1.21.0")]
#[case::envoy_or_older(
    "1.14.2, 1.13.2, 1.12.4 or older",
    ">= 1.14.0, <= 1.14.2 || >= 1.13.0, <= 1.13.2 || <= 1.12.4"
)]
#[case::valkey_and_below(
    "7.2.10 and below, 8.0.5 and below, 8.1.3 and below",
    "<= 7.2.10 || >= 8.0.0, <= 8.0.5 || >= 8.1.0, <= 8.1.3"
)]
#[case::redis_or_newer("6.2 or newer", ">= 6.2")]
#[case::caddy_and_later("v2.4.0 and later", ">= 2.4.0")]
#[case::rancher_plus("2.0.0+", ">= 2.0.0")]
#[case::argo_cd_prior_to(
    "All versions prior to 1.7.14 and 1.8.7",
    "< 1.7.14 || >= 1.8.0, < 1.8.7"
)]
#[case::envoy_list_with_and(
    "1.17.1, 1.16.2, 1.15.3, and 1.14.6",
    "= 1.17.1 || = 1.16.2 || = 1.15.3 || = 1.14.6"
)]
fn turns_words_into_bounds(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// 9. Ranges written with words, dashes or as intervals
#[rstest]
#[case::argo_cd_through("1.2.0 through 1.8.7", ">= 1.2.0, <= 1.8.7")]
#[case::argo_cd_through_and_exact(
    "3.0.0-rc1 through 3.2.0-rc1, 3.1.7, 3.0.18",
    ">= 3.0.0-rc1, <= 3.2.0-rc1 || = 3.1.7 || = 3.0.18"
)]
#[case::podman_to("v4.0.0 to v5.6.0", ">= 4.0.0, <= 5.6.0")]
#[case::jetty_to_twice(
    "10.0.0 to 10.0.9, 11.0.0 to 11.0.9",
    ">= 10.0.0, <= 10.0.9 || >= 11.0.0, <= 11.0.9"
)]
#[case::wazuh_from_to("from 3.5.0 to 4.3.10.", ">= 3.5.0, <= 4.3.10")]
#[case::external_secrets_en_dash("v0.10.0–v1.3.1", ">= 0.10.0, <= 1.3.1")]
#[case::nats_interval("2.2.0 <= V <= 2.10.1", ">= 2.2.0, <= 2.10.1")]
#[case::gitea_interval("1.22 < 1.27.1", ">= 1.22, < 1.27.1")]
fn turns_words_into_ranges(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// 10. Separators and operators spelled differently
#[rstest]
#[case::ghost_double_ampersand(">= 6.19.4 && < 6.21.1", ">= 6.19.4, < 6.21.1")]
#[case::kyverno_and(">= 1.18.0 and <= 1.19.1", ">= 1.18.0, <= 1.19.1")]
#[case::etcd_and_upper_bounds("< v3.4.26 and < v3.5.9", "< 3.4.26 || >= 3.5.0, < 3.5.9")]
#[case::prometheus_semicolon("< 3.5.3 ; >= 3.6.0 and <3.11.3", "< 3.5.3 || >= 3.6.0, < 3.11.3")]
#[case::ghost_unicode("≤ 5.59.0", "<= 5.59.0")]
#[case::kyverno_markdown_escape("\\>= 1.11.0, \\<= 1.16.2", ">= 1.11.0, <= 1.16.2")]
#[case::kyverno_backticks("`<= v1.18.2`", "<= 1.18.2")]
#[case::tensorflow_double_equals("== 2.8.0", "= 2.8.0")]
#[case::vllm_reversed("=< 0.17.1", "<= 0.17.1")]
#[case::electron_space_in_operator(">= 7.0.0-beta < =7.2.3", ">= 7.0.0-beta, <= 7.2.3")]
#[case::redis_note(">= 4.0 (32-bit only)", ">= 4.0")]
#[case::moby_major_only(">= v23, < v23.0.10", ">= 23, < 23.0.10")]
#[case::minio_lowercase_all("all", "*")]
#[case::istio_capital_all("All Versions", "*")]
fn fixes_separators_and_operators(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// 11. Missing commas inside alternatives
#[rstest]
#[case::electron(
    "< 28.3.2 || >= 29.0.0-alpha.1 < 29.3.3 || >= 30.0.0-alpha.1 < 30.0.3",
    "< 28.3.2 || >= 29.0.0-alpha.1, < 29.3.3 || >= 30.0.0-alpha.1, < 30.0.3"
)]
fn inserts_missing_commas_inside_alternatives(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// 12. Typos and phrases found in the survey of well-known projects
#[rstest]
#[case::valkey_reversed_operator("=>9.0.0, <= 9.0.2", ">= 9.0.0, <= 9.0.2")]
#[case::envoy_and_before("1.12.6 and before.", "<= 1.12.6")]
#[case::synthetic_through_and_including("1.0.0 through and including 1.2.3", ">= 1.0.0, <= 1.2.3")]
#[case::docker_calendar_versions("< 19.03.15, < 20.10.3", "< 19.3.15 || >= 20.0.0, < 20.10.3")]
#[case::vllm_leading_zero("< 030.0", "< 30.0.0")]
#[case::discourse_comma_inside_label(
    "stable <= 2.7.10; beta,tests-passed <= 2.8.0.beta8;",
    "<= 2.7.10, <= 2.8.0-beta8"
)]
fn fixes_typos_and_phrases(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// 13. A bare version next to a branch that misses an end is that end. Next to an upper bound of
// another release branch it stays exact, because upper bounds are often listed one per branch
#[rstest]
#[case::dotnet_runtime_lower_end(
    "8.0.0-preview.1.23110.8, <= 8.0.0",
    ">= 8.0.0-preview.1.23110.8, <= 8.0.0"
)]
#[case::metabase_lower_end("1.55.0, < 1.55.23", ">= 1.55.0, < 1.55.23")]
#[case::netty_lower_end("4.1.91.Final =< 4.1.117.Final", ">= 4.1.91, <= 4.1.117")]
#[case::harbor_partial_lower_ends("2.x < 2.4.3; 2.5<2.5.2", ">= 2.x, < 2.4.3 || >= 2.5, < 2.5.2")]
#[case::aspnetcore_upper_ends(
    ">=5.0.0,6.0.0, >=4.6.0, 4.7.0",
    ">= 5.0.0, <= 6.0.0 || >= 4.6.0, <= 4.7.0"
)]
#[case::cilium_other_branch(
    "1.7, 1.8, 1.9, 1.10, <=1.11.15, <= 1.12.8, <= 1.13.1",
    "= 1.7 || = 1.8 || = 1.9 || = 1.10 || <= 1.11.15 || >= 1.12.0, <= 1.12.8 || >= 1.13.0, <= 1.13.1"
)]
#[case::git_other_branches(
    "v2.48.0 <=v2.47.1 <=v2.46.2",
    "= 2.48.0 || >= 2.47.0, <= 2.47.1 || <= 2.46.2"
)]
#[case::containerd_after_upper_bound("< 1.4.12, 1.5.0, 1.5.1", "< 1.4.12 || = 1.5.0 || = 1.5.1")]
fn reads_bare_versions_next_to_bounds(#[case] input: &str, #[case] expected: &str) {
    assert_eq!(normalize_version_range(input), expected);
}

// Text without a usable version must not come out as something that parses. The caller only
// warns when parsing fails, so an invented meaning would go unnoticed.
#[rstest]
#[case::caddy_note_only("(confirmed on main @ e0f8d9b2047af417d8faf354b675941f3dac9891)")]
#[case::gitea_through_main("<= 1.24 through main (confirmed in v1.27.0-dev)")]
#[case::kyverno_none("NONE")]
#[case::podman_arrow("Podman v4.0->v4.9.3, and v5.0")]
fn garbage_stays_unparsable(#[case] input: &str) {
    let normalized = normalize_version_range(input);
    let still_fails = normalized
        .split("||")
        .any(|part| semver::VersionReq::parse(part.trim()).is_err());
    assert!(still_fails, "`{input}` became `{normalized}`, which parses");
}
