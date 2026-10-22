// `Target::validate` rejects a target of `kagami.yaml` before any API call is made. Targets are
// written in YAML flow style and the cases check the message the user gets.
use kagami::Target;
use rstest::rstest;

// 1. Mistakes in a target
#[rstest]
#[case::github_without_name(
    "{ version: 1.29.0, advisory_type: github }",
    "Please specify `name` when the `advisory_type` is `github`."
)]
#[case::github_repository_without_path(
    "{ version: 8.5.9, advisory_type: github_repository }",
    "Please specify `repository_path` when the `advisory_type` is `github_repository`."
)]
#[case::v_prefixed_version(
    "{ name: k8s.io/kubernetes, version: v1.29.0, advisory_type: github }",
    "`version` is not valid semver."
)]
#[case::partial_version(
    "{ name: k8s.io/kubernetes, version: 1.29, advisory_type: github }",
    "`version` is not valid semver."
)]
#[case::path_without_owner(
    "{ version: 8.5.9, advisory_type: github_repository, repository_path: php-src }",
    "`repository_path` is invalid."
)]
#[case::path_as_url(
    "{ version: 8.5.9, advisory_type: github_repository, repository_path: 'https://github.com/php/php-src' }",
    "`repository_path` is invalid."
)]
#[case::path_with_trailing_slash(
    "{ version: 8.5.9, advisory_type: github_repository, repository_path: php/php-src/ }",
    "`repository_path` is invalid."
)]
#[case::path_with_empty_owner(
    "{ version: 8.5.9, advisory_type: github_repository, repository_path: /php-src }",
    "`repository_path` is invalid."
)]
#[case::path_with_empty_name(
    "{ version: 8.5.9, advisory_type: github_repository, repository_path: php/ }",
    "`repository_path` is invalid."
)]
fn rejects_invalid_targets(#[case] yaml: &str, #[case] expected: &str) {
    let target: Target = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(target.validate().unwrap_err().to_string(), expected);
}

// 2. Valid targets
#[rstest]
#[case::github_repository(
    "{ version: 8.5.9, advisory_type: github_repository, repository_path: php/php-src }"
)]
#[case::github(
    "{ name: k8s.io/kubernetes, version: 1.29.0, ecosystem: go, advisory_type: github }"
)]
#[case::github_without_ecosystem("{ name: lodash, version: 4.17.20, advisory_type: github }")]
#[case::prerelease_version(
    "{ name: k8s.io/kubernetes, version: 1.33.0-rc.1, advisory_type: github }"
)]
fn accepts_valid_targets(#[case] yaml: &str) {
    let target: Target = yaml_serde::from_str(yaml).unwrap();

    target.validate().unwrap();
}

// 3. `repository_path` becomes the owner and the name of the repository
#[rstest]
#[case::php_src(
    "{ version: 8.5.9, advisory_type: github_repository, repository_path: php/php-src }"
)]
#[case::spaces_around_slash(
    "{ version: 8.5.9, advisory_type: github_repository, repository_path: 'php / php-src' }"
)]
fn splits_repository_path(#[case] yaml: &str) {
    let target: Target = yaml_serde::from_str(yaml).unwrap();

    assert_eq!(
        target.extract_repository_path().unwrap(),
        Some(["php", "php-src"])
    );
}
