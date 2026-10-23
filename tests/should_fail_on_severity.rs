// `should_fail_on_severity` decides whether kagami exits with `1` after the output. It does when
// any advisory is at the given severity or higher, and never when no severity is given.
use chrono::DateTime;
use kagami::AdvisoryType;
use kagami::advisory::{Advisory, CvssScore, CvssSeverities, Severity, TargetWithAdvisory};
use kagami::fail_on_severity::should_fail_on_severity;
use rstest::rstest;

#[rstest]
#[case::not_set(vec![Severity::Critical], None, false)]
#[case::no_advisories(vec![], Some(Severity::Unknown), false)]
#[case::same_severity(vec![Severity::High], Some(Severity::High), true)]
#[case::higher_severity(vec![Severity::Critical], Some(Severity::High), true)]
#[case::lower_severity(vec![Severity::Medium], Some(Severity::High), false)]
#[case::one_of_several_targets(vec![Severity::Low, Severity::Critical], Some(Severity::High), true)]
// `unknown` is the lowest severity
#[case::unknown_includes_unknown(vec![Severity::Unknown], Some(Severity::Unknown), true)]
#[case::low_excludes_unknown(vec![Severity::Unknown], Some(Severity::Low), false)]
fn fails_on_severity_or_higher(
    #[case] found: Vec<Severity>,
    #[case] fail_on_severity: Option<Severity>,
    #[case] expected: bool,
) {
    // Each advisory is found for a target of its own
    let results: Vec<TargetWithAdvisory> = found
        .iter()
        .map(|severity| TargetWithAdvisory {
            name: Some("lodash".to_string()),
            version: "4.17.20".to_string(),
            ecosystem: None,
            advisory_type: AdvisoryType::Github,
            repository_path: None,
            advisories: vec![Advisory {
                ghsa_id: "GHSA-0000-0000-0000".to_string(),
                cve_id: None,
                summary: String::new(),
                description: String::new(),
                severity: *severity,
                cvss_severities: CvssSeverities {
                    cvss_v3: CvssScore {
                        vector_string: None,
                        score: None,
                    },
                    cvss_v4: CvssScore {
                        vector_string: None,
                        score: None,
                    },
                },
                epss: None,
                html_url: String::new(),
                published_at: DateTime::UNIX_EPOCH,
                updated_at: DateTime::UNIX_EPOCH,
                withdrawn_at: None,
                vulnerabilities: vec![],
            }],
        })
        .collect();

    assert_eq!(
        should_fail_on_severity(&results, fail_on_severity),
        expected
    );
}
