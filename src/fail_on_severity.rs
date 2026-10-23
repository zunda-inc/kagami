use crate::advisory::{Severity, TargetWithAdvisory};

pub fn should_fail_on_severity(
    results: &Vec<TargetWithAdvisory>,
    severity: Option<Severity>,
) -> bool {
    let severity = match severity {
        Some(s) => s,
        None => return false,
    };

    let target_severities = match severity {
        Severity::Unknown => vec![
            Severity::Unknown,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ],
        Severity::Low => vec![
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ],
        Severity::Medium => vec![Severity::Medium, Severity::High, Severity::Critical],
        Severity::High => vec![Severity::High, Severity::Critical],
        Severity::Critical => vec![Severity::Critical],
    };

    !results
        .iter()
        .flat_map(|t| &t.advisories)
        .filter(|a| target_severities.contains(&a.severity))
        .collect::<Vec<_>>()
        .is_empty()
}
