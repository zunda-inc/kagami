use crate::advisory::{Advisory, CvssScore, Severity, TargetWithAdvisory, Vulnerability};
use crate::{AdvisoryType, OutputFormat};
use console::{Emoji, Style, Term, style};
use itertools::Itertools;
use std::cmp::Reverse;
use std::error::Error;
use std::fmt::Display;

static PACKAGE: Emoji<'_, '_> = Emoji("📦 ", "");
static CHECK: Emoji<'_, '_> = Emoji("✅ ", "");

const INDENT: &str = "  ";
/// Width of the severity badge column. Advisory details are aligned right after it.
const BADGE_WIDTH: usize = 8;
const LABEL_WIDTH: usize = 9;
const SEVERITY_ORDER: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Unknown,
];

pub fn output_to_stdout(
    output_format: &OutputFormat,
    results: &Vec<TargetWithAdvisory>,
) -> Result<(), Box<dyn Error>> {
    match output_format {
        OutputFormat::Json => {
            let json = serde_json::to_string(&results)?;
            println!("{json}");
        }
        OutputFormat::Yaml => {
            let yaml = yaml_serde::to_string(&results)?;
            println!("{yaml}");
        }
        OutputFormat::Text => output_text(results),
    };
    Ok(())
}

fn output_text(results: &[TargetWithAdvisory]) {
    if results.is_empty() {
        println!(
            "{CHECK}{}",
            style("No vulnerabilities found.").green().bold()
        );
        return;
    }

    let width = Term::stdout()
        .size_checked()
        .map_or(80, |(_, cols)| usize::from(cols))
        .clamp(40, 100);
    let rule = style("━".repeat(width)).cyan();

    // Results for one target are pushed consecutively, so print its header only once.
    let groups = results.iter().chunk_by(|&r| {
        (
            &r.name,
            &r.version,
            &r.ecosystem,
            &r.advisory_type,
            &r.repository_path,
        )
    });
    let mut target_count = 0;
    for (_, group) in &groups {
        let group: Vec<&TargetWithAdvisory> = group.collect();
        target_count += 1;

        println!("{rule}");
        println!("{PACKAGE}{}", target_title(group[0]));
        println!("{rule}");
        let mut advisories: Vec<&Advisory> = group.iter().flat_map(|r| &r.advisories).collect();
        advisories.sort_by_key(|a| Reverse(a.severity));
        for advisory in advisories {
            println!();
            print_advisory(advisory);
        }
        println!();
    }

    print_summary(results, target_count);
}

fn target_title(target: &TargetWithAdvisory) -> String {
    let name = target.name.as_deref();
    let repository_path = target.repository_path.as_deref();
    let title = name.or(repository_path).unwrap_or("(unnamed)");

    let meta = [
        target.ecosystem.as_deref(),
        Some(advisory_type_label(target.advisory_type)),
        // Only worth repeating when the title is not already the repository path.
        name.and(repository_path),
    ]
    .into_iter()
    .flatten()
    .join(" · ");

    format!(
        "{}  {}",
        style(format!("{title}@{}", target.version)).cyan().bold(),
        style(meta).dim()
    )
}

fn advisory_type_label(advisory_type: AdvisoryType) -> &'static str {
    match advisory_type {
        AdvisoryType::Github => "github",
        AdvisoryType::GithubRepository => "github_repository",
    }
}

fn print_advisory(advisory: &Advisory) {
    let (label, severity_style) = severity_style(advisory.severity);
    let badge = severity_style.apply_to(format!("{label:<BADGE_WIDTH$}"));

    let mut heading = style(&advisory.ghsa_id).bold().to_string();
    if let Some(cve_id) = &advisory.cve_id {
        heading = format!("{heading}  {}", style(cve_id).dim());
    }
    if let Some(withdrawn_at) = advisory.withdrawn_at {
        let withdrawn = format!("(withdrawn {})", withdrawn_at.format("%Y-%m-%d"));
        heading = format!("{heading}  {}", style(withdrawn).yellow());
    }
    println!("{INDENT}{badge}  {heading}");
    println!(
        "{INDENT}{:BADGE_WIDTH$}  {}",
        "",
        style(&advisory.summary).bold()
    );

    let cvss = &advisory.cvss_severities;
    if let Some(value) = cvss_value(&cvss.cvss_v3) {
        println!("{}", detail_line("CVSS v3", value));
    }
    if let Some(value) = cvss_value(&cvss.cvss_v4) {
        println!("{}", detail_line("CVSS v4", value));
    }
    if let Some(epss) = &advisory.epss {
        let value = format!(
            "{:.3}% (percentile {:.1}%)",
            epss.percentage * 100.0,
            epss.percentile * 100.0
        );
        println!("{}", detail_line("EPSS", value));
    }
    let dates = format!(
        "{}  {} {}",
        advisory.published_at.format("%Y-%m-%d"),
        style("updated").dim(),
        advisory.updated_at.format("%Y-%m-%d")
    );
    println!("{}", detail_line("Published", dates));
    for (i, vulnerability) in advisory.vulnerabilities.iter().enumerate() {
        let label = if i == 0 { "Affects" } else { "" };
        println!("{}", detail_line(label, vulnerability_line(vulnerability)));
    }
    println!(
        "{}",
        detail_line("Link", style(&advisory.html_url).dim().underlined())
    );
}

fn severity_style(severity: Severity) -> (&'static str, Style) {
    match severity {
        Severity::Critical => ("CRITICAL", Style::new().white().on_red().bold()),
        Severity::High => ("HIGH", Style::new().red().bold()),
        Severity::Medium => ("MEDIUM", Style::new().yellow().bold()),
        Severity::Low => ("LOW", Style::new().green().bold()),
        Severity::Unknown => ("UNKNOWN", Style::new().dim().bold()),
    }
}

fn cvss_value(score: &CvssScore) -> Option<String> {
    // GitHub reports a zero score without a vector when that CVSS version is not assessed.
    if score.vector_string.is_none() && score.score.is_none_or(|s| s <= 0.0) {
        return None;
    }
    let value = score.score.map_or("-".to_string(), |s| format!("{s:.1}"));
    Some(match score.vector_string.as_deref() {
        Some(vector) => format!("{}  {}", style(value).bold(), style(vector).dim()),
        None => style(value).bold().to_string(),
    })
}

fn vulnerability_line(vulnerability: &Vulnerability) -> String {
    let package = format!(
        "{}/{}",
        vulnerability.package.ecosystem, vulnerability.package.name
    );
    let patched = if vulnerability.patched_versions.is_empty() {
        style("no patched version".to_string()).dim()
    } else {
        style(format!(
            "patched: {}",
            vulnerability.patched_versions.join(", ")
        ))
        .green()
    };
    format!(
        "{}  {}  {patched}",
        style(package).bold(),
        style(&vulnerability.vulnerable_version_range).red()
    )
}

fn detail_line(label: &str, value: impl Display) -> String {
    format!(
        "{INDENT}{:BADGE_WIDTH$}  {} {value}",
        "",
        style(format!("{label:<LABEL_WIDTH$}")).dim()
    )
}

fn print_summary(results: &[TargetWithAdvisory], target_count: usize) {
    let advisories: Vec<&Advisory> = results.iter().flat_map(|r| &r.advisories).collect();
    let breakdown = SEVERITY_ORDER
        .iter()
        .map(|&severity| {
            let count = advisories.iter().filter(|a| a.severity == severity).count();
            (severity, count)
        })
        .filter(|(_, count)| *count > 0)
        .map(|(severity, count)| {
            let (label, severity_style) = severity_style(severity);
            format!("{} {count}", severity_style.apply_to(label.to_lowercase()))
        })
        .join(" · ");

    let total = format!(
        "{} advisor{} across {} target{}.",
        advisories.len(),
        if advisories.len() == 1 { "y" } else { "ies" },
        target_count,
        if target_count == 1 { "" } else { "s" },
    );
    println!("{}  {breakdown}", style(total).bold());
}
