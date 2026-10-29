use crate::advisory::{Advisory, CvssScore, Epss, Severity, TargetWithAdvisory, Vulnerability};
use crate::error::KagamiError;
use crate::{KagamiCommands, OutputFormat};
use chrono::{DateTime, Utc};
use clap::CommandFactory;
use console::{Color, Term, measure_text_width, style};
use log::trace;
use std::env;
use std::error::Error;

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
        OutputFormat::Text => output_text(results)?,
        OutputFormat::SimpleMarkdownText => output_simple_markdown_text(results)?,
    };
    Ok(())
}

fn output_simple_markdown_text(targets: &[TargetWithAdvisory]) -> Result<(), Box<dyn Error>> {
    let stdout_terminal = Term::stdout();
    let not_vulnerable = targets
        .iter()
        .flat_map(|v| &v.advisories)
        .collect::<Vec<_>>()
        .is_empty();

    if not_vulnerable {
        stdout_terminal.write_line("✅ There is no vulnerable targets!")?;
        return Ok(());
    }

    let vulnerable_targets = targets
        .iter()
        .filter(|v| !v.advisories.is_empty())
        .collect::<Vec<&TargetWithAdvisory>>();

    stdout_terminal.write_line(
        format!(
            "⚠️ *{}* vulnerable target(s) detected! ⚠️",
            vulnerable_targets.len()
        )
        .as_str(),
    )?;

    for target in vulnerable_targets {
        stdout_terminal.write_line(
            format!(
                "`{}@{}`{}",
                target
                    .name
                    .as_ref()
                    .or(target.repository_path.as_ref())
                    .unwrap_or(&"".to_string()),
                target.version,
                match &target.ecosystem {
                    Some(ecosystem) => format!(" ({})", ecosystem),
                    None => "".to_string(),
                }
            )
            .as_str(),
        )?;

        for advisory in &target.advisories {
            stdout_terminal.write_line(
                format!(
                    "{} [{}] {}",
                    emoji_severity(advisory.severity),
                    advisory.severity,
                    advisory.html_url
                )
                .as_str(),
            )?;
        }
    }

    Ok(())
}

fn output_text(targets: &Vec<TargetWithAdvisory>) -> Result<(), Box<dyn Error>> {
    let stdout_terminal = Term::stdout();
    let target_count = targets.len();
    let critical_count = get_count_by_severity_for_target(targets, Severity::Critical);
    let high_count = get_count_by_severity_for_target(targets, Severity::High);
    let medium_count = get_count_by_severity_for_target(targets, Severity::Medium);
    let low_count = get_count_by_severity_for_target(targets, Severity::Low);
    let unknown_count = get_count_by_severity_for_target(targets, Severity::Unknown);
    let total_count = critical_count + high_count + medium_count + low_count + unknown_count;

    stdout_terminal.write_line(
        format!(
            "{} Advisories found for {} targets - {} {}, {} {}, {} {}, {} {}, {} {}",
            style(total_count).bold().cyan(),
            style(target_count).bold().cyan(),
            styled_severity(Severity::Critical),
            style(critical_count).bold(),
            styled_severity(Severity::High),
            style(high_count).bold(),
            styled_severity(Severity::Medium),
            style(medium_count).bold(),
            styled_severity(Severity::Low),
            style(low_count).bold(),
            styled_severity(Severity::Unknown),
            style(unknown_count).bold()
        )
        .as_str(),
    )?;

    for target in targets {
        // Target header
        print_console_divider(&stdout_terminal)?;
        stdout_terminal.write_line(
            format!(
                "📦 {}@{} {} {}",
                style(
                    target
                        .name
                        .as_ref()
                        .or(target.repository_path.as_ref())
                        .unwrap_or(&"".to_string())
                )
                .cyan()
                .bold(),
                style(&target.version).cyan().bold(),
                style(target.advisory_type.to_string()).dim(),
                style(target.ecosystem.as_ref().unwrap_or(&"".to_string())).dim()
            )
            .as_str(),
        )?;
        print_console_divider(&stdout_terminal)?;

        // Counts for target
        let critical_count =
            get_count_by_severity_for_advisories(&target.advisories, Severity::Critical);
        let high_count = get_count_by_severity_for_advisories(&target.advisories, Severity::High);
        let medium_count =
            get_count_by_severity_for_advisories(&target.advisories, Severity::Medium);
        let low_count = get_count_by_severity_for_advisories(&target.advisories, Severity::Low);
        let unknown_count =
            get_count_by_severity_for_advisories(&target.advisories, Severity::Unknown);
        let total_count = critical_count + high_count + medium_count + low_count + unknown_count;

        stdout_terminal.write_line(
            format!(
                "{} Advisories found - {} {}, {} {}, {} {}, {} {}, {} {}",
                style(total_count).bold().cyan(),
                styled_severity(Severity::Critical),
                style(critical_count).bold(),
                styled_severity(Severity::High),
                style(high_count).bold(),
                styled_severity(Severity::Medium),
                style(medium_count).bold(),
                styled_severity(Severity::Low),
                style(low_count).bold(),
                styled_severity(Severity::Unknown),
                style(unknown_count).bold()
            )
            .as_str(),
        )?;

        for advisory in &target.advisories {
            // Title line
            stdout_terminal.write_line(
                format!(
                    "{} - {}",
                    styled_severity(advisory.severity),
                    style(&advisory.summary).cyan().bold()
                )
                .as_str(),
            )?;
            // Detailed output
            print_advisory_details(&stdout_terminal, advisory)?;
        }
    }

    Ok(())
}

fn styled_severity(severity: Severity) -> String {
    match severity {
        Severity::Unknown => style("Unknown").bold().white().bg(Color::Black),
        Severity::Low => style("Low").bold().green(),
        Severity::Medium => style("Medium").bold().yellow(),
        Severity::High => style("High").bold().red(),
        Severity::Critical => style("Critical").bold().white().bg(Color::Red),
    }
    .to_string()
}

fn emoji_severity(severity: Severity) -> String {
    match severity {
        Severity::Unknown => "⚪",
        Severity::Low => "⚪",
        Severity::Medium => "🟠",
        Severity::High => "🔴",
        Severity::Critical => "🚨",
    }
    .to_string()
}

fn print_advisory_details(terminal: &Term, advisory: &Advisory) -> Result<(), Box<dyn Error>> {
    let ids = match &advisory.cve_id {
        Some(cve_id) => format!("{} / {}", advisory.ghsa_id, cve_id),
        None => advisory.ghsa_id.clone(),
    };

    terminal.write_line(format!("{}{}", styled_detail_label("ID"), style(ids).bold()).as_str())?;
    terminal.write_line(
        format!(
            "{}{}",
            styled_detail_label("URL"),
            style(&advisory.html_url).underlined()
        )
        .as_str(),
    )?;
    terminal.write_line(
        format!(
            "{}{}",
            styled_detail_label("CVSS v3"),
            styled_cvss_score(&advisory.cvss_severities.cvss_v3)
        )
        .as_str(),
    )?;
    terminal.write_line(
        format!(
            "{}{}",
            styled_detail_label("CVSS v4"),
            styled_cvss_score(&advisory.cvss_severities.cvss_v4)
        )
        .as_str(),
    )?;
    terminal.write_line(
        format!(
            "{}{}",
            styled_detail_label("EPSS"),
            styled_epss(advisory.epss)
        )
        .as_str(),
    )?;
    terminal.write_line(
        format!(
            "{}{} (updated {})",
            styled_detail_label("Published"),
            formatted_date(&advisory.published_at),
            formatted_date(&advisory.updated_at)
        )
        .as_str(),
    )?;
    if let Some(withdrawn_at) = &advisory.withdrawn_at {
        terminal.write_line(
            format!(
                "{}{}",
                styled_detail_label("Withdrawn"),
                style(formatted_date(withdrawn_at)).yellow().bold()
            )
            .as_str(),
        )?;
    }
    for (index, vulnerability) in advisory.vulnerabilities.iter().enumerate() {
        // Only the first affected package carries the label, the others line up under it.
        let label = if index == 0 { "Affected" } else { "" };
        terminal.write_line(
            format!(
                "{}{}",
                styled_detail_label(label),
                styled_vulnerability(vulnerability)
            )
            .as_str(),
        )?;
    }
    terminal.write_line("")?;

    Ok(())
}

fn styled_detail_label(label: &str) -> String {
    let label_width = 11usize;
    style(format!("{label:<label_width$}")).dim().to_string()
}

fn styled_cvss_score(cvss: &CvssScore) -> String {
    // GitHub returns a 0.0 score without a vector string for a CVSS version it has not assessed.
    let score = cvss.score.filter(|score| *score > 0.0);
    match (score, &cvss.vector_string) {
        (Some(score), Some(vector)) => format!(
            "{} ({})",
            style(format!("{score:.1}")).bold(),
            style(vector).dim()
        ),
        (Some(score), None) => style(format!("{score:.1}")).bold().to_string(),
        (None, Some(vector)) => style(vector).dim().to_string(),
        (None, None) => style("N/A").dim().to_string(),
    }
}

fn styled_epss(epss: Option<Epss>) -> String {
    match epss {
        // EPSS values are fractions, so both are shown as percentages.
        Some(epss) => format!(
            "{}% ({:.1}th percentile)",
            style(format!("{:.3}", epss.percentage * 100.0)).bold(),
            epss.percentile * 100.0
        ),
        None => style("N/A").dim().to_string(),
    }
}

fn styled_vulnerability(vulnerability: &Vulnerability) -> String {
    // Repository advisories may leave the package or range empty, so only filled parts are shown.
    let package = [
        vulnerability.package.ecosystem.as_str(),
        vulnerability.package.name.as_str(),
    ]
    .into_iter()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join("/");

    let patched = if vulnerability.patched_versions.is_empty() {
        style("no patched version").red().to_string()
    } else {
        format!(
            "patched: {}",
            style(vulnerability.patched_versions.join(", ")).green()
        )
    };

    let mut parts: Vec<String> = vec![];
    if !package.is_empty() {
        parts.push(style(package).bold().to_string());
    }
    if !vulnerability.vulnerable_version_range.is_empty() {
        parts.push(vulnerability.vulnerable_version_range.clone());
    }
    parts.push(format!("({patched})"));

    parts.join(" ")
}

fn formatted_date(date: &DateTime<Utc>) -> String {
    date.format("%Y-%m-%d").to_string()
}

fn print_console_divider(terminal: &Term) -> Result<(), Box<dyn Error>> {
    let (_, width) = terminal.size();
    let min_size = 150u16;
    let write_width =
        [min_size, width]
            .into_iter()
            .min()
            .ok_or(Box::new(KagamiError::OptionalGuard(
                "write_width".to_string(),
            )))?;
    trace!(
        "Terminal width is {}, divider width is {}.",
        width, write_width
    );

    let divider_str = "━".repeat(usize::from(write_width));
    terminal.write_line(style(divider_str).cyan().to_string().as_str())?;

    Ok(())
}

fn get_count_by_severity_for_target(results: &[TargetWithAdvisory], severity: Severity) -> usize {
    results
        .iter()
        .flat_map(|v| &v.advisories)
        .filter(|v| v.severity == severity)
        .collect::<Vec<_>>()
        .len()
}

fn get_count_by_severity_for_advisories(results: &[Advisory], severity: Severity) -> usize {
    results
        .iter()
        .filter(|v| v.severity == severity)
        .collect::<Vec<_>>()
        .len()
}

pub fn output_version(fancy: bool) -> Result<(), Box<dyn Error>> {
    if !fancy {
        print!("{}", KagamiCommands::command().render_version());
        return Ok(());
    }

    output_fancy_version()
}

fn output_fancy_version() -> Result<(), Box<dyn Error>> {
    let stdout_terminal = Term::stdout();

    // 鏡 (kagami) means a mirror in Japanese
    let logo = [
        "    .####.         ###",
        "   .###'###. ################",
        "  .##'   '###   ##.    .##'",
        ".###'     '#'   '##    ##'",
        "'########## ##################",
        "  '''###'''   ..............",
        " ....###....  ##''''''''''##",
        " ###########  ##..........##",
        "     ###  .   ##''''''''''##",
        " '## ###  ##  ##..........##",
        "  ## ### ##'  '''##'''###'''",
        "  ## ### ''     ###   ###",
        "     ###...##  .##'   ###  '..",
        "'#########''#.###'    ###  .##",
        " ''''      ###''      '######'",
    ];
    let logo_width = 33usize;

    let details = [
        format!(
            "{}{}",
            styled_detail_label("Package"),
            style(env!("CARGO_PKG_NAME")).bold()
        ),
        format!(
            "{}{}",
            styled_detail_label("License"),
            style(env!("CARGO_PKG_LICENSE")).bold()
        ),
        format!(
            "{}{}",
            styled_detail_label("Repository"),
            style(env!("CARGO_PKG_REPOSITORY")).bold()
        ),
        format!(
            "{}{}",
            styled_detail_label("Platform"),
            style(format!("{} {}", env::consts::OS, env::consts::ARCH)).bold()
        ),
        format!(
            "{}{}",
            styled_detail_label("MSRV"),
            style(env!("CARGO_PKG_RUST_VERSION")).bold()
        ),
    ];
    let divider_width = details
        .iter()
        .map(|line| measure_text_width(line))
        .max()
        .unwrap_or(0);

    let mut info = vec![
        format!(
            "{} {}",
            style("kagami").cyan().bold(),
            style(env!("CARGO_PKG_VERSION")).bold()
        ),
        style("━".repeat(divider_width)).cyan().to_string(),
    ];
    info.extend(details);

    // The info is centered vertically next to the logo
    let info_top = logo.len().saturating_sub(info.len()) / 2;

    for row in 0..logo.len().max(info_top + info.len()) {
        let logo_line = logo.get(row).unwrap_or(&"");
        let info_line = row
            .checked_sub(info_top)
            .and_then(|index| info.get(index))
            .map(|line| line.as_str())
            .unwrap_or("");
        stdout_terminal.write_line(
            format!(
                "{}{}",
                styled_logo_line(format!("{logo_line:<logo_width$}").as_str(), row),
                info_line
            )
            .as_str(),
        )?;
    }

    Ok(())
}

fn styled_logo_line(line: &str, row: usize) -> String {
    // Orange, light green, sky blue, blue, light pink and deep pink run diagonally across the logo.
    // A row counts twice, as a character is about twice as tall as it is wide.
    let gradient = [
        (0xff, 0x92, 0x33),
        (0x97, 0xf2, 0x79),
        (0x57, 0xdd, 0xff),
        (0x47, 0x78, 0xff),
        (0xff, 0xa3, 0xd4),
        (0xfa, 0x2d, 0x86),
    ];
    // 33 columns and 15 rows of the logo make 61 steps along the diagonal
    let diagonal_length = 61usize;

    line.chars()
        .enumerate()
        .map(|(column, c)| {
            let index =
                ((column + row * 2) * gradient.len() / diagonal_length).min(gradient.len() - 1);
            let (red, green, blue) = gradient[index];
            style(c).true_color(red, green, blue).to_string()
        })
        .collect()
}
