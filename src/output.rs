use crate::OutputFormat;
use crate::advisory::{Advisory, Severity, TargetWithAdvisory};
use console::{Color, Term, style};
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
    };
    Ok(())
}

fn output_text(targets: &Vec<TargetWithAdvisory>) -> Result<(), Box<dyn Error>> {
    let stdout_terminal = console::Term::stdout();
    let target_count = targets.len();
    let critical_count = get_count_by_severity_for_target(&targets, Severity::Critical);
    let high_count = get_count_by_severity_for_target(&targets, Severity::High);
    let medium_count = get_count_by_severity_for_target(&targets, Severity::Medium);
    let low_count = get_count_by_severity_for_target(&targets, Severity::Low);
    let unknown_count = get_count_by_severity_for_target(&targets, Severity::Unknown);
    let total_count = critical_count + high_count + medium_count + low_count + unknown_count;

    stdout_terminal.write_line(
        format!(
            "{} Advisories found for {} targets - {} {}, {} {}, {} {}, {} {}, {} {}",
            style(total_count).bold().cyan(),
            style(target_count).bold().cyan(),
            style("Critical").bold().white().bg(Color::Red),
            style(critical_count).bold(),
            style("High").bold().red(),
            style(high_count).bold(),
            style("Medium").bold().yellow(),
            style(medium_count).bold(),
            style("Low").bold().green(),
            style(low_count).bold(),
            style("Unknown").bold().white().bg(Color::Black),
            style(unknown_count).bold()
        )
        .as_str(),
    )?;

    for target in targets {
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
                style("Critical").bold().white().bg(Color::Red),
                style(critical_count).bold(),
                style("High").bold().red(),
                style(high_count).bold(),
                style("Medium").bold().yellow(),
                style(medium_count).bold(),
                style("Low").bold().green(),
                style(low_count).bold(),
                style("Unknown").bold().white().bg(Color::Black),
                style(unknown_count).bold()
            )
            .as_str(),
        )?;
    }

    Ok(())
}

fn print_console_divider(terminal: &Term) -> Result<(), Box<dyn Error>> {
    let (_, width) = terminal.size();
    let min_size = 100u16;
    let write_width = [min_size, width]
        .into_iter()
        .min()
        .expect("`write_width` must not be None.");
    let divider_str = "━".repeat(usize::from(write_width));
    terminal.write_line(style(divider_str).cyan().to_string().as_str())?;
    Ok(())
}

fn get_count_by_severity_for_target(
    results: &Vec<TargetWithAdvisory>,
    severity: Severity,
) -> usize {
    results
        .iter()
        .flat_map(|v| &v.advisories)
        .filter(|v| v.severity == severity)
        .collect::<Vec<_>>()
        .len()
}

fn get_count_by_severity_for_advisories(results: &Vec<Advisory>, severity: Severity) -> usize {
    results
        .iter()
        .filter(|v| v.severity == severity)
        .collect::<Vec<_>>()
        .len()
}
