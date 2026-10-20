use crate::OutputFormat;
use crate::advisory::{Severity, TargetWithAdvisory};
use console::{Color, style};
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
        OutputFormat::Text => output_text(results),
    };
    Ok(())
}

fn output_text(targets: &Vec<TargetWithAdvisory>) {
    let target_count = targets.len();
    let critical_count = get_count_by_severity(&targets, Severity::Critical);
    let high_count = get_count_by_severity(&targets, Severity::High);
    let medium_count = get_count_by_severity(&targets, Severity::Medium);
    let low_count = get_count_by_severity(&targets, Severity::Low);
    let unknown_count = get_count_by_severity(&targets, Severity::Unknown);
    let total_count = critical_count + high_count + medium_count + low_count + unknown_count;

    println!(
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
    );

    for target in targets {

    }
}

fn get_count_by_severity(results: &Vec<TargetWithAdvisory>, severity: Severity) -> usize {
    results
        .iter()
        .flat_map(|v| &v.advisories)
        .filter(|v| v.severity == severity)
        .collect::<Vec<_>>()
        .len()
}
