use crate::KagamiCommands;
use crate::terminal_helper::{TerminalStyledLine, generate_terminal_lines};
use clap::CommandFactory;
use console::{Term, measure_text_width, style};
use std::collections::VecDeque;
use std::env;

static LOGO: [&str; 15] = [
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

#[derive(Clone)]
pub struct Rgb {
    red: u8,
    green: u8,
    blue: u8,
}

static GRADIENT_COLOR: [Rgb; 6] = [
    Rgb {
        red: 0xff,
        green: 0x92,
        blue: 0x33,
    }, // Pastel yellow
    Rgb {
        red: 0x97,
        green: 0xf2,
        blue: 0x79,
    }, // Pastel green
    Rgb {
        red: 0x57,
        green: 0xdd,
        blue: 0xff,
    }, // Pastel light blue
    Rgb {
        red: 0x47,
        green: 0x78,
        blue: 0xff,
    }, // Pastel Blue
    Rgb {
        red: 0xff,
        green: 0xa3,
        blue: 0xd4,
    }, // Pastel violet
    Rgb {
        red: 0xfa,
        green: 0x2d,
        blue: 0x86,
    }, // Pastel red
];

pub fn create_gradient_logo(
    logo: impl IntoIterator<Item = impl Into<String>>,
    gradient_colors: &[Rgb],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    // With 15 rows of up to 30 characters, shifting each row one character to the left
    // means the color tape needs 30 characters + (15 rows x 1 character shift) = 45 characters.
    // Dividing this by the number of colors, 6, gives 7.5 characters per color.
    // Create a color tape that changes color every 7.5 characters across 45 characters,
    // then shift it one character to the left for each row to get a nice effect.

    let logo: Vec<String> = logo.into_iter().map(|v| v.into()).collect();

    let shift_size_per_line = 1u32;
    let max_logo_line_length = u32::try_from(logo.iter().map(|l| l.len()).max().unwrap_or(0))?;
    let color_tape_length =
        max_logo_line_length + (u32::try_from(logo.len())? * shift_size_per_line);
    let length_by_color = (f64::from(color_tape_length)
        / f64::from(u32::try_from(gradient_colors.len())?))
    .ceil() as u64;

    let mut color_tape: VecDeque<&Rgb> = VecDeque::new();

    for color in gradient_colors {
        for _ in 0..length_by_color {
            color_tape.push_back(color);
        }
    }

    let mut lines: Vec<String> = vec![];

    for logo_line in logo {
        let mut line = String::new();
        for (idx, c) in logo_line.chars().enumerate() {
            let color = color_tape[idx];
            line = line
                + &style(c)
                    .true_color(color.red, color.green, color.blue)
                    .to_string();
        }
        lines.push(line);
        color_tape.pop_front();
    }

    Ok(lines)
}

pub fn output_version(is_fancy_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    let stdout_terminal = Term::stdout();

    if !is_fancy_output {
        stdout_terminal.write_line(&KagamiCommands::command().render_version())?;
    }

    output_fancy_version(&stdout_terminal)?;

    Ok(())
}

pub fn output_fancy_version(term: &Term) -> Result<(), Box<dyn std::error::Error>> {
    let mut details_strs: VecDeque<String> = VecDeque::new();
    let details = generate_terminal_lines(
        &[
            TerminalStyledLine {
                label: crate::terminal_helper::styled_detail_label("Package"),
                content: style(env!("CARGO_PKG_NAME")).bold().to_string(),
            },
            TerminalStyledLine {
                label: crate::terminal_helper::styled_detail_label("License"),
                content: style(env!("CARGO_PKG_LICENSE")).bold().to_string(),
            },
            TerminalStyledLine {
                label: crate::terminal_helper::styled_detail_label("Repository"),
                content: style(env!("CARGO_PKG_REPOSITORY")).bold().to_string(),
            },
            TerminalStyledLine {
                label: crate::terminal_helper::styled_detail_label("Platform"),
                content: style(format!("{} {}", env::consts::OS, env::consts::ARCH))
                    .bold()
                    .to_string(),
            },
            TerminalStyledLine {
                label: crate::terminal_helper::styled_detail_label("MSRV"),
                content: style(env!("CARGO_PKG_RUST_VERSION")).bold().to_string(),
            },
        ],
        None,
    );
    details_strs.push_back(format!(
        "{}@{}",
        style("kagami").cyan(),
        style(env!("CARGO_PKG_VERSION")).magenta()
    ));
    details_strs.push_back(style("━".repeat(50)).cyan().to_string());
    details_strs.extend(details.clone());

    let gradient_logo = create_gradient_logo(LOGO, &GRADIENT_COLOR)?;

    // NOTE: text width must be measured with `measure_text_width` because the logo lines
    // contain ANSI escape sequences for color, which do not contribute to the visible width of the text.
    let logo_lines_max_width = gradient_logo
        .iter()
        .map(|l| measure_text_width(l))
        .max()
        .unwrap_or(0);

    let details_start_line = (gradient_logo.len() - details.len()) / 2;

    for (idx, logo_line) in gradient_logo.iter().enumerate() {
        if idx >= details_start_line - 1 && !details_strs.is_empty() {
            let insert_white_space_width = logo_lines_max_width - measure_text_width(logo_line);
            let padding = 4;
            term.write_line(&format!(
                "{}{}{}",
                logo_line,
                " ".repeat(insert_white_space_width + padding),
                details_strs.pop_front().unwrap_or("".to_string())
            ))?;
            continue;
        }

        term.write_line(logo_line)?;
    }

    Ok(())
}
