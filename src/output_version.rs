use crate::KagamiCommands;
use crate::terminal_helper::{TerminalStyledLine, generate_terminal_lines};
use clap::CommandFactory;
use console::{Term, style};
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
struct Rgb {
    red: u32,
    green: u32,
    blue: u32,
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

pub fn create_gradient_logo() {
    // 最大30文字の行が15列あるとき、行ごとに1文字ずつ左にずらしていくので、合わせる色のテープは 30文字 + (15行 x ずらす1文字) = 45文字あれば良い
    // これをそれぞれの色の数、すなわち6色で割ると、1色あたり7.5文字になる
    // 45文字を7.5文字ごとに色を変えていった色のテープを作り、1文字ずつ左にずらしていくと、いい感じになる。
}

pub fn output_version(is_fancy_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    let stdout_terminal = Term::stdout();

    if !is_fancy_output {
        stdout_terminal.write_line(&KagamiCommands::command().render_version())?;
    }

    Ok(())
}

pub fn output_fancy_version(term: &Term) -> Result<(), Box<dyn std::error::Error>> {
    let mut details_strs: Vec<String> = vec![];
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
    details_strs.push(format!(
        "{}@{}",
        style("kagami").cyan(),
        style(env!("CARGO_PKG_VERSION")).magenta()
    ));
    details_strs.push(style("━".repeat(100)).cyan().to_string());
    details_strs.extend(details);

    Ok(())
}
