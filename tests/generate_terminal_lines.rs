// `generate_terminal_lines` puts each content after its label, lined up after the longest label and
// the gap, which is 2 spaces by default. A label is always one line, while a content can have
// several.
use kagami::terminal_helper::{TerminalStyledLine, generate_terminal_lines};

#[test]
fn no_lines_give_nothing() {
    assert_eq!(generate_terminal_lines(&[], None), Vec::<String>::new());
}

#[test]
fn contents_line_up_after_the_longest_label() {
    let lines = [
        TerminalStyledLine {
            label: "Package".to_string(),
            content: "kagami-cli".to_string(),
        },
        TerminalStyledLine {
            label: "Repository".to_string(),
            content: "https://github.com/zunda-inc/kagami".to_string(),
        },
        TerminalStyledLine {
            label: "MSRV".to_string(),
            content: "1.91".to_string(),
        },
    ];

    assert_eq!(
        generate_terminal_lines(&lines, None),
        vec![
            "Package     kagami-cli",
            "Repository  https://github.com/zunda-inc/kagami",
            "MSRV        1.91",
        ]
    );
}

// The lines after the first one of a content line up under its first line.
#[test]
fn content_lines_line_up_under_the_first_one() {
    let lines = [
        TerminalStyledLine {
            label: "ID".to_string(),
            content: "GHSA-mgvx-rpfc-9mpv".to_string(),
        },
        TerminalStyledLine {
            label: "Affected".to_string(),
            content: "go/k8s.io/ingress-nginx < 1.11.5\ngo/k8s.io/ingress-nginx >= 1.12.0-beta.0, < 1.12.1"
                .to_string(),
        },
    ];

    assert_eq!(
        generate_terminal_lines(&lines, None),
        vec![
            "ID        GHSA-mgvx-rpfc-9mpv",
            "Affected  go/k8s.io/ingress-nginx < 1.11.5",
            "          go/k8s.io/ingress-nginx >= 1.12.0-beta.0, < 1.12.1",
        ]
    );
}
