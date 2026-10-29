use console::{Term, measure_text_width};

#[derive(Clone)]
pub struct TerminalStyledLine {
    pub label: String,
    pub content: String,
}

impl TerminalStyledLine {
    pub fn label_length(self) -> usize {
        measure_text_width(&self.label)
    }
}

pub fn generate_terminal_lines(lines: &[TerminalStyledLine], h_gap: Option<usize>) -> Vec<String> {
    let h_gap = h_gap.unwrap_or(2);
    let max_label_length = lines
        .iter()
        .map(|l| l.clone().label_length())
        .max()
        .unwrap_or(0)
        + h_gap;
    let mut formatted_lines: Vec<String> = vec![];

    for line in lines {
        let insert_string_length = max_label_length - measure_text_width(&line.label);
        let content_lines = line.content.split("\n").collect::<Vec<&str>>();
        let content_first_line = content_lines[0];
        let label_line = format!(
            "{}{}{}",
            line.label,
            " ".repeat(insert_string_length),
            content_first_line
        );

        formatted_lines.push(label_line);

        for x in content_lines[1..].iter() {
            let content_line = format!("{}{}", " ".repeat(max_label_length), x);
            formatted_lines.push(content_line)
        }
    }

    formatted_lines
}

pub fn print_string_vec(
    terminal: &Term,
    lines: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    for line in lines {
        terminal.write_line(&line)?
    }

    Ok(())
}
