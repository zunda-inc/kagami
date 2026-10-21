use crate::normalize_version::{bound_every_version, interval_to_requirement};

// Turns the English of hand-written ranges into operators:
// `1.20.1 and earlier` -> `<= 1.20.1`
// `7.2.10 and below, 8.0.5 and below` -> `<= 7.2.10, <= 8.0.5`
// `6.2 or newer` -> `>= 6.2`
// `2.0.0+` -> `>= 2.0.0`
// `All versions prior to 1.7.14 and 1.8.7` -> `< 1.7.14, < 1.8.7`
// `2.2.0 <= V <= 2.10.1` -> `>= 2.2.0, <= 2.10.1`
// `1.2.0 through 1.8.7` -> `1.2.0 - 1.8.7` (the hyphen range is handled later)
// `>= 1.0 and < 2.0` -> `>= 1.0, < 2.0`
pub fn words_to_operators(range: &str) -> String {
    let range = strip_prefix_ignore_case(range, "all versions").unwrap_or(range);
    let range = strip_prefix_ignore_case(range, "from ").unwrap_or(range);

    let upper_bound_prefixes = [
        ("up to and including", "<="),
        ("up to", "<="),
        ("prior to", "<"),
        ("earlier than", "<"),
        ("before", "<"),
        ("until", "<"),
    ];
    for (phrase, operator) in upper_bound_prefixes {
        if let Some(versions) = strip_prefix_ignore_case(range, phrase) {
            return bound_every_version(versions, operator, "");
        }
    }

    let bound_suffixes = [
        ("and newer", ">="),
        ("or newer", ">="),
        ("and later", ">="),
        ("or later", ">="),
        ("and above", ">="),
        ("or above", ">="),
        ("and earlier", "<="),
        ("or earlier", "<="),
        ("and before", "<="),
        ("or before", "<="),
        ("and below", "<="),
        ("or below", "<="),
        ("and lower", "<="),
        ("or lower", "<="),
        ("and older", "<="),
        ("or older", "<="),
        ("and prior", "<="),
    ];
    for (phrase, operator) in bound_suffixes {
        if let Some(versions) = strip_suffix_ignore_case(range, phrase) {
            return bound_every_version(versions, operator, phrase);
        }
    }

    if let Some(version) = range.strip_suffix('+')
        && !version.contains([' ', ','])
    {
        return format!(">= {version}");
    }

    if let Some(requirement) = interval_to_requirement(range) {
        return requirement;
    }

    let range = replace_ignore_case(range, " up to and including ", " - ");
    let range = replace_ignore_case(&range, " through and including ", " - ");
    let range = replace_ignore_case(&range, " through ", " - ");
    let range = replace_ignore_case(&range, " until ", " - ");
    let range = replace_ignore_case(&range, " to ", " - ");
    replace_ignore_case(&range, " and ", ", ")
}

// ----- text helpers -----

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let candidate = text.get(..prefix.len())?;
    if candidate.eq_ignore_ascii_case(prefix) {
        Some(text[prefix.len()..].trim_start())
    } else {
        None
    }
}

fn strip_suffix_ignore_case<'a>(text: &'a str, suffix: &str) -> Option<&'a str> {
    let start = text.len().checked_sub(suffix.len())?;
    let candidate = text.get(start..)?;
    if candidate.eq_ignore_ascii_case(suffix) {
        Some(text[..start].trim_end())
    } else {
        None
    }
}

pub fn replace_ignore_case(text: &str, from: &str, to: &str) -> String {
    let lowercase_text = text.to_ascii_lowercase();
    let lowercase_from = from.to_ascii_lowercase();
    let mut result = String::new();
    let mut rest_starts_at = 0;
    for (index, _) in lowercase_text.match_indices(&lowercase_from) {
        result.push_str(&text[rest_starts_at..index]);
        result.push_str(to);
        rest_starts_at = index + from.len();
    }
    result.push_str(&text[rest_starts_at..]);
    result
}

// `≤`, `=<`, `=>`, `< =` and `==` become `<=`, `>=` and `=`. `&&`, `;` and the full-width comma become `,`.
// An en dash becomes ` - `. Markdown escapes, backticks and a trailing period are dropped.
pub fn replace_unusual_characters(range: &str) -> String {
    range
        .trim()
        .trim_end_matches('.')
        .replace('≤', "<=")
        .replace('≥', ">=")
        .replace("=<", "<=")
        .replace("=>", ">=")
        .replace("< =", "<=")
        .replace("> =", ">=")
        .replace("==", "=")
        .replace("&&", ",")
        .replace([';', '，'], ",")
        .replace(['–', '—'], " - ")
        .replace(['\\', '`'], "")
}
