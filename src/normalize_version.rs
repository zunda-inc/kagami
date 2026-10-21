//! Version ranges of GitHub repository advisories are written by hand, so they come in many shapes:
//! `>= v1.19.0`, `All`, `1.2.0 through 1.8.7`, `>= 2.1.0 < 2.2.7`, `<=4.1.135.Final`,
//! `1.20.1 and earlier`, `stable <= 2.8.13; beta <= 3.0.0.beta15`, ...
//!
//! `normalize_version_range` rewrites the shapes whose meaning is clear into the syntax that
//! `semver::VersionReq` accepts. It works as a list of small rules that are applied from top to
//! bottom; every rule is a function with an example in its comment. A shape no rule understands
//! comes out still unparsable, so that the caller fails to parse it and warns about it.
//!
//! Output format: one space between an operator and its version, `, ` between the comparators of
//! one requirement (AND) and ` || ` between alternatives (OR). A range that already parses is
//! returned unchanged, except a list of upper bounds like `< 1.8.4, < 1.9.1`, which is read as
//! release branches.

use crate::normalize_version_words::{
    replace_ignore_case, replace_unusual_characters, words_to_operators,
};
use itertools::Itertools;
use regex::Regex;
use semver::{Comparator, Op, Version, VersionReq};

pub fn normalize_version_range(range: impl Into<String>) -> String {
    let range = range.into();
    let original = range.clone();

    if parses(&range) {
        return upper_bound_lists_to_branches(&range);
    }

    let range = replace_unusual_characters(&range);
    let range = drop_notes_in_parentheses(&range);
    let range = drop_v_prefixes(&range);

    if is_every_version(&range) {
        return "*".to_string();
    }

    let range = words_to_operators(&range);

    let normalized = range
        .split("||")
        .map(normalize_alternative)
        .filter(|alternative| !alternative.is_empty())
        .join(" || ");

    if normalized.is_empty() {
        // Nothing usable was left, for example `(confirmed on main @ e0f8d9b)`. The caller gets
        // the original text, so that its warning shows what the advisory actually said.
        return original.to_string();
    }

    normalized
}

// ----- the whole range -----

// `>= 1.0.0, < 1.2.6 || = 2.0.0` parses when every alternative parses.
fn parses(range: &str) -> bool {
    range
        .split("||")
        .all(|alternative| VersionReq::parse(alternative.trim()).is_ok())
}

// `>= 4.0 (32-bit only)` becomes `>= 4.0`.
fn drop_notes_in_parentheses(range: &str) -> String {
    let without_note = match (range.find('('), range.rfind(')')) {
        (Some(open), Some(close)) if open < close => {
            format!("{}{}", &range[..open], &range[close + 1..])
        }
        (Some(open), _) => range[..open].to_string(),
        _ => range.to_string(),
    };
    without_note.trim().to_string()
}

// `v1.19.0` and `V1.19.0` become `1.19.0`. The `v` of `dev1` stays, it is inside a word.
fn drop_v_prefixes(range: &str) -> String {
    let v_before_digit = Regex::new(r"\b[vV](\d)").expect("the pattern is a constant");
    v_before_digit.replace_all(range, "$1").to_string()
}

// `All`, `all` and `All versions` mean every version.
fn is_every_version(range: &str) -> bool {
    let lowercase = range.trim().to_ascii_lowercase();
    lowercase == "all" || lowercase == "all versions"
}

// `1.14.2, 1.13.2 and 1.12.4` with `<=` -> `<= 1.14.2, <= 1.13.2, <= 1.12.4`.
// `repeated_phrase` is removed everywhere first, for `7.2.10 and below, 8.0.5 and below`.
pub fn bound_every_version(versions: &str, operator: &str, repeated_phrase: &str) -> String {
    let versions = if repeated_phrase.is_empty() {
        versions.to_string()
    } else {
        replace_ignore_case(versions, &format!(" {repeated_phrase}"), "")
    };
    let versions = replace_ignore_case(&versions, " and ", ",");
    versions
        .split(',')
        .map(str::trim)
        .filter(|version| !version.is_empty())
        .map(|version| format!("{operator} {version}"))
        .join(", ")
}

// `2.2.0 <= V <= 2.10.1` -> `>= 2.2.0, <= 2.10.1` and `1.22 < 1.27.1` -> `>= 1.22, < 1.27.1`.
pub fn interval_to_requirement(range: &str) -> Option<String> {
    let words = range.split_whitespace().collect::<Vec<_>>();

    let looks_like_version =
        |word: &str| word.starts_with(|c: char| c.is_ascii_digit()) && !word.contains(',');
    let looks_like_variable = |word: &str| word.starts_with(|c: char| c.is_ascii_alphabetic());
    let is_less_than = |word: &str| word == "<" || word == "<=";
    let flipped = |operator: &str| if operator == "<" { ">" } else { ">=" };

    match words.as_slice() {
        [from, lower_operator, variable, upper_operator, to]
            if looks_like_version(from)
                && looks_like_version(to)
                && looks_like_variable(variable)
                && is_less_than(lower_operator)
                && is_less_than(upper_operator) =>
        {
            Some(format!(
                "{} {from}, {upper_operator} {to}",
                flipped(lower_operator)
            ))
        }
        [from, operator, to]
            if looks_like_version(from) && looks_like_version(to) && is_less_than(operator) =>
        {
            Some(format!(">= {from}, {operator} {to}"))
        }
        _ => None,
    }
}

// ----- one alternative (the parts between `||`) -----

// Comma-separated items are the comparators of one requirement, like `>= 1.0.0, < 1.2.6`, unless an
// item is a requirement by itself: a hyphen range, a `>= a < b` pair or an exact version. Then the
// items are alternatives, like `3.0.0-rc1 - 3.2.0-rc1, 3.1.7` -> `>= 3.0.0-rc1, <= 3.2.0-rc1 || = 3.1.7`.
fn normalize_alternative(alternative: &str) -> String {
    let items = alternative
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();

    let has_digit = |item: &&str| item.chars().any(|c| c.is_ascii_digit());

    let some_item_has_a_digit = items.iter().any(has_digit);
    let requirements = items
        .iter()
        .filter(|item| !some_item_has_a_digit || has_digit(item))
        .map(|item| item_to_comparators(item))
        .collect::<Vec<_>>();

    let every_item_is_one_comparator = requirements
        .iter()
        .all(|comparators| comparators.len() == 1 && !comparators[0].starts_with("= "));

    if every_item_is_one_comparator {
        return group_into_branches(requirements.into_iter().flatten().collect());
    }

    requirements
        .into_iter()
        .map(group_into_branches)
        .join(" || ")
}

// `stable <= 2.8.13` -> ["<= 2.8.13"]
// `3.2.0 - 3.3.8` -> [">= 3.2.0", "<= 3.3.8"]
// `>= 2.1.0 < 2.2.7` -> [">= 2.1.0", "< 2.2.7"]
// `2.9.3+6eba5be` -> ["= 2.9.3"]
fn item_to_comparators(item: &str) -> Vec<String> {
    let item = drop_label(item);

    if let Some((from, to)) = item.split_once(" - ") {
        let (from, to) = (from.trim(), to.trim());
        let both_are_versions = [from, to]
            .iter()
            .all(|side| side.starts_with(|c: char| c.is_ascii_digit()));
        if both_are_versions {
            return vec![
                format!(">= {}", fix_version(from)),
                format!("<= {}", fix_version(to)),
            ];
        }
    }

    split_at_operators(&item)
        .iter()
        .map(|piece| format_comparator(piece))
        .collect()
}

// `stable <= 2.8.13` -> `<= 2.8.13`, `and 3.4.1` -> `3.4.1`: words in front of the first operator or
// version go, as long as they are separate words (the `edge-` of `edge-24.6.2` stays).
fn drop_label(item: &str) -> String {
    let start = item
        .find(|c: char| c.is_ascii_digit() || is_operator_char(c))
        .unwrap_or(0);
    let label = &item[..start];
    let label_is_separate_words =
        label.ends_with(' ') && !label.chars().any(|c| c.is_ascii_digit());
    if label_is_separate_words {
        item[start..].to_string()
    } else {
        item.to_string()
    }
}

// `>= 2.1.0 < 2.2.7` -> [">= 2.1.0", "< 2.2.7"], a bare `3.1.7` -> ["3.1.7"].
// A new piece starts wherever an operator starts.
fn split_at_operators(item: &str) -> Vec<String> {
    let mut pieces: Vec<String> = vec![];
    let mut previous_is_operator = true;
    for c in item.chars() {
        let starts_operator = is_operator_char(c) && !previous_is_operator;
        if starts_operator || pieces.is_empty() {
            pieces.push(String::new());
        }
        pieces.last_mut().unwrap().push(c);
        previous_is_operator = is_operator_char(c);
    }
    pieces
        .iter()
        .map(|piece| piece.trim().to_string())
        .filter(|piece| !piece.is_empty())
        .collect()
}

// `<=4.1.135.Final` -> `<= 4.1.135`, `3.1.7` -> `= 3.1.7`, `2.9.3+6eba5be` -> `= 2.9.3`.
fn format_comparator(piece: &str) -> String {
    let operator_end = piece
        .find(|c: char| !is_operator_char(c))
        .unwrap_or(piece.len());
    let (operator, version) = piece.split_at(operator_end);
    let version = fix_version(version.trim());
    if operator.is_empty() {
        format!("= {}", exact_version(&version))
    } else {
        format!("{operator} {version}")
    }
}

fn is_operator_char(c: char) -> bool {
    matches!(c, '<' | '>' | '=' | '~' | '^')
}

// ----- one version -----

// `4.1.135.Final` -> `4.1.135`, `3.0.0.beta15` -> `3.0.0-beta15`, `0.23.0rc2` -> `0.23.0-rc2`,
// `19.03.15` -> `19.3.15`. Anything else, such as a fourth number or a `v20210219` build stamp,
// is left as it is.
fn fix_version(version: &str) -> String {
    let version = drop_leading_zeros(version);
    let parts: Vec<&str> = version.split('.').collect();

    let fourth_part_is_a_word = parts.len() == 4
        && parts[3].starts_with(|c: char| c.is_ascii_alphabetic())
        && !is_build_stamp(parts[3]);
    if fourth_part_is_a_word {
        let number = parts[..3].join(".");
        let qualifier = parts[3];
        if ["Final", "RELEASE", "GA"].contains(&qualifier) {
            return number;
        }
        return format!("{number}-{qualifier}");
    }

    if parts.len() == 3 {
        let patch = parts[2];
        if let Some(letters_start) = patch.find(|c: char| c.is_ascii_alphabetic()) {
            let number = &patch[..letters_start];
            if !number.is_empty() && number.chars().all(|c| c.is_ascii_digit()) {
                return format!(
                    "{}.{}.{number}-{}",
                    parts[0],
                    parts[1],
                    &patch[letters_start..]
                );
            }
        }
    }

    version.to_string()
}

// `19.03.15` -> `19.3.15`: semver does not allow a leading zero in a number. `030.0` -> `30.0`.
fn drop_leading_zeros(version: &str) -> String {
    version
        .split('.')
        .map(|part| {
            let is_number = part.chars().all(|c| c.is_ascii_digit());
            if is_number && part.len() > 1 {
                part.trim_start_matches('0').to_string()
            } else {
                part.to_string()
            }
        })
        .map(|part| {
            if part.is_empty() {
                "0".to_string()
            } else {
                part
            }
        })
        .join(".")
}

// `v20210219` is a build stamp, not a pre-release.
fn is_build_stamp(qualifier: &str) -> bool {
    qualifier.len() > 1
        && qualifier.starts_with('v')
        && qualifier[1..].chars().all(|c| c.is_ascii_digit())
}

// `2.9.3+6eba5be` -> `2.9.3`: a requirement cannot carry build metadata.
fn exact_version(version: &str) -> String {
    match Version::parse(version) {
        Ok(parsed) => {
            let mut exact = format!("{}.{}.{}", parsed.major, parsed.minor, parsed.patch);
            if !parsed.pre.is_empty() {
                exact = format!("{exact}-{}", parsed.pre);
            }
            exact
        }
        Err(_) => version.to_string(),
    }
}

// ----- release branches -----

// `>= 2.1.0, < 2.2.7, >= 2.3.0, < 2.3.4` describes two release branches: a new one starts at every
// lower bound, so it becomes `>= 2.1.0, < 2.2.7 || >= 2.3.0, < 2.3.4`.
fn group_into_branches(comparators: Vec<String>) -> String {
    let mut branches: Vec<Vec<String>> = vec![];

    for comparator in comparators {
        let starts_new_branch = comparator.starts_with('>') && !branches.is_empty();
        if starts_new_branch || branches.is_empty() {
            branches.push(vec![]);
        }
        branches.last_mut().unwrap().push(comparator);
    }

    branches
        .iter()
        .map(|branch| {
            let requirement = branch.join(", ");
            upper_bounds_to_branches(&requirement).unwrap_or(requirement)
        })
        .join(" || ")
}

// A range that already parses is returned unchanged, unless an alternative is a list of upper bounds
// like `< 1.8.4, < 1.9.1`.
fn upper_bound_lists_to_branches(range: &str) -> String {
    let alternatives = range.split("||").map(str::trim).collect::<Vec<_>>();
    let has_upper_bound_list = alternatives
        .iter()
        .any(|alternative| upper_bounds_to_branches(alternative).is_some());

    if !has_upper_bound_list {
        return range.to_string();
    }

    alternatives
        .iter()
        .map(|alternative| {
            upper_bounds_to_branches(alternative).unwrap_or_else(|| alternative.to_string())
        })
        .join(" || ")
}

// `< 1.8.4, < 1.9.1` lists the fix of two release branches as upper bounds only. Read literally the
// comma is AND, which drops the 1.9 branch, so each upper bound gets its branch as lower bound:
// `>= 1.8.0, < 1.8.4 || >= 1.9.0, < 1.9.1`. Returns None when the requirement is not such a list.
fn upper_bounds_to_branches(requirement: &str) -> Option<String> {
    let parsed = VersionReq::parse(requirement).ok()?;
    let comparators = &parsed.comparators;

    let all_upper_bounds = comparators
        .iter()
        .all(|c| matches!(c.op, Op::Less | Op::LessEq));
    let all_full_versions = comparators
        .iter()
        .all(|c| c.minor.is_some() && c.patch.is_some() && c.pre.is_empty());
    let all_different_branches = comparators
        .iter()
        .map(|c| (c.major, c.minor))
        .unique()
        .count()
        == comparators.len();

    let is_upper_bound_list =
        comparators.len() >= 2 && all_upper_bounds && all_full_versions && all_different_branches;

    if !is_upper_bound_list {
        return None;
    }

    Some(comparators.iter().map(upper_bound_to_branch).join(" || "))
}

// `< 1.8.4` -> `>= 1.8.0, < 1.8.4`
fn upper_bound_to_branch(comparator: &Comparator) -> String {
    let operator = if comparator.op == Op::LessEq {
        "<="
    } else {
        "<"
    };
    let (major, minor) = (comparator.major, comparator.minor.unwrap());
    let patch = comparator.patch.unwrap();
    format!(">= {major}.{minor}.0, {operator} {major}.{minor}.{patch}")
}
