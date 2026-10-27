//! Version ranges of GitHub repository advisories are written by hand, so they come in many shapes:
//! `>= v1.19.0`, `All`, `1.2.0 through 1.8.7`, `>= 2.1.0 < 2.2.7`, `<=4.1.135.Final`,
//! `1.20.1 and earlier`, `stable <= 2.8.13; beta <= 3.0.0.beta15`, ...
//!
//! `normalize_version_range` rewrites the shapes whose meaning is clear into the syntax that
//! `semver::VersionReq` accepts; single versions are read by `lenient_semver`. It works as a list of small rules that are applied from top to
//! bottom; every rule is a function with an example in its comment. A shape no rule understands
//! comes out still unparsable, so that the caller fails to parse it and warns about it.
//!
//! Output format: one space between an operator and its version, `, ` between the comparators of
//! one requirement (AND) and ` || ` between alternatives (OR). A range that already parses is
//! returned unchanged, except a list of upper bounds like `< 1.8.4, < 1.9.1`, which is read as
//! release branches. A range with a version that has no operator goes through the rules even if
//! it parses: `semver` reads `10.0.0` as `^10.0.0` like Cargo does, while an advisory means that
//! version only.

use crate::normalize_version_words::{
    replace_ignore_case, replace_unusual_characters, words_to_operators,
};
use itertools::Itertools;
use regex::Regex;
use semver::{Comparator, Op, VersionReq};

/// Rewrites a hand-written version range into the syntax `semver::VersionReq` accepts.
///   `>= v1.19.0, < v1.19.6`                ->  `>= 1.19.0, < 1.19.6`
///   `1.2.0 through 1.8.7`                  ->  `>= 1.2.0, <= 1.8.7`
///   `>= 2.1.0 < 2.2.7,  >= 2.3.0 < 2.3.4`  ->  `>= 2.1.0, < 2.2.7 || >= 2.3.0, < 2.3.4`
///   `< 1.8.4, < 1.9.1`                     ->  `< 1.8.4 || >= 1.9.0, < 1.9.1`
///   `v1.18.0,v1.18.1`                      ->  `= 1.18.0 || = 1.18.1`
///   `10.0.0-rc.1`                          ->  `= 10.0.0-rc.1`  (parses, but as `^10.0.0-rc.1`)
///   `All`                                  ->  `*`
///   `>= 1.0.0, < 1.2.6`                    ->  `>= 1.0.0, < 1.2.6`  (already valid: unchanged)
///   `NONE`                                 ->  `= NONE`  (still unparsable: the caller warns)
pub fn normalize_version_range(range: impl Into<String>) -> String {
    let range = range.into();
    let original = range.clone();

    if parses(&range) && !has_version_without_operator(&range) {
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

// Whether `semver::VersionReq` accepts every alternative of the range as it is.
//   `>= 1.0.0, < 1.2.6 || = 2.0.0`  ->  true
//   `< 1.8.4, < 1.9.1`              ->  true
//   `>= v1.0.0`                     ->  false
fn parses(range: &str) -> bool {
    range
        .split("||")
        .all(|alternative| VersionReq::parse(alternative.trim()).is_ok())
}

// Whether a comparator of the range has no operator. `semver::VersionReq` reads such a version as
// `^` like Cargo does, so `10.0.0-rc.1` would cover every 10.x version, while an advisory means
// that version only.
//   `10.0.0-rc.1.25451.107`  ->  true
//   `1.18.0, 1.18.1`         ->  true
//   `>= 1.0.0, < 1.2.6`      ->  false
//   `^1.2.3`                 ->  false  (a `^` that was written is meant)
//   `*`                      ->  false
fn has_version_without_operator(range: &str) -> bool {
    range
        .split("||")
        .flat_map(|alternative| alternative.split(','))
        .any(|comparator| comparator.trim().starts_with(|c: char| c.is_ascii_digit()))
}

// Removes a note written in parentheses.
//   `>= 4.0 (32-bit only)`           ->  `>= 4.0`
//   `All versions (default config)`  ->  `All versions`
//   `(confirmed on main @ e0f8d9b)`  ->  `` (nothing is left)
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

// Removes the `v` or `V` written in front of a version.
//   `>= v1.19.0, < V1.19.6`  ->  `>= 1.19.0, < 1.19.6`
//   `v2.9.3+6eba5be`         ->  `2.9.3+6eba5be`
//   `>= 1.0.0-dev1`          ->  `>= 1.0.0-dev1`  (the `v` of `dev1` is inside a word)
fn drop_v_prefixes(range: &str) -> String {
    let v_before_digit = Regex::new(r"\b[vV](\d)").expect("the pattern is a constant");
    v_before_digit.replace_all(range, "$1").to_string()
}

// Whether the range is a way of saying "every version".
//   `All`                        ->  true
//   `all versions`               ->  true
//   `All versions prior to 1.7`  ->  false
fn is_every_version(range: &str) -> bool {
    let lowercase = range.trim().to_ascii_lowercase();
    lowercase == "all" || lowercase == "all versions"
}

// Puts the same operator in front of every version of a list. A phrase that was repeated after
// each version is removed first.
//   (`1.14.2, 1.13.2 and 1.12.4`, `<=`, ``)                   ->  `<= 1.14.2, <= 1.13.2, <= 1.12.4`
//   (`7.2.10 and below, 8.0.5 and below`, `<=`, `and below`)  ->  `<= 7.2.10, <= 8.0.5`
//   (`1.7.14 and 1.8.7`, `<`, ``)                             ->  `< 1.7.14, < 1.8.7`
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

// Reads a range written like a mathematical interval.
//   `2.2.0 <= V <= 2.10.1`          ->  Some(`>= 2.2.0, <= 2.10.1`)
//   `2.0.0 < version <= 2.7.1`      ->  Some(`> 2.0.0, <= 2.7.1`)
//   `1.22 < 1.27.1`                 ->  Some(`>= 1.22, < 1.27.1`)
//   `>= 1.0.0, < 1.2.6`             ->  None
//   `16.0.0, <= 15.0.1, <= 13.1.2`  ->  None  (the middle word is a version, not a variable)
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

// Rebuilds one alternative (the text between two `||`). The commas say little: advisories put them
// between release branches, inside them or both. So the comparators of all comma-separated items
// form one sequence, which `group_into_branches` cuts into branches. A word without a digit next
// to real items is a label and is dropped.
//   `>= 1.0.0, < 1.2.6`                                    ->  `>= 1.0.0, < 1.2.6`
//   `>= 2.1.0 < 2.2.7, >= 2.3.0 < 2.3.4`                   ->  `>= 2.1.0, < 2.2.7 || >= 2.3.0, < 2.3.4`
//   `>= 9.0.0, <= 9.0.13 >= 10.0.0, <= 10.0.3`             ->  `>= 9.0.0, <= 9.0.13 || >= 10.0.0, <= 10.0.3`
//   `3.0.0-rc1 - 3.2.0-rc1, 3.1.7`                         ->  `>= 3.0.0-rc1, <= 3.2.0-rc1 || = 3.1.7`
//   `stable <= 2.7.10, beta, tests-passed <= 2.8.0.beta8`  ->  `<= 2.7.10, <= 2.8.0-beta8`
//   `< 1.8.4, < 1.9.1`                                     ->  `< 1.8.4 || >= 1.9.0, < 1.9.1`
fn normalize_alternative(alternative: &str) -> String {
    let items = alternative
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();

    let has_digit = |item: &&str| item.chars().any(|c| c.is_ascii_digit());

    let some_item_has_a_digit = items.iter().any(has_digit);
    let comparators = items
        .iter()
        .filter(|item| !some_item_has_a_digit || has_digit(item))
        .flat_map(|item| item_to_comparators(item))
        .collect::<Vec<_>>();

    group_into_branches(comparators)
}

// Turns one comma-separated item into its comparators, each written as `operator version`.
//   `stable <= 2.8.13`  ->  [`<= 2.8.13`]
//   `3.2.0 - 3.3.8`     ->  [`>= 3.2.0`, `<= 3.3.8`]
//   `1.9.0-1.9.6`       ->  [`>= 1.9.0`, `<= 1.9.6`]
//   `>= 2.1.0 < 2.2.7`  ->  [`>= 2.1.0`, `< 2.2.7`]
//   `2.9.3+6eba5be`     ->  [`= 2.9.3`]
//   `<=4.1.135.Final`   ->  [`<= 4.1.135`]
fn item_to_comparators(item: &str) -> Vec<String> {
    let item = drop_label(item);

    if let Some((from, to)) = split_hyphen_range(&item) {
        return vec![
            format!(">= {}", fix_version(from)),
            format!("<= {}", fix_version(to)),
        ];
    }

    split_at_operators(&item)
        .iter()
        .map(|piece| format_comparator(piece))
        .collect()
}

// Splits a hyphen range into its two versions. Without spaces around the hyphen, only digits and
// dots may follow it, with at least one dot: a hyphen also starts a pre-release (`10.0.0-rc.1`)
// or ImageMagick's patch level (`7.1.1-4`).
//   `3.2.0 - 3.3.8`  ->  Some((`3.2.0`, `3.3.8`))
//   `1.9.0-1.9.6`    ->  Some((`1.9.0`, `1.9.6`))
//   `3.5-5.9`        ->  Some((`3.5`, `5.9`))
//   `10.0.0-rc.1`    ->  None
//   `7.1.1-4`        ->  None
//   `edge-24.6.2`    ->  None  (a word before the hyphen)
fn split_hyphen_range(item: &str) -> Option<(&str, &str)> {
    let starts_with_digit = |text: &str| text.starts_with(|c: char| c.is_ascii_digit());

    let (from, to, is_range) = match item.split_once(" - ") {
        Some((from, to)) => {
            let (from, to) = (from.trim(), to.trim());
            (from, to, starts_with_digit(from) && starts_with_digit(to))
        }
        None => {
            let (from, to) = item.split_once('-')?;
            let to_is_plain_version =
                to.contains('.') && to.chars().all(|c| c.is_ascii_digit() || c == '.');
            (from, to, starts_with_digit(from) && to_is_plain_version)
        }
    };

    if is_range { Some((from, to)) } else { None }
}

// Removes the words written in front of a comparator or version, like a release channel or a
// product name. The words must stand on their own: `edge-24.6.2` keeps its `edge-`.
//   `stable <= 2.8.13`    ->  `<= 2.8.13`
//   `jaeger-ui < 1.31.0`  ->  `< 1.31.0`
//   `and 3.4.1`           ->  `3.4.1`
//   `edge-24.6.2`         ->  `edge-24.6.2`
//   `1.3.x <= 1.3.17`     ->  `1.3.x <= 1.3.17`  (the label contains a digit)
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

// Cuts an item into pieces, a new piece starting wherever an operator starts.
//   `>= 2.1.0 < 2.2.7`  ->  [`>= 2.1.0`, `< 2.2.7`]
//   `>=9.2.0 <9.2.10`   ->  [`>=9.2.0`, `<9.2.10`]
//   `<=4.1.135.Final`   ->  [`<=4.1.135.Final`]
//   `3.1.7`             ->  [`3.1.7`]
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

// Writes one piece as `operator version` with the version fixed; a bare version becomes exact.
//   `<=4.1.135.Final`  ->  `<= 4.1.135`
//   `>= 19.03.15`      ->  `>= 19.3.15`
//   `< 23.7.6.111`     ->  `< 23.7.6`
//   `3.1.7`            ->  `= 3.1.7`
//   `2.9.3+6eba5be`    ->  `= 2.9.3`
fn format_comparator(piece: &str) -> String {
    let operator_end = piece
        .find(|c: char| !is_operator_char(c))
        .unwrap_or(piece.len());
    let (operator, version) = piece.split_at(operator_end);
    let version = fix_version(version.trim());
    if operator.is_empty() {
        format!("= {version}")
    } else {
        format!("{operator} {version}")
    }
}

// Whether the character can be part of an operator.
//   `<`, `>`, `=`, `~`, `^`  ->  true
//   `-`, `|`, `1`, ` `       ->  false
fn is_operator_char(c: char) -> bool {
    matches!(c, '<' | '>' | '=' | '~' | '^')
}

// ----- one version -----

// Rewrites a version that semver does not accept into one it does, with `lenient_semver` doing
// the reading. Build metadata is dropped because a requirement cannot carry it.
//   `4.1.135.Final`     ->  `4.1.135`      (Maven's release qualifier is metadata to lenient_semver)
//   `3.0.0.beta15`      ->  `3.0.0-beta15`  (a word after the patch number is a pre-release)
//   `0.23.0rc2`         ->  `0.23.0-0rc2`
//   `19.03.15`          ->  `19.3.15`
//   `2.9.3+6eba5be`     ->  `2.9.3`
//   `23.7.6.111`        ->  `23.7.6`  (a fourth number has no place in semver and is dropped)
//   `9.4.37.v20210219`  ->  `9.4.37`  (Jetty's build stamp is not a pre-release)
//   `7.2`               ->  `7.2`     (what `VersionReq` already accepts is left alone)
//   `3.0-6`             ->  `3.0-6`   (a hyphen could be a pre-release or a range: left alone)
fn fix_version(version: &str) -> String {
    // `VersionReq` accepts build metadata but ignores it, so it goes right away.
    let version = version.split('+').next().unwrap_or(version);

    let already_accepted = VersionReq::parse(version).is_ok();
    let has_hyphen = version.contains('-');
    if already_accepted || has_hyphen {
        return version.to_string();
    }

    let build_stamp = Regex::new(r"^(\d+\.\d+\.\d+)\.v\d+$").expect("the pattern is a constant");
    let without_stamp = build_stamp.replace(version, "$1");

    match lenient_semver::parse(&without_stamp) {
        Ok(parsed) => {
            let mut fixed = format!("{}.{}.{}", parsed.major, parsed.minor, parsed.patch);
            if !parsed.pre.is_empty() {
                fixed = format!("{fixed}-{}", parsed.pre);
            }
            fixed
        }
        Err(_) => version.to_string(),
    }
}

// ----- release branches -----

// Joins comparators into requirements. A lower bound starts a new release branch, an exact version
// is a branch by itself, and a list of upper bounds only is read as one branch per upper bound.
// An exact version that stands for a missing end of the branch next to it becomes that end first.
//   [`>= 1.0.0`, `< 1.2.6`]                         ->  `>= 1.0.0, < 1.2.6`
//   [`>= 2.1.0`, `< 2.2.7`, `>= 2.3.0`, `< 2.3.4`]  ->  `>= 2.1.0, < 2.2.7 || >= 2.3.0, < 2.3.4`
//   [`< 3.5.3`, `>= 3.6.0`, `< 3.11.3`]             ->  `< 3.5.3 || >= 3.6.0, < 3.11.3`
//   [`< 1.8.4`, `< 1.9.1`]                          ->  `< 1.8.4 || >= 1.9.0, < 1.9.1`
//   [`<= 1.11.14`, `<= 1.12.7`, `= 1.13.0`]         ->  `<= 1.11.14 || >= 1.12.0, <= 1.12.7 || = 1.13.0`
//   [`>= 5.0.0`, `= 6.0.0`]                         ->  `>= 5.0.0, <= 6.0.0`
fn group_into_branches(comparators: Vec<String>) -> String {
    let mut branches: Vec<Vec<String>> = vec![];
    let mut previous_is_exact = false;

    for comparator in exact_versions_to_bounds(&comparators) {
        let is_exact = comparator.starts_with("= ");
        let starts_new_branch = comparator.starts_with('>') || is_exact || previous_is_exact;
        if starts_new_branch || branches.is_empty() {
            branches.push(vec![]);
        }
        branches.last_mut().unwrap().push(comparator);
        previous_is_exact = is_exact;
    }

    branches
        .iter()
        .map(|branch| {
            let requirement = branch.join(", ");
            upper_bounds_to_branches(&requirement).unwrap_or(requirement)
        })
        .join(" || ")
}

// Hand-written ranges sometimes leave out the operator at one end of a branch, so an exact version
// next to a branch with a missing end becomes that end: right after a lower bound it is the upper
// end, and right before an upper bound of its own release branch it is the lower end. Upper bounds
// are often listed one per release branch, so one of another branch leaves the version exact.
//   [`>= 5.0.0`, `= 6.0.0`]               ->  [`>= 5.0.0`, `<= 6.0.0`]
//   [`= 1.55.0`, `< 1.55.23`]             ->  [`>= 1.55.0`, `< 1.55.23`]
//   [`= 1.3.x`, `<= 1.3.17`]              ->  [`>= 1.3.x`, `<= 1.3.17`]
//   [`= 16.0.21299`, `<= 15.0.21297`]     ->  [`= 16.0.21299`, `<= 15.0.21297`]  (another branch)
//   [`< 1.4.5`, `= 1.5.0`]                ->  [`< 1.4.5`, `= 1.5.0`]
fn exact_versions_to_bounds(comparators: &[String]) -> Vec<String> {
    comparators
        .iter()
        .enumerate()
        .map(|(index, comparator)| {
            let version = match comparator.strip_prefix("= ") {
                Some(version) => version,
                None => return comparator.clone(),
            };

            let follows_lower_bound = index > 0 && comparators[index - 1].starts_with('>');
            let precedes_upper_bound_of_branch = comparators
                .get(index + 1)
                .is_some_and(|next| is_upper_bound_of_branch(next, comparator));

            if follows_lower_bound {
                format!("<= {version}")
            } else if precedes_upper_bound_of_branch {
                format!(">= {version}")
            } else {
                comparator.clone()
            }
        })
        .collect()
}

// Whether a comparator is an upper bound in the release branch of an exact version. An exact
// version without a minor number, like `= 2.x`, stands for its whole major version.
//   (`< 1.55.23`, `= 1.55.0`)          ->  true
//   (`< 2.4.3`, `= 2.x`)               ->  true
//   (`<= 1.11.15`, `= 1.10`)           ->  false
//   (`<= 15.0.21297`, `= 16.0.21299`)  ->  false
//   (`>= 1.56.0`, `= 1.55.0`)          ->  false
fn is_upper_bound_of_branch(comparator: &str, exact_version: &str) -> bool {
    match (
        Comparator::parse(comparator),
        Comparator::parse(exact_version),
    ) {
        (Ok(bound), Ok(exact)) => {
            let is_upper_bound = matches!(bound.op, Op::Less | Op::LessEq);
            let same_major = bound.major == exact.major;
            let same_minor = exact.minor.is_none() || bound.minor == exact.minor;
            is_upper_bound && same_major && same_minor
        }
        _ => false,
    }
}

// For a range that already parses: returns it unchanged, except that a list of upper bounds is
// read as release branches.
//   `>= 1.0.0, < 1.2.6`            ->  `>= 1.0.0, < 1.2.6`
//   `< 1.8.4, < 1.9.1`             ->  `< 1.8.4 || >= 1.9.0, < 1.9.1`
//   `< 1.0.0 || < 1.8.4, < 1.9.1`  ->  `< 1.0.0 || < 1.8.4 || >= 1.9.0, < 1.9.1`
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

// Reads a requirement made of upper bounds only, like `< 1.8.4, < 1.9.1`, as the fix of several
// release branches. Literally the comma is AND, which would drop the 1.9 branch, so the bounds
// become alternatives, and each one but the lowest gets a lower bound that leaves out the fixed
// versions of the listed branches below it. Returns None for any other requirement.
//   `< 1.8.4, < 1.9.1`         ->  Some(`< 1.8.4 || >= 1.9.0, < 1.9.1`)
//   `<= 4.2.12, <= 4.1.132`    ->  Some(`>= 4.2.0, <= 4.2.12 || <= 4.1.132`)
//   `<8.4.26`                  ->  None  (one bound is kept literal)
//   `< 1.8.4, < 1.8.9`         ->  None  (same branch twice)
//   `<= 1.4.0-rc.2, <= 1.3.5`  ->  None  (pre-release)
//   `>= 1.0.0, < 1.2.6`        ->  None  (has a lower bound)
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

    let branches = comparators
        .iter()
        .map(|c| (c.major, c.minor.unwrap()))
        .collect::<Vec<_>>();

    Some(
        comparators
            .iter()
            .map(|comparator| {
                let branch = (comparator.major, comparator.minor.unwrap());
                let previous_branch = branches.iter().filter(|other| **other < branch).max();
                upper_bound_to_branch(comparator, previous_branch)
            })
            .join(" || "),
    )
}

// Gives an upper bound a lower bound that leaves out the listed branch before it, which has a fix
// of its own. Minor versions that the list skips came out before the listed one and never got the
// fix, so the bound reaches back to the minor version after the previous branch, or to the start
// of its major version if that branch is in an older one (whose later minor versions may have come
// out with the fix). The lowest bound keeps no lower bound, as the versions before it never got
// the fix either.
//   (`< 1.9.1`, after 1.8)    ->  `>= 1.9.0, < 1.9.1`
//   (`< 3.27.3`, after 3.20)  ->  `>= 3.21.0, < 3.27.3`  (Quarkus lists its LTS branches only)
//   (`< 2.4.0`, after 1.3)    ->  `>= 2.0.0, < 2.4.0`    (OpenSearch: 2.0.0-2.3.0 are affected)
//   (`< 1.8.4`, the lowest)   ->  `< 1.8.4`
fn upper_bound_to_branch(comparator: &Comparator, previous_branch: Option<&(u64, u64)>) -> String {
    let operator = if comparator.op == Op::LessEq {
        "<="
    } else {
        "<"
    };
    let (major, minor) = (comparator.major, comparator.minor.unwrap());
    let patch = comparator.patch.unwrap();
    let upper_bound = format!("{operator} {major}.{minor}.{patch}");

    match previous_branch {
        Some(&(previous_major, previous_minor)) if previous_major == major => {
            format!(">= {major}.{}.0, {upper_bound}", previous_minor + 1)
        }
        Some(_) => format!(">= {major}.0.0, {upper_bound}"),
        None => upper_bound,
    }
}
