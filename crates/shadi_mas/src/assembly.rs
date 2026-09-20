// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//! ASSEMBLY: joint modeling. Agents debate in natural language and may name a
//! class. The three paper classes are examples, not a closed set.

use crate::types::PatternKind;

/// Soft ASSEMBLY session. Prose is the debate; the hypothesis is inferred.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AssemblySession {
    pub transcript: Vec<String>,
    pub inferred: Option<PatternKind>,
    pub remap_count: u32,
}

impl AssemblySession {
    pub fn ingest(&mut self, text: impl Into<String>) {
        let text = text.into();
        self.inferred = infer_pattern(&text).or(self.inferred);
        self.transcript.push(text);
    }

    pub fn remap(&mut self, text: impl Into<String>) {
        self.remap_count += 1;
        self.inferred = None;
        self.ingest(text);
    }
}

/// Infer a class from ASSEMBLY text. `CLASS <name>` wins; otherwise keywords.
/// A named class outside the three examples is [`PatternKind::Unmapped`].
pub fn infer_pattern(text: &str) -> Option<PatternKind> {
    if let Some(named) = class_line(text) {
        return Some(named);
    }
    keyword_scores(text)
}

/// First line that names a class wins. A `CLASS` marker with no name after it
/// claims nothing, so it is skipped and later lines still count.
fn class_line(text: &str) -> Option<PatternKind> {
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed
            .strip_prefix("CLASS ")
            .or_else(|| trimmed.strip_prefix("CLASS="))
            .or_else(|| trimmed.strip_prefix("class "))
        else {
            continue;
        };
        let Some(token) = rest
            .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .find(|t| !t.is_empty())
        else {
            continue;
        };
        return Some(PatternKind::parse_name(token).unwrap_or(PatternKind::Unmapped));
    }
    None
}

fn keyword_scores(text: &str) -> Option<PatternKind> {
    let lower = text.to_ascii_lowercase();
    let preference = count_hits(
        &lower,
        &[
            "preference",
            "jacobi",
            "neighbor",
            "quadratic",
            "shared score",
        ],
    );
    let cascade = count_hits(
        &lower,
        &[
            "cascade",
            "inventory",
            "pipeline",
            "supply chain",
            "retailer",
            "factory",
            "order-up-to",
        ],
    );
    let resource = count_hits(
        &lower,
        &[
            "resource",
            "extraction",
            "quota",
            "renewable",
            "stock",
            "lambda",
        ],
    );
    let best = [
        (PatternKind::Preference, preference),
        (PatternKind::Cascade, cascade),
        (PatternKind::Resource, resource),
    ]
    .into_iter()
    .max_by_key(|(_, n)| *n)?;
    if best.1 == 0 {
        return None;
    }
    let ties = [preference, cascade, resource]
        .into_iter()
        .filter(|n| *n == best.1)
        .count();
    if ties > 1 {
        return None;
    }
    Some(best.0)
}

fn count_hits(hay: &str, needles: &[&str]) -> usize {
    needles.iter().filter(|n| hay.contains(*n)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_line_maps_paper_examples() {
        assert_eq!(
            infer_pattern("CLASS preference"),
            Some(PatternKind::Preference)
        );
        assert_eq!(infer_pattern("CLASS cascade\n"), Some(PatternKind::Cascade));
        assert_eq!(
            infer_pattern("we agree\nCLASS resource"),
            Some(PatternKind::Resource)
        );
        assert_eq!(
            infer_pattern("CLASS development"),
            Some(PatternKind::Development)
        );
        assert_eq!(infer_pattern("CLASS=cascade"), Some(PatternKind::Cascade));
    }

    #[test]
    fn unknown_class_is_unmapped() {
        assert_eq!(
            infer_pattern("CLASS matching-markets"),
            Some(PatternKind::Unmapped)
        );
    }

    #[test]
    fn class_line_is_found_after_unrelated_lines() {
        assert_eq!(
            infer_pattern("agents debate the setup\nCLASS development"),
            Some(PatternKind::Development)
        );
        assert_eq!(
            infer_pattern("first\nsecond\n  class matching-markets\n"),
            Some(PatternKind::Unmapped)
        );
    }

    #[test]
    fn class_marker_without_a_name_is_skipped() {
        assert_eq!(infer_pattern("CLASS="), None);
        assert_eq!(
            infer_pattern("CLASS=\nCLASS development"),
            Some(PatternKind::Development)
        );
    }

    #[test]
    fn keywords_infer_without_class_line() {
        assert_eq!(
            infer_pattern("blend neighbor scores on a line"),
            Some(PatternKind::Preference)
        );
        assert_eq!(
            infer_pattern("factory and retailer inventory pipeline"),
            Some(PatternKind::Cascade)
        );
        assert_eq!(
            infer_pattern("shared renewable stock and extraction quota"),
            Some(PatternKind::Resource)
        );
    }

    #[test]
    fn session_keeps_last_stable_hypothesis() {
        let mut session = AssemblySession::default();
        session.ingest("talk only");
        assert_eq!(session.inferred, None);
        session.ingest("CLASS preference");
        assert_eq!(session.inferred, Some(PatternKind::Preference));
        session.ingest("more talk");
        assert_eq!(session.inferred, Some(PatternKind::Preference));
        session.remap("CLASS matching-markets");
        assert_eq!(session.inferred, Some(PatternKind::Unmapped));
        assert_eq!(session.remap_count, 1);
    }
}
