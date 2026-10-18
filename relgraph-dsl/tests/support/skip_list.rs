//! Reviewed skip lists for upstream corpus runners.
//!
//! A skip list is one YAML file with sorted `entries`. Each entry covers either
//! one case ID (an exact ID, or an ID prefix that ends at a `::` boundary, such
//! as a stage) or a named rule that the runner defines. Every entry states a
//! `reason`, a `tag` from that reason's vocabulary ([`SkipReason::TAGS`]), the
//! plan `task` expected to remove it (or `permanent`), and a `justification`.
//!
//! [`check`] fails when a non-passing case is not covered, and when an entry
//! covers no non-passing case (so the list can only shrink as cases start to
//! pass). The file must also be in the canonical serialized form, so that
//! review diffs stay minimal and deterministic.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Why a case is skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SkipReason {
    /// Relgraph deliberately lacks the feature the case exercises.
    UnsupportedFeature,
    /// Relgraph supports the area but behaves differently from upstream.
    SemanticDivergence,
    /// The harness cannot yet express or compare the case.
    HarnessGap,
}

impl SkipReason {
    /// Allowed `tag` values per reason.
    ///
    /// - `unsupported-feature`: the missing feature area. `validation` and
    ///   `manifest` are validation rules Relgraph does not implement yet
    ///   (plan tasks 5 and 6); the others name a runtime or API surface.
    /// - `semantic-divergence`: `bug` (Relgraph should change; a plan task
    ///   owns it) or `deliberate` (a recorded design decision, normally
    ///   `permanent`).
    /// - `harness-gap`: `harness`.
    pub const TAGS: &[(SkipReason, &[&str])] = &[
        (
            SkipReason::UnsupportedFeature,
            &[
                "cel",
                "contextual-tuples",
                "inline-condition",
                "ipaddress",
                "json-model",
                "list-api",
                "manifest",
                "userset-subject",
                "validation",
            ],
        ),
        (SkipReason::SemanticDivergence, &["bug", "deliberate"]),
        (SkipReason::HarnessGap, &["harness"]),
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedFeature => "unsupported-feature",
            Self::SemanticDivergence => "semantic-divergence",
            Self::HarnessGap => "harness-gap",
        }
    }

    fn allows_tag(self, tag: &str) -> bool {
        Self::TAGS
            .iter()
            .any(|(reason, tags)| *reason == self && tags.contains(&tag))
    }
}

/// One reviewed skip entry. Exactly one of `case` and `rule` is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkipEntry {
    /// Case ID, or a case-ID prefix ending at a `::` boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<String>,
    /// Name of a runner-defined rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Skip category.
    pub reason: SkipReason,
    /// Sub-category from [`SkipReason::TAGS`].
    pub tag: String,
    /// Plan task expected to remove the entry, or `permanent`.
    pub task: String,
    /// Reviewed free-text explanation.
    pub justification: String,
}

impl SkipEntry {
    fn key(&self) -> String {
        match (&self.rule, &self.case) {
            (Some(rule), None) => format!("rule {rule}"),
            (None, Some(case)) => format!("case {case}"),
            _ => String::from("<invalid entry>"),
        }
    }
}

/// The deserialized skip-list file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkipList {
    /// Entries sorted by rule name, then case ID.
    pub entries: Vec<SkipEntry>,
}

/// How a non-passing case failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotPassingKind {
    /// The case ran and Relgraph disagreed with upstream.
    Fail,
    /// The harness has no mapping for an expectation or diagnostic.
    HarnessGap,
    /// The case is never run (for example an unsupported output format).
    NotRun,
}

/// The result of one corpus case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Relgraph agrees with upstream.
    Pass,
    /// Upstream marks the case `skip: true`; it is not run or gated.
    UpstreamSkip,
    /// The case needs a skip-list entry.
    NotPassing {
        /// Failure category.
        kind: NotPassingKind,
        /// Human-readable comparison detail.
        detail: String,
        /// Reason proposed when the case is not yet covered.
        suggested_reason: SkipReason,
        /// Plan task proposed when the case is not yet covered.
        suggested_task: &'static str,
    },
}

/// A case ID with its corpus file and outcome.
#[derive(Debug, Clone)]
pub struct CaseResult {
    /// Corpus file name.
    pub file: &'static str,
    /// Unique case ID.
    pub id: String,
    /// Comparison result.
    pub outcome: Outcome,
}

/// Loads a skip list and verifies that it is in canonical form.
pub fn load(path: &Path, header: &str) -> Result<SkipList, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let body = text.strip_prefix(header).ok_or_else(|| {
        format!(
            "{} must start with the fixed header:\n{header}",
            path.display()
        )
    })?;
    let list: SkipList = serde_yaml::from_str(body)
        .map_err(|error| format!("could not parse {}: {error}", path.display()))?;
    let mut problems = Vec::new();
    let mut keys = BTreeSet::new();
    for entry in &list.entries {
        if entry.case.is_some() == entry.rule.is_some() {
            problems.push(format!(
                "entry must set exactly one of `case` and `rule`: {entry:?}"
            ));
        }
        if entry.task.trim().is_empty() || entry.justification.trim().is_empty() {
            problems.push(format!("{} needs a task and a justification", entry.key()));
        }
        if !entry.reason.allows_tag(&entry.tag) {
            problems.push(format!(
                "{} has tag {:?}, which is not allowed for {}",
                entry.key(),
                entry.tag,
                entry.reason.as_str()
            ));
        }
        if !keys.insert(entry.key()) {
            problems.push(format!("{} is listed twice", entry.key()));
        }
    }
    let mut sorted = list.clone();
    sorted.entries.sort_by_key(SkipEntry::key);
    let canonical = format!("{header}{}", serialize(&sorted));
    if canonical != text {
        problems.push(format!(
            "{} is not sorted and canonically serialized; replace it with:\n{canonical}",
            path.display()
        ));
    }
    if problems.is_empty() {
        Ok(list)
    } else {
        Err(problems.join("\n"))
    }
}

fn serialize(list: &SkipList) -> String {
    serde_yaml::to_string(list).expect("skip lists serialize to YAML")
}

fn covers(entry: &SkipEntry, id: &str, rule_covers: &dyn Fn(&str, &str) -> bool) -> bool {
    match (&entry.case, &entry.rule) {
        (Some(case), None) => {
            id == case
                || id
                    .strip_prefix(case.as_str())
                    .is_some_and(|rest| rest.starts_with("::"))
        }
        (None, Some(rule)) => rule_covers(rule, id),
        _ => false,
    }
}

/// Checks coverage in both directions and returns every problem found.
///
/// `known_rules` lists the rule names the runner defines; `rule_covers` decides
/// whether a rule covers a case ID.
pub fn check(
    list: &SkipList,
    results: &[CaseResult],
    known_rules: &[&str],
    rule_covers: &dyn Fn(&str, &str) -> bool,
) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    for result in results {
        if !seen.insert(result.id.as_str()) {
            problems.push(format!("duplicate case ID {:?}", result.id));
        }
    }

    for entry in &list.entries {
        if let Some(rule) = &entry.rule
            && !known_rules.contains(&rule.as_str())
        {
            problems.push(format!("unknown skip rule {rule:?}"));
            continue;
        }
        let covered: Vec<&CaseResult> = results
            .iter()
            .filter(|result| covers(entry, &result.id, rule_covers))
            .collect();
        if covered.is_empty() {
            problems.push(format!("{} covers no corpus case", entry.key()));
        } else if covered
            .iter()
            .all(|result| !matches!(result.outcome, Outcome::NotPassing { .. }))
        {
            problems.push(format!(
                "{} is stale: every covered case now passes; remove the entry",
                entry.key()
            ));
        }
    }

    let mut suggestions = String::new();
    for result in results {
        let Outcome::NotPassing {
            detail,
            suggested_reason,
            suggested_task,
            ..
        } = &result.outcome
        else {
            continue;
        };
        if list
            .entries
            .iter()
            .any(|entry| covers(entry, &result.id, rule_covers))
        {
            continue;
        }
        problems.push(format!("{} is not covered: {detail}", result.id));
        let _ = write!(
            suggestions,
            "- case: {}\n  reason: {}\n  tag: <classify>\n  task: '{}'\n  justification: {}\n",
            yaml_scalar(&result.id),
            suggested_reason.as_str(),
            suggested_task,
            yaml_scalar(detail),
        );
    }
    if !suggestions.is_empty() {
        problems.push(format!(
            "suggested entries (classify the tag and review before adding):\n{suggestions}"
        ));
    }
    problems
}

/// Counts non-passing cases per corpus file by the `reason/tag` of the entry
/// that covers them. A rule entry takes precedence over a case entry, matching
/// the runners, which report a rule's cause before a stage's.
pub fn covered_counts(
    list: &SkipList,
    results: &[CaseResult],
    rule_covers: &dyn Fn(&str, &str) -> bool,
) -> BTreeMap<&'static str, BTreeMap<String, usize>> {
    let mut counts = BTreeMap::<&'static str, BTreeMap<String, usize>>::new();
    for result in results {
        if !matches!(result.outcome, Outcome::NotPassing { .. }) {
            continue;
        }
        let entry = list
            .entries
            .iter()
            .filter(|entry| entry.rule.is_some())
            .chain(list.entries.iter().filter(|entry| entry.case.is_some()))
            .find(|entry| covers(entry, &result.id, rule_covers));
        let label = entry.map_or_else(
            || String::from("uncovered"),
            |entry| format!("{}/{}", entry.reason.as_str(), entry.tag),
        );
        *counts
            .entry(result.file)
            .or_default()
            .entry(label)
            .or_default() += 1;
    }
    counts
}

fn yaml_scalar(value: &str) -> String {
    serde_yaml::to_string(value)
        .expect("strings serialize to YAML")
        .trim_end()
        .to_owned()
}
