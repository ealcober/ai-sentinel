// SPDX-License-Identifier: Apache-2.0
//! The syntax tree of AISME-PL, one type per production of Annex B §B.0.
//!
//! Everything here is *as written*: order preserved, nothing resolved, nothing
//! validated beyond what the grammar itself fixes (a group name is a
//! [`PermissionGroup`], a verdict is a [`Verdict`]). Resolution of `${…}`
//! variables, reachability, `except` well-formedness and the guardrails are
//! the compiler's (`F1.PL.02`), which reports against the spans kept here.

use aisme_ebpf_common::Verdict;

use crate::ontology::{
    PathClass, PermissionGroup, Proto, ResultOrigin, Severity, SuppressionOrigin,
};
use crate::taint::Taint;

/// Where in the source a construct was written, as a byte range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Span {
    /// First byte.
    pub start: usize,
    /// One past the last byte.
    pub end: usize,
}

/// A whole policy source, in the order written.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Policy {
    /// `[session.defaults]`, when present.
    pub defaults: Option<SessionDefaults>,
    /// `[[rule]]` blocks.
    pub rules: Vec<Rule>,
    /// `[[suppression]]` blocks.
    pub suppressions: Vec<Suppression>,
    /// `[[assert]]` blocks.
    pub asserts: Vec<Assert>,
}

/// `[session.defaults]`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SessionDefaults {
    /// Days of mandatory learning mode (§2.14: 7).
    pub learning_mode_days: Option<u32>,
    /// Always-grants and suppression rules decay together.
    pub grant_ttl_days: Option<u32>,
    /// `"default"` or `"strict"` — strict makes every group non-promptable.
    pub profile: Option<Profile>,
    /// Where it was written.
    pub span: Span,
}

/// The `profile` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// The shipped defaults.
    Default,
    /// Every group non-promptable.
    Strict,
}

/// A `[[rule]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// `id`: unique; the diff key.
    pub id: String,
    /// `group`.
    pub group: PermissionGroup,
    /// `match`: keys are AND, list values are OR within a key.
    pub r#match: Match,
    /// `verdict`.
    pub verdict: Verdict,
    /// `except`: narrows this rule's own match set, nothing else (§B.11).
    pub except: Option<Match>,
    /// `taint`: categories the rule's match confers.
    pub taint: Option<Taint>,
    /// `severity_floor`.
    pub severity_floor: Option<Severity>,
    /// `promptable`; `false` is what `I-05` requires on its three groups.
    pub promptable: Option<bool>,
    /// `suppressible`; `false` is what `I-26` requires on the same three.
    pub suppressible: Option<bool>,
    /// `audit`.
    pub audit: Option<Audit>,
    /// `event`: the OpenTelemetry event name a hit emits.
    pub event: Option<String>,
    /// `escalate_if`.
    pub escalate_if: Option<EscalateIf>,
    /// `degrade_open`: a backend that cannot express the verdict may degrade
    /// downward (§B.9 requires this to be said, never assumed).
    pub degrade_open: Option<bool>,
    /// Where it was written.
    pub span: Span,
}

/// `audit`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audit {
    /// Counted, not logged individually.
    Aggregate,
    /// Every hit logged.
    Individual,
}

/// `escalate_if`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EscalateIf {
    /// A `PERSISTENCE_CONFIG` write that adds an *executing* key escalates
    /// (`DT-06`).
    pub adds_executing_key: bool,
}

/// A `match` or `except` block: a conjunction of keys.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Match {
    /// The keys, in the order written. Duplicates are refused by the parser.
    pub keys: Vec<MatchKey>,
    /// Where it was written.
    pub span: Span,
}

impl Match {
    /// The key of the same dimension as `key`, if present.
    #[must_use]
    pub fn get(&self, dimension: Dimension) -> Option<&MatchKey> {
        self.keys.iter().find(|k| k.dimension() == dimension)
    }
}

/// One `match_key` of §B.0. A list value is OR within the key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MatchKey {
    /// Paths at or below any of these.
    PathUnder(Vec<Text>),
    /// Paths matching any of these globs.
    PathGlob(Vec<Text>),
    /// Any of these classes.
    PathClass(Vec<PathClass>),
    /// Executables of any of these classes (`"package-manager"`, …).
    ExecClass(Vec<String>),
    /// Executables at any of these paths.
    ExecPath(Vec<Text>),
    /// Destinations inside any of these (CIDR, host, or a `${…}` list).
    DestIn(Vec<Text>),
    /// Destinations outside all of these.
    DestNotIn(Vec<Text>),
    /// Any of these ports.
    PortIn(Vec<u16>),
    /// Any of these transports.
    Proto(Vec<Proto>),
    /// Any of these categories set.
    TaintAny(Taint),
    /// All of these categories set.
    TaintAll(Taint),
    /// No declassification in effect.
    NotDeclassified(bool),
    /// Any of these tool names.
    ToolName(Vec<String>),
    /// A `ToolResult` from any of these origins.
    Origin(Vec<ResultOrigin>),
    /// A `ToolResult` carrying instructions.
    InstructionBearing(bool),
    /// Scope relative to the session: `"user"`, `"workspace"`, `"system"`.
    ScopeRel(Vec<String>),
    /// Younger than this many seconds (a file the session wrote < N s ago).
    AgeLt(u64),
    /// The first action of its class in this session.
    FirstOfKind(bool),
}

/// The dimension a key matches on; an `except` operand must share the
/// dimension of the term it narrows (§B.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Dimension {
    /// `path_under`, `path_glob`, `path_class`.
    Path,
    /// `exec_class`, `exec_path`.
    Exec,
    /// `dest_in`, `dest_not_in`, `port_in`, `proto`.
    Network,
    /// `taint_any`, `taint_all`, `not_declassified`.
    Taint,
    /// `tool_name`, `origin`, `instruction_bearing`.
    Tool,
    /// `scope_rel`, `age_lt`, `first_of_kind`.
    Session,
}

impl MatchKey {
    /// The grammar's spelling.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            MatchKey::PathUnder(_) => "path_under",
            MatchKey::PathGlob(_) => "path_glob",
            MatchKey::PathClass(_) => "path_class",
            MatchKey::ExecClass(_) => "exec_class",
            MatchKey::ExecPath(_) => "exec_path",
            MatchKey::DestIn(_) => "dest_in",
            MatchKey::DestNotIn(_) => "dest_not_in",
            MatchKey::PortIn(_) => "port_in",
            MatchKey::Proto(_) => "proto",
            MatchKey::TaintAny(_) => "taint_any",
            MatchKey::TaintAll(_) => "taint_all",
            MatchKey::NotDeclassified(_) => "not_declassified",
            MatchKey::ToolName(_) => "tool_name",
            MatchKey::Origin(_) => "origin",
            MatchKey::InstructionBearing(_) => "instruction_bearing",
            MatchKey::ScopeRel(_) => "scope_rel",
            MatchKey::AgeLt(_) => "age_lt",
            MatchKey::FirstOfKind(_) => "first_of_kind",
        }
    }

    /// The dimension.
    #[must_use]
    pub const fn dimension(&self) -> Dimension {
        match self {
            MatchKey::PathUnder(_) | MatchKey::PathGlob(_) | MatchKey::PathClass(_) => {
                Dimension::Path
            }
            MatchKey::ExecClass(_) | MatchKey::ExecPath(_) => Dimension::Exec,
            MatchKey::DestIn(_)
            | MatchKey::DestNotIn(_)
            | MatchKey::PortIn(_)
            | MatchKey::Proto(_) => Dimension::Network,
            MatchKey::TaintAny(_) | MatchKey::TaintAll(_) | MatchKey::NotDeclassified(_) => {
                Dimension::Taint
            }
            MatchKey::ToolName(_) | MatchKey::Origin(_) | MatchKey::InstructionBearing(_) => {
                Dimension::Tool
            }
            MatchKey::ScopeRel(_) | MatchKey::AgeLt(_) | MatchKey::FirstOfKind(_) => {
                Dimension::Session
            }
        }
    }

    /// Every key name the grammar admits, in §B.0 order.
    pub const NAMES: [&'static str; 18] = [
        "path_under",
        "path_glob",
        "path_class",
        "exec_class",
        "exec_path",
        "dest_in",
        "dest_not_in",
        "port_in",
        "proto",
        "taint_any",
        "taint_all",
        "not_declassified",
        "tool_name",
        "origin",
        "instruction_bearing",
        "scope_rel",
        "age_lt",
        "first_of_kind",
    ];
}

/// A string value that may carry `${…}` variables (`${workspace}`,
/// `${session.network_allow}`), kept unresolved: resolution needs the
/// session, which the compiler has and the parser does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Text {
    /// The segments, in order.
    pub segments: Vec<Segment>,
}

/// A piece of a [`Text`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    /// Literal text.
    Lit(String),
    /// A `${name}` reference, without the delimiters.
    Var(String),
}

impl Text {
    /// Split `${…}` references out of a string.
    #[must_use]
    pub fn parse(raw: &str) -> Text {
        let mut segments = Vec::new();
        let mut rest = raw;
        while let Some(open) = rest.find("${") {
            if let Some(close) = rest[open..].find('}') {
                if open > 0 {
                    segments.push(Segment::Lit(rest[..open].to_owned()));
                }
                segments.push(Segment::Var(rest[open + 2..open + close].to_owned()));
                rest = &rest[open + close + 1..];
            } else {
                break;
            }
        }
        if !rest.is_empty() {
            segments.push(Segment::Lit(rest.to_owned()));
        }
        Text { segments }
    }

    /// Whether any segment is a variable.
    #[must_use]
    pub fn has_vars(&self) -> bool {
        self.segments.iter().any(|s| matches!(s, Segment::Var(_)))
    }

    /// The literal text, when there are no variables.
    #[must_use]
    pub fn literal(&self) -> Option<&str> {
        match self.segments.as_slice() {
            [Segment::Lit(s)] => Some(s),
            [] => Some(""),
            _ => None,
        }
    }
}

/// A `[[suppression]]`: changes notification only (`I-26`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Suppression {
    /// `match`.
    pub r#match: Match,
    /// `scope`, as written (`"workspace"`).
    pub scope: String,
    /// `ttl_days`.
    pub ttl_days: u32,
    /// `origin`.
    pub origin: SuppressionOrigin,
    /// `report`: the learning-mode report that produced it.
    pub report: Option<String>,
    /// Where it was written.
    pub span: Span,
}

/// An `[[assert]]`: a compile-time guardrail over the whole rule set (§B.12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assert {
    /// `never = { group = …, verdict = [...] }`: no rule on `group` may
    /// carry any of these verdicts.
    pub never_group: PermissionGroup,
    /// The forbidden verdicts.
    pub never_verdicts: Vec<Verdict>,
    /// Where it was written.
    pub span: Span,
}

/// The taint category names the grammar spells, in bit order.
pub const TAINT_NAMES: [(&str, Taint); 5] = [
    ("SECRET_MATERIAL", Taint::SECRET_MATERIAL),
    ("UNTRUSTED_INPUT", Taint::UNTRUSTED_INPUT),
    ("GENERATED_CODE", Taint::GENERATED_CODE),
    ("EXTERNAL_EGRESS", Taint::EXTERNAL_EGRESS),
    ("CREDENTIAL_ACCESS", Taint::CREDENTIAL_ACCESS),
];

/// A taint category by its grammar name.
#[must_use]
pub fn taint_named(name: &str) -> Option<Taint> {
    TAINT_NAMES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
}

/// A path class by its grammar name — the upper-case spelling of the group
/// it answers to, plus `WORKSPACE` for the unclassified inside.
#[must_use]
pub fn path_class_named(name: &str) -> Option<PathClass> {
    Some(match name {
        "WORKSPACE" => PathClass::Unclassified,
        "FILES_OUTSIDE_WORKSPACE" => PathClass::OutsideWorkspace,
        "SYSTEM_CONFIG" => PathClass::SystemConfig,
        "CREDENTIALS" => PathClass::Credentials,
        "PERSISTENCE" => PathClass::Persistence,
        "PERSISTENCE_CONFIG" => PathClass::PersistenceConfig,
        "SELF_PROTECTION" => PathClass::SelfProtection,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_splits_variables_and_keeps_literals() {
        let t = Text::parse("${workspace}/node_modules");
        assert_eq!(
            t.segments,
            [
                Segment::Var("workspace".into()),
                Segment::Lit("/node_modules".into())
            ]
        );
        assert!(t.has_vars());
        assert_eq!(t.literal(), None);
        let plain = Text::parse("/etc");
        assert_eq!(plain.literal(), Some("/etc"));
        let dangling = Text::parse("a${b");
        assert_eq!(
            dangling.segments,
            [Segment::Lit("a${b".into())],
            "unclosed is literal"
        );
        assert_eq!(Text::parse("").segments, []);
    }

    #[test]
    fn every_key_has_a_name_in_the_grammar_and_a_dimension() {
        let keys = [
            MatchKey::PathUnder(vec![]),
            MatchKey::PathGlob(vec![]),
            MatchKey::PathClass(vec![]),
            MatchKey::ExecClass(vec![]),
            MatchKey::ExecPath(vec![]),
            MatchKey::DestIn(vec![]),
            MatchKey::DestNotIn(vec![]),
            MatchKey::PortIn(vec![]),
            MatchKey::Proto(vec![]),
            MatchKey::TaintAny(Taint::EMPTY),
            MatchKey::TaintAll(Taint::EMPTY),
            MatchKey::NotDeclassified(true),
            MatchKey::ToolName(vec![]),
            MatchKey::Origin(vec![]),
            MatchKey::InstructionBearing(true),
            MatchKey::ScopeRel(vec![]),
            MatchKey::AgeLt(0),
            MatchKey::FirstOfKind(true),
        ];
        for (key, name) in keys.iter().zip(MatchKey::NAMES) {
            assert_eq!(key.name(), name);
        }
        assert_eq!(MatchKey::PathGlob(vec![]).dimension(), Dimension::Path);
        assert_eq!(MatchKey::Proto(vec![]).dimension(), Dimension::Network);
        assert_eq!(taint_named("SECRET_MATERIAL"), Some(Taint::SECRET_MATERIAL));
        assert_eq!(
            taint_named("secret_material"),
            None,
            "case is part of the name"
        );
        assert_eq!(
            path_class_named("PERSISTENCE_CONFIG"),
            Some(PathClass::PersistenceConfig)
        );
    }
}
