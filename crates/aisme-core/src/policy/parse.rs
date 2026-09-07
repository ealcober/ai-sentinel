// SPDX-License-Identifier: Apache-2.0
//! TOML text → [`Policy`], refusing everything §B.0 does not admit.
//!
//! Closed grammar: an unknown table, key or value is an error, never
//! ignored — a key the reader skips is a rule the author believes exists
//! (general rule 9). `tier` is reserved and not implemented (§B.13), so it is
//! refused by name. Every error carries a line and column; all errors of a
//! source are collected, not only the first.

use core::ops::Range;

use aisme_ebpf_common::Verdict;
use toml_edit::{Array, Document, InlineTable, Item, Table, Value};

use super::ast::{
    path_class_named, taint_named, Assert, Audit, EscalateIf, Match, MatchKey, Policy, Profile,
    Rule, SessionDefaults, Span, Suppression, Text,
};
use crate::ontology::{PermissionGroup, Proto, ResultOrigin, Severity, SuppressionOrigin};
use crate::taint::Taint;

/// One thing the source got wrong, and where.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line.
    pub line: usize,
    /// 1-based column, in bytes.
    pub col: usize,
    /// What was wrong.
    pub message: String,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}: {}", self.line, self.col, self.message)
    }
}

impl core::error::Error for ParseError {}

/// Parse a policy source.
///
/// # Errors
///
/// Every error found, each with its position; the policy is not returned
/// when any exists.
pub fn parse(source: &str) -> Result<Policy, Vec<ParseError>> {
    // `Document` keeps every span; `DocumentMut` would drop them, and the
    // diagnostics are the point.
    let doc: Document<&str> = match Document::parse(source) {
        Ok(doc) => doc,
        Err(e) => {
            let span = e.span().unwrap_or(0..0);
            return Err(vec![ParseError {
                line: line_of(source, span.start),
                col: col_of(source, span.start),
                message: format!("TOML: {}", e.message()),
            }]);
        }
    };
    let mut p = Parser {
        source,
        errors: Vec::new(),
        policy: Policy::default(),
    };
    for (key, item) in doc.as_table() {
        p.top_level(key, item);
    }
    p.check_unique_ids();
    if p.errors.is_empty() {
        Ok(p.policy)
    } else {
        Err(p.errors)
    }
}

struct Parser<'s> {
    source: &'s str,
    errors: Vec<ParseError>,
    policy: Policy,
}

impl Parser<'_> {
    fn error(&mut self, span: Option<Range<usize>>, message: String) {
        let start = span.map_or(0, |r| r.start);
        self.errors.push(ParseError {
            line: line_of(self.source, start),
            col: col_of(self.source, start),
            message,
        });
    }

    fn top_level(&mut self, key: &str, item: &Item) {
        match key {
            "session" => match item.as_table() {
                Some(session) => self.session(session),
                None => self.error(item.span(), "`session` must be a table: `[session.defaults]`".into()),
            },
            "rule" => match item.as_array_of_tables() {
                Some(rules) => {
                    for table in rules {
                        if let Some(rule) = self.rule(table) {
                            self.policy.rules.push(rule);
                        }
                    }
                }
                None => self.error(item.span(), "`rule` must be an array of tables: `[[rule]]`".into()),
            },
            "suppression" => match item.as_array_of_tables() {
                Some(blocks) => {
                    for table in blocks {
                        if let Some(s) = self.suppression(table) {
                            self.policy.suppressions.push(s);
                        }
                    }
                }
                None => self.error(item.span(), "`suppression` must be an array of tables: `[[suppression]]`".into()),
            },
            "assert" => match item.as_array_of_tables() {
                Some(blocks) => {
                    for table in blocks {
                        if let Some(a) = self.assert(table) {
                            self.policy.asserts.push(a);
                        }
                    }
                }
                None => self.error(item.span(), "`assert` must be an array of tables: `[[assert]]`".into()),
            },
            "tier" => self.error(item.span(), "`tier` is reserved and not implemented (Annex B §B.13)".into()),
            other => self.error(
                item.span(),
                format!("unknown top-level `{other}`; the grammar has session.defaults, [[rule]], [[suppression]] and [[assert]]"),
            ),
        }
    }

    fn session(&mut self, session: &Table) {
        for (key, item) in session {
            match key {
                "defaults" => match item.as_table() {
                    Some(defaults) => self.defaults(defaults),
                    None => self.error(item.span(), "`session.defaults` must be a table".into()),
                },
                other => self.error(
                    item.span(),
                    format!("unknown `session.{other}`; only `session.defaults` exists"),
                ),
            }
        }
    }

    fn defaults(&mut self, table: &Table) {
        let mut out = SessionDefaults {
            span: span_of(table.span()),
            ..SessionDefaults::default()
        };
        for (key, item) in table {
            let Some(value) = item.as_value() else {
                self.error(item.span(), format!("`{key}` must be a value"));
                continue;
            };
            match key {
                "learning_mode_days" => out.learning_mode_days = self.u32(key, value),
                "grant_ttl_days" => out.grant_ttl_days = self.u32(key, value),
                "profile" => {
                    out.profile = self.string(key, value).and_then(|s| match s {
                        "default" => Some(Profile::Default),
                        "strict" => Some(Profile::Strict),
                        other => {
                            self.error(
                                value.span(),
                                format!("`profile` is \"default\" or \"strict\", not \"{other}\""),
                            );
                            None
                        }
                    });
                }
                other => self.error(item.span(), format!("unknown `session.defaults.{other}`")),
            }
        }
        if self.policy.defaults.is_some() {
            self.error(table.span(), "`[session.defaults]` appears twice".into());
        }
        self.policy.defaults = Some(out);
    }

    fn rule(&mut self, table: &Table) -> Option<Rule> {
        let span = span_of(table.span());
        let mut id = None;
        let mut group = None;
        let mut r#match = None;
        let mut verdict = None;
        let mut rule = Rule {
            id: String::new(),
            group: PermissionGroup::FilesOutsideWorkspace,
            r#match: Match::default(),
            verdict: Verdict::Allow,
            except: None,
            taint: None,
            severity_floor: None,
            promptable: None,
            suppressible: None,
            audit: None,
            event: None,
            escalate_if: None,
            degrade_open: None,
            span,
        };
        let mut present: Vec<&str> = Vec::with_capacity(4);
        for (key, item) in table {
            present.push(key);
            let Some(value) = item.as_value() else {
                self.error(item.span(), format!("`{key}` must be a value, not a table"));
                continue;
            };
            match key {
                "id" => id = self.string(key, value).map(str::to_owned),
                "group" => group = self.group(value),
                "match" => r#match = self.match_block(value),
                "verdict" => verdict = self.verdict(value),
                "except" => rule.except = self.match_block(value),
                "taint" => rule.taint = self.taint_list(value),
                "severity_floor" => {
                    rule.severity_floor = self.string(key, value).and_then(|s| match s {
                        "low" => Some(Severity::Low),
                        "medium" => Some(Severity::Medium),
                        "high" => Some(Severity::High),
                        "critical" => Some(Severity::Critical),
                        other => {
                            self.error(
                                value.span(),
                                format!(
                                    "`severity_floor` is low|medium|high|critical, not \"{other}\""
                                ),
                            );
                            None
                        }
                    });
                }
                "promptable" => rule.promptable = self.bool(key, value),
                "suppressible" => rule.suppressible = self.bool(key, value),
                "audit" => {
                    rule.audit = self.string(key, value).and_then(|s| match s {
                        "aggregate" => Some(Audit::Aggregate),
                        "individual" => Some(Audit::Individual),
                        other => {
                            self.error(
                                value.span(),
                                format!(
                                    "`audit` is \"aggregate\" or \"individual\", not \"{other}\""
                                ),
                            );
                            None
                        }
                    });
                }
                "event" => rule.event = self.string(key, value).map(str::to_owned),
                "escalate_if" => rule.escalate_if = self.escalate_if(value),
                "degrade_open" => rule.degrade_open = self.bool(key, value),
                "tier" => self.error(
                    item.span(),
                    "`tier` is reserved and not implemented (Annex B §B.13)".into(),
                ),
                other => self.error(item.span(), format!("unknown rule key `{other}`")),
            }
        }
        // Missing means never written; a field written wrongly has already
        // been reported once, and is not reported again as absent.
        for name in ["id", "group", "match", "verdict"] {
            if !present.contains(&name) {
                self.error(table.span(), format!("rule is missing `{name}`"));
            }
        }
        rule.id = id?;
        rule.group = group?;
        rule.r#match = r#match?;
        rule.verdict = verdict?;
        Some(rule)
    }

    fn suppression(&mut self, table: &Table) -> Option<Suppression> {
        let span = span_of(table.span());
        let mut r#match = None;
        let mut scope = None;
        let mut ttl_days = None;
        let mut origin = None;
        let mut report = None;
        let mut present: Vec<&str> = Vec::with_capacity(4);
        for (key, item) in table {
            present.push(key);
            let Some(value) = item.as_value() else {
                self.error(item.span(), format!("`{key}` must be a value, not a table"));
                continue;
            };
            match key {
                "match" => r#match = self.match_block(value),
                "scope" => scope = self.string(key, value).map(str::to_owned),
                "ttl_days" => ttl_days = self.u32(key, value),
                "origin" => {
                    origin = self.string(key, value).and_then(|s| match s {
                        "learned" => Some(SuppressionOrigin::Learned),
                        "manual" => Some(SuppressionOrigin::Manual),
                        "shipped" => Some(SuppressionOrigin::Shipped),
                        other => {
                            self.error(
                                value.span(),
                                format!("`origin` is learned|manual|shipped, not \"{other}\""),
                            );
                            None
                        }
                    });
                }
                "report" => report = self.string(key, value).map(str::to_owned),
                other => self.error(item.span(), format!("unknown suppression key `{other}`")),
            }
        }
        for name in ["match", "scope", "ttl_days", "origin"] {
            if !present.contains(&name) {
                self.error(table.span(), format!("suppression is missing `{name}`"));
            }
        }
        Some(Suppression {
            r#match: r#match?,
            scope: scope?,
            ttl_days: ttl_days?,
            origin: origin?,
            report,
            span,
        })
    }

    fn assert(&mut self, table: &Table) -> Option<Assert> {
        let span = span_of(table.span());
        let mut never = None;
        for (key, item) in table {
            match key {
                "never" => match item.as_value().and_then(Value::as_inline_table) {
                    Some(inline) => never = self.never(inline),
                    None => self.error(
                        item.span(),
                        "`never` must be an inline table: `{ group = …, verdict = [...] }`".into(),
                    ),
                },
                other => self.error(
                    item.span(),
                    format!("unknown assert key `{other}`; only `never` exists (§B.12)"),
                ),
            }
        }
        if never.is_none() {
            self.error(table.span(), "assert is missing `never`".into());
        }
        let (never_group, never_verdicts) = never?;
        Some(Assert {
            never_group,
            never_verdicts,
            span,
        })
    }

    fn never(&mut self, inline: &InlineTable) -> Option<(PermissionGroup, Vec<Verdict>)> {
        let mut group = None;
        let mut verdicts = None;
        let mut present: Vec<&str> = Vec::with_capacity(2);
        for (key, value) in inline {
            present.push(key);
            match key {
                "group" => group = self.group(value),
                "verdict" => {
                    verdicts = self.array(key, value).map(|items| {
                        items
                            .iter()
                            .filter_map(|v| self.verdict(v))
                            .collect::<Vec<_>>()
                    });
                }
                other => self.error(
                    value.span(),
                    format!("unknown `never.{other}`; `group` and `verdict` only"),
                ),
            }
        }
        if !present.contains(&"group") || !present.contains(&"verdict") {
            self.error(
                inline.span(),
                "`never` needs both `group` and `verdict`".into(),
            );
        }
        Some((group?, verdicts?))
    }

    fn match_block(&mut self, value: &Value) -> Option<Match> {
        let Some(inline) = value.as_inline_table() else {
            self.error(
                value.span(),
                "`match` must be an inline table: `{ key = value, ... }`".into(),
            );
            return None;
        };
        let mut out = Match {
            keys: Vec::new(),
            span: span_of(inline.span()),
        };
        for (key, value) in inline {
            let parsed = self.match_key(key, value);
            if let Some(parsed) = parsed {
                if out.keys.iter().any(|k| k.name() == parsed.name()) {
                    self.error(
                        value.span(),
                        format!("`{key}` appears twice in one match; a list value is the OR"),
                    );
                } else {
                    out.keys.push(parsed);
                }
            }
        }
        if inline.is_empty() {
            self.error(inline.span(), "a match needs at least one key".into());
        }
        Some(out)
    }

    /// One `match_key` of §B.0, by name.
    fn match_key(&mut self, key: &str, value: &Value) -> Option<MatchKey> {
        match key {
            "path_under" => self.texts(key, value).map(MatchKey::PathUnder),
            "path_glob" => self.texts(key, value).map(MatchKey::PathGlob),
            "path_class" => self.strings(key, value).map(|names| {
                MatchKey::PathClass(
                    names
                        .iter()
                        .filter_map(|(name, span)| {
                            let class = path_class_named(name);
                            if class.is_none() {
                                self.error(span.clone(), format!("unknown path class \"{name}\""));
                            }
                            class
                        })
                        .collect(),
                )
            }),
            "exec_class" => self
                .strings(key, value)
                .map(|v| MatchKey::ExecClass(owned(v))),
            "exec_path" => self.texts(key, value).map(MatchKey::ExecPath),
            "dest_in" => self.texts(key, value).map(MatchKey::DestIn),
            "dest_not_in" => self.texts(key, value).map(MatchKey::DestNotIn),
            "port_in" => self.ports(value).map(MatchKey::PortIn),
            "proto" => self.strings(key, value).map(|names| {
                MatchKey::Proto(
                    names
                        .iter()
                        .filter_map(|(name, span)| match name.as_str() {
                            "tcp" => Some(Proto::Tcp),
                            "udp" => Some(Proto::Udp),
                            "quic" => Some(Proto::Quic),
                            "unix" => Some(Proto::Unix),
                            other => {
                                self.error(
                                    span.clone(),
                                    format!("`proto` is tcp|udp|quic|unix, not \"{other}\""),
                                );
                                None
                            }
                        })
                        .collect(),
                )
            }),
            "taint_any" => self.taint_list(value).map(MatchKey::TaintAny),
            "taint_all" => self.taint_list(value).map(MatchKey::TaintAll),
            "not_declassified" => self.bool(key, value).map(MatchKey::NotDeclassified),
            "tool_name" => self
                .strings(key, value)
                .map(|v| MatchKey::ToolName(owned(v))),
            "origin" => self.strings(key, value).map(|names| {
                MatchKey::Origin(
                    names
                        .iter()
                        .filter_map(|(name, span)| match name.as_str() {
                            "file" => Some(ResultOrigin::File),
                            "web" => Some(ResultOrigin::Web),
                            "mcp" => Some(ResultOrigin::Mcp),
                            "sdk" => Some(ResultOrigin::Sdk),
                            other => {
                                self.error(
                                    span.clone(),
                                    format!("`origin` is file|web|mcp|sdk, not \"{other}\""),
                                );
                                None
                            }
                        })
                        .collect(),
                )
            }),
            "instruction_bearing" => self.bool(key, value).map(MatchKey::InstructionBearing),
            "scope_rel" => self
                .strings(key, value)
                .map(|v| MatchKey::ScopeRel(owned(v))),
            "age_lt" => self.u64(key, value).map(MatchKey::AgeLt),
            "first_of_kind" => self.bool(key, value).map(MatchKey::FirstOfKind),
            other => {
                self.error(
                    value.span(),
                    format!(
                        "unknown match key `{other}`; the grammar's keys are {}",
                        MatchKey::NAMES.join(", ")
                    ),
                );
                None
            }
        }
    }

    fn escalate_if(&mut self, value: &Value) -> Option<EscalateIf> {
        let Some(inline) = value.as_inline_table() else {
            self.error(value.span(), "`escalate_if` must be an inline table".into());
            return None;
        };
        let mut out = EscalateIf::default();
        for (key, value) in inline {
            match key {
                "adds_executing_key" => {
                    out.adds_executing_key = self.bool(key, value).unwrap_or(false);
                }
                other => self.error(
                    value.span(),
                    format!("unknown `escalate_if.{other}`; only `adds_executing_key` exists"),
                ),
            }
        }
        Some(out)
    }

    // ---- value readers; each reports its own error and returns None ----

    fn string<'v>(&mut self, key: &str, value: &'v Value) -> Option<&'v str> {
        let s = value.as_str();
        if s.is_none() {
            self.error(value.span(), format!("`{key}` must be a string"));
        }
        s
    }

    fn bool(&mut self, key: &str, value: &Value) -> Option<bool> {
        let b = value.as_bool();
        if b.is_none() {
            self.error(value.span(), format!("`{key}` must be true or false"));
        }
        b
    }

    fn u32(&mut self, key: &str, value: &Value) -> Option<u32> {
        let n = value.as_integer().and_then(|i| u32::try_from(i).ok());
        if n.is_none() {
            self.error(
                value.span(),
                format!("`{key}` must be a non-negative integer"),
            );
        }
        n
    }

    fn u64(&mut self, key: &str, value: &Value) -> Option<u64> {
        let n = value.as_integer().and_then(|i| u64::try_from(i).ok());
        if n.is_none() {
            self.error(
                value.span(),
                format!("`{key}` must be a non-negative integer"),
            );
        }
        n
    }

    fn array<'v>(&mut self, key: &str, value: &'v Value) -> Option<&'v Array> {
        let a = value.as_array();
        if a.is_none() {
            self.error(value.span(), format!("`{key}` must be an array"));
        }
        a
    }

    /// A string or an array of strings, each with its span.
    fn strings(&mut self, key: &str, value: &Value) -> Option<Vec<(String, Option<Range<usize>>)>> {
        if let Some(s) = value.as_str() {
            return Some(vec![(s.to_owned(), value.span())]);
        }
        let Some(array) = value.as_array() else {
            self.error(
                value.span(),
                format!("`{key}` must be a string or an array of strings"),
            );
            return None;
        };
        let mut out = Vec::with_capacity(array.len());
        for item in array {
            match item.as_str() {
                Some(s) => out.push((s.to_owned(), item.span())),
                None => self.error(item.span(), format!("`{key}` entries must be strings")),
            }
        }
        if out.is_empty() {
            self.error(value.span(), format!("`{key}` must not be empty"));
            return None;
        }
        Some(out)
    }

    fn texts(&mut self, key: &str, value: &Value) -> Option<Vec<Text>> {
        self.strings(key, value)
            .map(|v| v.iter().map(|(s, _)| Text::parse(s)).collect())
    }

    fn ports(&mut self, value: &Value) -> Option<Vec<u16>> {
        let items: Vec<&Value> = if value.as_integer().is_some() {
            vec![value]
        } else if let Some(array) = value.as_array() {
            array.iter().collect()
        } else {
            self.error(
                value.span(),
                "`port_in` must be an integer or an array of integers".into(),
            );
            return None;
        };
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            match item.as_integer().map(u16::try_from) {
                Some(Ok(port)) => out.push(port),
                _ => self.error(item.span(), "`port_in` entries must be 0..=65535".into()),
            }
        }
        Some(out)
    }

    fn taint_list(&mut self, value: &Value) -> Option<Taint> {
        let names = self.strings("taint", value)?;
        let mut taint = Taint::EMPTY;
        for (name, span) in names {
            match taint_named(&name) {
                Some(t) => taint = taint.union(t),
                None => self.error(
                    span,
                    format!("unknown taint category \"{name}\" (§2.14 names five)"),
                ),
            }
        }
        Some(taint)
    }

    fn group(&mut self, value: &Value) -> Option<PermissionGroup> {
        let name = self.string("group", value)?;
        let group = PermissionGroup::parse(name);
        if group.is_none() {
            self.error(
                value.span(),
                format!(
                    "unknown group \"{name}\"; GROUP is one of {}",
                    group_names()
                ),
            );
        }
        group
    }

    fn verdict(&mut self, value: &Value) -> Option<Verdict> {
        let name = self.string("verdict", value)?;
        let verdict = match name {
            "allow" => Some(Verdict::Allow),
            "warn" => Some(Verdict::Warn),
            "escalate" => Some(Verdict::Escalate),
            "deny" => Some(Verdict::Deny),
            _ => None,
        };
        if verdict.is_none() {
            self.error(
                value.span(),
                format!("`verdict` is allow|warn|escalate|deny, not \"{name}\""),
            );
        }
        verdict
    }

    fn check_unique_ids(&mut self) {
        let mut seen: Vec<&str> = Vec::with_capacity(self.policy.rules.len());
        let mut dups = Vec::new();
        for rule in &self.policy.rules {
            if seen.contains(&rule.id.as_str()) {
                dups.push((rule.span, rule.id.clone()));
            } else {
                seen.push(&rule.id);
            }
        }
        for (span, id) in dups {
            self.error(
                Some(span.start..span.end),
                format!("rule id \"{id}\" appears twice; `id` is unique — it is the diff key"),
            );
        }
    }
}

fn owned(v: Vec<(String, Option<Range<usize>>)>) -> Vec<String> {
    v.into_iter().map(|(s, _)| s).collect()
}

fn group_names() -> String {
    PermissionGroup::ALL
        .iter()
        .map(|g| g.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

fn span_of(range: Option<Range<usize>>) -> Span {
    range.map_or(Span::default(), |r| Span {
        start: r.start,
        end: r.end,
    })
}

fn line_of(source: &str, offset: usize) -> usize {
    source[..offset.min(source.len())].matches('\n').count() + 1
}

fn col_of(source: &str, offset: usize) -> usize {
    let offset = offset.min(source.len());
    offset - source[..offset].rfind('\n').map_or(0, |i| i + 1) + 1
}
