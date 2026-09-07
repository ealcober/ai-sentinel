// SPDX-License-Identifier: Apache-2.0
//! The compiler: [`Policy`] → [`CompiledPolicy`], with static validation
//! (`F1.PL.02`). Fails at compile, never at runtime.
//!
//! Four checks, each a compile error with the rule it names:
//!
//! - **Unreachable rules, as §B.10 defines them**: a rule that can never be
//!   the strictest for any input. Decided by *provable* subsumption — `R` is
//!   unreachable when some `S` has `match(R) ⊆ match(S)` and a stricter
//!   verdict. The inclusion is decided key by key and claimed only when it
//!   is certain (a literal prefix under a literal prefix, a set inside a
//!   set); refusing a reachable rule would block a valid policy, while
//!   missing an unreachable one loses a diagnostic, so doubt resolves to
//!   "reachable".
//! - **`except` well-formedness** (§B.11): each `except` key narrows a
//!   dimension the rule's own `match` has; nesting cannot be written in
//!   TOML and no key can name another rule, so those two are the parser's.
//! - **`assert never` guardrails** (§B.12): a rule on the asserted group with
//!   a forbidden verdict does not compile.
//! - **Unbounded globs**: a pattern the kernel's bounded loop could not
//!   walk. The budget below is a declared proxy — at most one `**`, at most
//!   eight wildcard segments — until `F3.PT.03` measures the verifier; the
//!   constant is one place to change.
//!
//! `${…}` variables resolve here, against [`Bindings`] the session supplies:
//! an unbound variable is an error, never an empty string.

use aisme_ebpf_common::Verdict;

use super::ast::{
    Assert, Dimension, Match, MatchKey, Policy, Profile, Rule, Segment, Span, Suppression, Text,
};
use crate::ontology::{GrantedBy, SuppressionOrigin};
use crate::ontology::{PermissionGroup, Severity};
use crate::taint::Taint;

/// The glob budget: a declared proxy for the verifier's loop budget until
/// `F3.PT.03` measures it.
pub const MAX_DOUBLE_STAR: usize = 1;
/// See [`MAX_DOUBLE_STAR`].
pub const MAX_WILDCARD_SEGMENTS: usize = 8;

/// What `${…}` variables resolve to for one session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bindings {
    vars: Vec<(String, Vec<String>)>,
}

impl Bindings {
    /// No variables bound.
    #[must_use]
    pub fn new() -> Bindings {
        Bindings::default()
    }

    /// Bind `name` to one value.
    #[must_use]
    pub fn with(mut self, name: &str, value: &str) -> Bindings {
        self.vars.push((name.to_owned(), vec![value.to_owned()]));
        self
    }

    /// Bind `name` to a list; a `Text` that is exactly `${name}` expands to
    /// every element.
    #[must_use]
    pub fn with_list(mut self, name: &str, values: &[&str]) -> Bindings {
        self.vars.push((
            name.to_owned(),
            values.iter().map(|v| (*v).to_owned()).collect(),
        ));
        self
    }

    fn get(&self, name: &str) -> Option<&[String]> {
        self.vars
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }
}

/// Why a policy did not compile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    /// The rule (or suppression) at fault, when one is.
    pub rule_id: Option<String>,
    /// Where it was written.
    pub span: Span,
    /// What went wrong.
    pub kind: CompileErrorKind,
}

/// The kinds of compile error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileErrorKind {
    /// §B.10: the rule can never be the strictest for any input.
    Unreachable {
        /// The rule whose match includes this one's, with a stricter verdict.
        shadowed_by: String,
    },
    /// §B.11: an `except` key on a dimension the match does not have.
    ExceptDimension {
        /// The offending key.
        key: &'static str,
    },
    /// §B.12: a guardrail the rule violates.
    AssertViolated {
        /// Which assert, by position.
        assert_index: usize,
    },
    /// A glob past the budget.
    GlobBudget {
        /// The pattern.
        pattern: String,
    },
    /// A `${…}` the session did not bind.
    UnboundVariable {
        /// Its name.
        name: String,
    },
    /// A list variable used inside a longer string.
    ListVariableInText {
        /// Its name.
        name: String,
    },
    /// `I-05`: the three never-promptable groups cannot be made promptable,
    /// suppressible, or escalated — an escalation is a prompt.
    NeverPromptable {
        /// The group.
        group: PermissionGroup,
        /// Which field or verdict tried.
        what: &'static str,
    },
    /// `profile = "strict"` makes every group non-promptable; a rule that
    /// says `promptable = true` under it does not compile.
    StrictProfile,
    /// `I-26`: a suppression that targets — fits entirely inside the match
    /// of — a rule it may not silence: an `I-05` group, an `escalate`, a
    /// `deny`, a `CRITICAL` severity floor, or `suppressible = false`.
    SuppressionTargets {
        /// The rule it would silence.
        rule_id: String,
        /// Why that rule may not be silenced.
        because: &'static str,
    },
    /// A grant on an `I-05` group: never grantable through a prompt.
    GrantNeverPromptable {
        /// The group.
        group: PermissionGroup,
    },
    /// A grant that fits entirely inside a `deny` rule can never answer an
    /// escalation: nothing under it escalates.
    GrantUnreachable {
        /// The deny rule.
        shadowed_by: String,
    },
}

impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Some(id) = &self.rule_id {
            write!(f, "rule \"{id}\": ")?;
        }
        match &self.kind {
            CompileErrorKind::Unreachable { shadowed_by } => write!(
                f,
                "unreachable — every input it matches is already decided at least as strictly by \"{shadowed_by}\" (§B.10)"
            ),
            CompileErrorKind::ExceptDimension { key } => write!(
                f,
                "`except` key `{key}` narrows a dimension the rule's `match` does not have (§B.11)"
            ),
            CompileErrorKind::AssertViolated { assert_index } => {
                write!(f, "violates [[assert]] #{} (§B.12)", assert_index + 1)
            }
            CompileErrorKind::GlobBudget { pattern } => write!(
                f,
                "glob \"{pattern}\" exceeds the budget ({MAX_DOUBLE_STAR} `**`, {MAX_WILDCARD_SEGMENTS} wildcard segments)"
            ),
            CompileErrorKind::UnboundVariable { name } => write!(f, "`${{{name}}}` is not bound for this session"),
            CompileErrorKind::ListVariableInText { name } => {
                write!(f, "`${{{name}}}` is a list and cannot sit inside a longer string")
            }
            CompileErrorKind::StrictProfile => write!(
                f,
                "`promptable = true` under `profile = \"strict\"`, which makes every group non-promptable (F7.PS.06)"
            ),
            CompileErrorKind::SuppressionTargets { rule_id, because } => write!(
                f,
                "suppression targets rule \"{rule_id}\", which {because} — a suppression silences warn and timeline noise, nothing else (I-26)"
            ),
            CompileErrorKind::GrantNeverPromptable { group } => write!(
                f,
                "grant on {}: never grantable through a prompt (I-05)",
                group.as_str()
            ),
            CompileErrorKind::GrantUnreachable { shadowed_by } => write!(
                f,
                "grant can never apply: everything it covers is denied by \"{shadowed_by}\", and a deny is not promptable"
            ),
            CompileErrorKind::NeverPromptable { group, what } => write!(
                f,
                "{} is never promptable (I-05): {what} does not compile — a prompt is an attack surface on this group",
                group.as_str()
            ),
        }
    }
}

impl core::error::Error for CompileError {}

/// A compiled policy: resolved, validated, canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPolicy {
    /// The session settings, defaults applied.
    pub settings: Settings,
    /// Rules in canonical order (by id), each with a resolved predicate.
    pub rules: Vec<CompiledRule>,
    /// Grants, in the same space (§B.2 `PL-06`), canonical by id.
    pub grants: Vec<CompiledGrant>,
    /// Suppression rules, in the same space, in the order written (they have
    /// no id of their own in the grammar; their position is their identity).
    pub suppressions: Vec<CompiledSuppression>,
}

/// A grant the adjudicator recorded (`F7.PS.02`), offered to the compiler.
/// Grants are not in the policy grammar: they live in the per-machine
/// store and enter here as input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantInput {
    /// The grant's id, the diff key.
    pub id: String,
    /// The group answered.
    pub group: PermissionGroup,
    /// The scope answered, in the match language.
    pub scope: Match,
    /// `Always` or this session.
    pub kind: GrantKind,
    /// Who answered.
    pub granted_by: GrantedBy,
}

/// How long a grant lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GrantKind {
    /// Until `grant_ttl_days` of non-use (`Always` in the prompt).
    Always,
    /// Until the session ends.
    Session,
}

/// A grant in the rule space: same predicate machinery, a TTL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledGrant {
    /// The id.
    pub id: String,
    /// The group.
    pub group: PermissionGroup,
    /// The scope, resolved and canonical.
    pub predicate: Predicate,
    /// Days of non-use before it expires; `None` dies with the session.
    pub ttl_days: Option<u32>,
    /// Who answered.
    pub granted_by: GrantedBy,
}

/// A suppression rule in the rule space (`I-26`: notification only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledSuppression {
    /// The match, resolved and canonical.
    pub predicate: Predicate,
    /// The scope, as written.
    pub scope: String,
    /// Days before it decays, like a grant.
    pub ttl_days: u32,
    /// Where it came from.
    pub origin: SuppressionOrigin,
    /// The learning-mode report that produced it.
    pub report: Option<String>,
}

/// `[session.defaults]`, resolved: what was written, else Annex B's shipped
/// values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Days of mandatory learning mode (§2.14: 7).
    pub learning_mode_days: u32,
    /// Always-grants and suppression rules decay together (Annex B: 30).
    pub grant_ttl_days: u32,
    /// Whether every group is non-promptable.
    pub strict: bool,
}

impl Settings {
    /// Annex B's shipped values.
    pub const DEFAULT: Settings = Settings {
        learning_mode_days: 7,
        grant_ttl_days: 30,
        strict: false,
    };
}

impl Default for Settings {
    fn default() -> Settings {
        Settings::DEFAULT
    }
}

/// One compiled rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRule {
    /// The source id — `decided_by` names this.
    pub id: String,
    /// The group.
    pub group: PermissionGroup,
    /// The verdict.
    pub verdict: Verdict,
    /// The predicate, resolved and canonical.
    pub predicate: Predicate,
    /// The `except` predicate, resolved and canonical.
    pub except: Option<Predicate>,
    /// Categories a match confers.
    pub taint: Taint,
    /// The floor.
    pub severity_floor: Option<Severity>,
    /// Whether an escalation on this rule may ask a human. Resolved: as
    /// written, else `true` — except on `I-05`'s three groups, where it is
    /// `false` and `true` does not compile.
    pub promptable: bool,
    /// Whether a suppression rule may silence this rule's notifications.
    /// Resolved the same way (`I-26` on the same three groups).
    pub suppressible: bool,
    /// The event a hit emits.
    pub event: Option<String>,
}

/// A conjunction of resolved terms, canonical: sorted by key name, values
/// sorted and deduplicated, so equal meaning is equal bytes (`PL-03`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Predicate {
    /// The terms.
    pub terms: Vec<Term>,
}

/// One resolved term. Same shape as [`MatchKey`], with every `Text` resolved
/// to strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Term {
    /// Prefixes, canonical.
    PathUnder(Vec<String>),
    /// Globs.
    PathGlob(Vec<String>),
    /// Path classes, as their discriminants.
    PathClass(Vec<u8>),
    /// Executable classes.
    ExecClass(Vec<String>),
    /// Executable paths.
    ExecPath(Vec<String>),
    /// Destinations inside.
    DestIn(Vec<String>),
    /// Destinations outside.
    DestNotIn(Vec<String>),
    /// Ports.
    PortIn(Vec<u16>),
    /// Transports, as `Proto` debug names.
    Proto(Vec<String>),
    /// Any of.
    TaintAny(Taint),
    /// All of.
    TaintAll(Taint),
    /// No declassification.
    NotDeclassified(bool),
    /// Tool names.
    ToolName(Vec<String>),
    /// Origins, as discriminants.
    Origin(Vec<u8>),
    /// Instruction-bearing.
    InstructionBearing(bool),
    /// Scope relative to the session.
    ScopeRel(Vec<String>),
    /// Younger than, seconds.
    AgeLt(u64),
    /// First of its kind.
    FirstOfKind(bool),
}

impl Term {
    /// The key name, for ordering and messages.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Term::PathUnder(_) => "path_under",
            Term::PathGlob(_) => "path_glob",
            Term::PathClass(_) => "path_class",
            Term::ExecClass(_) => "exec_class",
            Term::ExecPath(_) => "exec_path",
            Term::DestIn(_) => "dest_in",
            Term::DestNotIn(_) => "dest_not_in",
            Term::PortIn(_) => "port_in",
            Term::Proto(_) => "proto",
            Term::TaintAny(_) => "taint_any",
            Term::TaintAll(_) => "taint_all",
            Term::NotDeclassified(_) => "not_declassified",
            Term::ToolName(_) => "tool_name",
            Term::Origin(_) => "origin",
            Term::InstructionBearing(_) => "instruction_bearing",
            Term::ScopeRel(_) => "scope_rel",
            Term::AgeLt(_) => "age_lt",
            Term::FirstOfKind(_) => "first_of_kind",
        }
    }

    /// Whether every input this term admits, the `other` term (same key)
    /// admits too — claimed only when certain.
    fn included_in(&self, other: &Term) -> bool {
        match (self, other) {
            (Term::PathUnder(mine), Term::PathUnder(theirs)) => {
                mine.iter().all(|m| theirs.iter().any(|t| path_under(m, t)))
            }
            // A glob whose literal head lies under a prefix is inside it.
            (Term::PathGlob(mine), Term::PathGlob(theirs)) => subset(mine, theirs),
            (Term::PathClass(m), Term::PathClass(t)) | (Term::Origin(m), Term::Origin(t)) => {
                subset(m, t)
            }
            (Term::ExecClass(m), Term::ExecClass(t))
            | (Term::ExecPath(m), Term::ExecPath(t))
            | (Term::DestIn(m), Term::DestIn(t))
            | (Term::Proto(m), Term::Proto(t))
            | (Term::ToolName(m), Term::ToolName(t))
            | (Term::ScopeRel(m), Term::ScopeRel(t)) => subset(m, t),
            (Term::PortIn(m), Term::PortIn(t)) => subset(m, t),
            // Excluding more is narrower: mine ⊇ theirs.
            (Term::DestNotIn(m), Term::DestNotIn(t)) => subset(t, m),
            // any-of: fewer categories is narrower; all-of: more is narrower.
            (Term::TaintAny(m), Term::TaintAny(t)) => t.contains(*m),
            (Term::TaintAll(m), Term::TaintAll(t)) => m.contains(*t),
            (Term::NotDeclassified(m), Term::NotDeclassified(t))
            | (Term::InstructionBearing(m), Term::InstructionBearing(t))
            | (Term::FirstOfKind(m), Term::FirstOfKind(t)) => m == t,
            (Term::AgeLt(m), Term::AgeLt(t)) => m <= t,
            _ => false,
        }
    }
}

impl Predicate {
    /// Whether every input this predicate admits, `other` admits too: every
    /// term of `other` is matched by an included term of the same key here
    /// (a term here that `other` lacks only narrows this side). Cross-key
    /// inclusion is claimed in one case that is certain: a glob whose
    /// literal head lies under `other`'s `path_under` prefix.
    #[must_use]
    pub fn included_in(&self, other: &Predicate) -> bool {
        other.terms.iter().all(|theirs| {
            self.terms.iter().any(|mine| mine.included_in(theirs))
                || matches!((theirs, self.term("path_glob")),
                    (Term::PathUnder(prefixes), Some(Term::PathGlob(globs)))
                        if globs.iter().all(|g| prefixes.iter().any(|p| path_under(glob_head(g), p))))
        })
    }

    fn term(&self, name: &str) -> Option<&Term> {
        self.terms.iter().find(|t| t.name() == name)
    }
}

/// Compile a parsed policy for one session, with no grants.
///
/// # Errors
///
/// Every error found, each naming its rule.
pub fn compile(policy: &Policy, bindings: &Bindings) -> Result<CompiledPolicy, Vec<CompileError>> {
    compile_with(policy, bindings, &[])
}

/// Compile a parsed policy for one session, with the grants the machine's
/// store holds: grants and suppression rules land in the same rule space
/// as the rules, with their TTLs (§B.2 `PL-06`).
///
/// # Errors
///
/// Every error found, each naming its rule, grant or suppression.
pub fn compile_with(
    policy: &Policy,
    bindings: &Bindings,
    grants: &[GrantInput],
) -> Result<CompiledPolicy, Vec<CompileError>> {
    let mut errors = Vec::new();
    let settings = policy
        .defaults
        .as_ref()
        .map_or(Settings::DEFAULT, |d| Settings {
            learning_mode_days: d
                .learning_mode_days
                .unwrap_or(Settings::DEFAULT.learning_mode_days),
            grant_ttl_days: d.grant_ttl_days.unwrap_or(Settings::DEFAULT.grant_ttl_days),
            strict: d.profile == Some(Profile::Strict),
        });
    let mut rules = Vec::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        if let Some(compiled) = compile_rule(rule, bindings, settings, &mut errors) {
            rules.push(compiled);
        }
    }
    check_asserts(&policy.rules, &policy.asserts, &mut errors);
    check_reachability(&rules, &policy.rules, &mut errors);
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    let suppressions = policy
        .suppressions
        .iter()
        .filter_map(|s| compile_suppression(s, &rules, bindings, &mut errors))
        .collect();
    let mut compiled_grants: Vec<CompiledGrant> = grants
        .iter()
        .filter_map(|g| compile_grant(g, &rules, settings, bindings, &mut errors))
        .collect();
    compiled_grants.sort_by(|a, b| a.id.cmp(&b.id));
    if errors.is_empty() {
        Ok(CompiledPolicy {
            settings,
            rules,
            grants: compiled_grants,
            suppressions,
        })
    } else {
        errors.sort_by_key(|e| e.span.start);
        Err(errors)
    }
}

fn compile_rule(
    rule: &Rule,
    bindings: &Bindings,
    settings: Settings,
    errors: &mut Vec<CompileError>,
) -> Option<CompiledRule> {
    let before = errors.len();
    // `profile = "strict"`: every group non-promptable, and saying otherwise
    // is refused rather than quietly overridden.
    if settings.strict && rule.promptable == Some(true) && !rule.group.never_promptable() {
        errors.push(CompileError {
            rule_id: Some(rule.id.clone()),
            span: rule.span,
            kind: CompileErrorKind::StrictProfile,
        });
    }
    if let Some(except) = &rule.except {
        for key in &except.keys {
            if rule.r#match.get(key.dimension()).is_none() {
                errors.push(CompileError {
                    rule_id: Some(rule.id.clone()),
                    span: except.span,
                    kind: CompileErrorKind::ExceptDimension { key: key.name() },
                });
            }
        }
    }
    // I-05: the never-promptable groups. `promptable = true` and
    // `suppressible = true` are refused, and so is `escalate`, because an
    // escalation is a prompt by another name. Absent, both default to false
    // here and to true elsewhere.
    let never = rule.group.never_promptable();
    if never {
        for (field, what) in [
            (rule.promptable, "`promptable = true`"),
            (rule.suppressible, "`suppressible = true`"),
        ] {
            if field == Some(true) {
                errors.push(CompileError {
                    rule_id: Some(rule.id.clone()),
                    span: rule.span,
                    kind: CompileErrorKind::NeverPromptable {
                        group: rule.group,
                        what,
                    },
                });
            }
        }
        if rule.verdict == Verdict::Escalate {
            errors.push(CompileError {
                rule_id: Some(rule.id.clone()),
                span: rule.span,
                kind: CompileErrorKind::NeverPromptable {
                    group: rule.group,
                    what: "`verdict = \"escalate\"`",
                },
            });
        }
    }
    let predicate = resolve(&rule.r#match, &rule.id, bindings, errors);
    let except = rule
        .except
        .as_ref()
        .map(|e| resolve(e, &rule.id, bindings, errors));
    if errors.len() > before {
        return None;
    }
    Some(CompiledRule {
        id: rule.id.clone(),
        group: rule.group,
        verdict: rule.verdict,
        predicate,
        except,
        taint: rule.taint.unwrap_or(Taint::EMPTY),
        severity_floor: rule.severity_floor,
        promptable: !settings.strict && rule.promptable.unwrap_or(!never),
        suppressible: rule.suppressible.unwrap_or(!never),
        event: rule.event.clone(),
    })
}

/// `I-26` as the compiler enforces it: a suppression may silence `warn` and
/// timeline noise, nothing else. It *targets* a rule when its match fits
/// entirely inside that rule's — a suppression aimed at silencing it — and
/// then the rule's verdict, group, severity floor and `suppressible` decide.
/// Mere overlap is not targeting: Annex B's own sketch silences
/// `${workspace}/node_modules` beside a global `**/.env` escalation.
fn compile_suppression(
    s: &Suppression,
    rules: &[CompiledRule],
    bindings: &Bindings,
    errors: &mut Vec<CompileError>,
) -> Option<CompiledSuppression> {
    let before = errors.len();
    let predicate = resolve(&s.r#match, "[[suppression]]", bindings, errors);
    if errors.len() > before {
        return None;
    }
    for rule in rules {
        if !predicate.included_in(&rule.predicate) {
            continue;
        }
        let because = if rule.group.never_promptable() {
            Some("is on a never-promptable group (I-05)")
        } else if rule.verdict == Verdict::Escalate {
            Some("escalates")
        } else if rule.verdict == Verdict::Deny {
            Some("denies")
        } else if rule.severity_floor == Some(Severity::Critical) {
            Some("carries a CRITICAL severity floor")
        } else if !rule.suppressible {
            Some("says `suppressible = false`")
        } else {
            None
        };
        if let Some(because) = because {
            errors.push(CompileError {
                rule_id: None,
                span: s.span,
                kind: CompileErrorKind::SuppressionTargets {
                    rule_id: rule.id.clone(),
                    because,
                },
            });
        }
    }
    if errors.len() > before {
        return None;
    }
    Some(CompiledSuppression {
        predicate,
        scope: s.scope.clone(),
        ttl_days: s.ttl_days,
        origin: s.origin,
        report: s.report.clone(),
    })
}

/// A grant answers an escalation for its scope. It is refused on an `I-05`
/// group (never grantable) and when everything it covers is already denied
/// (nothing under it escalates, so it could never apply).
fn compile_grant(
    g: &GrantInput,
    rules: &[CompiledRule],
    settings: Settings,
    bindings: &Bindings,
    errors: &mut Vec<CompileError>,
) -> Option<CompiledGrant> {
    let before = errors.len();
    if g.group.never_promptable() {
        errors.push(CompileError {
            rule_id: Some(g.id.clone()),
            span: g.scope.span,
            kind: CompileErrorKind::GrantNeverPromptable { group: g.group },
        });
    }
    let predicate = resolve(&g.scope, &g.id, bindings, errors);
    if let Some(deny) = rules.iter().find(|r| {
        r.group == g.group
            && r.verdict == Verdict::Deny
            && r.except.is_none()
            && predicate.included_in(&r.predicate)
    }) {
        errors.push(CompileError {
            rule_id: Some(g.id.clone()),
            span: g.scope.span,
            kind: CompileErrorKind::GrantUnreachable {
                shadowed_by: deny.id.clone(),
            },
        });
    }
    if errors.len() > before {
        return None;
    }
    Some(CompiledGrant {
        id: g.id.clone(),
        group: g.group,
        predicate,
        ttl_days: match g.kind {
            GrantKind::Always => Some(settings.grant_ttl_days),
            GrantKind::Session => None,
        },
        granted_by: g.granted_by,
    })
}

fn resolve(
    m: &Match,
    rule_id: &str,
    bindings: &Bindings,
    errors: &mut Vec<CompileError>,
) -> Predicate {
    let mut terms = Vec::with_capacity(m.keys.len());
    for key in &m.keys {
        let err = |kind| CompileError {
            rule_id: Some(rule_id.to_owned()),
            span: m.span,
            kind,
        };
        let term = match key {
            MatchKey::PathUnder(texts) => {
                Term::PathUnder(canon(texts_to_strings(texts, bindings, &err, errors)))
            }
            MatchKey::PathGlob(texts) => {
                let globs = canon(texts_to_strings(texts, bindings, &err, errors));
                for g in &globs {
                    if !glob_within_budget(g) {
                        errors.push(err(CompileErrorKind::GlobBudget { pattern: g.clone() }));
                    }
                }
                Term::PathGlob(globs)
            }
            MatchKey::PathClass(classes) => {
                Term::PathClass(canon(classes.iter().map(|c| *c as u8).collect()))
            }
            MatchKey::ExecClass(v) => Term::ExecClass(canon(v.clone())),
            MatchKey::ExecPath(texts) => {
                Term::ExecPath(canon(texts_to_strings(texts, bindings, &err, errors)))
            }
            MatchKey::DestIn(texts) => {
                Term::DestIn(canon(texts_to_strings(texts, bindings, &err, errors)))
            }
            MatchKey::DestNotIn(texts) => {
                Term::DestNotIn(canon(texts_to_strings(texts, bindings, &err, errors)))
            }
            MatchKey::PortIn(ports) => Term::PortIn(canon(ports.clone())),
            MatchKey::Proto(protos) => {
                Term::Proto(canon(protos.iter().map(|p| format!("{p:?}")).collect()))
            }
            MatchKey::TaintAny(t) => Term::TaintAny(*t),
            MatchKey::TaintAll(t) => Term::TaintAll(*t),
            MatchKey::NotDeclassified(b) => Term::NotDeclassified(*b),
            MatchKey::ToolName(v) => Term::ToolName(canon(v.clone())),
            MatchKey::Origin(o) => Term::Origin(canon(o.iter().map(|o| *o as u8).collect())),
            MatchKey::InstructionBearing(b) => Term::InstructionBearing(*b),
            MatchKey::ScopeRel(v) => Term::ScopeRel(canon(v.clone())),
            MatchKey::AgeLt(n) => Term::AgeLt(*n),
            MatchKey::FirstOfKind(b) => Term::FirstOfKind(*b),
        };
        terms.push(term);
    }
    terms.sort_by_key(Term::name);
    Predicate { terms }
}

fn texts_to_strings(
    texts: &[Text],
    bindings: &Bindings,
    err: &dyn Fn(CompileErrorKind) -> CompileError,
    errors: &mut Vec<CompileError>,
) -> Vec<String> {
    let mut out = Vec::with_capacity(texts.len());
    for text in texts {
        // Exactly `${name}` may expand to a list; anywhere else a variable
        // must be a single value.
        if let [Segment::Var(name)] = text.segments.as_slice() {
            match bindings.get(name) {
                Some(values) => out.extend(values.iter().cloned()),
                None => errors.push(err(CompileErrorKind::UnboundVariable {
                    name: name.clone(),
                })),
            }
            continue;
        }
        let mut s = String::new();
        let mut ok = true;
        for segment in &text.segments {
            match segment {
                Segment::Lit(l) => s.push_str(l),
                Segment::Var(name) => match bindings.get(name) {
                    Some([one]) => s.push_str(one),
                    Some(_) => {
                        errors.push(err(CompileErrorKind::ListVariableInText {
                            name: name.clone(),
                        }));
                        ok = false;
                    }
                    None => {
                        errors.push(err(CompileErrorKind::UnboundVariable {
                            name: name.clone(),
                        }));
                        ok = false;
                    }
                },
            }
        }
        if ok {
            out.push(s);
        }
    }
    out
}

fn canon<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort();
    v.dedup();
    v
}

fn subset<T: PartialEq>(mine: &[T], theirs: &[T]) -> bool {
    mine.iter().all(|m| theirs.contains(m))
}

/// `path` is `prefix` or lies under it, by components.
fn path_under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return path.starts_with('/');
    }
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The literal head of a glob: everything before the first wildcard
/// character, cut back to a component boundary.
fn glob_head(glob: &str) -> &str {
    let end = glob.find(['*', '?', '[']).unwrap_or(glob.len());
    let head = &glob[..end];
    match head.rfind('/') {
        Some(0) => "/",
        Some(i) => &head[..i],
        None => "",
    }
}

fn glob_within_budget(glob: &str) -> bool {
    let double = glob.matches("**").count();
    let wildcard_segments = glob
        .split('/')
        .filter(|seg| seg.contains(['*', '?', '[']))
        .count();
    double <= MAX_DOUBLE_STAR && wildcard_segments <= MAX_WILDCARD_SEGMENTS
}

fn check_asserts(rules: &[Rule], asserts: &[Assert], errors: &mut Vec<CompileError>) {
    for (i, assert) in asserts.iter().enumerate() {
        for rule in rules {
            if rule.group == assert.never_group && assert.never_verdicts.contains(&rule.verdict) {
                errors.push(CompileError {
                    rule_id: Some(rule.id.clone()),
                    span: rule.span,
                    kind: CompileErrorKind::AssertViolated { assert_index: i },
                });
            }
        }
    }
}

fn check_reachability(compiled: &[CompiledRule], source: &[Rule], errors: &mut Vec<CompileError>) {
    for r in compiled {
        let shadow = compiled.iter().find(|s| {
            s.id != r.id
                && s.verdict > r.verdict
                && r.predicate.included_in(&s.predicate)
                // S's except must not carve anything out of R that R does
                // not carve out itself; certain only when S has none, or R's
                // except includes S's.
                && match (&s.except, &r.except) {
                    (None, _) => true,
                    (Some(se), Some(re)) => se.included_in(re),
                    (Some(_), None) => false,
                }
        });
        if let Some(s) = shadow {
            let span = source
                .iter()
                .find(|x| x.id == r.id)
                .map_or(Span::default(), |x| x.span);
            errors.push(CompileError {
                rule_id: Some(r.id.clone()),
                span,
                kind: CompileErrorKind::Unreachable {
                    shadowed_by: s.id.clone(),
                },
            });
        }
    }
}

/// The dimension of a term name, for callers that reason about `except`.
#[must_use]
pub fn dimension_of(name: &str) -> Option<Dimension> {
    Some(match name {
        "path_under" | "path_glob" | "path_class" => Dimension::Path,
        "exec_class" | "exec_path" => Dimension::Exec,
        "dest_in" | "dest_not_in" | "port_in" | "proto" => Dimension::Network,
        "taint_any" | "taint_all" | "not_declassified" => Dimension::Taint,
        "tool_name" | "origin" | "instruction_bearing" => Dimension::Tool,
        "scope_rel" | "age_lt" | "first_of_kind" => Dimension::Session,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_under_is_by_component() {
        assert!(path_under("/etc/hosts", "/etc"));
        assert!(path_under("/etc", "/etc/"));
        assert!(!path_under("/etcetera", "/etc"));
        assert!(path_under("/x", "/"));
    }

    #[test]
    fn glob_heads_and_budget() {
        assert_eq!(glob_head("/etc/**/*.conf"), "/etc");
        assert_eq!(glob_head("**/.env"), "");
        assert_eq!(glob_head("/a/b*"), "/a");
        assert_eq!(glob_head("/*"), "/");
        assert!(glob_within_budget("**/.env"));
        assert!(!glob_within_budget("**/**/x"));
        assert!(!glob_within_budget("/*/*/*/*/*/*/*/*/*/x"));
    }

    #[test]
    fn term_inclusion_goes_the_right_way_for_negative_keys() {
        let narrow = Term::DestNotIn(vec!["a".into(), "b".into()]);
        let wide = Term::DestNotIn(vec!["a".into()]);
        assert!(narrow.included_in(&wide), "excluding more is narrower");
        assert!(!wide.included_in(&narrow));
        let any_one = Term::TaintAny(Taint::SECRET_MATERIAL);
        let any_two = Term::TaintAny(Taint::SECRET_MATERIAL | Taint::CREDENTIAL_ACCESS);
        assert!(any_one.included_in(&any_two));
        assert!(!any_two.included_in(&any_one));
        let all_two = Term::TaintAll(Taint::SECRET_MATERIAL | Taint::CREDENTIAL_ACCESS);
        let all_one = Term::TaintAll(Taint::SECRET_MATERIAL);
        assert!(all_two.included_in(&all_one), "requiring more is narrower");
        assert!(Term::AgeLt(5).included_in(&Term::AgeLt(10)));
        assert!(!Term::PathUnder(vec!["/a".into()]).included_in(&Term::ExecPath(vec!["/a".into()])));
    }
}
