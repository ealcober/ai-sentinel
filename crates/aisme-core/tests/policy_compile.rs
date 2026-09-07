// SPDX-License-Identifier: Apache-2.0
//! `F1.PL.02`: the compiler's static validation, on Annex B's own text and
//! on the cases §B.10–§B.12 name.

use aisme_core::ontology::GrantedBy;
use aisme_core::policy::ast::Match;
use aisme_core::policy::{
    compile, compile_with, parse, Bindings, CompileErrorKind, GrantInput, GrantKind, Settings, Term,
};
use aisme_ebpf_common::Verdict;

const SKETCH: &str = include_str!("fixtures/sketch.toml");

fn bindings() -> Bindings {
    Bindings::new().with("workspace", "/home/u/proj").with_list(
        "session.network_allow",
        &["registry.npmjs.org", "api.anthropic.com"],
    )
}

fn compile_src(
    src: &str,
) -> Result<aisme_core::policy::CompiledPolicy, Vec<aisme_core::policy::CompileError>> {
    let policy = parse(src).unwrap_or_else(|e| panic!("{e:#?}"));
    compile(&policy, &bindings())
}

fn rule(id: &str, group: &str, m: &str, verdict: &str, extra: &str) -> String {
    format!("[[rule]]\nid = \"{id}\"\ngroup = \"{group}\"\nmatch = {m}\nverdict = \"{verdict}\"\n{extra}\n")
}

#[test]
fn the_sketch_compiles_resolved_and_canonical() {
    let compiled = compile_src(SKETCH).unwrap_or_else(|e| panic!("{e:#?}"));
    let ids: Vec<&str> = compiled.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "credentials-ask",
            "network-slam",
            "persistence-config",
            "system-config-deny",
            "user-scope-install",
            "workspace-free"
        ],
        "canonical order, by id"
    );
    let free = compiled
        .rules
        .iter()
        .find(|r| r.id == "workspace-free")
        .unwrap();
    assert_eq!(
        free.predicate.terms,
        [Term::PathUnder(vec!["/home/u/proj".into()])],
        "${{workspace}} resolved"
    );
    let slam = compiled
        .rules
        .iter()
        .find(|r| r.id == "network-slam")
        .unwrap();
    assert_eq!(
        slam.predicate.terms[0],
        Term::DestNotIn(vec![
            "api.anthropic.com".into(),
            "registry.npmjs.org".into()
        ]),
        "the list variable expanded and sorted; terms sorted by key"
    );
    let sysconf = compiled
        .rules
        .iter()
        .find(|r| r.id == "system-config-deny")
        .unwrap();
    assert_eq!(
        sysconf.predicate.terms,
        [Term::PathUnder(vec![
            "/boot".into(),
            "/etc".into(),
            "/usr/lib/systemd".into()
        ])]
    );
    assert_eq!(
        sysconf.except.as_ref().unwrap().terms,
        [Term::PathGlob(vec!["/etc/hosts".into()])]
    );
    assert_eq!(sysconf.verdict, Verdict::Deny);
    assert!(!sysconf.promptable && !sysconf.suppressible);
    let creds = compiled
        .rules
        .iter()
        .find(|r| r.id == "credentials-ask")
        .unwrap();
    assert!(
        creds.promptable && creds.suppressible,
        "defaults outside I-05"
    );
}

#[test]
fn i05_groups_cannot_be_made_promptable_suppressible_or_escalated() {
    for group in ["SYSTEM_CONFIG", "FILELESS_EXECUTE", "SELF_PROTECTION"] {
        let src = rule(
            "p",
            group,
            "{ path_under = \"/x\" }",
            "deny",
            "promptable = true",
        );
        let errs = compile_src(&src).unwrap_err();
        assert!(
            matches!(&errs[0].kind, CompileErrorKind::NeverPromptable { what, .. } if what.contains("promptable")),
            "{group}: {errs:#?}"
        );
        assert!(errs[0].to_string().contains("I-05"), "{}", errs[0]);
        let src = rule(
            "s",
            group,
            "{ path_under = \"/x\" }",
            "deny",
            "suppressible = true",
        );
        let errs = compile_src(&src).unwrap_err();
        assert!(
            matches!(&errs[0].kind, CompileErrorKind::NeverPromptable { what, .. } if what.contains("suppressible")),
            "{group}"
        );
        let src = rule("e", group, "{ path_under = \"/x\" }", "escalate", "");
        let errs = compile_src(&src).unwrap_err();
        assert!(
            matches!(&errs[0].kind, CompileErrorKind::NeverPromptable { what, .. } if what.contains("escalate")),
            "{group}"
        );
        // Written the way I-05 wants, or with nothing written, it compiles
        // and resolves to non-promptable, non-suppressible.
        let ok = rule(
            "d",
            group,
            "{ path_under = \"/x\" }",
            "deny",
            "promptable = false\nsuppressible = false",
        ) + &rule("d2", group, "{ path_under = \"/y\" }", "deny", "");
        let compiled = compile_src(&ok).unwrap_or_else(|e| panic!("{e:#?}"));
        assert!(compiled
            .rules
            .iter()
            .all(|r| !r.promptable && !r.suppressible));
    }
    // Outside I-05, escalate and promptable = true are ordinary.
    let src = rule(
        "c",
        "CREDENTIALS",
        "{ path_glob = \"**/.env\" }",
        "escalate",
        "promptable = true",
    );
    compile_src(&src).unwrap_or_else(|e| panic!("{e:#?}"));
}

#[test]
fn an_allow_wholly_shadowed_by_a_broader_deny_is_unreachable() {
    // The AppArmor case §B.10 names: the narrower allow contributes nothing.
    let src = rule(
        "etc-deny",
        "SYSTEM_CONFIG",
        "{ path_under = \"/etc\" }",
        "deny",
        "",
    ) + &rule(
        "hosts-allow",
        "SYSTEM_CONFIG",
        "{ path_under = \"/etc/hosts\" }",
        "allow",
        "",
    );
    let errs = compile_src(&src).unwrap_err();
    assert_eq!(errs.len(), 1, "{errs:#?}");
    assert_eq!(errs[0].rule_id.as_deref(), Some("hosts-allow"));
    assert_eq!(
        errs[0].kind,
        CompileErrorKind::Unreachable {
            shadowed_by: "etc-deny".into()
        }
    );
    assert!(errs[0].to_string().contains("§B.10"));
    // Written with `except`, the same intent compiles: the deny no longer
    // covers /etc/hosts, so nothing is shadowed.
    let fixed = rule(
        "etc-deny",
        "SYSTEM_CONFIG",
        "{ path_under = \"/etc\" }",
        "deny",
        "except = { path_glob = [\"/etc/hosts\"] }",
    ) + &rule(
        "hosts-allow",
        "SYSTEM_CONFIG",
        "{ path_under = \"/etc/hosts\" }",
        "allow",
        "",
    );
    compile_src(&fixed).unwrap_or_else(|e| panic!("{e:#?}"));
}

#[test]
fn doubt_resolves_to_reachable() {
    // A glob against a prefix in the other direction, an incomparable taint
    // rule, an equal verdict: none of these is refused.
    let src = rule(
        "a",
        "CREDENTIALS",
        "{ path_glob = \"**/.env\" }",
        "escalate",
        "",
    ) + &rule("b", "CREDENTIALS", "{ path_under = \"/home\" }", "deny", "")
        + &rule(
            "c",
            "NETWORK_EGRESS",
            "{ taint_any = [\"SECRET_MATERIAL\"] }",
            "deny",
            "",
        )
        + &rule(
            "d",
            "SYSTEM_CONFIG",
            "{ path_under = \"/etc/x\" }",
            "deny",
            "",
        )
        + &rule(
            "e",
            "SYSTEM_CONFIG",
            "{ path_under = \"/etc\" }",
            "deny",
            "",
        );
    compile_src(&src).unwrap_or_else(|e| panic!("{e:#?}"));
    // But a glob whose literal head lies under a prefix is certain.
    let shadowed = rule(
        "wide",
        "SYSTEM_CONFIG",
        "{ path_under = \"/etc\" }",
        "deny",
        "",
    ) + &rule(
        "narrow",
        "SYSTEM_CONFIG",
        "{ path_glob = \"/etc/cron.d/*\" }",
        "warn",
        "",
    );
    let errs = compile_src(&shadowed).unwrap_err();
    assert_eq!(errs[0].rule_id.as_deref(), Some("narrow"));
}

#[test]
fn except_must_narrow_a_dimension_the_match_has() {
    let src = rule(
        "x",
        "SYSTEM_CONFIG",
        "{ path_under = \"/etc\" }",
        "deny",
        "except = { proto = \"tcp\" }",
    );
    let errs = compile_src(&src).unwrap_err();
    assert_eq!(
        errs[0].kind,
        CompileErrorKind::ExceptDimension { key: "proto" }
    );
    assert!(errs[0].to_string().contains("§B.11"));
}

#[test]
fn a_guardrail_is_a_compile_error() {
    let src =
        "[[assert]]\nnever = { group = \"SELF_PROTECTION\", verdict = [\"allow\", \"warn\"] }\n"
            .to_owned()
            + &rule(
                "oops",
                "SELF_PROTECTION",
                "{ path_under = \"/etc/aisme\" }",
                "warn",
                "",
            );
    let errs = compile_src(&src).unwrap_err();
    assert_eq!(errs[0].rule_id.as_deref(), Some("oops"));
    assert_eq!(
        errs[0].kind,
        CompileErrorKind::AssertViolated { assert_index: 0 }
    );
    assert!(errs[0].to_string().contains("§B.12"));
    // The same rule with `deny` passes the guardrail.
    let ok =
        "[[assert]]\nnever = { group = \"SELF_PROTECTION\", verdict = [\"allow\", \"warn\"] }\n"
            .to_owned()
            + &rule(
                "fine",
                "SELF_PROTECTION",
                "{ path_under = \"/etc/aisme\" }",
                "deny",
                "",
            );
    compile_src(&ok).unwrap_or_else(|e| panic!("{e:#?}"));
}

#[test]
fn globs_past_the_budget_and_unbound_variables_do_not_compile() {
    let glob = rule(
        "g",
        "CREDENTIALS",
        "{ path_glob = \"**/**/.env\" }",
        "escalate",
        "",
    );
    let errs = compile_src(&glob).unwrap_err();
    assert!(
        matches!(&errs[0].kind, CompileErrorKind::GlobBudget { pattern } if pattern == "**/**/.env")
    );
    let unbound = rule(
        "u",
        "FILES_OUTSIDE_WORKSPACE",
        "{ path_under = \"${project}\" }",
        "allow",
        "",
    );
    let errs = compile_src(&unbound).unwrap_err();
    assert_eq!(
        errs[0].kind,
        CompileErrorKind::UnboundVariable {
            name: "project".into()
        }
    );
    let list_in_text = rule(
        "l",
        "NETWORK_EGRESS",
        "{ dest_in = \"${session.network_allow}:443\" }",
        "allow",
        "",
    );
    let errs = compile_src(&list_in_text).unwrap_err();
    assert_eq!(
        errs[0].kind,
        CompileErrorKind::ListVariableInText {
            name: "session.network_allow".into()
        }
    );
}

/// `F1.PL.06`: the five grammar items, and what `strict` does.
#[test]
fn the_pl06_grammar_items_compile_and_strict_makes_every_group_non_promptable() {
    let src = "[session.defaults]\nprofile = \"strict\"\ngrant_ttl_days = 14\n".to_owned()
        + &rule(
            "warned",
            "PACKAGE_INSTALL",
            "{ exec_class = \"package-manager\" }",
            "warn",
            "suppressible = true",
        )
        + &rule(
            "hooks",
            "PERSISTENCE_CONFIG",
            "{ path_class = \"PERSISTENCE_CONFIG\" }",
            "warn",
            "",
        )
        + &rule(
            "creds",
            "CREDENTIALS",
            "{ path_glob = \"**/.env\" }",
            "escalate",
            "",
        );
    let compiled = compile_src(&src).unwrap_or_else(|e| panic!("{e:#?}"));
    assert_eq!(
        compiled.settings,
        Settings {
            learning_mode_days: 7,
            grant_ttl_days: 14,
            strict: true
        },
        "written values win, the rest are Annex B's defaults"
    );
    assert!(
        compiled.rules.iter().all(|r| !r.promptable),
        "strict: non-promptable everywhere"
    );
    let warned = compiled.rules.iter().find(|r| r.id == "warned").unwrap();
    assert_eq!(warned.verdict, Verdict::Warn);
    assert!(
        warned.suppressible,
        "strict is about prompting, not suppression"
    );
    let hooks = compiled.rules.iter().find(|r| r.id == "hooks").unwrap();
    assert_eq!(
        hooks.predicate.terms,
        [Term::PathClass(vec![
            aisme_core::ontology::PathClass::PersistenceConfig as u8
        ])]
    );

    // Saying `promptable = true` under strict is refused, not overridden.
    let contradiction = "[session.defaults]\nprofile = \"strict\"\n".to_owned()
        + &rule(
            "ask",
            "CREDENTIALS",
            "{ path_glob = \"**/.env\" }",
            "escalate",
            "promptable = true",
        );
    let errs = compile_src(&contradiction).unwrap_err();
    assert_eq!(errs[0].kind, CompileErrorKind::StrictProfile);
    assert!(errs[0].to_string().contains("F7.PS.06"));

    // Without a [session.defaults] block, the shipped values apply.
    let bare = rule("r", "EXECUTE", "{ exec_class = \"a\" }", "warn", "");
    assert_eq!(compile_src(&bare).unwrap().settings, Settings::DEFAULT);
}

/// `F1.PL.07`: grants and suppressions in the same rule space, and `I-26`.
#[test]
fn the_sketch_suppression_compiles_beside_the_escalation_it_merely_overlaps() {
    let compiled = compile_src(SKETCH).unwrap_or_else(|e| panic!("{e:#?}"));
    assert_eq!(compiled.suppressions.len(), 1);
    let s = &compiled.suppressions[0];
    assert_eq!(
        s.predicate.terms,
        [Term::PathUnder(vec!["/home/u/proj/node_modules".into()])]
    );
    assert_eq!(s.ttl_days, 30);
    assert_eq!(s.report.as_deref(), Some("lm-2026-08-24"));
}

#[test]
fn a_suppression_that_targets_what_it_may_not_silence_does_not_compile() {
    let sup = |m: &str| {
        format!("[[suppression]]\nmatch = {m}\nscope = \"workspace\"\nttl_days = 30\norigin = \"manual\"\n")
    };
    let cases = [
        (
            rule(
                "esc",
                "CREDENTIALS",
                "{ path_glob = \"**/.env\" }",
                "escalate",
                "",
            ),
            sup("{ path_glob = \"**/.env\" }"),
            "escalates",
        ),
        (
            rule(
                "den",
                "PERSISTENCE",
                "{ path_under = \"/etc/cron.d\" }",
                "deny",
                "",
            ),
            sup("{ path_under = \"/etc/cron.d/nightly\" }"),
            "denies",
        ),
        (
            rule(
                "sys",
                "SYSTEM_CONFIG",
                "{ path_under = \"/etc\" }",
                "deny",
                "",
            ),
            sup("{ path_under = \"/etc/hosts\" }"),
            "I-05",
        ),
        (
            rule(
                "crit",
                "EXECUTE",
                "{ exec_class = \"a\" }",
                "warn",
                "severity_floor = \"critical\"",
            ),
            sup("{ exec_class = \"a\" }"),
            "CRITICAL",
        ),
        (
            rule(
                "nosup",
                "EXECUTE",
                "{ exec_class = \"b\" }",
                "warn",
                "suppressible = false",
            ),
            sup("{ exec_class = \"b\" }"),
            "suppressible = false",
        ),
    ];
    for (r, s, because) in cases {
        let errs = compile_src(&(r + &s)).unwrap_err();
        assert!(
            matches!(&errs[0].kind, CompileErrorKind::SuppressionTargets { because: b, .. } if b.contains(because)),
            "{because}: {errs:#?}"
        );
        assert!(errs[0].to_string().contains("I-26"));
    }
    // A warn it merely overlaps, or a warn it fits inside, is what suppression is for.
    let ok = rule(
        "noise",
        "PACKAGE_INSTALL",
        "{ exec_class = \"package-manager\" }",
        "warn",
        "",
    ) + &sup("{ exec_class = \"package-manager\", scope_rel = \"user\" }");
    compile_src(&ok).unwrap_or_else(|e| panic!("{e:#?}"));
}

#[test]
fn grants_land_in_the_rule_space_with_their_ttl_and_are_refused_where_they_cannot_apply() {
    let policy = parse(SKETCH).unwrap();
    let grant = |id: &str, group: &str, m: &str, kind: GrantKind| GrantInput {
        id: id.into(),
        group: aisme_core::ontology::PermissionGroup::parse(group).unwrap(),
        scope: parse(&rule("tmp", group, m, "allow", ""))
            .unwrap()
            .rules
            .remove(0)
            .r#match,
        kind,
        granted_by: GrantedBy::Human { uid: 1000 },
    };
    let always = grant(
        "g-always",
        "CREDENTIALS",
        "{ path_glob = \"${workspace}/.env\" }",
        GrantKind::Always,
    );
    let session = grant(
        "g-session",
        "NETWORK_EGRESS",
        "{ dest_in = \"api.example.com\" }",
        GrantKind::Session,
    );
    let compiled = compile_with(&policy, &bindings(), &[session.clone(), always.clone()])
        .unwrap_or_else(|e| panic!("{e:#?}"));
    let ids: Vec<&str> = compiled.grants.iter().map(|g| g.id.as_str()).collect();
    assert_eq!(ids, ["g-always", "g-session"], "canonical by id");
    assert_eq!(
        compiled.grants[0].ttl_days,
        Some(30),
        "Always decays with grant_ttl_days"
    );
    assert_eq!(
        compiled.grants[1].ttl_days, None,
        "Session dies with the session"
    );
    assert_eq!(
        compiled.grants[0].predicate.terms,
        [Term::PathGlob(vec!["/home/u/proj/.env".into()])]
    );

    let on_i05 = grant(
        "g-sys",
        "SYSTEM_CONFIG",
        "{ path_under = \"/etc/hosts\" }",
        GrantKind::Always,
    );
    let errs = compile_with(&policy, &bindings(), &[on_i05]).unwrap_err();
    assert!(
        matches!(errs[0].kind, CompileErrorKind::GrantNeverPromptable { .. }),
        "{errs:#?}"
    );
    assert!(errs[0].to_string().contains("I-05"));

    // A grant entirely inside a deny of its own group can never apply.
    let src = rule(
        "cron-deny",
        "PERSISTENCE",
        "{ path_under = \"/etc/cron.d\" }",
        "deny",
        "",
    );
    let denied = parse(&src).unwrap();
    let inside = grant(
        "g-cron",
        "PERSISTENCE",
        "{ path_under = \"/etc/cron.d/x\" }",
        GrantKind::Session,
    );
    let errs = compile_with(&denied, &bindings(), &[inside]).unwrap_err();
    assert_eq!(
        errs[0].kind,
        CompileErrorKind::GrantUnreachable {
            shadowed_by: "cron-deny".into()
        }
    );
    let _ = Match::default();
}
