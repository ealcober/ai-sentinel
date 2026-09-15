// SPDX-License-Identifier: Apache-2.0
//! `F1.PL.09`: over-blocking triage and the cross-version strictness check,
//! on Annex B's sketch.

use aisme_core::ontology::GrantedBy;
use aisme_core::policy::{
    at_least_as_strict, compile, compile_with, over_blocking, parse, Bindings, GrantInput,
    GrantKind, Weakening,
};
use aisme_ebpf_common::Verdict;

const SKETCH: &str = include_str!("fixtures/sketch.toml");

fn bindings() -> Bindings {
    Bindings::new()
        .with("workspace", "/home/u/proj")
        .with("home", "/home/u")
        .with_list("session.network_allow", &["registry.npmjs.org"])
}

fn compiled(src: &str) -> aisme_core::policy::CompiledPolicy {
    compile(&parse(src).unwrap(), &bindings()).unwrap_or_else(|e| panic!("{e:#?}"))
}

#[test]
fn over_blocking_lists_who_raises_whom_strictest_first() {
    let policy = compiled(SKETCH);
    let triage = over_blocking(&policy);
    let by_id = |id: &str| triage.iter().find(|r| r.rule_id == id);
    // The slam shares no key with the path rules, so it may meet any of
    // them; it raises everything below deny.
    let slam = by_id("network-slam").unwrap();
    assert_eq!(slam.verdict, Verdict::Deny);
    let over: Vec<&str> = slam.over.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        over,
        [
            "credentials-ask",
            "persistence-config",
            "user-scope-install",
            "workspace-free"
        ]
    );
    assert_eq!(slam.over[0].1, Verdict::Escalate, "strictest first");
    // credentials-ask (escalate, **/.env) raises the workspace allow and the
    // two warns; not the deny.
    let creds = by_id("credentials-ask").unwrap();
    let over: Vec<&str> = creds.over.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        over,
        ["persistence-config", "user-scope-install", "workspace-free"]
    );
    // system-config-deny (/etc, /boot, /usr/lib/systemd) cannot meet the
    // workspace allow: disjoint prefixes.
    let sysconf = by_id("system-config-deny").unwrap();
    assert!(!sysconf.over.iter().any(|(id, _)| id == "workspace-free"));
    // An allow raises no one, so it has no entry.
    assert!(by_id("workspace-free").is_none());
}

#[test]
fn strictness_is_proven_for_additions_and_unproven_for_relaxations() {
    let base = compiled(SKETCH);
    assert_eq!(at_least_as_strict(&base, &base), Ok(()));
    // Adding a rule keeps every old one covered.
    let plus = compiled(&format!("{SKETCH}\n[[rule]]\nid = \"extra\"\ngroup = \"DEVICE\"\nmatch = {{ tool_name = \"camera\" }}\nverdict = \"deny\"\n"));
    assert_eq!(at_least_as_strict(&plus, &base), Ok(()));
    assert!(
        at_least_as_strict(&base, &plus).is_err(),
        "the other way round, `extra` is uncovered"
    );
    // Relaxing one verdict is reported by name, with what it says now.
    let relaxed = compiled(&SKETCH.replacen("verdict = \"escalate\"", "verdict = \"warn\"", 1));
    let weak = at_least_as_strict(&relaxed, &base).unwrap_err();
    assert_eq!(
        weak,
        [Weakening::Uncovered {
            rule_id: "credentials-ask".into(),
            verdict: Verdict::Escalate,
            replaced_by: Some(("credentials-ask".into(), Verdict::Warn)),
        }]
    );
    // Narrowing a match (a new except) is not proven either.
    let narrowed = compiled(&SKETCH.replacen(
        "match   = { taint_any = [\"SECRET_MATERIAL\",\"CREDENTIAL_ACCESS\"],",
        "match   = { taint_any = [\"SECRET_MATERIAL\"],",
        1,
    ));
    assert!(
        matches!(&at_least_as_strict(&narrowed, &base).unwrap_err()[..], [Weakening::Uncovered { rule_id, .. }] if rule_id == "network-slam")
    );
    // A new grant answers escalations the old policy would have asked about.
    let policy = parse(SKETCH).unwrap();
    let grant = GrantInput {
        id: "g1".into(),
        group: aisme_core::ontology::PermissionGroup::Credentials,
        scope: parse("[[rule]]\nid = \"t\"\ngroup = \"CREDENTIALS\"\nmatch = { path_glob = \"${workspace}/.env\" }\nverdict = \"allow\"\n").unwrap().rules.remove(0).r#match,
        kind: GrantKind::Session,
        granted_by: GrantedBy::Human { uid: 1 },
    };
    let granted = compile_with(&policy, &bindings(), &[grant]).unwrap();
    assert_eq!(
        at_least_as_strict(&granted, &base),
        Err(vec![Weakening::NewGrant {
            grant_id: "g1".into()
        }])
    );
    assert_eq!(
        at_least_as_strict(&base, &granted),
        Ok(()),
        "dropping a grant only tightens"
    );
}

/// A path pattern that starts with `~/` is refused, and the refusal names it.
///
/// **This is a rule that could never fire, which is worse than no rule at all**:
/// the gate that tests it still passes. The tilde is expanded by a shell, so a
/// process asks the kernel for `/home/<user>/.aws/credentials` and a pattern
/// still carrying the tilde matches nothing. Measured on 2026-09-15 before this
/// diagnostic existed: the shipped skeleton's credential rule read `~/.aws/**`,
/// and `cat ~/.aws/credentials` under it was answered with **0 asked** — the
/// escalate path was never exercised by the gate that existed to exercise it.
///
/// Both `path_glob` and `path_under` are checked, because the defect is about
/// the tilde and not about globbing.
#[test]
fn a_path_that_starts_with_a_tilde_is_refused_by_name() {
    for key in ["path_glob", "path_under"] {
        let source = format!(
            "[[rule]]\nid = \"tilde\"\ngroup = \"CREDENTIALS\"\n\
             match = {{ {key} = \"~/.aws/credentials\" }}\nverdict = \"escalate\"\n"
        );
        let policy = parse(&source).unwrap();
        let errors = compile(&policy, &bindings())
            .expect_err("a tilde path compiled, so a rule that cannot fire would have shipped");
        let said = errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<String>>()
            .join("; ");
        assert!(
            said.contains("~/.aws/credentials") && said.contains("shell"),
            "the refusal must name the pattern and say why, got: {said}"
        );
    }

    // And a tilde anywhere else is an ordinary character: a file really named
    // `report~` must keep working, or the diagnostic becomes its own defect.
    let ordinary = parse(
        "[[rule]]\nid = \"backup\"\ngroup = \"CREDENTIALS\"\n\
         match = { path_glob = \"${workspace}/report~\" }\nverdict = \"allow\"\n",
    )
    .unwrap();
    assert!(
        compile(&ordinary, &bindings()).is_ok(),
        "a tilde inside a path is not a home shorthand"
    );
}
