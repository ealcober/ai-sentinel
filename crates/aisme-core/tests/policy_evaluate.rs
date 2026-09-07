// SPDX-License-Identifier: Apache-2.0
//! `F1.PL.10`: evaluation records `decided_by`, grants answer escalations as
//! `granted_by`, suppressions become `suppressed_by` and nothing else.

use aisme_core::ontology::{GrantedBy, PermissionGroup};
use aisme_core::policy::{
    compile, compile_with, evaluate, parse, Bindings, CompiledPolicy, EventFacts, GrantInput,
    GrantKind,
};
use aisme_core::taint::Taint;
use aisme_ebpf_common::Verdict;

const SKETCH: &str = include_str!("fixtures/sketch.toml");

fn bindings() -> Bindings {
    Bindings::new().with("workspace", "/home/u/proj").with_list(
        "session.network_allow",
        &["registry.npmjs.org", "api.anthropic.com"],
    )
}

fn sketch() -> CompiledPolicy {
    compile(&parse(SKETCH).unwrap(), &bindings()).unwrap()
}

fn file(group: PermissionGroup, path: &str) -> EventFacts<'_> {
    EventFacts {
        group: Some(group),
        path: Some(path),
        ..EventFacts::default()
    }
}

#[test]
fn the_verdict_is_the_max_and_decided_by_names_the_rule_that_supplied_it() {
    let policy = sketch();
    let passwd = evaluate(&policy, &file(PermissionGroup::SystemConfig, "/etc/passwd"));
    assert_eq!(passwd.verdict, Verdict::Deny);
    assert_eq!(passwd.decided_by.as_deref(), Some("system-config-deny"));
    // §B.11: the except carves /etc/hosts out of that rule; nothing else
    // matches, so the answer is allow and nobody decided it.
    let hosts = evaluate(&policy, &file(PermissionGroup::SystemConfig, "/etc/hosts"));
    assert_eq!(hosts.verdict, Verdict::Allow);
    assert_eq!(hosts.decided_by, None);
    assert_eq!(hosts.matched, 0);
    // A .env under the workspace: the credentials rule escalates.
    let env = evaluate(
        &policy,
        &file(PermissionGroup::Credentials, "/home/u/proj/.env"),
    );
    assert_eq!(env.verdict, Verdict::Escalate);
    assert_eq!(env.decided_by.as_deref(), Some("credentials-ask"));
    // A rule of another group never applies, whatever its match.
    let wrong_group = evaluate(&policy, &file(PermissionGroup::Persistence, "/etc/passwd"));
    assert_eq!(wrong_group.verdict, Verdict::Allow);
    assert_eq!(wrong_group.decided_by, None);
}

#[test]
fn the_slam_fires_on_the_compound_condition_and_names_itself() {
    let policy = sketch();
    let egress = |dest: &'static str, taint: Taint, declassified: bool| EventFacts {
        group: Some(PermissionGroup::NetworkEgress),
        dest: Some(dest),
        taint: Some(taint),
        declassified: Some(declassified),
        ..EventFacts::default()
    };
    let slam = evaluate(
        &policy,
        &egress("evil.example", Taint::SECRET_MATERIAL, false),
    );
    assert_eq!(slam.verdict, Verdict::Deny);
    assert_eq!(slam.decided_by.as_deref(), Some("network-slam"));
    for benign in [
        egress("registry.npmjs.org", Taint::SECRET_MATERIAL, false),
        egress("evil.example", Taint::UNTRUSTED_INPUT, false),
        egress("evil.example", Taint::SECRET_MATERIAL, true),
    ] {
        let d = evaluate(&policy, &benign);
        assert_eq!(
            (d.verdict, d.decided_by),
            (Verdict::Allow, None),
            "{benign:?}"
        );
    }
    // An absent fact is not a value: with no taint known, the taint term
    // does not match.
    let unknown = EventFacts {
        group: Some(PermissionGroup::NetworkEgress),
        dest: Some("evil.example"),
        declassified: Some(false),
        ..EventFacts::default()
    };
    assert_eq!(evaluate(&policy, &unknown).verdict, Verdict::Allow);
}

#[test]
fn a_grant_answers_an_escalation_and_is_named_while_a_deny_stays_a_deny() {
    let policy = parse(SKETCH).unwrap();
    let grant = GrantInput {
        id: "g-env".into(),
        group: PermissionGroup::Credentials,
        scope: parse("[[rule]]\nid = \"t\"\ngroup = \"CREDENTIALS\"\nmatch = { path_glob = \"${workspace}/.env\" }\nverdict = \"allow\"\n").unwrap().rules.remove(0).r#match,
        kind: GrantKind::Session,
        granted_by: GrantedBy::Human { uid: 1000 },
    };
    let granted = compile_with(&policy, &bindings(), &[grant]).unwrap();
    let env = evaluate(
        &granted,
        &file(PermissionGroup::Credentials, "/home/u/proj/.env"),
    );
    assert_eq!(env.verdict, Verdict::Allow);
    assert_eq!(
        env.decided_by.as_deref(),
        Some("credentials-ask"),
        "the rule is still named"
    );
    assert_eq!(env.granted_by.as_deref(), Some("g-env"));
    // Outside the grant's scope the escalation stands.
    let other = evaluate(
        &granted,
        &file(PermissionGroup::Credentials, "/home/u/other/.env"),
    );
    assert_eq!((other.verdict, other.granted_by), (Verdict::Escalate, None));
    // A grant never touches a deny.
    let passwd = evaluate(
        &granted,
        &file(PermissionGroup::SystemConfig, "/etc/passwd"),
    );
    assert_eq!((passwd.verdict, passwd.granted_by), (Verdict::Deny, None));
}

#[test]
fn a_suppression_is_recorded_and_changes_nothing_else() {
    let policy = sketch();
    let noise = evaluate(
        &policy,
        &file(
            PermissionGroup::FilesOutsideWorkspace,
            "/home/u/proj/node_modules/x/y.js",
        ),
    );
    assert_eq!(noise.verdict, Verdict::Allow);
    assert_eq!(noise.decided_by.as_deref(), Some("workspace-free"));
    assert_eq!(noise.suppressed_by, Some(0), "I-26: notification silenced");
    let outside = evaluate(
        &policy,
        &file(
            PermissionGroup::FilesOutsideWorkspace,
            "/home/u/proj/src/main.rs",
        ),
    );
    assert_eq!(outside.suppressed_by, None);
    // Even where it matches, the verdict is what it was: an escalation
    // under node_modules is still an escalation.
    let env = evaluate(
        &policy,
        &file(
            PermissionGroup::Credentials,
            "/home/u/proj/node_modules/x/.env",
        ),
    );
    assert_eq!(
        (env.verdict, env.suppressed_by),
        (Verdict::Escalate, Some(0))
    );
}

#[test]
fn ties_are_attributed_to_the_first_rule_in_canonical_order_every_time() {
    let src = "[[rule]]\nid = \"zeta\"\ngroup = \"EXECUTE\"\nmatch = { exec_class = \"a\" }\nverdict = \"warn\"\n\n[[rule]]\nid = \"alpha\"\ngroup = \"EXECUTE\"\nmatch = { exec_class = \"a\" }\nverdict = \"warn\"\n";
    let policy = compile(&parse(src).unwrap(), &bindings()).unwrap();
    let facts = EventFacts {
        group: Some(PermissionGroup::Execute),
        exec_class: Some("a"),
        ..EventFacts::default()
    };
    for _ in 0..3 {
        let d = evaluate(&policy, &facts);
        assert_eq!(d.decided_by.as_deref(), Some("alpha"));
        assert_eq!(d.matched, 2);
    }
    // A stricter rule later in canonical order takes the attribution. Its
    // match is narrower than the warns' — with the same match the compiler
    // would refuse the two warns as unreachable (F1.PL.02), correctly.
    let src2 = format!(
        "{src}\n[[rule]]\nid = \"omega\"\ngroup = \"EXECUTE\"\nmatch = {{ exec_class = \"a\", scope_rel = \"user\" }}\nverdict = \"deny\"\n"
    );
    let policy = compile(&parse(&src2).unwrap(), &bindings()).unwrap_or_else(|e| panic!("{e:#?}"));
    let user = EventFacts {
        scope_rel: Some("user"),
        ..facts.clone()
    };
    // Canonical order is alpha, omega, zeta: alpha matches, omega denies,
    // and evaluation stops there — §B.10's sound early exit — so zeta is
    // never visited and `matched` counts two.
    let d = evaluate(&policy, &user);
    assert_eq!(
        (d.verdict, d.decided_by.as_deref(), d.matched),
        (Verdict::Deny, Some("omega"), 2)
    );
    let d = evaluate(&policy, &facts);
    assert_eq!(
        (d.verdict, d.decided_by.as_deref()),
        (Verdict::Warn, Some("alpha")),
        "no scope fact: omega does not match"
    );
}
