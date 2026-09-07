// SPDX-License-Identifier: Apache-2.0
//! `F1.PL.01`: the parser takes Annex B's own text and refuses what the
//! grammar does not admit.

use aisme_core::ontology::{PermissionGroup, Severity, SuppressionOrigin};
use aisme_core::policy::ast::{Audit, Profile, Segment};
use aisme_core::policy::{parse, MatchKey, ParseError};
use aisme_core::taint::Taint;
use aisme_ebpf_common::Verdict;

const SKETCH: &str = include_str!("fixtures/sketch.toml");

fn errors(source: &str) -> Vec<ParseError> {
    parse(source).expect_err("expected the parser to refuse")
}

fn one_error(source: &str) -> ParseError {
    let errs = errors(source);
    assert_eq!(errs.len(), 1, "{errs:#?}");
    errs.into_iter().next().unwrap()
}

#[test]
fn the_annex_b_sketch_parses_whole() {
    let policy = parse(SKETCH).unwrap_or_else(|e| panic!("{e:#?}"));
    let defaults = policy.defaults.as_ref().unwrap();
    assert_eq!(defaults.learning_mode_days, Some(7));
    assert_eq!(defaults.grant_ttl_days, Some(30));
    assert_eq!(defaults.profile, Some(Profile::Default));

    let ids: Vec<&str> = policy.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "workspace-free",
            "system-config-deny",
            "user-scope-install",
            "persistence-config",
            "credentials-ask",
            "network-slam"
        ],
        "in the order written"
    );

    let free = &policy.rules[0];
    assert_eq!(free.group, PermissionGroup::FilesOutsideWorkspace);
    assert_eq!(free.verdict, Verdict::Allow);
    assert_eq!(free.audit, Some(Audit::Aggregate));
    match &free.r#match.keys[..] {
        [MatchKey::PathUnder(paths)] => {
            assert_eq!(paths[0].segments, [Segment::Var("workspace".into())]);
        }
        other => panic!("{other:?}"),
    }

    let sysconf = &policy.rules[1];
    assert_eq!(sysconf.verdict, Verdict::Deny);
    assert_eq!(sysconf.promptable, Some(false));
    assert_eq!(sysconf.suppressible, Some(false));
    let except = sysconf.except.as_ref().unwrap();
    assert!(
        matches!(&except.keys[..], [MatchKey::PathGlob(g)] if g[0].literal() == Some("/etc/hosts"))
    );
    assert!(matches!(&sysconf.r#match.keys[..], [MatchKey::PathUnder(p)] if p.len() == 3));
    assert!(
        sysconf.span.start < except.span.start,
        "spans follow the text"
    );

    let install = &policy.rules[2];
    assert_eq!(install.r#match.keys.len(), 2);
    assert!(matches!(&install.r#match.keys[1], MatchKey::ScopeRel(s) if s == &["user"]));

    let persistence = &policy.rules[3];
    assert!(persistence.escalate_if.unwrap().adds_executing_key);
    assert!(matches!(&persistence.r#match.keys[..], [MatchKey::PathGlob(g)] if g.len() == 6));

    let creds = &policy.rules[4];
    assert_eq!(creds.taint, Some(Taint::SECRET_MATERIAL));
    assert_eq!(creds.severity_floor, Some(Severity::High));
    assert_eq!(creds.verdict, Verdict::Escalate);

    let slam = &policy.rules[5];
    assert_eq!(slam.event.as_deref(), Some("aisme.exfiltration.blocked"));
    assert_eq!(slam.r#match.keys.len(), 3);
    assert_eq!(
        slam.r#match.keys[0],
        MatchKey::TaintAny(Taint::SECRET_MATERIAL | Taint::CREDENTIAL_ACCESS)
    );
    assert!(matches!(
        &slam.r#match.keys[1],
        MatchKey::DestNotIn(d) if d[0].segments == [Segment::Var("session.network_allow".into())]
    ));
    assert_eq!(slam.r#match.keys[2], MatchKey::NotDeclassified(true));

    assert_eq!(policy.suppressions.len(), 1);
    let s = &policy.suppressions[0];
    assert_eq!(s.scope, "workspace");
    assert_eq!(s.ttl_days, 30);
    assert_eq!(s.origin, SuppressionOrigin::Learned);
    assert_eq!(s.report.as_deref(), Some("lm-2026-08-24"));

    assert_eq!(policy.asserts.len(), 1);
    assert_eq!(
        policy.asserts[0].never_group,
        PermissionGroup::SelfProtection
    );
    assert_eq!(
        policy.asserts[0].never_verdicts,
        [Verdict::Allow, Verdict::Warn]
    );
}

#[test]
fn parsing_is_deterministic() {
    assert_eq!(parse(SKETCH), parse(SKETCH));
}

#[test]
fn tier_is_reserved_and_refused_by_name() {
    let err = one_error("[[rule]]\nid = \"x\"\ngroup = \"EXECUTE\"\nmatch = { exec_class = \"a\" }\nverdict = \"deny\"\ntier = 1\n");
    assert!(err.message.contains("reserved"), "{err}");
    assert_eq!(err.line, 6);
    let top = one_error("[tier]\nlevel = 1\n");
    assert!(top.message.contains("§B.13"), "{top}");
}

#[test]
fn unknown_keys_are_errors_not_ignored() {
    let rule = one_error("[[rule]]\nid = \"x\"\ngroup = \"EXECUTE\"\nmatch = { exec_class = \"a\" }\nverdict = \"deny\"\nprority = 3\n");
    assert!(
        rule.message.contains("unknown rule key `prority`"),
        "{rule}"
    );
    let key = one_error("[[rule]]\nid = \"x\"\ngroup = \"EXECUTE\"\nmatch = { exec_glob = \"a\" }\nverdict = \"deny\"\n");
    assert!(
        key.message.contains("unknown match key `exec_glob`"),
        "{key}"
    );
    assert!(
        key.message.contains("path_under"),
        "names the grammar's keys"
    );
    let top = one_error("[[rules]]\nid = \"x\"\n");
    assert!(top.message.contains("unknown top-level `rules`"), "{top}");
    let sup = one_error("[[suppression]]\nmatch = { tool_name = \"a\" }\nscope = \"workspace\"\nttl_days = 1\norigin = \"manual\"\nreason = \"x\"\n");
    assert!(
        sup.message.contains("unknown suppression key `reason`"),
        "{sup}"
    );
}

#[test]
fn missing_required_fields_are_named_one_by_one() {
    let errs = errors("[[rule]]\nid = \"x\"\n");
    let messages: Vec<&str> = errs.iter().map(|e| e.message.as_str()).collect();
    assert_eq!(
        messages,
        [
            "rule is missing `group`",
            "rule is missing `match`",
            "rule is missing `verdict`"
        ]
    );
}

#[test]
fn duplicate_ids_and_duplicate_match_keys_are_refused() {
    let two = "[[rule]]\nid = \"same\"\ngroup = \"EXECUTE\"\nmatch = { exec_class = \"a\" }\nverdict = \"deny\"\n\n[[rule]]\nid = \"same\"\ngroup = \"EXECUTE\"\nmatch = { exec_class = \"b\" }\nverdict = \"allow\"\n";
    let err = one_error(two);
    assert!(err.message.contains("\"same\" appears twice"), "{err}");
    assert_eq!(err.line, 7, "the second one");
    let dup = one_error("[[rule]]\nid = \"x\"\ngroup = \"EXECUTE\"\nmatch = { exec_class = \"a\", exec_class = \"b\" }\nverdict = \"deny\"\n");
    assert!(
        dup.message.contains("TOML") || dup.message.contains("twice"),
        "{dup}"
    );
}

#[test]
fn values_are_typed_and_closed() {
    let ttl = one_error("[[suppression]]\nmatch = { tool_name = \"a\" }\nscope = \"workspace\"\nttl_days = \"30\"\norigin = \"manual\"\n");
    assert!(
        ttl.message
            .contains("`ttl_days` must be a non-negative integer"),
        "{ttl}"
    );
    let group = one_error("[[rule]]\nid = \"x\"\ngroup = \"NETWORK\"\nmatch = { proto = \"tcp\" }\nverdict = \"deny\"\n");
    assert!(
        group.message.contains("unknown group \"NETWORK\""),
        "{group}"
    );
    assert!(
        group.message.contains("NETWORK_EGRESS"),
        "lists the real names"
    );
    let verdict = one_error("[[rule]]\nid = \"x\"\ngroup = \"EXECUTE\"\nmatch = { exec_class = \"a\" }\nverdict = \"block\"\n");
    assert!(
        verdict.message.contains("allow|warn|escalate|deny"),
        "{verdict}"
    );
    let taint = one_error("[[rule]]\nid = \"x\"\ngroup = \"EXECUTE\"\nmatch = { taint_any = [\"SECRETS\"] }\nverdict = \"deny\"\n");
    assert!(
        taint.message.contains("unknown taint category \"SECRETS\""),
        "{taint}"
    );
    let proto = one_error("[[rule]]\nid = \"x\"\ngroup = \"NETWORK_EGRESS\"\nmatch = { proto = \"http\" }\nverdict = \"deny\"\n");
    assert!(proto.message.contains("tcp|udp|quic|unix"), "{proto}");
    let port = one_error("[[rule]]\nid = \"x\"\ngroup = \"NETWORK_EGRESS\"\nmatch = { port_in = [80, 70000] }\nverdict = \"deny\"\n");
    assert!(port.message.contains("0..=65535"), "{port}");
    let empty =
        one_error("[[rule]]\nid = \"x\"\ngroup = \"EXECUTE\"\nmatch = { }\nverdict = \"deny\"\n");
    assert!(empty.message.contains("at least one key"), "{empty}");
    let profile = one_error("[session.defaults]\nprofile = \"paranoid\"\n");
    assert!(
        profile.message.contains("\"default\" or \"strict\""),
        "{profile}"
    );
    let never = one_error(
        "[[assert]]\nnever = { group = \"SELF_PROTECTION\", verdict = [\"allow\"], unless = 1 }\n",
    );
    assert!(never.message.contains("unknown `never.unless`"), "{never}");
}

#[test]
fn a_toml_syntax_error_is_positioned() {
    let err = one_error("[[rule]]\nid = \"x\n");
    assert!(err.message.starts_with("TOML:"), "{err}");
    assert_eq!(err.line, 2);
}

#[test]
fn every_error_of_a_source_is_reported_together() {
    let errs = errors(
        "[[rule]]\nid = \"x\"\ngroup = \"NOPE\"\nmatch = { nope = 1 }\nverdict = \"maybe\"\n",
    );
    assert_eq!(errs.len(), 3, "{errs:#?}");
    let lines: Vec<usize> = errs.iter().map(|e| e.line).collect();
    assert_eq!(lines, [3, 4, 5]);
}
