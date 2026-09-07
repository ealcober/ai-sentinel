// SPDX-License-Identifier: Apache-2.0
//! `F1.PL.08`: a backend that cannot express a verdict or a key rejects the
//! rule at compile time with a tier-specific message, checked against §B.9;
//! every verdict the map changes is named.

use aisme_core::policy::{
    compile, parse, BackendCapabilities, BackendKind, Bindings, CompiledPolicy, Degradation,
    LowerError, LoweringPlan, PolicyBackend, Rejection, VerdictMap,
};
use aisme_ebpf_common::Verdict;

const SKETCH: &str = include_str!("fixtures/sketch.toml");

fn compiled(src: &str) -> CompiledPolicy {
    let policy = parse(src).unwrap_or_else(|e| panic!("{e:#?}"));
    let bindings = Bindings::new()
        .with("workspace", "/home/u/proj")
        .with_list("session.network_allow", &["registry.npmjs.org"]);
    compile(&policy, &bindings).unwrap_or_else(|e| panic!("{e:#?}"))
}

fn plan_of(policy: &CompiledPolicy, kind: BackendKind) -> (BackendCapabilities, LoweringPlan) {
    let caps = BackendCapabilities::of(kind);
    (caps, LoweringPlan::of(&caps, policy))
}

#[test]
fn landlock_takes_the_path_rules_names_its_degradations_and_rejects_the_rest_by_key() {
    let policy = compiled(SKETCH);
    let (caps, plan) = plan_of(&policy, BackendKind::Landlock);
    let accepted: Vec<(&str, Verdict, Degradation)> = plan
        .accepted
        .iter()
        .map(|l| (l.rule_id.as_str(), l.enforced, l.degradation))
        .collect();
    assert_eq!(
        accepted,
        [
            ("credentials-ask", Verdict::Deny, Degradation::Upward),
            ("persistence-config", Verdict::Allow, Degradation::Downward),
            ("system-config-deny", Verdict::Deny, Degradation::Exact),
            ("workspace-free", Verdict::Allow, Degradation::Exact),
        ]
    );
    let rejected: Vec<(&str, &Rejection)> = plan
        .rejected
        .iter()
        .map(|(id, r)| (id.as_str(), r))
        .collect();
    assert_eq!(
        rejected,
        [
            (
                "network-slam",
                &Rejection::UnsupportedKey { key: "dest_not_in" }
            ),
            (
                "user-scope-install",
                &Rejection::UnsupportedKey { key: "scope_rel" }
            ),
        ]
    );
    // Every rule is accounted for: nothing dropped without a line.
    assert_eq!(
        plan.accepted.len() + plan.rejected.len(),
        policy.rules.len()
    );
    let changed: Vec<&str> = plan.changed().map(|l| l.rule_id.as_str()).collect();
    assert_eq!(changed, ["credentials-ask", "persistence-config"]);
    let messages = plan.messages(&caps);
    assert_eq!(messages.len(), 4);
    assert!(
        messages[0]
            .contains("Landlock: rule \"network-slam\" rejected — cannot evaluate `dest_not_in`"),
        "{}",
        messages[0]
    );
    assert!(
        messages[0].contains("F0.VER.20"),
        "the tier-specific caveat travels with the message"
    );
    assert!(
        messages[2].contains("credentials-ask") && messages[2].contains("fail closed"),
        "{}",
        messages[2]
    );
}

#[test]
fn cgroup_connect_takes_the_slam_and_the_bpf_trie_takes_everything_but_tool_keys() {
    let policy = compiled(SKETCH);
    let (_, cgroup) = plan_of(&policy, BackendKind::CgroupConnect);
    let slam = cgroup
        .accepted
        .iter()
        .find(|l| l.rule_id == "network-slam")
        .expect("the slam is network + taint");
    assert_eq!(
        (slam.enforced, slam.degradation),
        (Verdict::Deny, Degradation::Exact)
    );
    assert!(cgroup
        .rejected
        .iter()
        .all(|(_, r)| matches!(r, Rejection::UnsupportedKey { .. })));
    let (_, bpf) = plan_of(&policy, BackendKind::BpfTrie);
    assert_eq!(bpf.rejected, []);
    assert_eq!(bpf.changed().count(), 0, "the identity map changes nothing");
    let tool = compiled("[[rule]]\nid = \"t\"\ngroup = \"NETWORK_EGRESS\"\nmatch = { tool_name = \"curl\" }\nverdict = \"warn\"\n");
    let (_, bpf) = plan_of(&tool, BackendKind::BpfTrie);
    assert_eq!(
        bpf.rejected,
        [(
            "t".to_owned(),
            Rejection::UnsupportedKey { key: "tool_name" }
        )],
        "user space only"
    );
}

/// A narrowed backend — one that measured itself unable to deny — degrades
/// escalate and deny downward. That is refused unless the rule says so.
struct FailOpen;

impl PolicyBackend for FailOpen {
    type Artifact = usize;
    fn kind(&self) -> BackendKind {
        BackendKind::Sentinel
    }
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            map: VerdictMap([Verdict::Allow, Verdict::Warn, Verdict::Warn, Verdict::Warn]),
            ..BackendCapabilities::of(BackendKind::Sentinel)
        }
    }
    fn lower(&self, policy: &CompiledPolicy) -> Result<usize, LowerError> {
        let plan = self.plan(policy);
        match plan.rejected.first() {
            Some((id, rejection)) => Err(LowerError {
                backend: self.kind(),
                rule_id: Some(id.clone()),
                message: format!("{rejection:?}"),
            }),
            None => Ok(plan.accepted.len()),
        }
    }
}

#[test]
fn a_downward_degradation_of_escalate_or_deny_needs_degrade_open() {
    let base = "[[rule]]\nid = \"e\"\ngroup = \"CREDENTIALS\"\nmatch = { path_glob = \"**/.env\" }\nverdict = \"escalate\"\n";
    let refused = FailOpen.lower(&compiled(base)).unwrap_err();
    assert_eq!(refused.rule_id.as_deref(), Some("e"));
    assert!(
        refused.message.contains("DowngradeRefused"),
        "{}",
        refused.message
    );
    let plan = FailOpen.plan(&compiled(base));
    assert_eq!(
        plan.rejected[0].1,
        Rejection::DowngradeRefused {
            written: Verdict::Escalate,
            would_enforce: Verdict::Warn
        }
    );
    assert!(plan.messages(&FailOpen.capabilities())[0].contains("degrade_open = true"));
    // With the marker the rule is taken, and the change is named, not hidden.
    let open = format!("{base}degrade_open = true\n");
    assert_eq!(FailOpen.lower(&compiled(&open)), Ok(1));
    let plan = FailOpen.plan(&compiled(&open));
    assert_eq!(plan.changed().count(), 1);
    assert_eq!(plan.accepted[0].degradation, Degradation::Downward);
    // warn → allow downward never needs the marker: only escalate and deny do.
    assert_eq!(
        BackendCapabilities::of(BackendKind::Landlock)
            .map
            .degradation(Verdict::Warn),
        Degradation::Downward
    );
    let warn = "[[rule]]\nid = \"w\"\ngroup = \"EXECUTE\"\nmatch = { exec_class = \"x\" }\nverdict = \"warn\"\n";
    let (_, landlock) = plan_of(&compiled(warn), BackendKind::Landlock);
    assert_eq!(landlock.rejected, []);
}
