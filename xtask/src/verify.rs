// SPDX-License-Identifier: Apache-2.0
//! The hermetic checks: no VM, no network, no fixture beyond the repository,
//! and they run in seconds (Annex H §H.3). All four are in `commit`.

use crate::annex_h::COMMANDS;
use crate::SKIP;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

const PLAN: &str = "docs/01_phase5_implementation_plan.md";
const BACKLOG: &str = "docs/reports/01_f0-verification.md";

/// Collects failures so a run reports every one, not just the first.
#[derive(Default)]
struct Report {
    failures: Vec<String>,
}

impl Report {
    fn check(&mut self, ok: bool, label: &str, detail: impl FnOnce() -> String) {
        if ok {
            println!("  PASS  {label}");
        } else {
            println!("  FAIL  {label}");
            self.failures.push(format!("{label}: {}", detail()));
        }
    }

    fn finish(self, command: &str) -> u8 {
        if self.failures.is_empty() {
            println!("PASS {command}");
            0
        } else {
            eprintln!(
                "\nFAIL {command} — {} check(s) failed:",
                self.failures.len()
            );
            for f in &self.failures {
                eprintln!("  {f}");
            }
            1
        }
    }
}

fn read(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

// ---------------------------------------------------------------- layering

/// Layer of a crate, as `L0`…`L4` from `layers.toml`.
/// The `A-02` violations in a dependency graph: edges that point upward, and
/// sibling edges inside L2.
///
/// A pure function over (layer table, direct edges) so the rule can be run on
/// a graph that is not this workspace's — which is what `F1.PA.07` asks for:
/// the gate must fail on a planted `aisme-core -> aisme-linux` edge, and a
/// check nobody has seen fail is a check nobody should trust.
pub(crate) fn direction_violations(
    layers: &BTreeMap<String, u8>,
    edges: &[(String, String)],
) -> Violations {
    let mut v = Violations::default();
    for (name, dname) in edges {
        let (Some(&from), Some(&to)) = (layers.get(name), layers.get(dname)) else {
            continue;
        };
        if to > from {
            v.upward
                .push(format!("{name} (L{from}) -> {dname} (L{to})"));
        } else if to == from && from == 2 {
            v.siblings.push(format!("{name} -> {dname}, both L2"));
        }
    }
    v
}

/// What [`direction_violations`] found.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Violations {
    /// Edges from a lower layer to a higher one.
    pub(crate) upward: Vec<String>,
    /// Edges between two L2 crates.
    pub(crate) siblings: Vec<String>,
}

fn layer_ord(layer: &str) -> Option<u8> {
    layer.strip_prefix('L').and_then(|n| n.parse().ok())
}

/// `§3.1` dependency direction, read from `layers.toml` and `cargo metadata`.
///
/// Strictly downward: a crate may depend only on a lower layer. Siblings are
/// permitted outside `L2`; inside `L2` they are not, because an adapter that
/// depends on another adapter is a platform coupling the core cannot see.
pub(crate) fn layering() -> u8 {
    println!("verify-layering — §3.1 rules over layers.toml and cargo metadata\n");
    let mut r = Report::default();

    let Some(raw) = read("layers.toml") else {
        eprintln!("skip: layers.toml not found");
        return SKIP;
    };
    let doc: toml::Value = match raw.parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL verify-layering: layers.toml does not parse: {e}");
            return 1;
        }
    };
    let mut layers: BTreeMap<String, u8> = BTreeMap::new();
    if let Some(tbl) = doc.get("crates").and_then(toml::Value::as_table) {
        for (k, v) in tbl {
            if let Some(o) = v.as_str().and_then(layer_ord) {
                layers.insert(k.clone(), o);
            }
        }
    }
    r.check(!layers.is_empty(), "layers.toml declares crates", || {
        "the [crates] table is empty or missing".into()
    });

    let Some(meta) = metadata() else {
        eprintln!("skip: `cargo metadata` did not run");
        return SKIP;
    };
    let packages = meta["packages"].as_array().cloned().unwrap_or_default();
    let members: BTreeMap<String, &serde_json::Value> = packages
        .iter()
        .filter_map(|p| p["name"].as_str().map(|n| (n.to_owned(), p)))
        .collect();

    let unlayered: Vec<&String> = members
        .keys()
        .filter(|m| !layers.contains_key(*m))
        .collect();
    r.check(
        unlayered.is_empty(),
        "every workspace member declares a layer",
        || format!("{unlayered:?} are members with no layers.toml entry"),
    );

    let phantom: Vec<&String> = layers
        .keys()
        .filter(|c| !members.contains_key(*c))
        .collect();
    r.check(
        phantom.is_empty(),
        "every layered crate is a workspace member",
        || format!("{phantom:?} are layered but not members"),
    );

    let mut direct_deps: Vec<(String, String)> = Vec::new();
    for (name, pkg) in &members {
        if !layers.contains_key(name) {
            continue;
        }
        for dep in pkg["dependencies"].as_array().into_iter().flatten() {
            if let Some(dname) = dep["name"].as_str() {
                direct_deps.push((name.clone(), dname.to_owned()));
            }
        }
    }
    let Violations { upward, siblings } = direction_violations(&layers, &direct_deps);
    r.check(
        upward.is_empty(),
        "no crate depends on a higher layer",
        || upward.join("; "),
    );
    r.check(
        siblings.is_empty(),
        "no sibling dependency inside L2",
        || siblings.join("; "),
    );

    architecture_rules(&mut r, &layers, &direct_deps);

    if let Some(root) = doc
        .get("composition_root")
        .and_then(|v| v.get("path"))
        .and_then(toml::Value::as_str)
    {
        let state = if Path::new(root).exists() {
            "present"
        } else {
            "not yet created (F1)"
        };
        println!("  ----  composition root: {root} — {state}");
    }
    r.finish("verify-layering")
}

/// `A-01`, `A-03`, `A-05` and the forbidden-dependency gate.
///
/// `A-02` is checked in `layering` itself, from `layers.toml`, because that is
/// where each crate's layer is declared. These four need source or the resolved
/// dependency graph, so they live in `rules`.
fn architecture_rules(
    r: &mut Report,
    layers: &BTreeMap<String, u8>,
    direct_deps: &[(String, String)],
) {
    // A-01, A-03 and A-05 need source or the resolved graph, so they live in
    // `rules`. A-02 is the two checks above, which read layers.toml.
    let adapters: std::collections::BTreeSet<String> = layers
        .iter()
        .filter(|(_, &l)| l == 2)
        .map(|(k, _)| k.clone())
        .collect();
    let engines: std::collections::BTreeSet<String> = layers
        .iter()
        .filter(|(_, &l)| l == 3)
        .map(|(k, _)| k.clone())
        .collect();
    for (label, outcome) in [
        (
            "A-01  aisme-core is platform-free",
            crate::rules::a01_core_is_platform_free(direct_deps),
        ),
        (
            "A-03  aisme-ebpf-common is no_std with zero deps",
            crate::rules::a03_wire_is_no_std_zero_deps(direct_deps),
        ),
        (
            "A-05  only the composition root names an adapter",
            crate::rules::a05_composition_root_is_the_only_platform_module(&adapters, &engines),
        ),
        (
            "F0.GATE.05  no forbidden dependency",
            crate::rules::forbidden_dependencies(),
        ),
    ] {
        let detail = outcome.err();
        r.check(detail.is_none(), label, || detail.unwrap_or_default());
    }
    println!("  ----  A-04 (no platform type in aisme-core's public API) needs that API: F1");
    println!("  ----  A-06 (review for L0-L2 deps and L3 unsafe) is a policy, owned by DEP.SUP.06");
}

fn metadata() -> Option<serde_json::Value> {
    let out = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

// ---------------------------------------------------------------- budgets

/// `budgets.toml` shape, and one line per metric.
///
/// A metric is any table carrying `target` or `hard`. `direction` is mandatory on
/// every one of them: inferring it from target-versus-hard is undefined when the
/// two are equal, which is exactly the case for the `0/0` entries.
pub(crate) fn budgets(args: &[&str]) -> u8 {
    println!("verify-budgets — budgets.toml shape, measurement and drift\n");
    let mut r = Report::default();

    let Some(raw) = read("budgets.toml") else {
        eprintln!("skip: budgets.toml not found");
        return SKIP;
    };
    let doc: toml::Value = match raw.parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL verify-budgets: budgets.toml does not parse: {e}");
            return 1;
        }
    };

    let mut metrics = Vec::new();
    collect_metrics(&doc, String::new(), &mut metrics);
    r.check(!metrics.is_empty(), "budgets.toml declares metrics", || {
        "no table carries target or hard".into()
    });

    let mut bad = Vec::new();
    let mut hards: Vec<(String, f64)> = Vec::new();
    for (path, t) in &metrics {
        match t.get("direction").and_then(toml::Value::as_str) {
            Some("min" | "max") => {}
            Some(other) => bad.push(format!(
                "{path}: direction = {other:?}, expected min or max"
            )),
            None => bad.push(format!("{path}: no direction")),
        }
        if let Some(h) = t.get("hard").and_then(as_f64) {
            hards.push((format!("{path}.hard"), h));
        }
    }
    r.check(bad.is_empty(), "every metric declares a direction", || {
        bad.join("; ")
    });

    // The drift check is hermetic and instant, so it runs every time rather than
    // only behind its flag: a gate that has to be asked for a check is a gate
    // that will not be asked. `--drift` runs it alone.
    let failures = crate::budgets::drift(&read(PLAN).unwrap_or_default(), &hards);
    r.check(
        failures.is_empty(),
        "§2.22, budgets.toml and the root documents agree (F0.GATE.07)",
        || failures.join("; "),
    );
    if args.contains(&"--drift") {
        return r.finish("verify-budgets --drift");
    }

    measure_and_report(&mut r, &metrics);
    r.finish("verify-budgets")
}

/// Compare every metric that has an artefact against its hard ceiling, and name
/// every metric that has none. An absent artefact is skipped, never passed.
fn measure_and_report(r: &mut Report, metrics: &[(String, &toml::value::Table)]) {
    let measured = crate::budgets::measure();
    let mut breaches = Vec::new();
    let mut lines = String::new();

    for (path, t) in metrics {
        let Some(m) = measured.iter().find(|m| m.key == path) else {
            let _ = writeln!(lines, "    skipped: no artefact — {path}");
            continue;
        };
        let direction = t
            .get("direction")
            .and_then(toml::Value::as_str)
            .unwrap_or("");
        let hard = t.get("hard").and_then(as_f64).unwrap_or(f64::NAN);
        if crate::budgets::breaches(direction, m.value, hard) {
            breaches.push(format!(
                "{path}: {:.2} {} exceeds hard {hard}",
                m.value, m.unit
            ));
            let _ = writeln!(
                lines,
                "    BREACH  {path} = {:.2} {} (hard {hard})",
                m.value, m.unit
            );
        } else {
            let _ = writeln!(
                lines,
                "    ok      {path} = {:.2} {} (hard {hard})",
                m.value, m.unit
            );
        }
    }

    println!(
        "\n  {} metrics, {} measured:",
        metrics.len(),
        measured.len()
    );
    print!("{lines}");
    r.check(
        breaches.is_empty(),
        "no measured metric breaches its hard ceiling",
        || breaches.join("; "),
    );
}

/// `hard` may be written as an integer or a float; both are the same budget.
fn as_f64(v: &toml::Value) -> Option<f64> {
    v.as_float().or_else(|| {
        #[allow(clippy::cast_precision_loss)] // budgets are small integers
        v.as_integer().map(|i| i as f64)
    })
}

/// Walk the TOML tree collecting every table that looks like a metric.
fn collect_metrics<'a>(
    v: &'a toml::Value,
    path: String,
    out: &mut Vec<(String, &'a toml::value::Table)>,
) {
    let Some(tbl) = v.as_table() else { return };
    if tbl.contains_key("target") || tbl.contains_key("hard") {
        out.push((path, tbl));
        return;
    }
    for (k, child) in tbl {
        if child.is_table() {
            let next = if path.is_empty() {
                k.clone()
            } else {
                format!("{path}.{k}")
            };
            collect_metrics(child, next, out);
        }
    }
}

// ---------------------------------------------------------------- docs

/// Cross-document consistency. `F0.REPO.03` owns the Annex H half and `I-27`;
/// the rest of the list in `F0.GATE.08` is named below rather than skipped.
pub(crate) fn docs() -> u8 {
    println!("verify-docs — cross-document consistency\n");
    let mut r = Report::default();

    let Some(plan) = read(PLAN) else {
        eprintln!("skip: {PLAN} not found");
        return SKIP;
    };

    let rows = annex_h_rows(&plan);
    r.check(
        rows.len() == COMMANDS.len(),
        "Annex H row count matches the argument parser",
        || {
            format!(
                "Annex H has {} rows, the parser knows {}",
                rows.len(),
                COMMANDS.len()
            )
        },
    );

    let unreachable: Vec<&String> = rows
        .iter()
        .filter(|n| !COMMANDS.iter().any(|c| c.name == n.as_str()))
        .collect();
    r.check(
        unreachable.is_empty(),
        "every Annex H command is reachable through the parser",
        || format!("{unreachable:?} have a row but no dispatch entry"),
    );

    let unspecified: Vec<&str> = COMMANDS
        .iter()
        .map(|c| c.name)
        .filter(|n| !rows.iter().any(|r| r == n))
        .collect();
    r.check(
        unspecified.is_empty(),
        "every parser command has an Annex H row",
        || format!("{unspecified:?} are dispatchable but unspecified"),
    );

    let tasks = task_ids(&plan);
    let orphans: Vec<&str> = COMMANDS
        .iter()
        .map(|c| c.owner)
        .filter(|o| !tasks.iter().any(|t| t == o))
        .collect();
    r.check(
        orphans.is_empty(),
        "every Annex H row names a task that exists",
        || format!("{orphans:?} own a command but are not task rows"),
    );

    let cited = cited_commands(&plan);
    let dangling: Vec<&String> = cited
        .iter()
        .filter(|n| !COMMANDS.iter().any(|c| c.name == n.as_str()))
        .collect();
    r.check(
        dangling.is_empty(),
        "every `cargo xtask` string in the plan has a row",
        || format!("{dangling:?} are cited but not in Annex H"),
    );

    println!("\n  corpus and fixture manifests (§4.14):");
    let asset_failures = crate::assets::check();
    r.check(
        asset_failures.is_empty(),
        "every manifest hash matches its content",
        || asset_failures.join("; "),
    );

    r.check(
        no_triggered_workflows(),
        "no hosted-CI workflow exists at all (I-27)",
        || {
            "a GitHub workflow or action file exists — this project has zero hosted-CI cost, so \
             the rule is no workflow at all, not a workflow with safe triggers"
                .into()
        },
    );

    cross_document_checks(&mut r, &plan);

    r.finish("verify-docs")
}

/// The `F0.GATE.08` list. Each check names itself and its failure reason, so a
/// red gate says which document disagrees with which.
fn cross_document_checks(r: &mut Report, plan: &str) {
    use crate::docgate as g;
    println!("\n  cross-document checks (F0.GATE.08):");
    let checks: Vec<(&str, Result<(), String>)> = vec![
        ("SPDX headers match the LICENSE.md map", g::spdx_headers()),
        (
            "manifest licences match the LICENSE.md map",
            g::manifest_licences(),
        ),
        (
            "the read order agrees between CLAUDE.md and AGENTS.md",
            g::read_order_agrees(),
        ),
        (
            "the definition of done still requires the ADR re-read",
            g::dod_has_adr_line(),
        ),
        (
            "STATE.md carries its §7.3 headings, in order",
            g::state_headings(),
        ),
        (
            "STATE.md's header date is not older than its last commit",
            g::state_last_updated_is_recent(),
        ),
        (
            "STATE.md's Next up does not contradict its own Done table",
            g::state_next_up_agrees_with_done(),
        ),
        ("ADR numbers are contiguous", g::adrs_contiguous()),
        (
            "the §7.4 seed memories exist and cite a source",
            g::seed_memories(plan),
        ),
        ("NN_slug.md naming under docs/, and no NN_-", g::nn_naming()),
        (
            "every task ID in a commit subject has a changelog line",
            g::changelog_covers_commits(),
        ),
        (
            "every `<task-id>` row citation resolves to that row",
            g::task_citations_resolve(),
        ),
        (
            "the phase addends sum to the stated critical path",
            g::phase_sums(plan),
        ),
        ("Cargo.lock and layers.toml are tracked", g::tracked_files()),
        (
            "every § reference resolves to a heading",
            g::section_refs(plan),
        ),
        (
            "[CUT] items are echoed in the threat model's non-goals",
            g::cuts_in_threat_model(plan),
        ),
        (
            "Annex B §B.9 verdict maps are monotone",
            g::verdict_maps_monotone(plan),
        ),
        (
            "the eBPF probes pin the same nightly as crates/aisme-ebpf",
            g::probe_pin_matches_ebpf(),
        ),
        (
            "budget keys named in prose exist in budgets.toml",
            g::prose_budget_keys(),
        ),
        (
            "the Part VI tree matches crates/ and layers.toml",
            g::part_vi_tree(plan),
        ),
    ];
    for (label, outcome) in checks {
        let detail = outcome.err();
        r.check(detail.is_none(), label, || detail.unwrap_or_default());
    }
}

/// The command names in Annex H §H.4, in plan order.
fn annex_h_rows(plan: &str) -> Vec<String> {
    let Some(start) = plan.find("### H.4") else {
        return Vec::new();
    };
    let tail = &plan[start..];
    let end = tail.find("## Annex I").unwrap_or(tail.len());
    tail[..end]
        .lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("| `cargo xtask ")?;
            let (name, after) = rest.split_once('`')?;
            after.starts_with(" | `").then(|| name.trim().to_owned())
        })
        .collect()
}

/// Every `cargo xtask <command>` the plan cites outside Annex H's own table.
fn cited_commands(plan: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in plan.match_indices("cargo xtask ") {
        let rest = &plan[i + "cargo xtask ".len()..];
        let raw: String = rest
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == ' ')
            .collect();
        let words: Vec<&str> = raw.split_whitespace().collect();
        let Some(&head) = words.first() else { continue };
        if head.starts_with('-') {
            continue; // `cargo xtask --help` is the parser's own flag, not a command
        }
        let name = if crate::NAMESPACES.contains(&head) && words.len() >= 2 {
            format!("{head} {}", words[1])
        } else {
            head.to_owned()
        };
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Every task ID that begins a table row in the plan.
///
/// Three namespaces carry tasks: `F<n>.*` for the phases, `WIN.*` for the
/// deferred Windows driver (Annex F) and `DEP.*` for the cross-phase deployment
/// work of Part V. All three own `xtask` commands, so all three count here.
fn task_ids(plan: &str) -> Vec<String> {
    plan.lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("| `")?;
            let (id, _) = rest.split_once('`')?;
            let mut parts = id.split('.');
            let head = parts.next()?;
            let namespaced = head == "WIN"
                || head == "DEP"
                || (head.starts_with('F') && head[1..].chars().all(|c| c.is_ascii_digit()));
            let ok = namespaced
                && id.split('.').count() == 3
                && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '.');
            ok.then(|| id.to_owned())
        })
        .collect()
}

/// Anything under this path GitHub can bill for. The rule (`I-27`) is zero
/// hosted-CI cost, and the only way to hold it mechanically is to have no
/// workflow at all: a file's *content* cannot be trusted to keep it free.
/// `workflow_dispatch` bills when someone presses the button; a `schedule:`
/// added in a later commit bills forever; a reusable workflow bills through
/// whoever calls it. So the check is over **existence**, not triggers.
///
/// This replaces a content check that read
/// `["on:", "push:", "pull_request:", "schedule:"].iter().all(...)` — it
/// demanded all four keys, so the single most dangerous file, one carrying
/// only `on: push:`, passed the gate. It had also never run against anything,
/// because the repository has no `.github` at all, which is exactly the state
/// it exists to defend. The unit tests below run it against synthetic
/// listings so it is exercised whether or not the directory ever appears.
///
/// A one-off hosted run stays possible the way the rule says: it is announced,
/// verified and **removed again**, so the file does not live in the tree.
fn hosted_ci_files(entries: &[String]) -> Vec<String> {
    let mut found: Vec<String> = entries
        .iter()
        .filter(|p| {
            let p = p.replace('\\', "/");
            // Every path GitHub reads to run something billable.
            p.contains(".github/workflows/")
                || p.ends_with("/action.yml")
                || p.ends_with("/action.yaml")
                || p == ".github/action.yml"
                || p == ".github/action.yaml"
        })
        .cloned()
        .collect();
    found.sort();
    found
}

/// Walk `.github` and hand every path to [`hosted_ci_files`].
fn no_triggered_workflows() -> bool {
    let mut entries = Vec::new();
    let mut dirs = vec![PathBuf::from(".github")];
    while let Some(d) = dirs.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else {
                entries.push(p.to_string_lossy().replace("./", ""));
            }
        }
    }
    hosted_ci_files(&entries).is_empty()
}

#[cfg(test)]
mod i27_tests {
    use super::hosted_ci_files;

    #[test]
    fn a_workflow_that_only_pushes_is_caught() {
        // The case the previous check missed: it demanded "on:", "push:",
        // "pull_request:" AND "schedule:" all be present, so the one file that
        // bills on every push — carrying only the first two — passed clean.
        // Existence is the rule now, so its content never gets a vote.
        let found = hosted_ci_files(&[".github/workflows/ci.yml".to_owned()]);
        assert_eq!(found, vec![".github/workflows/ci.yml".to_owned()]);
    }

    #[test]
    fn a_manually_triggered_workflow_is_caught_too() {
        // workflow_dispatch has no trigger a content check would flag, and
        // bills the moment anyone presses the button.
        assert_eq!(
            hosted_ci_files(&[".github/workflows/manual.yaml".to_owned()]).len(),
            1
        );
    }

    #[test]
    fn composite_actions_are_caught_wherever_they_sit() {
        let found = hosted_ci_files(&[
            ".github/actions/setup/action.yml".to_owned(),
            "tools/release/action.yaml".to_owned(),
        ]);
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn the_rest_of_dot_github_is_free_and_stays_allowed() {
        // Issue templates, CODEOWNERS, funding and a PR template cost nothing
        // and are not automation; the rule is about what GitHub *runs*.
        let found = hosted_ci_files(&[
            ".github/ISSUE_TEMPLATE/bug.md".to_owned(),
            ".github/CODEOWNERS".to_owned(),
            ".github/FUNDING.yml".to_owned(),
            ".github/pull_request_template.md".to_owned(),
        ]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_repository_with_no_dot_github_has_nothing_to_report() {
        assert!(hosted_ci_files(&[]).is_empty());
    }
}

// ---------------------------------------------------------------- backlog

/// Every live `F0.VER.nn` row of plan §F0.4 has a recorded outcome.
///
/// "The register is empty at GATE F0" becomes a machine check rather than a
/// habit. Failing today is correct: most rows are still unmeasured.
pub(crate) fn backlog() -> u8 {
    println!("verify-backlog — every §F0.4 row has a recorded outcome\n");
    let Some(report) = read(BACKLOG) else {
        eprintln!("skip: {BACKLOG} not found — F0.WSL.01 creates it");
        return SKIP;
    };
    let Some(plan) = read(PLAN) else {
        eprintln!("skip: {PLAN} not found");
        return SKIP;
    };

    let declared: Vec<String> = (1..=99)
        .map(|n| format!("F0.VER.{n:02}"))
        .filter(|id| plan.contains(&format!("`{id}`")))
        .collect();

    let mut recorded = Vec::new();
    let mut empty = Vec::new();
    let mut unverified = Vec::new();
    for line in report.lines() {
        if !line.starts_with("| `F0.VER.") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let Some(id) = cells.get(1).and_then(|c| c.split('`').nth(1)) else {
            continue;
        };
        let outcome = cells.get(cells.len() - 2).copied().unwrap_or("");
        if outcome.is_empty() {
            empty.push(id.to_owned());
        } else if outcome.starts_with("**`UNVERIFIED`**") || outcome.starts_with("`UNVERIFIED`") {
            // §F0.4: a row that needs hardware this host lacks is recorded with
            // the hardware named and stays open — exit 2, not 1.
            unverified.push(id.to_owned());
            recorded.push(id.to_owned());
        } else {
            recorded.push(id.to_owned());
        }
    }

    let absent: Vec<&String> = declared
        .iter()
        .filter(|id| !recorded.contains(id) && !empty.contains(id))
        .collect();

    println!("  {} rows declared in §F0.4", declared.len());
    println!("  {} recorded: {}", recorded.len(), recorded.join(", "));
    if !absent.is_empty() {
        println!("  {} with no row in the register: {absent:?}", absent.len());
    }
    if empty.is_empty() && absent.is_empty() {
        if unverified.is_empty() {
            println!("\nPASS verify-backlog — the register is empty");
            return 0;
        }
        println!(
            "\nSKIP verify-backlog — every row is recorded; {} need hardware this host lacks: {}",
            unverified.len(),
            unverified.join(", ")
        );
        return SKIP;
    }
    eprintln!(
        "\nFAIL verify-backlog — {} row(s) without an outcome:",
        empty.len() + absent.len()
    );
    for id in empty.iter().chain(absent) {
        eprintln!("  {id}");
    }
    eprintln!("\nExpected before GATE F0. Each row needs HOLDS, FAILS or WITHDRAWN in");
    eprintln!("{BACKLOG}, with the command run and what was observed.");
    1
}

#[cfg(test)]
mod layering_tests {
    use super::{direction_violations, Violations};
    use std::collections::BTreeMap;

    /// The real layer table, read from `layers.toml` — so a rename there is
    /// caught here rather than silently making the test vacuous.
    fn layers() -> BTreeMap<String, u8> {
        let raw = std::fs::read_to_string(crate::workspace_root().join("layers.toml")).unwrap();
        let doc: toml::Value = raw.parse().unwrap();
        doc["crates"]
            .as_table()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), super::layer_ord(v.as_str().unwrap()).unwrap()))
            .collect()
    }

    fn edge(from: &str, to: &str) -> Vec<(String, String)> {
        vec![(from.to_owned(), to.to_owned())]
    }

    #[test]
    fn the_real_edges_of_the_f1_crates_point_downward() {
        let layers = layers();
        let real = [
            ("aisme-core", "aisme-ebpf-common"),
            ("aisme-correlate", "aisme-core"),
            ("aisme-agentd", "aisme-core"),
            ("aisme-agentd", "aisme-ebpf-common"),
        ]
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .to_vec();
        assert_eq!(direction_violations(&layers, &real), Violations::default());
    }

    #[test]
    fn a_planted_core_to_linux_edge_fails_the_rule() {
        // A-02, mechanically: the moment `aisme-core` (L1) names an adapter
        // (L2), the direction check reports it. This is the edge the rule
        // exists to stop, and the check is shown failing on it.
        let violations = direction_violations(&layers(), &edge("aisme-core", "aisme-linux"));
        assert_eq!(violations.upward, ["aisme-core (L1) -> aisme-linux (L2)"]);
        assert!(violations.siblings.is_empty());
    }

    #[test]
    fn a_planted_l2_sibling_edge_fails_the_rule() {
        let violations = direction_violations(&layers(), &edge("aisme-linux", "sentinel-core"));
        assert_eq!(
            violations.siblings,
            ["aisme-linux -> sentinel-core, both L2"]
        );
        assert!(violations.upward.is_empty());
    }

    #[test]
    fn an_edge_to_something_unlayered_is_not_a_direction_violation() {
        // Third-party crates carry no layer; they are policed by A-06 and
        // cargo deny, not by direction.
        let violations = direction_violations(&layers(), &edge("aisme-core", "toml_edit"));
        assert_eq!(violations, Violations::default());
    }
}
