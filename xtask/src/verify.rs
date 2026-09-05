//! The hermetic checks: no VM, no network, no fixture beyond the repository,
//! and they run in seconds (Annex H §H.3). All four are in `commit`.

use crate::annex_h::COMMANDS;
use crate::SKIP;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
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

    let mut upward = Vec::new();
    let mut siblings = Vec::new();
    let mut direct_deps: Vec<(String, String)> = Vec::new();
    for (name, pkg) in &members {
        let Some(&from) = layers.get(name) else {
            continue;
        };
        for dep in pkg["dependencies"].as_array().into_iter().flatten() {
            let Some(dname) = dep["name"].as_str() else {
                continue;
            };
            direct_deps.push((name.clone(), dname.to_owned()));
            let Some(&to) = layers.get(dname) else {
                continue;
            };
            if to > from {
                upward.push(format!("{name} (L{from}) -> {dname} (L{to})"));
            } else if to == from && from == 2 {
                siblings.push(format!("{name} -> {dname}, both L2"));
            }
        }
    }
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
            crate::rules::a05_composition_root_is_the_only_platform_module(&adapters),
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
        "no workflow triggers on push, PR or schedule (I-27)",
        || {
            ".github/workflows carries a triggered workflow — this project has zero hosted-CI cost"
                .into()
        },
    );

    println!("\n  Owed by F0.GATE.08, not checked here: SPDX headers, the read-order lists,");
    println!("  the DoD ADR line, STATE.md's §7.3 headings, ADR contiguity, the Part I index,");
    println!("  NN_ naming, phase-table sums, Cargo.lock and layers.toml tracked, the §B.9");
    println!("  monotone maps, budget claims resolving to keys, and §-reference title prefixes.");
    r.finish("verify-docs")
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

fn no_triggered_workflows() -> bool {
    let dir = Path::new(".github/workflows");
    let Ok(entries) = std::fs::read_dir(dir) else {
        return true;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            let Some(body) = read(&p.to_string_lossy()) else {
                continue;
            };
            if ["on:", "push:", "pull_request:", "schedule:"]
                .iter()
                .all(|k| body.contains(k))
            {
                return false;
            }
        }
    }
    true
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
        println!("\nPASS verify-backlog — the register is empty");
        return 0;
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
