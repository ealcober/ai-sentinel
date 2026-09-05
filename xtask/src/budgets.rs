//! Measuring a budget (`F0.GATE.04`) and checking the copies agree (`F0.GATE.07`).
//!
//! §2.22 states the rule this enforces: budget values live in exactly two places,
//! the plan's table and `budgets.toml`. A third copy would drift, so the headline
//! figures in `CLAUDE.md` and `README.md` are checked against the canonical keys
//! rather than trusted.

use std::path::Path;

/// A metric this gate can measure today. Everything else has no artefact yet.
///
/// Binary size is the one budget a stub workspace can breach, which makes it the
/// one that can prove the gate fails on a breach rather than only on a parse
/// error.
pub(crate) struct Measured {
    pub(crate) key: &'static str,
    pub(crate) value: f64,
    pub(crate) unit: &'static str,
}

/// Measure what exists. Absent artefacts are reported as skipped, never as pass.
pub(crate) fn measure() -> Vec<Measured> {
    let mut out = Vec::new();
    let binary = Path::new("target/release/aisme-agentd");
    if let Ok(meta) = std::fs::metadata(binary) {
        #[allow(clippy::cast_precision_loss)] // a binary is far below 2^53 bytes
        let mb = meta.len() as f64 / (1024.0 * 1024.0);
        out.push(Measured {
            key: "process.agentd.binary.size_mb",
            value: mb,
            unit: "MB",
        });
    }
    out
}

/// `min` fails above `hard`, `max` fails below it; equality passes.
pub(crate) fn breaches(direction: &str, value: f64, hard: f64) -> bool {
    match direction {
        "min" => value > hard,
        "max" => value < hard,
        _ => true, // an unknown direction is a policy error, not a pass
    }
}

/// The three figures `CLAUDE.md` and `README.md` state as headline claims, with
/// the `budgets.toml` key each one must equal.
const HEADLINES: &[(&str, f64, &str)] = &[
    ("process.agentd.rss_mb", 50.0, "50 MB agentd RSS"),
    ("cpu.aggregate_pct", 3.0, "3% aggregate CPU"),
    ("latency.t0_p99_us", 15.0, "15 µs T0 p99"),
];

/// `F0.GATE.07` — the plan's §2.22 table, `budgets.toml`, and the two root
/// documents agree.
///
/// The table names its metrics in prose ("RSS `aisme-agentd`") while
/// `budgets.toml` names them by key, so the row check matches on the **hard
/// value**: every hard ceiling in the table must exist as some key's `hard`. That
/// catches the drift that actually happens — a number edited in one copy and not
/// the other — and it does not prove the row-to-key mapping, which only the three
/// headline figures below pin exactly.
pub(crate) fn drift(plan: &str, hards: &[(String, f64)]) -> Vec<String> {
    let mut failures = Vec::new();

    for (key, expected, label) in HEADLINES {
        match hards.iter().find(|(k, _)| k == &format!("{key}.hard")) {
            None => failures.push(format!("{key}.hard is not in budgets.toml")),
            Some((_, actual)) => {
                if (actual - expected).abs() > f64::EPSILON {
                    failures.push(format!(
                        "{label}: CLAUDE.md and README.md say {expected}, {key}.hard is {actual}"
                    ));
                }
            }
        }
    }

    // Compare in a canonical unit. The table writes "2.5 s" where budgets.toml
    // writes `t2_p95_ms = 2500`: the same budget, and a naive value match calls
    // it drift. The key suffix carries the machine unit, the cell carries the
    // human one.
    let canonical: Vec<f64> = hards
        .iter()
        .map(|(k, v)| to_canonical(*v, unit_of_key(k)))
        .collect();
    for (metric, hard, unit) in table_rows(plan) {
        // `[POST]` rows are in the table and deliberately absent from
        // budgets.toml, which says so in a comment where the section would be.
        if metric.contains("[POST") {
            continue;
        }
        let want = to_canonical(hard, unit);
        if !canonical.iter().any(|v| (v - want).abs() < 1e-6) {
            failures.push(format!(
                "§2.22 row \"{metric}\" has hard ceiling {hard} {unit}, which no budgets.toml key carries"
            ));
        }
    }
    failures
}

/// The unit a `budgets.toml` key declares in its own name.
fn unit_of_key(key: &str) -> &'static str {
    let stem = key.strip_suffix(".hard").unwrap_or(key);
    for (suffix, unit) in [
        ("_mb", "MB"),
        ("_mbps", "Mbps"),
        ("_pct", "%"),
        ("_ms", "ms"),
        ("_us", "us"),
        ("_mb_per_day", "MB"),
    ] {
        if stem.ends_with(suffix) {
            return unit;
        }
    }
    ""
}

/// Times to microseconds, everything else unchanged. Comparing `2.5 s` with
/// `2500 ms` is the whole point; comparing MB with % is not something the table
/// ever asks for.
fn to_canonical(value: f64, unit: &str) -> f64 {
    match unit {
        "s" => value * 1_000_000.0,
        "ms" => value * 1_000.0,
        _ => value, // "us", "µs", MB, %, Mbps and counts are already canonical
    }
}

/// The §2.22 rows, as `(metric, hard ceiling)`. Rows whose ceiling is not a plain
/// number — a ratio like `0 / 2` — are skipped and named by the caller.
fn table_rows(plan: &str) -> Vec<(String, f64, &'static str)> {
    let Some(start) = plan.find("| Metric | Target | Hard ceiling") else {
        return Vec::new();
    };
    plan[start..]
        .lines()
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .filter_map(|l| {
            let cells: Vec<&str> = l.split('|').map(str::trim).collect();
            let metric = cells.get(1)?;
            let cell = cells.get(3)?;
            let hard = number(cell)?;
            Some(((*metric).to_owned(), hard, unit_of_cell(cell)))
        })
        .collect()
}

/// The unit written in a §2.22 cell, as the table writes it.
fn unit_of_cell(cell: &str) -> &'static str {
    let c = cell.replace(['*', '`'], "");
    // Order matters: "ms" must be tried before "s".
    for (needle, unit) in [
        ("µs", "µs"),
        ("ms", "ms"),
        ("MB", "MB"),
        ("Mbps", "Mbps"),
        ("%", "%"),
        (" s", "s"),
    ] {
        if c.contains(needle) {
            return unit;
        }
    }
    ""
}

/// The first number in a table cell, ignoring markdown emphasis and units.
fn number(cell: &str) -> Option<f64> {
    let cleaned: String = cell.replace(['*', '`'], "");
    let mut digits = String::new();
    for c in cleaned.chars() {
        if c.is_ascii_digit() || (c == '.' && !digits.is_empty()) {
            digits.push(c);
        } else if !digits.is_empty() {
            break;
        }
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{breaches, drift, number, table_rows};

    fn at_root() {
        std::env::set_current_dir(crate::workspace_root()).unwrap();
    }

    #[test]
    fn breach_is_decided_by_direction_and_equality_passes() {
        assert!(breaches("min", 51.0, 50.0));
        assert!(!breaches("min", 50.0, 50.0), "equality must pass");
        assert!(!breaches("min", 49.0, 50.0));
        assert!(breaches("max", 0.94, 0.95));
        assert!(!breaches("max", 0.95, 0.95), "equality must pass");
        // The 0/0 entries are why direction is mandatory: target == hard, so the
        // direction cannot be inferred.
        assert!(!breaches("min", 0.0, 0.0));
        assert!(breaches("min", 1.0, 0.0));
        assert!(
            breaches("sideways", 1.0, 1.0),
            "an unknown direction is never a pass"
        );
    }

    #[test]
    fn number_reads_a_markdown_cell() {
        assert_eq!(number("**50 MB**"), Some(50.0));
        assert_eq!(number("3.0% of one core"), Some(3.0));
        assert_eq!(number("`0.5%`"), Some(0.5));
        assert_eq!(number("—"), None);
    }

    #[test]
    fn the_plan_table_parses_and_carries_the_known_ceilings() {
        at_root();
        let plan = std::fs::read_to_string("docs/01_phase5_implementation_plan.md").unwrap();
        let rows = table_rows(&plan);
        assert!(rows.len() > 10, "only {} §2.22 rows parsed", rows.len());
        assert!(rows
            .iter()
            .any(|(m, h, _)| m.contains("aisme-agentd") && (*h - 50.0).abs() < 1e-9));
    }

    #[test]
    fn seconds_in_the_table_and_milliseconds_in_the_keys_are_the_same_budget() {
        use super::{to_canonical, unit_of_cell, unit_of_key};
        assert_eq!(unit_of_cell("2.5 s"), "s");
        assert_eq!(unit_of_key("latency.t2_p95_ms.hard"), "ms");
        assert!(
            (to_canonical(2.5, "s") - to_canonical(2500.0, "ms")).abs() < 1e-6,
            "2.5 s and 2500 ms must compare equal, or every time budget reads as drift"
        );
        assert_eq!(unit_of_cell("**50 MB**"), "MB");
        assert_eq!(unit_of_key("process.agentd.rss_mb.hard"), "MB");
    }

    #[test]
    fn drift_reports_a_headline_that_disagrees_with_budgets_toml() {
        at_root();
        let plan = std::fs::read_to_string("docs/01_phase5_implementation_plan.md").unwrap();
        // A budgets set where agentd RSS is 60, not the 50 the two root documents
        // claim. The gate must say so.
        let wrong = vec![
            ("process.agentd.rss_mb.hard".to_owned(), 60.0),
            ("cpu.aggregate_pct.hard".to_owned(), 3.0),
            ("latency.t0_p99_us.hard".to_owned(), 15.0),
        ];
        let failures = drift(&plan, &wrong);
        assert!(
            failures.iter().any(|f| f.contains("50 MB agentd RSS")),
            "drift did not notice a headline mismatch: {failures:?}"
        );
    }
}
