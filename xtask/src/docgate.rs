// SPDX-License-Identifier: Apache-2.0
//! `F0.GATE.08` — the cross-document checks `verify-docs` runs beyond Annex H.
//!
//! Each returns `Ok(())` or the reason it failed. They are mechanical on purpose:
//! a documentation rule nobody can run is a rule that decays.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn fail(v: &[String]) -> Result<(), String> {
    if v.is_empty() {
        Ok(())
    } else {
        Err(v.join("; "))
    }
}

/// The SPDX id `LICENSE.md` maps a path to.
fn expected_spdx(path: &str) -> &'static str {
    if path.starts_with("crates/aisme-ebpf-common") {
        "GPL-2.0-only OR BSD-2-Clause"
    } else if path.starts_with("crates/aisme-ebpf") {
        "GPL-2.0-only"
    } else {
        "Apache-2.0"
    }
}

/// Every crate's **manifest** declares the licence `LICENSE.md` maps it to.
///
/// The source headers and the manifest are two different claims, and only the
/// manifest is what `cargo deny`, crates.io and every downstream consumer read.
/// `license.workspace = true` silently resolves to the workspace Apache-2.0,
/// which is wrong for the two crates the kernel forces to be GPL.
pub(crate) fn manifest_licences() -> Result<(), String> {
    let workspace = read("Cargo.toml");
    let ws_licence = workspace
        .lines()
        .find_map(|l| l.trim().strip_prefix("license = "))
        .map(|v| v.trim().trim_matches('"').to_owned())
        .unwrap_or_default();

    let mut bad = Vec::new();
    let mut dirs: Vec<String> = std::fs::read_dir("crates")
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path().to_string_lossy().replace('\\', "/"))
        .collect();
    dirs.push("xtask".to_owned());
    dirs.sort();

    for dir in dirs {
        let manifest = format!("{dir}/Cargo.toml");
        let body = read(&manifest);
        if body.is_empty() {
            continue;
        }
        let declared = if body.contains("license.workspace = true") {
            ws_licence.clone()
        } else {
            body.lines()
                .find_map(|l| l.trim().strip_prefix("license = "))
                .map(|v| v.trim().trim_matches('"').to_owned())
                .unwrap_or_default()
        };
        let want = expected_spdx(&dir);
        if declared != want {
            bad.push(format!(
                "{manifest} declares `{declared}`, LICENSE.md maps it to `{want}`"
            ));
        }
    }
    fail(&bad)
}

/// Every source file carries the SPDX id `LICENSE.md` maps its path to.
///
/// The two eBPF crates are not Apache-2.0 and the kernel is why: a BPF program
/// calling a `gpl_only` helper must declare GPL, and the wire types are compiled
/// into both sides.
pub(crate) fn spdx_headers() -> Result<(), String> {
    let mut bad = Vec::new();
    for (dir, expected) in [
        ("crates/aisme-ebpf-common", "GPL-2.0-only OR BSD-2-Clause"),
        ("crates/aisme-ebpf", "GPL-2.0-only"),
    ] {
        for path in rust_files(dir) {
            let want = format!("// SPDX-License-Identifier: {expected}");
            if !read(&path).starts_with(&want) {
                bad.push(format!("{path} does not start with `{want}`"));
            }
        }
    }
    for dir in ["crates", "xtask"] {
        for path in rust_files(dir) {
            if path.starts_with("crates/aisme-ebpf") {
                continue;
            }
            if !read(&path).starts_with("// SPDX-License-Identifier: Apache-2.0") {
                bad.push(format!("{path} lacks the Apache-2.0 SPDX header"));
            }
        }
    }
    fail(&bad)
}

fn rust_files(root: &str) -> Vec<String> {
    let mut out = Vec::new();
    walk(Path::new(root), &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rs")) {
            out.push(p.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// The ordered path list in `CLAUDE.md` and `AGENTS.md` §1 is the same list.
///
/// Two files both claiming to be canonical is how a session ends up following
/// neither.
pub(crate) fn read_order_agrees() -> Result<(), String> {
    let a = ordered_paths(&section(&read("CLAUDE.md"), "## Read order"));
    let b = ordered_paths(&section(&read("docs/ai/AGENTS.md"), "### On start"));
    if a.is_empty() {
        return Err("no read order found in CLAUDE.md".into());
    }
    if a == b {
        Ok(())
    } else {
        Err(format!("CLAUDE.md lists {a:?}, AGENTS.md lists {b:?}"))
    }
}

/// The text under a heading, up to the next heading of the same or higher level.
///
/// Scoping matters: both files also carry a *write* order, and a whole-file scan
/// would splice the two lists together and then report them as disagreeing.
fn section(body: &str, heading: &str) -> String {
    let Some(start) = body.find(heading) else {
        return String::new();
    };
    let rest = &body[start + heading.len()..];
    // Stop at the next heading of ANY level. `\n## ` alone would run past
    // `### On finish`, splice the write order onto the read order, and then
    // report the two files as disagreeing about a list neither of them has.
    let end = rest
        .match_indices('\n')
        .find(|(i, _)| rest[i + 1..].starts_with('#'))
        .map_or(rest.len(), |(i, _)| i);
    rest[..end].to_owned()
}

/// The `docs/…` paths of a numbered read-order list, in order.
fn ordered_paths(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in body.lines() {
        let t = line.trim_start();
        if !t.starts_with(|c: char| c.is_ascii_digit()) || !t.contains('.') {
            continue;
        }
        for token in t.split_whitespace() {
            let tok = token.trim_matches(|c: char| !c.is_ascii_graphic() || "`*—←,".contains(c));
            // CLAUDE.md writes its own entry as "**This file**"; AGENTS.md names
            // it. Same entry, so normalise before comparing.
            let tok = if t.contains("This file") {
                "CLAUDE.md"
            } else {
                tok
            };
            if (tok.starts_with("docs/") || tok == "CLAUDE.md") && !out.contains(&tok.to_owned()) {
                out.push(tok.to_owned());
                break;
            }
        }
    }
    out
}

/// The definition of done still requires re-reading the relevant ADR.
pub(crate) fn dod_has_adr_line() -> Result<(), String> {
    if read("docs/ai/AGENTS.md").contains("the relevant ADR was re-read") {
        Ok(())
    } else {
        Err("AGENTS.md §2 no longer requires the ADR re-read (ADR-01 decision 3)".into())
    }
}

/// `STATE.md` carries the §7.3 headings, in that order. Extra headings are fine.
pub(crate) fn state_headings() -> Result<(), String> {
    let required = [
        "Where we are",
        "Done",
        "Next up",
        "Blocked",
        "Notes for whoever picks this up",
    ];
    let body = read("docs/ai/STATE.md");
    let present: Vec<&str> = body
        .lines()
        .filter_map(|l| l.strip_prefix("## "))
        .map(str::trim)
        .collect();
    let mut missing = Vec::new();
    let mut last = 0;
    for want in required {
        match present.iter().position(|h| h.contains(want)) {
            None => missing.push(format!("missing heading `## {want}`")),
            Some(i) if i < last => missing.push(format!("`## {want}` is out of §7.3 order")),
            Some(i) => last = i,
        }
    }
    fail(&missing)
}

/// ADR numbers are contiguous from 00 with no gap.
pub(crate) fn adrs_contiguous() -> Result<(), String> {
    let mut nums: Vec<u32> = std::fs::read_dir("docs/adr")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.split('_').next()?.parse().ok()
        })
        .collect();
    nums.sort_unstable();
    let gaps: Vec<String> = (0..nums.len())
        .filter(|i| nums[*i] != u32::try_from(*i).unwrap_or(u32::MAX))
        .map(|i| format!("expected {i:02}, found {:02}", nums[i]))
        .collect();
    fail(&gaps)
}

/// `NN_slug.md` under `docs/`, and never `NN_-slug.md`.
///
/// `docs/ai/*` is exempt: those are instruction files referenced by fixed name.
pub(crate) fn nn_naming() -> Result<(), String> {
    let mut bad = Vec::new();
    let mut dirs = vec![Path::new("docs").to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let s = p.to_string_lossy().replace('\\', "/");
            if s.starts_with("docs/ai") || s.starts_with("docs/research") {
                continue;
            }
            if p.is_dir() {
                dirs.push(p);
                continue;
            }
            let Some(name) = p.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            let is_md = Path::new(name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("md"));
            if !is_md || name == "CHANGELOG.md" || name == "README.md" {
                continue;
            }
            let numbered = name.len() > 3
                && name[..2].chars().all(|c| c.is_ascii_digit())
                && name.as_bytes()[2] == b'_';
            if !numbered {
                bad.push(format!("{s} is not NN_slug.md"));
            } else if name.as_bytes().get(3) == Some(&b'-') {
                bad.push(format!("{s} has NN_- , which Rule 4 forbids"));
            }
        }
    }
    fail(&bad)
}

/// The phase table sums to the critical path the plan states.
pub(crate) fn phase_sums(plan: &str) -> Result<(), String> {
    let Some(line) = plan.lines().find(|l| l.contains("Critical path: F0")) else {
        return Err("no critical-path sentence found".into());
    };
    // The sentence has two `=`: "F0 -> ... = 1 + 2.5 + ... = 11.5 weeks". The
    // addends sit between them and the total follows the second, so splitting on
    // the first `=` alone reads the phase names and sums to nothing.
    let parts: Vec<&str> = line.split('=').collect();
    if parts.len() < 3 {
        return Err(format!("cannot read the critical-path sentence: {line}"));
    }
    let numbers: Vec<f64> = parts[1]
        .split('+')
        .filter_map(|t| t.split_whitespace().next()?.parse().ok())
        .collect();
    let stated: Option<f64> = parts[2]
        .split_whitespace()
        .next()
        .and_then(|t| t.replace("**", "").parse().ok());
    let sum: f64 = numbers.iter().sum();
    match stated {
        Some(s) if (s - sum).abs() < 1e-9 => Ok(()),
        Some(s) => Err(format!("the addends sum to {sum}, the sentence says {s}")),
        None => Err("could not read the stated total".into()),
    }
}

/// `Cargo.lock` and `layers.toml` are tracked; GATE F0 asserts it too.
pub(crate) fn tracked_files() -> Result<(), String> {
    let out = Command::new("git")
        .args(["ls-files", "--error-unmatch", "Cargo.lock", "layers.toml"])
        .output();
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(_) => Err("Cargo.lock or layers.toml is not tracked".into()),
        Err(e) => Err(format!("git did not run: {e}")),
    }
}

/// The seed memories of plan §7.4 exist, are well formed, and cite a source.
///
/// The count comes from the plan's own table rather than a constant here: a row
/// added there without a file is exactly the drift this checks for.
pub(crate) fn seed_memories(plan: &str) -> Result<(), String> {
    const TYPES: [&str; 5] = [
        "platform-limit",
        "toolchain",
        "performance",
        "domain",
        "process",
    ];
    let expected: Vec<String> = section(plan, "### 7.4 ")
        .lines()
        .filter_map(|l| {
            let rest = l.strip_prefix("| `")?;
            let (slug, after) = rest.split_once('`')?;
            // Digits belong in a slug: wsl2-capabilities, hardware-keys-are-p256,
            // landlock-l2-file-deny. Excluding them silently shrank this check to
            // six of the eleven seeds.
            let is_slug = slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
            (after.starts_with(" |") && is_slug).then(|| slug.to_owned())
        })
        .collect();
    if expected.is_empty() {
        return Err("no seed rows found in plan §7.4".into());
    }
    // A check that quietly covers a subset is worse than no check, so the number
    // of files on disk must equal the number of rows in the plan.
    let on_disk = std::fs::read_dir("docs/ai/memory")
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("md"))
        })
        .count();
    if on_disk != expected.len() {
        return Err(format!(
            "plan §7.4 lists {} seeds, docs/ai/memory holds {on_disk} files",
            expected.len()
        ));
    }

    let mut bad = Vec::new();
    for slug in &expected {
        let path = format!("docs/ai/memory/{slug}.md");
        let body = read(&path);
        if body.is_empty() {
            bad.push(format!("{path} is missing or empty"));
            continue;
        }
        if !body.starts_with("---\n") {
            bad.push(format!("{path} has no frontmatter"));
            continue;
        }
        for field in ["name:", "description:", "type:"] {
            if !body.contains(&format!("\n{field}")) {
                bad.push(format!("{path} lacks `{field}`"));
            }
        }
        let declared_type = body
            .lines()
            .find_map(|l| l.strip_prefix("type: "))
            .map_or("", str::trim);
        if !TYPES.contains(&declared_type) {
            bad.push(format!(
                "{path} has type `{declared_type}`, not one of {TYPES:?}"
            ));
        }
        if !body.contains(&format!("name: {slug}")) {
            bad.push(format!("{path} does not name itself `{slug}`"));
        }
        match body.split("**Source:**").nth(1) {
            None => bad.push(format!("{path} cites no source")),
            Some(rest) if rest.lines().next().unwrap_or("").trim().is_empty() => {
                bad.push(format!("{path} has an empty source"));
            }
            Some(_) => {}
        }
    }
    fail(&bad)
}

/// Every `§n.m` the plan cites resolves to a heading it contains.
pub(crate) fn section_refs(plan: &str) -> Result<(), String> {
    let headings: BTreeSet<String> = plan
        .lines()
        .filter_map(|l| {
            let t = l.trim_start_matches('#').trim();
            l.starts_with("##")
                .then(|| t.split_whitespace().next().unwrap_or("").to_owned())
        })
        .collect();
    let mut missing = BTreeSet::new();
    for (i, _) in plan.match_indices('§') {
        let rest = &plan[i + '§'.len_utf8()..];
        let r: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        let r = r.trim_end_matches('.');
        if r.contains('.') && !headings.contains(r) {
            missing.insert(r.to_owned());
        }
    }
    let msgs: Vec<String> = missing
        .into_iter()
        .map(|m| format!("§{m} resolves to no heading"))
        .collect();
    fail(&msgs)
}

/// Every `[CUT]` marker in the plan is echoed in the threat model's non-goals.
pub(crate) fn cuts_in_threat_model(plan: &str) -> Result<(), String> {
    let non_goals = read("docs/security/01_threat-model.md");
    if !plan.contains("[CUT]") {
        return Ok(());
    }
    if non_goals.to_lowercase().contains("non-goal") {
        Ok(())
    } else {
        Err("the plan marks [CUT] items but the threat model states no non-goals".into())
    }
}
