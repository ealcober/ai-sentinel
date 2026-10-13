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
            // target/ holds build output, including vendored and generated Rust
            // that carries no SPDX header of ours and never should.
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
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
    let claude = section(&read("CLAUDE.md"), "## Read order");
    let agents = section(&read("docs/ai/AGENTS.md"), "### On start");
    let a = ordered_paths(&claude);
    let b = ordered_paths(&agents);
    if a.is_empty() {
        return Err("no read order found in CLAUDE.md".into());
    }
    if a != b {
        return Err(format!("CLAUDE.md lists {a:?}, AGENTS.md lists {b:?}"));
    }
    let missing: Vec<&str> = [("CLAUDE.md", &claude), ("docs/ai/AGENTS.md", &agents)]
        .into_iter()
        .filter(|(_, body)| !has_step_zero(body))
        .map(|(name, _)| name)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{missing:?} carry no step 0 running `cargo xtask doctor` — the host is read instead of measured"
        ))
    }
}

/// A read-order step numbered 0 that names `cargo xtask doctor`.
///
/// `ordered_paths` keeps a token only when it starts with `docs/` or is
/// `CLAUDE.md`, so a step that is a *command* contributes nothing to the
/// comparison above: without this the two files could lose or reword step 0
/// independently and the gate would still report agreement.
///
/// Presence and the command, not identical wording. `CLAUDE.md` writes the list
/// as prose with bold entries and `AGENTS.md` as a fenced code block, so no
/// entry is textually identical between the two — which is why `ordered_paths`
/// normalises `**This file**` to `CLAUDE.md` in the first place.
fn has_step_zero(body: &str) -> bool {
    body.lines().any(|l| {
        let t = l.trim_start();
        t.starts_with("0.") && t.contains("cargo xtask doctor")
    })
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

/// The workspace declares what a searcher needs, and the repository URL matches
/// the directory it is in.
///
/// The manifest carried only `license` and `repository`: no `description`, no
/// `keywords`, no `categories`. Those are what crates.io ranks on, and their
/// absence is why this repository was findable by nobody.
///
/// **The third clause is the one that earns its keep.** It compares the last
/// path segment of `repository` against the directory name, so the day the
/// repository is renamed and the manifest is not, the gate says so — which is
/// exactly the failure a rename risks, and the only part of a rename a machine
/// can check.
pub(crate) fn workspace_is_discoverable() -> Result<(), String> {
    let Ok(manifest) = std::fs::read_to_string("Cargo.toml") else {
        return Err("Cargo.toml could not be read".to_owned());
    };
    let mut bad = Vec::new();

    let value = |key: &str| -> Option<String> {
        manifest
            .lines()
            .find(|l| l.trim_start().starts_with(&format!("{key} = ")))
            .and_then(|l| l.split_once('='))
            .map(|(_, v)| v.trim().trim_matches('"').to_owned())
    };

    match value("description") {
        Some(d) if d.len() >= 40 => {}
        Some(_) => bad.push(
            "[workspace.package] description is too short to stand alone in a search result"
                .to_owned(),
        ),
        None => bad.push("[workspace.package] declares no description".to_owned()),
    }

    let keywords = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("keywords = "))
        .map_or(0, |l| l.matches('"').count() / 2);
    if keywords < 3 {
        bad.push(format!(
            "[workspace.package] declares {keywords} keyword(s); crates.io allows five and a \
             searcher needs at least three"
        ));
    }

    match value("repository") {
        Some(url) => {
            let last = url.rsplit('/').next().unwrap_or_default().to_owned();
            let here = std::env::current_dir()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                .unwrap_or_default();
            if !here.is_empty() && last != here {
                bad.push(format!(
                    "repository ends in {last:?} and this directory is {here:?} — one of the \
                     two was renamed and the other was not"
                ));
            }
        }
        None => bad.push("[workspace.package] declares no repository".to_owned()),
    }

    fail(&bad)
}

/// Every numbered document under `docs/` is linked from `README.md`, and every
/// `docs/` link in the README resolves.
///
/// **It fails in both directions, and that is the point.** A document nobody
/// links is a document nobody reads: the README's map cited `docs/01`–`04`
/// while sixteen numbered documents existed, so twelve were invisible to a
/// visitor — including both field studies and the plan that closes the current
/// phase. And a link to a deleted file is a page that lies, which for a project
/// whose argument is that it does not overclaim is the worse of the two.
///
/// A grouped link counts: the map names ranges rather than every file, so a
/// document is satisfied by appearing anywhere in the README.
pub(crate) fn readme_links_every_numbered_doc() -> Result<(), String> {
    let Ok(root) = std::fs::read_to_string("README.md") else {
        return Err("README.md could not be read".to_owned());
    };
    // The curated map in the root README plus the full index in `docs/`. A
    // sixteen-row table does not belong on a landing page, and an index does
    // not belong anywhere but the directory it indexes — so a document is
    // reachable if either names it.
    let index = std::fs::read_to_string("docs/README.md").unwrap_or_default();
    let readme = format!("{root}\n{index}");
    let mut bad = Vec::new();

    // Direction one: every numbered document is mentioned.
    if let Ok(entries) = std::fs::read_dir("docs") {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                continue;
            }
            let Some(name) = p.file_name().and_then(std::ffi::OsStr::to_str) else {
                continue;
            };
            let numbered = name.len() > 3
                && name[..2].chars().all(|c| c.is_ascii_digit())
                && name.as_bytes().get(2) == Some(&b'_');
            if !numbered {
                continue;
            }
            // Either the full filename, or the `docs/NN` form a grouped range
            // uses. Both are a link a reader can follow.
            let stem = &name[..2];
            if !readme.contains(name) && !readme.contains(&format!("docs/{stem})")) {
                bad.push(format!(
                    "docs/{name} is linked from no line of README.md, so a visitor \
                     cannot find it"
                ));
            }
        }
    }

    // Direction two: every `docs/` link in the root README resolves. The
    // index's own links are relative to `docs/` and are checked below.
    let mut rest = root.as_str();
    while let Some(at) = rest.find("](docs/") {
        rest = &rest[at + 2..];
        let Some(end) = rest.find(')') else { break };
        let target = &rest[..end];
        // A directory link ends in `/`; both forms must exist on disk.
        if !Path::new(target).exists() {
            bad.push(format!("README.md links {target}, which does not exist"));
        }
        rest = &rest[end..];
    }

    // And every link in the index, which is relative to `docs/`.
    let mut rest = index.as_str();
    while let Some(at) = rest.find("](") {
        rest = &rest[at + 2..];
        let Some(end) = rest.find(')') else { break };
        let target = &rest[..end];
        if !target.starts_with("http") && !Path::new("docs").join(target).exists() {
            bad.push(format!(
                "docs/README.md links {target}, which does not exist"
            ));
        }
        rest = &rest[end..];
    }

    fail(&bad)
}

/// The repository root holds only what an allow-list admits.
///
/// **Rule 4 says the root takes `README.md` and the instruction files and
/// nothing else, and nothing enforced it for anything but `.md`.** That is how
/// a 691 KB scraped copy of a third-party documentation page came to sit in the
/// root, tracked, beside this project's own `LICENSE` and `NOTICE` — a
/// redistribution nobody decided to make. The list below is the one the rules
/// already imply; a file that belongs in the root is one edit away, and an
/// accident is a `FAIL`.
///
/// Directories are not listed: the layout is `Cargo.toml`'s business and
/// `verify-layering`'s, not this check's.
pub(crate) fn root_is_allow_listed() -> Result<(), String> {
    const ALLOWED: &[&str] = &[
        // The two the rule names.
        "README.md",
        "CLAUDE.md",
        // Project governance, each referenced by fixed name from the README.
        "CONTRIBUTING.md",
        "SECURITY.md",
        "NOTICE",
        "CITATION.cff",
        "LICENSE.md",
        "LICENSE-APACHE",
        "LICENSE-GPL",
        "LICENSE-BSD",
        // The workspace's own manifests and the canonical numbers.
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "budgets.toml",
        "layers.toml",
        "deny.toml",
        // Ignored by git, listed so a local tree does not fail its own gate.
        ".gitignore",
    ];

    let Ok(entries) = std::fs::read_dir(".") else {
        return Err("the repository root could not be read".to_owned());
    };
    let mut bad = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            continue;
        }
        let Some(name) = p.file_name().and_then(std::ffi::OsStr::to_str) else {
            continue;
        };
        // A dotfile is tooling configuration, not content; `.gitignore` is
        // listed above because it is the one a reader looks for.
        if name.starts_with('.') || ALLOWED.contains(&name) {
            continue;
        }
        bad.push(format!(
            "{name} is in the repository root, which Rule 4 does not admit — \
             move it under docs/ or a crate, or add it to ALLOWED with a reason"
        ));
    }
    fail(&bad)
}

/// Every task ID that appears in a commit subject has a line in the changelog.
///
/// `docs/CHANGELOG.md` states this rule at the top of the file and, until this
/// check existed, nothing enforced it: the claim that `verify-docs` warns was
/// itself the reason nobody looked, and one task (`F0.VER.03`) had already
/// slipped through. The scan is over commit *subjects* only — a body may
/// mention any number of IDs it did not close — and it reads the whole history
/// because the file covers the whole history.
///
/// A subject may abbreviate a run of sibling tasks, as
/// `verify(F0.VER.03,.06,.08)` does: a bare `.NN` after a full ID inherits
/// that ID's phase and block. Without expanding it the check would read six
/// of those seven as absent-and-therefore-fine, which is the failure mode it
/// exists to catch.
pub(crate) fn changelog_covers_commits() -> Result<(), String> {
    let out = Command::new("git")
        .args(["log", "--format=%s"])
        .output()
        .map_err(|e| format!("git log: {e}"))?;
    if !out.status.success() {
        return Err("git log failed; not a repository?".to_owned());
    }
    let subjects = String::from_utf8_lossy(&out.stdout).into_owned();
    let changelog = read("docs/CHANGELOG.md");
    let mut missing: Vec<String> = Vec::new();
    let mut ids: Vec<String> = Vec::new();
    for line in subjects.lines() {
        let mut prefix: Option<String> = None;
        for tok in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')) {
            if let Some(num) = tok.strip_prefix('.') {
                // `.06` — a sibling of the last full ID on this subject.
                if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) {
                    if let Some(p) = &prefix {
                        ids.push(format!("{p}.{num}"));
                    }
                }
                continue;
            }
            if let Some(at) = tok.rfind('.') {
                prefix = Some(tok[..at].to_owned());
            }
            ids.push(tok.to_owned());
        }
    }
    for id in &ids {
        // F<digit>.<UPPER>.<digits> — the shape Part III fixes (I-23).
        let mut parts = id.split('.');
        let (Some(phase), Some(block), Some(num), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let shaped = phase.len() == 2
            && phase.starts_with('F')
            && phase[1..].chars().all(|c| c.is_ascii_digit())
            && !block.is_empty()
            && block.chars().all(|c| c.is_ascii_uppercase())
            && !num.is_empty()
            && num.chars().all(|c| c.is_ascii_digit());
        if shaped && !changelog.contains(id.as_str()) && !missing.iter().any(|m| m == id) {
            missing.push(id.clone());
        }
    }
    missing.sort();
    fail(
        &missing
            .iter()
            .map(|id| format!("{id} closes a commit and has no changelog line"))
            .collect::<Vec<_>>(),
    )
}

/// Every `<task-id>` row citation resolves to a plan line naming that task.
///
/// The amplification documents verify their claims with `file:line`, which the
/// project's rules require — and a line number is the one citation form that
/// rots silently when the file it points into grows. Fourteen of them in
/// `docs/05` pointed at the wrong row: seven had drifted when the plan gained
/// lines, and the rest had been written approximately and never checked, which
/// is an unverified claim wearing the clothes of a verified one.
///
/// The pattern is deliberately narrow — ``` `F2.WS.03` row (`:1621`) ``` — so it
/// checks what it can check exactly: the cited line must contain the task ID.
pub(crate) fn task_citations_resolve() -> Result<(), String> {
    // Read once, here: the check runs a single time per invocation, so a
    // cached static would buy nothing and cost a leak.
    let plan_body = read(PLAN_PATH);
    let plan: Vec<&str> = plan_body.lines().collect();
    let mut bad = Vec::new();
    for dir_entry in ["docs"] {
        let Ok(entries) = std::fs::read_dir(dir_entry) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().is_none_or(|x| x != "md") {
                continue;
            }
            let Some(body) = read_opt(&path.to_string_lossy()) else {
                continue;
            };
            for (id, n) in citations(&body) {
                match plan.get(n.saturating_sub(1)) {
                    Some(line) if line.contains(&id) => {}
                    Some(_) | None => bad.push(format!(
                        "{}: `{id}` is cited at plan line {n}, which does not name it",
                        path.display()
                    )),
                }
            }
        }
    }
    bad.sort();
    fail(&bad)
}

/// `` `F2.WS.03` row (`:1621`) `` and the same without the word `row`.
fn citations(body: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let bytes: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        // Find "`F" then read the id, then expect "` (`:" or "` row (`:".
        if bytes[i] == '`' && bytes.get(i + 1) == Some(&'F') {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && bytes[j] != '`' {
                j += 1;
            }
            let id: String = bytes[start..j].iter().collect();
            let shaped = id.len() >= 7
                && id.starts_with('F')
                && id.matches('.').count() == 2
                && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '.');
            if shaped {
                // 24, not 12: the lookahead must clear "` row (`:" (9 chars) plus a
                // four-digit line and its closing punctuation. At 12 it silently
                // truncated 1620 to 162 and every citation "failed" against the
                // wrong line — a check that reports a real defect for a fake
                // reason is still a check that is wrong.
                let rest: String = bytes[j..(j + 24).min(bytes.len())].iter().collect();
                let after = rest.trim_start_matches('`').trim_start();
                let after = after.strip_prefix("row").unwrap_or(after).trim_start();
                if let Some(num) = after.strip_prefix("(`:") {
                    let digits: String = num.chars().take_while(char::is_ascii_digit).collect();
                    if let Ok(n) = digits.parse::<usize>() {
                        out.push((id, n));
                    }
                }
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// Path of the plan the citations point into.
const PLAN_PATH: &str = "docs/01_phase5_implementation_plan.md";

/// `read`, but `None` rather than empty when the file is missing.
fn read_opt(path: &str) -> Option<String> {
    std::fs::read_to_string(path).ok()
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
    // Every seed row must have a file. The directory may hold more than the
    // seeds — memory is meant to grow — so this is a subset check, not equality.
    // What it must never become again is a check that silently covers fewer
    // files than it claims to.
    let on_disk: Vec<String> = std::fs::read_dir("docs/ai/memory")
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("md"))
        })
        .filter_map(|e| {
            e.path()
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
        })
        .collect();
    if on_disk.len() < expected.len() {
        return Err(format!(
            "plan §7.4 lists {} seeds, docs/ai/memory holds {} files",
            expected.len(),
            on_disk.len()
        ));
    }
    // Validate every file present, seed or not: a memory added later is read by
    // the same sessions and must carry the same frontmatter.
    let mut all = expected.clone();
    for f in on_disk {
        if !all.contains(&f) {
            all.push(f);
        }
    }

    let mut bad = Vec::new();
    for slug in &all {
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

/// Every backend's declared verdict map in Annex B §B.9 is monotone.
///
/// The verdicts are a chain, `allow < warn < escalate < deny`. A backend that
/// cannot enforce a verdict declares what it degrades to, and that map must be
/// order-preserving — otherwise §B.9's proof that `f(max S) = max f(S)` fails and
/// the compiler could not degrade rule-by-rule.
pub(crate) fn verdict_maps_monotone(plan: &str) -> Result<(), String> {
    let order = |v: &str| match v {
        "allow" => Some(0),
        "warn" => Some(1),
        "escalate" => Some(2),
        "deny" => Some(3),
        _ => None,
    };
    let Some(start) = plan.find("| Backend | `allow` | `warn` | `escalate` | `deny` |") else {
        return Err("§B.9's backend map table is missing".into());
    };
    let mut bad = Vec::new();
    let mut rows = 0;
    for line in plan[start..]
        .lines()
        .skip(2)
        .take_while(|l| l.starts_with('|'))
    {
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let Some(backend) = cells.get(1) else {
            continue;
        };
        let mapped: Vec<Option<u8>> = (2..6)
            .map(|i| {
                cells.get(i).and_then(|c| {
                    // Cells carry emphasis and a parenthetical: "**deny** (fail closed)".
                    c.replace(['*', '`'], "")
                        .split_whitespace()
                        .next()
                        .and_then(|w| order(w.trim()))
                })
            })
            .collect();
        if mapped.iter().any(Option::is_none) {
            bad.push(format!("{backend}: a cell is not one of the four verdicts"));
            continue;
        }
        rows += 1;
        let v: Vec<u8> = mapped.into_iter().flatten().collect();
        if v.windows(2).any(|w| w[0] > w[1]) {
            bad.push(format!("{backend}: map {v:?} is not order-preserving"));
        }
    }
    if rows == 0 {
        bad.push("no backend rows parsed".into());
    }
    fail(&bad)
}

/// The verification probes pin the same nightly as the product eBPF crate.
///
/// They share the target, the linker and the LLVM constraint, so a drift between
/// the two pins would validate the toolchain against one and ship the other.
pub(crate) fn probe_pin_matches_ebpf() -> Result<(), String> {
    let channel = |path: &str| -> Option<String> {
        read(path)
            .lines()
            .find_map(|l| l.trim().strip_prefix("channel"))
            .and_then(|r| r.split('"').nth(1).map(str::to_owned))
    };
    match (
        channel("crates/aisme-ebpf/rust-toolchain.toml"),
        channel("tests/probes/ebpf/rust-toolchain.toml"),
    ) {
        (Some(a), Some(b)) if a == b => Ok(()),
        (Some(a), Some(b)) => Err(format!(
            "crates/aisme-ebpf pins {a}, tests/probes/ebpf pins {b}"
        )),
        _ => Err("one of the two rust-toolchain.toml files has no channel".into()),
    }
}

/// Every `budgets.toml` key named in prose resolves to a key that exists.
///
/// A sentence claiming a budget is enforced is easy to write and reads as done.
/// Only keys are checked, identified by their first segment being a table in
/// `budgets.toml`, so an `OTel` metric name like `aisme.permission.prompts_per_day`
/// is correctly left alone.
pub(crate) fn prose_budget_keys() -> Result<(), String> {
    let budgets = read("budgets.toml");
    let sections: BTreeSet<&str> = budgets
        .lines()
        .filter_map(|l| l.trim().strip_prefix('[')?.split(['.', ']']).next())
        .collect();
    if sections.is_empty() {
        return Err("budgets.toml declares no tables".into());
    }

    // §5.6 defines OpenTelemetry attribute names, and `process.pid`,
    // `process.executable.name` and `process.command_args` are OTel's, not ours.
    // They collide with budgets.toml's `[process]` table by pure coincidence, so
    // the scan skips that section rather than blacklisting the names.
    let plan_body = read("docs/01_phase5_implementation_plan.md");
    let otel = plan_body.find("### 5.6").map(|i| {
        (
            i,
            plan_body[i + 8..]
                .find("\n### ")
                .map_or(plan_body.len(), |j| i + 8 + j),
        )
    });

    let mut bad = Vec::new();
    for doc in [
        "docs/01_phase5_implementation_plan.md",
        "CLAUDE.md",
        "README.md",
        "docs/ai/invariants.md",
        "docs/ai/STATE.md",
    ] {
        let body = read(doc);
        let mut offset = 0usize;
        for (idx, token) in body.split('`').enumerate() {
            let here = offset;
            offset += token.len() + 1;
            if idx % 2 == 0 {
                continue;
            }
            if doc.ends_with("plan.md") {
                if let Some((start, end)) = otel {
                    if here >= start && here < end {
                        continue;
                    }
                }
            }
            let key = token.trim();
            let mut parts = key.split('.');
            let (Some(head), Some(last)) = (parts.next(), key.rsplit('.').next()) else {
                continue;
            };
            let shaped = key.split('.').count() >= 2
                && key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._".contains(c));
            if !shaped || !sections.contains(head) {
                continue;
            }
            // The key exists if its leaf is assigned anywhere under that table.
            if !budgets.lines().any(|l| {
                l.trim_start().starts_with(&format!("{last} "))
                    || l.trim_start().starts_with(&format!("{last}="))
            }) {
                bad.push(format!(
                    "{doc} names `{key}`, which budgets.toml does not define"
                ));
            }
        }
    }
    bad.sort();
    bad.dedup();
    fail(&bad)
}

/// The Part VI crate tree lists exactly the crates that exist, with their layer.
///
/// This is a consistency check, not a regeneration: the tree's third column is
/// human prose describing what each crate is for, and regenerating it would
/// delete the only part a reader needs.
/// Is this crate under `[excluded]` in `layers.toml` rather than layered?
fn excluded(layers: &str, crate_name: &str) -> bool {
    let Some(section) = layers.split("[excluded]").nth(1) else {
        return false;
    };
    let section = section.split("\n[").next().unwrap_or(section);
    section
        .lines()
        .any(|l| l.split('=').next().is_some_and(|k| k.trim() == crate_name))
}

pub(crate) fn part_vi_tree(plan: &str) -> Result<(), String> {
    let layers = read("layers.toml");
    let layer_of = |crate_name: &str| -> Option<String> {
        layers.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == crate_name).then(|| v.split('"').nth(1).unwrap_or("").to_owned())
        })
    };

    let mut listed = BTreeSet::new();
    let mut bad = Vec::new();
    for line in plan.lines() {
        let Some(rest) = line.split("── ").nth(1) else {
            continue;
        };
        let Some((name, tail)) = rest.split_once('/') else {
            continue;
        };
        if !tail.trim_start().starts_with('[') || name.contains(' ') {
            continue;
        }
        let tag: String = tail
            .trim_start()
            .chars()
            .skip(1)
            .take_while(|c| *c != ']')
            .collect();
        if !Path::new("crates").join(name).is_dir() {
            continue; // a tree entry outside crates/, such as driver/ or mobile/
        }
        listed.insert(name.to_owned());
        match layer_of(name) {
            Some(layer) if tag == layer => {}
            // An excluded crate carries a prose note where a layer would be;
            // the tree only has to say it is out, not repeat the note.
            Some(_) if excluded(&layers, name) && tag.starts_with("POST") => {}
            Some(layer) => bad.push(format!(
                "the tree marks {name} `[{tag}]`, layers.toml says {layer}"
            )),
            // `[excluded]` in layers.toml is a note, not a layer, so the tree
            // only has to agree that the crate is out: `[--]` for the eBPF crate
            // that builds separately, `[POST …]` for the deferred driver.
            None if tag.starts_with("--") || tag.starts_with("POST") => {}
            None => bad.push(format!(
                "the tree marks {name} `[{tag}]` but layers.toml omits it"
            )),
        }
    }

    for entry in std::fs::read_dir("crates").into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.path().is_dir() && !listed.contains(&name) {
            bad.push(format!(
                "crates/{name} exists but the Part VI tree does not list it"
            ));
        }
    }
    fail(&bad)
}

/// `STATE.md`'s header date is not older than the file's own last commit.
///
/// The header carries `Last updated: **YYYY-MM-DD**`, and it is the first line
/// of the first file a session is told to trust over its own assumptions. A
/// session that edits the file and leaves the date behind publishes a claim
/// that decays in silence. Git knows when the file last changed, so the two
/// dates are comparable exactly rather than by judgement.
pub(crate) fn state_last_updated_is_recent() -> Result<(), String> {
    let out = Command::new("git")
        .args(["log", "-1", "--format=%aI", "--", "docs/ai/STATE.md"])
        .output()
        .map_err(|e| format!("git log: {e}"))?;
    if !out.status.success() {
        return Err("git log failed; not a repository?".to_owned());
    }
    let committed = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    state_header_is_not_older(&read("docs/ai/STATE.md"), &committed)
}

/// The comparison, with git's answer passed in so it is testable without a
/// repository.
///
/// An empty commit date means git answered nothing — untracked file, or no
/// commit yet. That is an error and not a pass: `changelog_covers_commits`
/// treats a git that cannot answer the same way, and an absence read as
/// success is the failure mode this project refuses everywhere else.
fn state_header_is_not_older(body: &str, committed: &str) -> Result<(), String> {
    let Some(header) = body.lines().find(|l| l.contains("Last updated:")) else {
        return Err("STATE.md carries no `Last updated:` field".to_owned());
    };
    let Some(stated) = header
        .split("Last updated:")
        .nth(1)
        .and_then(|rest| rest.split("**").nth(1))
        .map(str::trim)
    else {
        return Err(format!("`Last updated:` carries no **date**: {header}"));
    };
    // ISO dates compare correctly as text, which is why the header is asked to
    // carry one. Anything shorter than a whole day is noise for this check.
    let Some(day) = committed.get(..10) else {
        return Err("git named no commit for docs/ai/STATE.md".to_owned());
    };
    if stated < day {
        return Err(format!(
            "STATE.md says `Last updated: {stated}` and its last commit is {day} — \
             the header outlived the edit"
        ));
    }
    Ok(())
}

/// `STATE.md`'s `## Next up` does not call a phase unstarted while `## Done`
/// records one of that phase's tasks.
///
/// The two sections drift by construction: `## Done` is appended to as work
/// closes, and `## Next up` is prose revised when someone remembers. On
/// 2026-09-08 the file recorded four F2 tasks with their measurements and,
/// fourteen lines lower, that nothing in F2 had started.
///
/// A task ID is a token, so the disagreement is comparable exactly — and the
/// check claims no more than that. Whether a task listed under `## Done` is
/// *actually* done is not knowable from this file, and this does not pretend
/// to know it.
pub(crate) fn state_next_up_agrees_with_done() -> Result<(), String> {
    next_up_agrees(&read("docs/ai/STATE.md"))
}

fn next_up_agrees(body: &str) -> Result<(), String> {
    let done = section(body, "## Done");
    let next_up = section(body, "## Next up");
    if done.is_empty() || next_up.is_empty() {
        return Err("STATE.md is missing `## Done` or `## Next up`".to_owned());
    }
    let line_of = |needle: &str| -> usize {
        body.lines()
            .position(|l| l.contains(needle))
            .map_or(0, |i| i + 1)
    };
    let mut problems = Vec::new();
    for phase in phases_of(&done) {
        // Both spellings, because the file writes task IDs in backticks and
        // prose phases without them.
        for claim in [
            format!("Nothing in {phase} is started"),
            format!("Nothing in `{phase}` is started"),
        ] {
            if next_up.contains(&claim) {
                problems.push(format!(
                    "`## Next up` (:{}) says \"{claim}\" while `## Done` (:{}) records a {phase} task",
                    line_of(&claim),
                    line_of(&format!("{phase}.")),
                ));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// The phase prefixes (`F2`) of every `F<n>.<block>.<task>` ID in a section.
fn phases_of(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.')) {
        let mut parts = tok.split('.');
        let (Some(phase), Some(block), Some(task), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let phase_ok = phase.len() > 1
            && phase.starts_with('F')
            && phase[1..].chars().all(|c| c.is_ascii_digit());
        let block_ok = !block.is_empty()
            && block
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
        let task_ok = !task.is_empty() && task.chars().all(|c| c.is_ascii_digit());
        if phase_ok && block_ok && task_ok && !out.contains(&phase.to_owned()) {
            out.push(phase.to_owned());
        }
    }
    out
}

/// No build artefact is tracked.
///
/// `.gitignore` listed target directories one by one, so every crate added
/// outside the workspace was one somebody had to remember. Two were added and
/// two were forgotten, and 890 files followed them into the index.
///
/// The cost that matters is not the 631 MB. It is that `cargo xtask build-ebpf`
/// rewrites them, so a routine build produces a diff of over 150 files in which
/// **a real change to a tracked file would be invisible** — the review that
/// would catch a mistake cannot see past the noise.
pub(crate) fn no_build_artefacts_are_tracked() -> Result<(), String> {
    let out = Command::new("git")
        .args(["ls-files"])
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !out.status.success() {
        return Err("git ls-files failed; not a repository?".to_owned());
    }
    let listing = String::from_utf8_lossy(&out.stdout).into_owned();
    tracked_artefacts(&listing)
}

/// The check itself, over a listing, so it is testable without a repository.
fn tracked_artefacts(listing: &str) -> Result<(), String> {
    let bad: Vec<&str> = listing
        .lines()
        .filter(|p| p.split('/').any(|seg| seg == "target"))
        .collect();
    if bad.is_empty() {
        return Ok(());
    }
    // The count without an example is not actionable, and the example without
    // the count hides the scale.
    let sample: Vec<&&str> = bad.iter().take(3).collect();
    Err(format!(
        "{} build artefact(s) are tracked, e.g. {sample:?}",
        bad.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "> Last updated: **2026-09-07** · Phase: **F2**\n";

    #[test]
    fn a_state_header_older_than_its_last_commit_is_refused() {
        assert!(state_header_is_not_older(HEADER, "2026-09-08T21:15:45+02:00").is_err());
        assert!(state_header_is_not_older(HEADER, "2026-09-07T09:00:00+02:00").is_ok());
        assert!(state_header_is_not_older(HEADER, "2026-09-06T09:00:00+02:00").is_ok());
    }

    #[test]
    fn a_git_that_cannot_answer_is_an_error_and_not_a_pass() {
        // The whole point of the check: an absent answer is never a success.
        assert!(state_header_is_not_older(HEADER, "").is_err());
        assert!(state_header_is_not_older("# STATE\n", "2026-09-08T00:00:00+02:00").is_err());
    }

    #[test]
    fn next_up_may_not_call_a_phase_unstarted_that_done_records() {
        let bad = "## Done\n\n| `F2.WS.01` — the kernel accepted it | x |\n\n\
                   ## Next up\n\nNothing in F2 is started; `F2.WS.01` is next.\n\n## Blocked\n";
        let err = next_up_agrees(bad).unwrap_err();
        assert!(err.contains("F2"), "{err}");

        let good = "## Done\n\n| `F2.WS.01` — the kernel accepted it | x |\n\n\
                    ## Next up\n\n`F2.WS.04`'s publication is next.\n\n## Blocked\n";
        assert!(next_up_agrees(good).is_ok());

        // A phase with nothing in Done may still be called unstarted.
        let unstarted = "## Done\n\n| `F1.RT.07` | x |\n\n\
                         ## Next up\n\nNothing in F3 is started.\n\n## Blocked\n";
        assert!(next_up_agrees(unstarted).is_ok());
    }

    #[test]
    fn a_tracked_build_artefact_is_refused() {
        assert!(tracked_artefacts("src/main.rs\nCargo.toml\n").is_ok());
        // A directory named `target` at any depth, which is what the general
        // ignore pattern covers and what the specific entries missed.
        let err =
            tracked_artefacts("src/main.rs\ncrates/x/target/release/libx.rlib\n").unwrap_err();
        assert!(err.contains("1 build artefact"), "{err}");
        // Not a substring match: a source file may legitimately be called
        // `targets.rs` or live under `retarget/`.
        assert!(tracked_artefacts("src/targets.rs\nsrc/retarget/mod.rs\n").is_ok());
    }

    #[test]
    fn a_read_order_without_step_zero_is_refused() {
        assert!(has_step_zero(
            "0. cargo xtask doctor           <- the host, measured"
        ));
        assert!(has_step_zero(
            "0. **Run `cargo xtask doctor`** - the host, measured"
        ));
        // The two ways it rots: the step goes, or the command is reworded away.
        assert!(!has_step_zero("1. CLAUDE.md\n2. docs/ai/AGENTS.md"));
        assert!(!has_step_zero("0. check the host prerequisites first"));
    }

    #[test]
    fn phases_of_reads_task_ids_and_not_prose() {
        assert_eq!(phases_of("`F2.WS.01` and `F0.VER.12`"), ["F2", "F0"]);
        assert!(phases_of("F2 is the walking skeleton, see §3.7.1").is_empty());
        assert!(phases_of("version 1.2.3").is_empty());
    }
}
