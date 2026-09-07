// SPDX-License-Identifier: Apache-2.0
//! Taint scenarios, mock-driven (`cargo xtask test-taint --scenario <name>
//! --mock`, `F1.ON.05`). Each test is one scenario; the xtask command filters
//! by name. No kernel, no sensor: the events are the sequence §2.14 and
//! Annex G describe, applied through the algebra as the correlate step will.

use aisme_core::labels::TreeLabels;
use aisme_core::taint::{DecayPolicy, Taint};

const REPO: &[u8] = b"/work/repo";
const SECOND: u64 = 1_000_000_000;

/// `RF-09`: instruction-bearing input followed by a first-of-kind action —
/// reachable only because a fetch labels the tree and `File.taint` carries it
/// to the reader (plan Annex G, `H-13` as corrected). The taint half:
///
/// 1. the agent spawns `git clone`, a child; the child inherits nothing
/// 2. the child fetches into `/work/repo`: the tree root is labelled
///    `UNTRUSTED_INPUT`, and so is the child
/// 3. the child exits — its taint goes with it, the label stays on the tree
/// 4. the agent reads `/work/repo/README.md`: the file carries the tree's
///    label though nothing tainted ever wrote it, and the agent acquires it
///
/// The corrected algebra reaches the agent. The naive design (taint the
/// process that fetched, and only it) would leave the agent clean at step 4
/// and `DT-02` would have nothing to fire on.
#[test]
fn rf_09() {
    let mut labels = TreeLabels::with_capacity(16);
    let agent = Taint::EMPTY;

    // 1
    let child = Taint::inherit(agent);
    assert_eq!(child, Taint::EMPTY);

    // 2
    labels
        .label_root(REPO, Taint::label_on_fetch(Taint::EMPTY))
        .unwrap();
    let child = Taint::label_on_fetch(child);
    assert!(child.contains(Taint::UNTRUSTED_INPUT));

    // 3 — the child exits: its taint is not carried anywhere, and `child` is
    // not used again below; only the tree's label remains.
    assert_eq!(labels.label_for(REPO), Taint::UNTRUSTED_INPUT);

    // 4
    let readme = labels.effective(Taint::EMPTY, b"/work/repo/README.md");
    assert_eq!(
        readme,
        Taint::UNTRUSTED_INPUT,
        "the tree's label, no writer needed"
    );
    let agent = Taint::on_read(agent, readme);
    assert!(
        agent.contains(Taint::UNTRUSTED_INPUT),
        "the corrected algebra reaches the agent: {agent:?}"
    );

    // Negative: a file outside the fetched tree leaves the agent as it was.
    let clean = Taint::EMPTY;
    let elsewhere = labels.effective(Taint::EMPTY, b"/work/other/notes.md");
    assert_eq!(Taint::on_read(clean, elsewhere), Taint::EMPTY);

    // And the label the agent acquired decays after §2.14's 300 s idle.
    let policy = DecayPolicy::DEFAULT;
    assert!(agent
        .decay(0, 299 * SECOND, policy)
        .contains(Taint::UNTRUSTED_INPUT));
    assert!(!agent
        .decay(0, 301 * SECOND, policy)
        .contains(Taint::UNTRUSTED_INPUT));
}

/// The workflows §2.14 says the naive rule breaks within minutes must not
/// trip the slam: a `.env` read by the test runner followed by `npm install`,
/// and `git push` after reading `~/.ssh/config` — both to allowlisted
/// destinations.
#[test]
fn benign_secret_reads_do_not_slam_against_the_allowlist() {
    let labels = TreeLabels::with_capacity(4);
    let env_file = labels.effective(Taint::SECRET_MATERIAL, b"/work/app/.env");
    let test_runner = Taint::on_read(Taint::EMPTY, env_file);
    assert!(test_runner.contains(Taint::SECRET_MATERIAL));
    // npm install: the registry is in the session allowlist.
    assert!(!test_runner.slam_condition(true, false));
    // The same egress to a destination outside the allowlist would slam.
    assert!(test_runner.slam_condition(false, false));
    // git push after ~/.ssh/config, to the project host.
    let git = Taint::on_read(Taint::EMPTY, Taint::CREDENTIAL_ACCESS);
    assert!(!git.slam_condition(true, false));
}
