// SPDX-License-Identifier: Apache-2.0
//! The Annex H inventory, as data.
//!
//! Generated from plan Annex H §H.4 and checked back against it by
//! `verify-docs`: a command in the plan with no row here is unreachable through
//! the argument parser, and a row here with no plan entry is a command nobody
//! specified. Both are failures, not warnings.
//!
//! Adding a command means adding its Annex H row first, then the task that
//! implements it, then the entry here.

/// A gate cadence. Levels are cumulative: `pr` runs everything `commit` runs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(crate) enum Level {
    Commit,
    Pr,
    Nightly,
    Weekly,
}

impl Level {
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "commit" => Some(Self::Commit),
            "pr" => Some(Self::Pr),
            "nightly" => Some(Self::Nightly),
            "weekly" => Some(Self::Weekly),
            _ => None,
        }
    }
}

/// One row of Annex H §H.4.
pub(crate) struct Command {
    /// Everything after `cargo xtask`, including any sub-namespace.
    pub(crate) name: &'static str,
    /// The task that implements it. Named in the exit-3 message.
    pub(crate) owner: &'static str,
    /// The phase that owns it.
    pub(crate) phase: &'static str,
    /// The lowest cadence that runs it; `None` means invoked directly.
    pub(crate) level: Option<Level>,
}

/// Phase identifier to the name the exit-3 message prints.
pub(crate) fn phase_name(phase: &str) -> &'static str {
    match phase {
        "F0" => "Repository bootstrap and guard rails",
        "F1" => "Core, ontology, policy model, interface freeze",
        "F2" => "Walking skeleton",
        "F3" => "Linux/WSL2 kernel sensors and enforcement",
        "F4" => "Semantic capture ladder",
        "F5" => "Correlation, taint, tamper-evident forensics",
        "F6" => "Semantic compression and Observer",
        "F7" => "Policy surface and Circuit Breaker",
        "F8" => "Desktop control plane",
        "F9" => "AI Sentinel SDK",
        "F10" => "AI Sentinel on-device engine",
        "F11" => "Mobile control plane and remote adjudication",
        "WIN" => "Windows minifilter — [POST], Annex F, do not implement",
        _ => "unknown phase",
    }
}

/// Every command in Annex H §H.4, in plan order.
pub(crate) const COMMANDS: &[Command] = &[
    Command {
        name: "bench-hotloop",
        owner: "F1.RT.03",
        phase: "F1",
        level: Some(Level::Nightly),
    },
    Command {
        name: "bench-t0",
        owner: "F2.WS.09",
        phase: "F2",
        level: Some(Level::Nightly),
    },
    Command {
        name: "bench-soak",
        owner: "F7.CB.07",
        phase: "F7",
        level: Some(Level::Weekly),
    },
    Command {
        name: "build-ebpf",
        owner: "F0.REPO.03",
        phase: "F0",
        level: None,
    },
    Command {
        name: "dist",
        owner: "F0.REPO.03",
        phase: "F0",
        level: None,
    },
    Command {
        name: "doctor",
        owner: "F0.REPO.06",
        phase: "F0",
        level: Some(Level::Commit),
    },
    Command {
        name: "gate",
        owner: "F0.REPO.03",
        phase: "F0",
        level: None,
    },
    Command {
        name: "sdk test-absent-sentinel",
        owner: "F9.DOC.01",
        phase: "F9",
        level: Some(Level::Pr),
    },
    Command {
        name: "sdk test-conformance",
        owner: "F9.DOC.01",
        phase: "F9",
        level: Some(Level::Pr),
    },
    Command {
        name: "sdk test-consistency",
        owner: "F9.DOC.01",
        phase: "F9",
        level: Some(Level::Pr),
    },
    Command {
        name: "sdk test-forgery",
        owner: "F9.DOC.01",
        phase: "F9",
        level: Some(Level::Pr),
    },
    Command {
        name: "sdk test-overhead",
        owner: "F9.DOC.01",
        phase: "F9",
        level: Some(Level::Pr),
    },
    Command {
        name: "sdk test-veto-e2e",
        owner: "F9.DOC.01",
        phase: "F9",
        level: Some(Level::Pr),
    },
    Command {
        name: "sdk test-warn",
        owner: "F9.DOC.01",
        phase: "F9",
        level: Some(Level::Pr),
    },
    Command {
        name: "sentinel test-attribution",
        owner: "F10.CORE.09",
        phase: "F10",
        level: Some(Level::Pr),
    },
    Command {
        name: "sentinel test-benign",
        owner: "F10.CORE.09",
        phase: "F10",
        level: Some(Level::Pr),
    },
    Command {
        name: "sentinel test-classifier",
        owner: "F10.CORE.09",
        phase: "F10",
        level: Some(Level::Pr),
    },
    Command {
        name: "sentinel test-no-payload-read",
        owner: "F10.CORE.09",
        phase: "F10",
        level: Some(Level::Pr),
    },
    Command {
        name: "sentinel test-sdk-loopback",
        owner: "F10.CORE.09",
        phase: "F10",
        level: Some(Level::Pr),
    },
    Command {
        name: "sentinel test-slam",
        owner: "F10.CORE.09",
        phase: "F10",
        level: Some(Level::Pr),
    },
    Command {
        name: "sentinel verify-budgets",
        owner: "F10.CORE.02",
        phase: "F10",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-a11y",
        owner: "F8.A11Y.01",
        phase: "F8",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-battery",
        owner: "F11.CC.01",
        phase: "F11",
        level: Some(Level::Weekly),
    },
    Command {
        name: "test-benign",
        owner: "F7.CB.02",
        phase: "F7",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-compression",
        owner: "F6.IRR.01",
        phase: "F6",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-correlation",
        owner: "F5.CO.01",
        phase: "F5",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-degrade-no-uprobe",
        owner: "F4.VAL.01",
        phase: "F4",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-detect",
        owner: "F1.DT.01",
        phase: "F1",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-enforce",
        owner: "F3.EN.08",
        phase: "F3",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-failsafe",
        owner: "F7.CB.02",
        phase: "F7",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-grant-lifecycle",
        owner: "F7.CB.02",
        phase: "F7",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-fuzz",
        owner: "F3.RB.01",
        phase: "F3",
        level: Some(Level::Nightly),
    },
    Command {
        name: "test-kernels",
        owner: "F3.EN.08",
        phase: "F3",
        level: Some(Level::Commit),
    },
    Command {
        name: "test-keylog-socket",
        owner: "F4.VAL.01",
        phase: "F4",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-merkle-tamper",
        owner: "F5.FO.04",
        phase: "F5",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-mobile-e2e",
        owner: "F11.CC.01",
        phase: "F11",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-no-hardware-key",
        owner: "F11.CC.01",
        phase: "F11",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-observer-injection",
        owner: "F6.IRR.01",
        phase: "F6",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-observer-proposals",
        owner: "F6.IRR.01",
        phase: "F6",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-observer-schema",
        owner: "F6.IRR.01",
        phase: "F6",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-observer-score-never-lower",
        owner: "F8.API.02",
        phase: "F8",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-pairing",
        owner: "F11.CC.01",
        phase: "F11",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-paths",
        owner: "F3.EN.08",
        phase: "F3",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-policy-compiler",
        owner: "F1.PL.05",
        phase: "F1",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-prompt-budget",
        owner: "F7.CB.02",
        phase: "F7",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-protocol-contract",
        owner: "F8.API.02",
        phase: "F8",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-redaction",
        owner: "F4.VAL.01",
        phase: "F4",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-redteam",
        owner: "F7.CB.02",
        phase: "F7",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-relay-blindness",
        owner: "F11.CC.01",
        phase: "F11",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-remote-authz",
        owner: "F11.CC.01",
        phase: "F11",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-scope-narrow",
        owner: "F7.CB.02",
        phase: "F7",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-skeleton",
        owner: "F2.WS.10",
        phase: "F2",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-slam",
        owner: "F3.EN.08",
        phase: "F3",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-suppression",
        owner: "F7.CB.02",
        phase: "F7",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-taint",
        owner: "F1.ON.05",
        phase: "F1",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-tls",
        owner: "F4.VAL.01",
        phase: "F4",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-tls-selftest",
        owner: "F4.VAL.01",
        phase: "F4",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-ui-e2e",
        owner: "F8.API.02",
        phase: "F8",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-uiagent-chaos",
        owner: "F8.API.02",
        phase: "F8",
        level: Some(Level::Pr),
    },
    Command {
        name: "test-warn-semantics",
        owner: "F7.CB.02",
        phase: "F7",
        level: Some(Level::Pr),
    },
    Command {
        name: "win test-deadlock",
        owner: "WIN.US.06",
        phase: "WIN",
        level: None,
    },
    Command {
        name: "win test-irp-storm",
        owner: "WIN.US.06",
        phase: "WIN",
        level: None,
    },
    Command {
        name: "win test-unload",
        owner: "WIN.US.06",
        phase: "WIN",
        level: None,
    },
    Command {
        name: "win verify-driver",
        owner: "WIN.US.06",
        phase: "WIN",
        level: None,
    },
    Command {
        name: "verify-budgets",
        owner: "F0.GATE.04",
        phase: "F0",
        level: Some(Level::Commit),
    },
    Command {
        name: "verify-backlog",
        owner: "F0.REPO.03",
        phase: "F0",
        level: Some(Level::Commit),
    },
    Command {
        name: "verify-docs",
        owner: "F0.REPO.03",
        phase: "F0",
        level: Some(Level::Commit),
    },
    Command {
        name: "verify-layering",
        owner: "F0.REPO.03",
        phase: "F0",
        level: Some(Level::Commit),
    },
    Command {
        name: "vm probe",
        owner: "F0.REPO.03",
        phase: "F0",
        level: Some(Level::Pr),
    },
    Command {
        name: "vm run",
        owner: "F0.REPO.03",
        phase: "F0",
        level: Some(Level::Pr),
    },
    Command {
        name: "vm up",
        owner: "F0.REPO.03",
        phase: "F0",
        level: Some(Level::Pr),
    },
];
