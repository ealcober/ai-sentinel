# Invariants

Constraints that may not be violated. Changing any of these requires an ADR, not a pull request comment. Most are enforced by CI gates.

## 1. Security invariants

**I-01 — Read-only observation.**
AISME never modifies the memory, control flow or cryptographic state of an observed process. It does not patch binaries, does not defeat certificate pinning, does not inject DLLs, and does not hot-patch instructions. *Test: `T4.5.06`.* (Finding `H-06`.)

**I-02 — No self-concealment.**
AISME does not hide its presence from the system or from monitored processes. It does not falsify `/proc`, does not rewrite another process's memory, and does not use `bpf_probe_write_user`. When a process probes for instrumentation, that is recorded as a signal, not defeated. (Finding `H-05`.)

**I-03 — AISME never degrades pre-existing security.**
No feature of AISME may make the host or a monitored application less secure than it was without AISME installed.

**I-04 — The Observer LLM cannot authorize.**
Its output may only raise severity or request human confirmation. A low risk score never unblocks anything deterministic policy blocked. Its input is treated as untrusted attacker-controlled data. *Test: `T4.10` / `RF-10`.* (Findings `H-11`, `H-12`.)

**I-05 — Three permission groups are never promptable.**
`SYSTEM_CONFIG`, `FILELESS_EXECUTE` and `SELF_PROTECTION` are denied by policy and cannot be granted through an in-flow prompt. A prompt is an attack surface.

**I-06 — Remote authorization is asymmetric.**
A remote `DENY` requires only a paired device. A remote `ALLOW` requires hardware-backed biometric confirmation and is forbidden entirely for `CRITICAL`-class operations.

**I-07 — The relay is blind.**
No AISME-operated relay or server ever holds plaintext telemetry, verdicts or notification content. *Test: `T4.10.03`.*

**I-08 — Prompts and chain-of-thought are the user's private data.**
Stored encrypted at rest, excluded from OTLP export by default (hashes and classifications only), subject to a configurable retention window.

## 2. Kernel-safety invariants

**I-09 — No eBPF program blocks waiting for user space.**
All LSM hooks return in bounded time, reading only maps. Synchronous user-space decisions use `seccomp_unotify`; slow adjudication uses the cgroup freezer. *Static gate: `T4.2.06`.* (Finding `H-01`.)

**I-10 — A failure of AISME degrades service; it never hangs the machine.**
Every wait is bounded. Every fallback path is explicit and configurable. Daemon death, driver unload and probe detachment all have defined, tested behaviour.

**I-11 — The Windows verdict thread performs no filesystem I/O.** *(INACTIVE — Windows driver deferred by ADR-02. Reactivate with phase F3.)*
Re-entrancy deadlock. *Test: `T4.3.05`.*

**I-12 — No kernel-touching test ever runs on a host OS.**
Snapshot-restored disposable VMs only, for every developer and every CI runner.

**I-13 — The Windows minifilter contains no business logic.** *(INACTIVE — deferred by ADR-02.)*
Filtering, lookup and message passing only. Target < 3,000 LoC. All intelligence lives in the Rust daemon. (Finding `H-14`.)

## 3. Resource invariants (CI-enforced)

**The numbers live in `budgets.toml`**, which `cargo xtask verify-budgets` reads, and in the plan's §2.22 table with their rationale and measurement protocol. They are deliberately **not** restated here — a third copy would drift, and CI gate `F0.CI.07` fails the build if the two authoritative copies disagree.

The invariant is the enforcement, not the number:

> Every budget in `budgets.toml` has a `hard` value. Exceeding it fails CI and blocks release. Changing a `hard` value requires an ADR.

**I-14 — Non-session processes pay effectively nothing.**
Overhead on processes outside an AI session ≤ 0.5%. This is the architecture's central performance claim. *Test: `T4.4.14`.*

## 4. Correctness and product invariants

**I-15 — A false positive is as serious as a missed detection.**
The benign corpus gate tolerates **zero** blocks and at most 2 escalations. A product that blocks `npm ci` is dead on arrival.

**I-16 — Honest coverage.**
The product displays its real capability tier on the device it is running on, and never implies protection it does not have. *Test: `T4.11.13`.*

**I-17 — Coverage gaps appear in the forensic record as gaps.**
If observation lapsed, the log says so. Silently continuing implies observation that did not happen.

**I-18 — Forensic logs are tamper-evident, not immutable.**
Documentation and UI use the correct term. Real non-repudiation requires external root anchoring. (Finding `H-17`.)

**I-19 — Every missing capability degrades one documented function.**
No absence produces undefined behaviour, and the system never fails to start because a capability is missing.

**I-20 — Enforcement is deterministic.**
T0 and T1 decisions are made by compiled policy. If the Observer LLM or the network is unavailable, protection is unchanged.

## 5. Engineering invariants

**I-21 — No JSON on the hot path.** `serde_json` is a forbidden dependency of `aisme-agentd`.
**I-22 — Zero heap allocation in the hot loop steady state.** *Test: `F1.RT.03`.*
**I-23 — Task IDs are stable and append-only.** Dead tasks become `DEPRECATED`.
**I-24 — All code and documentation in English.**
**I-25 — Findings `H-01`…`H-19` override the original research.** Contradicting one requires an ADR.
