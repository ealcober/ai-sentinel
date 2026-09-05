# Changelog

All notable changes to this repository. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). One line per closed task or applied review point, newest first within a section, each naming its commit and — where one exists — its task ID. This file is exempt from the `NN_` numbering that applies to the rest of `docs/` because its name is fixed by convention.

**Rule.** Every commit that closes a task adds a line here, in the same commit. `verify-docs` warns when a `<task-id>` in a commit subject has no changelog line.

## [Unreleased]

### State
- **Phase F0 in progress.** No product code yet. Next: `F0.REPO.01`/`F0.REPO.05` (the Cargo workspace), then `F0.REPO.02`, `F0.REPO.03` and `F0.REPO.06`.

### Added
- **`F0.WSL.01`** — WSL2 capability probe on kernel `6.18.33.1`. Landlock **ABI 7 and enforcing** (a write outside the allowed path returns `EACCES` under a real ruleset), `CONFIG_BPF_LSM=y` compiled with `bpf` absent from the active LSM list, cgroup v2 only, BTF present, systemd PID 1, **no TPM**, `/dev/kvm` present but the user is not in group `kvm`. Answers in `docs/ai/memory/wsl2-capabilities.md`; outcomes in `docs/reports/01_f0-verification.md`.
- `docs/reports/01_f0-verification.md` — the §F0.4 outcome register, one row per `F0.VER.nn` with an `Outcome` column. **`F0.VER.04` and `F0.VER.18` hold, `F0.VER.21` fails** (remedy `usermod -aG kvm`, owned by `F0.REPO.06`), `F0.VER.16` and `F0.VER.19` are blocked on the toolchain alone.

### Changed
- Plan §2.16.1 records the measured WSL2 answers the plan asked F0 to obtain, and gains a Landlock row. Platform matrix, `DEP.INS.03` and Annex D state that WSL2 is **L2 by default and reaches L3 through `.wslconfig`**, with no custom kernel.
- **Risk `R-08` closed** (WSL2 lacking `CONFIG_BPF_LSM`); `R-15` no longer applies to WSL2. `ADR-02`'s `F0.WSL.01` follow-up closed.
- `STATE.md` "Next up" ordering corrected: `cargo xtask doctor` is `F0.REPO.06`'s deliverable and needs `F0.REPO.03` and the workspace, so it cannot precede them. The plan is unchanged on this — its Done-when gates `F0.VM.01`, not the phase.

## [0.2.0] — 2026-09-03 — sealed for implementation

### Seal (`docs/04_final_coherence_seal.md`)
- Three read-only audits (F0–F2 executability; cross-document contradictions; Parts IV–VIII and annexes) plus a manual pass and a probe of the owner's WSL2 host: 134 numbered findings, all applied except the four recorded in the seal §4.
- **Day-one blockers removed**: GATE F0 `test -f` with four operands (a shell error), `grep "read-only"` case mismatch, GATE F1's inverted `serde_json` check, the F2 skeleton hooking `openat2` where glibc issues `openat` (also `F3.OB.03`), `F0.ASSET.02` needing `aisme run` before F2 exists.
- **Host prerequisites** (`F0.REPO.06`, `cargo xtask doctor`, GATE F0) and `F0.VER.21` (KVM inside WSL2). Measured on the owner's host: `/dev/kvm` present, VT-x on all CPUs, user not in group `kvm`; no `qemu`, `virtme-ng`, `clang`, `bpf-linker` or nightly.
- **`F0.VER.nn` numbering**: `F0.VER.nn` is `R1-nn` of `docs/02`; `F0.VER.15` is `DEPRECATED`; outcomes in `docs/reports/01_f0-verification.md` with an `Outcome` column that `verify-backlog` reads.
- **Annex H**: 71 commands; owners corrected so no gate runs a command that exits 3 in that gate (`verify-budgets` → `F0.GATE.04`, `bench-hotloop` → `F1.RT.03`, `test-taint` → `F1.ON.05`, `test-detect` → `F1.DT.01`, and six more); `bench-soak` (`F7.CB.07`) and `test-fuzz` added; levels cumulative; `win *` and `test-battery` re-levelled.
- **Gates**: GATE F8a (protocol freeze) separated from F8b; `T4.5.06` (`test-tls --integrity`) in GATE F4; `build-ebpf` in GATE F1; `cargo test --workspace`; L2- budget line in GATE F3; tiers on the F5 budget lines; `AISME_TERMINAL_ANSWER` for unattended GATE F2.
- **Annex G/C**: `F5.DT.09`…`F5.DT.13` implement `DT-03`, `DT-04(a,c)`, `DT-06`, `DT-07`, `DT-10`; `BN-17`/`BN-18` twins for `RF-17`/`RF-22`; `annex-c` corpus view; fixture names aligned with §4.5.1.
- **Annex B**: `assert` and `degrade_open` in the grammar; requirement IDs `PL-01`…`PL-08`; `tier` removed from the sketch; `scope_rel`.
- **Annex I**: four authorization classes (remote peer added); `hw_pubkey?`; error rows for an unsigned remote `allow` and unknown ids; `F8.API.01` names all twelve methods.
- **Budgets**: five §2.22 rows for machine-only keys; `compressor_precision`; boundary semantics (`>`/`<` hard, equality passes); gates cite `hard` with `target` in parentheses.
- **Contradictions closed**: H-19 row vs `ADR-05`; four service tiers; twenty-two trait implementations; five tracks; F9 starts at GATE F1; milestone weeks 7.5/6.5/10.5/9.5; `Outcome` vs `Verdict`; T2 timeouts per channel; P-256 in both diagrams; Windows phase naming; `FILES_OUTSIDE_WORKSPACE` writes at L2 (Landlock deny, grant binds later processes); read/write orders and the commit rule aligned across `CLAUDE.md`/`AGENTS.md`; every "CI" wording made local (`I-27`); §7 numbering; history clauses removed (Rule 5).
- `ADR-06`/`ADR-07` dated from git (2026-09-03); `ADR-01`…`ADR-04` follow-ups updated.


### Added
- **`Q-11` resolved** (`ADR-07`): rule combining stays strictest-verdict-wins. Adds Annex B §B.10 (total order, combining, `decided_by` provenance), §B.11 (`except` narrows a rule, never overrides one), §B.12 (guardrails are compile-time assertions), §B.13 (tiers reserved for authority, never specificity); §B.9 gains a monotone verdict map per backend; `F1.PL.09`/`F1.PL.10`.
- **Licensing** (`ADR-06`): Apache-2.0 workspace-wide; GPL-2.0-only for `crates/aisme-ebpf` and dual GPL-2.0-only OR BSD-2-Clause for `crates/aisme-ebpf-common`, both required by the kernel's `gpl_only` helper rule; CC-BY-4.0 for `docs/`. Adds `LICENSE.md`, `LICENSE-APACHE`, `LICENSE-GPL`, `LICENSE-BSD`, `NOTICE`, `CITATION.cff`, `CONTRIBUTING.md` (DCO, no CLA) and `SECURITY.md`.
- `docs/03_challenge_accionabilidad.md` — executability review, 12 points, 35 findings, all applied. (`2ce1e47`…`bc667b6`)
- Plan Annex H — the `xtask` command surface: 71 commands, each with an owning task and a gate level; exit code 3 = not implemented yet. (`19b9a0d`)
- Plan Annex I — control-plane protocol: 12 methods, three authorization classes, error model, backpressure rule. (`9627400`)
- Plan §F1.1.1 — `EventKind` taxonomy in ten reserved ranges; payload variants tied to ranges. (`19b9a0d`)
- Plan Annex B §B.0/B.9/B.10 — AISME-PL grammar, backend capability matrix, strictest-verdict precedence. (`9627400`)
- Plan §4.14 — corpus manifests and fixture contracts; the flow corpus is synthetic-first. (`eee1a85`)
- Plan §F0.4 — the verification backlog, 20 rows, 4 `[BLOCKING]`, each with both predicted outcomes. (`eee1a85`)
- Plan §3.7.1 — phase Entry/Exit contracts and the seven-item freeze list; the mock rule. (`1354b79`)
- `F0.ASSET.02`, `F1.SIM.01/02` — the recorded reference trace and its replayer. (`eee1a85`)
- `docs/adr/04_tauri-v2-mobile-with-uniffi-fallback.md`, `docs/adr/05_multiplatform-detection-scope.md`. (`1eb85c1`)
- `docs/security/01_threat-model.md` — assets, ranked adversaries, trust boundaries, non-goals. (`773e822`)
- `docs/02_challenge_ampliacion_sistema.md` — correctness review, 34 points, 209 findings, all applied. (`db94c07`…`946ef15`)
- Plan Annex G — detection catalogue: 15 detectors, red-flag classes RF-17…24, benign twins. (`61b8c2a`)
- Plan §2.2.1 — tier L2 through Landlock and cgroup connect hooks; `F3.3` L2 enforcement tasks. (`859ac02`, `658a714`)
- `warn` verdict and suppression rules; invariant `I-26`. (`546d4e4`, `dc4f389`, `c0c7a96`)
- Invariant `I-27` — zero hosted-CI cost; `.github/` removed. (`ebd1255`, `dc4f389`)
- `layers.toml`; `Cargo.lock` policy (tracked from `F0.REPO.01`); `budgets.toml` directions and profiles; `docs/adr/00_template.md`; `docs/design/02_aisme-run.md`. (`481141b`, `95a454f`, `ad5958c`, `b0a82ee`)
- `docs/CHANGELOG.md` (this file); execution directives in `CLAUDE.md`.

### Changed
- Documents renamed to `NN_slug.md` per Rule 4; ADR identifiers `ADR-01`…`ADR-05`. (`ebd1255`)
- Part V task IDs use the `DEP.*` namespace; F0 gates are `F0.GATE.*`. (`298dc6e`, `859ac02`)
- Hardware signing is P-256; the Noise static is a software X25519 key and the hardware key signs every remote `ALLOW`. (`2a8c0fd`)
- Critical path is 11.5 weeks with F8 split into F8a (parallel) and F8b (after F7). (`eb5be4c`)
- The plan speaks in the present: narrated history moved to git and to the two reviews.

### Decided (owner, 2026-08-17)
- Q-01 300 Mbps · Q-02 `scope.toml` narrow-only · Q-03 grants and suppressions per-machine · Q-04 ADRs as `NN_slug.md` · Q-05 repository initialised · Q-06 plan and reports renamed · Q-07 `docs/ai/` exempt from numbering · Q-08 P-256 in hardware · Q-09 zero hosted-CI cost · Q-10 `DEP.*` for Part V.

### Open
- Trademark registration for *AISME* and *AI Sentinel* (`ADR-06` follow-up).
- The commercial-edition question, which the DCO makes irreversible after the first external contribution is merged (`ADR-06`).

## [0.1.0] — 2026-08-17

### Added
- First commit: research documents, extracted text, the plan through Part IV, repository skeleton, `README.md`, `CLAUDE.md`, `docs/ai/`, `ADR-01`…`ADR-03`, `docs/design/01_permission-model.md`. (`b8b7a27`)
