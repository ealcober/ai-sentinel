# Changelog

All notable changes to this repository. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). One line per closed task or applied review point, newest first within a section, each naming its commit and — where one exists — its task ID. This file is exempt from the `NN_` numbering that applies to the rest of `docs/` because its name is fixed by convention.

**Rule.** Every commit that closes a task adds a line here, in the same commit. `verify-docs` warns when a `<task-id>` in a commit subject has no changelog line.

## [Unreleased]

### State
- Planning complete and executable; no product code. Next: phase F0, starting with the four `[BLOCKING]` verifications of plan §F0.4.

### Added
- **`Q-11` resolved** (`ADR-07`): rule combining stays strictest-verdict-wins. Adds Annex B §B.10 (total order, combining, `decided_by` provenance), §B.11 (`except` narrows a rule, never overrides one), §B.12 (guardrails are compile-time assertions), §B.13 (tiers reserved for authority, never specificity); §B.9 gains a monotone verdict map per backend; `F1.PL.09`/`F1.PL.10`.
- **Licensing** (`ADR-06`): Apache-2.0 workspace-wide; GPL-2.0-only for `crates/aisme-ebpf` and dual GPL-2.0-only OR BSD-2-Clause for `crates/aisme-ebpf-common`, both required by the kernel's `gpl_only` helper rule; CC-BY-4.0 for `docs/`. Adds `LICENSE.md`, `LICENSE-APACHE`, `LICENSE-GPL`, `LICENSE-BSD`, `NOTICE`, `CITATION.cff`, `CONTRIBUTING.md` (DCO, no CLA) and `SECURITY.md`.
- `docs/03_challenge_accionabilidad.md` — executability review, 12 points, 35 findings, all applied. (`2ce1e47`…`bc667b6`)
- Plan Annex H — the `xtask` command surface: 68 commands, each with an owning task and a gate level; exit code 3 = not implemented yet. (`19b9a0d`)
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
- `layers.toml`; `budgets.toml` directions and profiles; `docs/adr/00_template.md`; `docs/design/02_aisme-run.md`. (`481141b`, `95a454f`, `ad5958c`, `b0a82ee`)
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
