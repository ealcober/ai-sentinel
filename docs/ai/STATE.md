# STATE — live project status

> **Update this file at the end of every working session.** It is the first thing the next session reads.
> Last updated: **2026-09-05** · Last nightly: — · Last weekly: — · Phase: **F0 in progress** · Code written: **the workspace skeleton — 19 members, stubs only, no behaviour**

## Where we are

**Planning is complete and executable.** The plan (`docs/01_phase5_implementation_plan.md`) is ~3,850 lines, Parts 0 through VIII plus Annexes A–I, reviewed three times with every finding applied: `docs/02_…` for correctness, `docs/03_…` for executability, `docs/04_…` the final coherence seal. **No product code exists and the Cargo workspace has no members** — that is task `F0.REPO.01`.

**Task IDs are frozen** (`I-23`, `ADR-03`). Every gate command exists from F0 (Annex H; an unimplemented one exits 3 naming the phase that owes it), every type has values (§F1.1.1), the policy language has a grammar (Annex B §B.0), the protocol has shapes (Annex I), every corpus has a manifest (§4.14), every named deliverable has a task, and every phase states what it assumes and what it hands on (§3.7.1). The execution directives are in `CLAUDE.md` §"How to execute the plan"; every closed task adds a line to `docs/CHANGELOG.md`. **F0 can start.**

## Done

| Item | Where |
|---|---|
| Four research documents analysed and challenged | `docs/research/` + `extracted/` (plain text, LLM-readable) |
| 19 architectural findings `H-01`…`H-19` with corrections | Plan Part II |
| Corrected topology, resource invariants, degradation model | Plan §2.21–2.23 |
| **Software architecture**: layering + dependency rules, trait catalogue, event lifecycle, concurrency, error model, versioning | Plan §3.1–3.6 |
| **Walking-skeleton delivery strategy** and phase order | Plan §3.7 + `ADR-03` |
| Development phases F0–F11 with task IDs and gates | Plan Part III |
| Exhaustive test plan: Ring-0 injection, budget certification, crypto interception, correlation ground truth, IRR, red team + benign corpus, chaos, Sentinel | Plan Part IV |
| Deployment: builds, self-contained packaging, SBOM/supply chain, install/uninstall, mobile distribution, OTel conventions, runbooks | Plan Part V |
| Folder structure, LLM state/memory protocol, risk register, critical path, milestones | Plan Parts VI–VIII |
| Annexes: ontology, AISME-PL, red flag catalogue, capability matrix, glossary, Windows spec | Plan Annexes A–F |
| **ADR-03: walking skeleton, interface freeze, layered architecture** | `docs/adr/03_*.md` |
| Repository skeleton, README, CLAUDE.md, AGENTS.md, invariants.md | repo root + `docs/ai/` |
| Permission model design note (multiplatform prompt delivery) | `docs/design/01_permission-model.md` |
| **ADR-02: Windows driver deferred, WSL2 is the Windows strategy** | `docs/adr/02_*.md` |
| **Challenge review of the whole system**: 34 points, 209 findings, R1/R2 registers, ten owner decisions | `docs/02_challenge_ampliacion_sistema.md` |
| **All 34 patches applied**, one commit per point, coherence pass clean | git history |
| Detection catalogue: 15 detectors, 8 new red-flag classes, an 18-entry benign corpus with 8 twins | Plan Annex G, Annex C, §4.13 |
| `warn` verdict and suppression rules (`I-26`) across policy, engine and UI | Plan F1/F7/F8, `01_permission-model.md` |
| Tier L2 made real: Landlock + cgroup connect hooks, both without a reboot | Plan §2.2.1, F3.3 |
| `layers.toml`, `budgets.toml` with directions and profiles, `docs/adr/00_template.md`, `docs/design/02_aisme-run.md` | repo root, `docs/` |
| **Actionability review**: 12 points, 35 findings, all applied | `docs/03_challenge_accionabilidad.md` |
| **Annex H** — the `xtask` command surface: 71 commands, each with its owning task and gate level | Plan Annex H |
| **Annex I** — the control-plane protocol: 12 methods, three authorization classes, error model | Plan Annex I |
| `EventKind` taxonomy with reserved ranges; AISME-PL grammar, backend matrix and precedence | Plan §F1.1.1, Annex B §B.0/B.9/B.10 |
| Test-asset formats; the verification backlog (21 rows: 20 live, `F0.VER.15` deprecated, 4 blocking); the reference-trace manifest | Plan §4.14, §F0.4, `F0.ASSET.02` |
| **ADR-04** (Tauri v2 + uniffi) and **ADR-05** (multiplatform detection scope) | `docs/adr/` |
| **Threat model**: ranked adversaries, trust boundaries, collected non-goals | `docs/security/01_threat-model.md` |
| Phase Entry/Exit contracts and the eight-item freeze list | Plan §3.7.1 |
| **Final coherence seal**: three audits plus a host probe, 134 findings, gate lines executed, host prerequisites (`F0.REPO.06`) | `docs/04_final_coherence_seal.md` |
| **`F0.GATE.03`** validated — `cargo deny check` passes all four sections. Its first run failed `bans` and exposed a real licensing defect: `crates/aisme-ebpf-common/Cargo.toml` declared the workspace Apache-2.0 while its SPDX header and `LICENSE.md` say `GPL-2.0-only OR BSD-2-Clause`. Fixed, and `verify-docs` gained the manifest-licence check that catches it | `deny.toml`, `xtask/src/docgate.rs` |
| **`F0.GATE.08`** mostly — ten cross-document checks inside `verify-docs`: SPDX headers against the `LICENSE.md` map (28 files now carry one), read order, the DoD ADR line, §7.3 headings, ADR contiguity, `NN_` naming, phase sums, tracked files, § references, `[CUT]` echoes. **Three still owed**: `--tree` regeneration, §B.9 monotone maps, prose budget claims | `xtask/src/docgate.rs` |
| **`F0.GATE.04`** / **`F0.GATE.07`** — `verify-budgets` measures what has an artefact (`process.agentd.binary.size_mb` = 0.29 MB against a 12 MB ceiling) and **fails on a breach**; the drift check runs on every invocation, comparing §2.22, `budgets.toml` and the two root documents in a canonical unit | `xtask/src/budgets.rs` |
| **`F0.GATE.01`** partial / **`F0.GATE.02`** / **`F0.GATE.03`** — `gate --level` runs the §4.12 toolchain steps too: `fmt --all --check` and `clippy -- -D warnings` (both PASS), and `cargo deny check`, which **SKIPs because cargo-deny is not installed**. `.githooks/pre-commit` exists and is **not enabled**: it would block every commit while `doctor` legitimately fails. `deny.toml` is validated | `deny.toml`, `.githooks/pre-commit`, `xtask/src/gate.rs` |
| **`F0.GATE.05`** / **`F0.GATE.06`** — the forbidden-dependency and dependency-direction gates, both inside `verify-layering`. `A-01`, `A-02`, `A-03`, `A-05` and the `serde_json`/`frida-*`/`bpf_probe_write_user` bans are mechanical; `A-04` needs the F1 public API and `A-06` is a review policy (`DEP.SUP.06`) | `xtask/src/rules.rs` |
| **`F0.ASSET.01`** / **`F0.ASSET.02`** — the §4.14 manifest format on five asset directories, and the hash check inside `verify-docs`, which names the version it certified. The reference-trace manifest carries its schema; the recording is `F2.WS.08`'s | `tests/corpus/*/manifest.toml`, `tests/fixtures/reference-trace/manifest.toml` |
| **`F0.REPO.06`** — `cargo xtask doctor`: 11 host prerequisites, each with its remedy and what it unblocks. Reports, never installs. **Exits 1 today — 4 of 11 present** on the owner's host, so its Done-when ("exits 0 on the owner's WSL2 host") is not met until the lines below are run | `xtask/src/doctor.rs` |
| **`F0.REPO.03`** — `xtask`: all **71** Annex H commands parse, unimplemented ones exit 3 naming their task and phase. Working: `verify-layering`, `verify-budgets`, `verify-docs`, `verify-backlog`, `gate --level`, `dist`. `build-ebpf` and `vm *` are implemented and exit **2** with the remedy until their tooling exists | `xtask/src/` |
| **`F0.REPO.02`**, root half — root toolchain **moved to `1.97.1`** and MSRV to `1.87`, because `F0.VER.01` **fails**: `aya 0.14.0` and `aya-ebpf 0.2.1` declare `rust-version 1.87.0` and `bpf-linker 0.11.0` is `edition 2024`. Workspace still passes `check`, `clippy -D warnings` and `fmt --check` under it. The eBPF nightly pin is **blocked**, see below | `rust-toolchain.toml`, `Cargo.toml` |
| **`F0.REPO.01`** / **`F0.REPO.05`** — Cargo workspace: 19 members, each in its `layers.toml` layer, `aisme-ebpf` and `aisme-windows` excluded. `cargo check --workspace` and `cargo clippy -- -D warnings` both pass clean; the only inter-crate edge is `aisme-core → aisme-ebpf-common` (L1→L0) | `Cargo.toml`, `.cargo/config.toml`, 20 manifests |
| **`F0.WSL.01`** — WSL2 capability probe. Landlock **ABI 7 and enforcing**; `CONFIG_BPF_LSM=y` compiled but `bpf` absent from the active LSM list; cgroup v2 only; BTF present; systemd PID 1; **no TPM**; `/dev/kvm` present, user not in group `kvm` | `docs/ai/memory/wsl2-capabilities.md`, `docs/reports/01_f0-verification.md` |

## Next up

**Phase F0.** Ordered; task IDs from Plan Part III.

**`F0.WSL.01`, `F0.REPO.01`, `F0.REPO.05`, `F0.REPO.03`, `F0.REPO.06`, `F0.ASSET.01` and `F0.ASSET.02` are done.** `F0.REPO.02`'s eBPF half is blocked, see below. What remains, in order:

1. `F0.GATE.04`…`F0.GATE.08` — budget gate, forbidden-dependency gate, dependency-direction gate, doc-drift gate, `verify-docs`. **All exist before F1 code lands.** All run locally (`I-27`).
2. `F0.VM.01` / `F0.VM.02` / `F0.WSL.02` — VM images and the kernel matrix with the expected tier asserted per kernel, including WSL2 with and without systemd.
3. `F0.DOC.01` — write the **eleven** seed memories from Plan §7.4 (fact, why it matters, source — transcribe, do not reconstruct).
4. `F0.VER.*` — the remaining rows of §F0.4, any order, appended to `docs/reports/01_f0-verification.md`. **`F0.VER.04` and `F0.VER.18` hold; `F0.VER.21` fails with a known remedy; `F0.VER.15` is `DEPRECATED`.** `F0.VER.16` and `F0.VER.19` are blocked only on the toolchain. **Every live row has a recorded outcome at GATE F0.**

Already in place, not F0 work: `F0.REPO.00` (repository), `F0.SEC.01` (`docs/security/01_threat-model.md`), `ADR-04` and `ADR-05`, `docs/adr/00_template.md`.

**Then F1, and treat it as the highest-leverage phase in the plan.** It ends with the interface freeze (§3.2), after which five tracks run in parallel against contracts that cannot move. An interface defect found in F1 costs hours; the same defect found in F6 invalidates three tracks. Do not compress it.

## Blocked

**`F0.GATE.01`'s hook is deliberately not enabled.** `.githooks/pre-commit` runs `gate --level commit`, which fails today because `doctor` and `verify-backlog` fail for good reasons. Enabling it now (`git config core.hooksPath .githooks`) would block every commit on host provisioning. Enable it once `doctor` reaches 0.

**`F0.REPO.02`, the eBPF half only.** The root `rust-toolchain.toml` is pinned at `1.97.1` and verified: `rustfmt`, `clippy`, `rust-src` and the `x86_64-unknown-linux-gnu` target present, `cargo check --workspace`, `cargo clippy -- -D warnings` and `cargo fmt --all --check` all clean.

`crates/aisme-ebpf/rust-toolchain.toml` still carries `channel = "nightly"` and `TODO(F0.REPO.02)`: the exact nightly, and **the Aya version it was validated against**. Validating means building the crate for `bpfel-unknown-none` through `-Z build-std=core`, which needs a nightly toolchain (none installed) and `bpf-linker` (absent). Writing a version nobody built against would be a claim entering the repository unverified, which general rule 1 and `CLAUDE.md` execution directive 7 both forbid.

**What unblocks it.** `cargo xtask doctor` prints this list, with what each item unblocks, and exits 1 while any is missing — that is the authoritative copy; the lines below are the same ones. The nightly is installed; `bpf-linker` needs a system LLVM, and its own build script says `cargo install` is not the recommended route without one. On Ubuntu 26.04 the matching version is LLVM 21, which is what `llvm-dev` resolves to:

```bash
sudo apt install -y llvm-21-dev libpolly-21-dev libzstd-dev clang bpftool \
                    qemu-system-x86 virtme-ng tpm2-tools strace
cargo +nightly install bpf-linker --no-default-features --features llvm-21
```

`bpf-linker 0.11.0` defaults to the `llvm-23` feature, which Ubuntu 26.04 does not carry, hence `--no-default-features --features llvm-21`. The `+nightly` is needed because the crate is `edition 2024`. That one `apt` line also covers the rest of `F0.REPO.06`: `bpftool` and `clang` for BTF, `qemu-system-x86` and `virtme-ng` for `F0.VM.*`, `tpm2-tools` for `F0.VER.12`, `strace` for the capture tests.

The same install unblocks `F0.VER.16` (the cgroup `connect` attach test) and `F0.VER.19` (the `EventKind` range check under the verifier), whose kernel prerequisites are all present and which lack only a loader. Group membership for KVM (`F0.VER.21`) is `sudo usermod -aG kvm $USER` followed by a new login.

**Not blocked by this:** everything except `build-ebpf` and `vm *`, both of which already exist and exit 2 with the exact remedy.

## Open, not blocking

- **Trademark** registration for *AISME* and *AI Sentinel*. The licence deliberately does not cover the names (`ADR-06`).
- **The commercial-edition question.** The DCO means the project cannot be relicensed without every contributor's agreement. The owner is the sole copyright holder **until the first external contribution is merged**; the decision must be taken before that, not after (`ADR-06`).

## Open decisions needing an ADR

None open. Three ADRs are owed **at implementation time, not before F0**, each with the task that implements the decision: scope narrow-only (`F7.PS.07`), per-machine grants (`F7.PS.02`), P-256 attestation (`F5.FO.02`). `Q-12` (the non-`serde_json` JSON-RPC codec for `F1.IPC.01`) is a task-level choice under `I-21`, taken at that task and recorded in its commit.

## Decisions taken, and where each is recorded

All ten owner questions are answered (`docs/02_…` §Owner answers). Each decision lives in the plan, not only in the report:

| Decision | Recorded in |
|---|---|
| `.aisme/scope.toml` is untrusted input and may only **narrow** a session's scope | `F7.PS.07` |
| Grants and suppression rules are **per-machine, never synced** | `F7.PS.02` |
| A grant is **not** a declassification; egress stays separately gated | Plan §2.14, taint model |
| Hardware attestation is **P-256** wherever a hardware key exists; Ed25519 only in software; `key_hw` recorded and shown | Plan §2.18, `F5.FO.02`, `F8.UI.07` |
| **Zero hosted-CI cost** — every gate local, nothing on push | `I-27` |
| `aisme run` is the documented default onboarding path | `docs/design/02_aisme-run.md`, F8 |

**ADR-04** (Tauri v2 + `uniffi` fallback), **ADR-05** (multiplatform detection scope), **ADR-06** (open-source licensing) and **ADR-07** (rule combining, closing `Q-11`) are written. **No ADR is owed and no question is open.**

## Notes for whoever picks this up

- **Read Plan §3.1–3.2 before writing any code.** The layering rules (`A-01`…`A-06`) and the trait catalogue are the architecture. `aisme-core` must never learn what OS it is on — that single rule is what makes one engine serve Linux, WSL2, Android, iOS and the SDK.
- **F2 is a walking skeleton, not a feature phase.** Its out-of-scope list is as binding as its task list. If it grows features it becomes F3 with extra steps and the whole risk-transfer benefit is lost.
- **Plan Part II is the most valuable artefact here.** It exists specifically to stop the research's rejected designs from being re-implemented by a well-meaning contributor. Read it before writing kernel code. The precedence rule is in Plan §7.6.
- **Windows is served by WSL2** (ADR-02). The native driver spec lives in **Annex F** marked `[POST]` — do not implement it. Keep the `Sensor`/`Enforcer`/`Adjudicator` trait boundaries (§3.2); they are what makes that decision cheaply reversible.
- **The hardest unsolved problems**, both with documented fallbacks so neither can block the MVP: prompt delivery on headless/GUI Linux (`docs/design/01_permission-model.md` §7.3) and F4 tier-D offset resolution on stripped BoringSSL.
- **The benign corpus (§4.8.2) matters as much as the red team corpus.** A product that blocks `npm ci` is dead on arrival. Milestone M5 is the real go/no-go for exactly this reason.
- The permission model note is `SPEC` (`docs/design/01_permission-model.md`) and carries the `warn` verdict and suppression rules. F1, F7 and F8 implement it.
- **Two primitives make tier L2 real**: Landlock (in-kernel file deny) and `BPF_CGROUP_INET*_CONNECT` (in-kernel network deny). Both work without a reboot and without BPF-LSM, which matters because WSL2 — the Windows strategy — is L2 by default. **Landlock is confirmed on WSL2** (`F0.WSL.01`: ABI 7, `EACCES` outside the allowed path under a real ruleset); the matrix kernels are `F0.VM.02`, and the cgroup hook still needs a loader (`F0.VER.16`).
- **Every gate runs locally** (`I-27`). Do not propose GitHub Actions, self-hosted runners or scheduled cloud jobs. `.github/` does not exist and `verify-docs` fails if a push-triggered workflow appears.
- **The report's R1 register is the F0 verification backlog**, and its outcomes live in `docs/reports/01_f0-verification.md`. Sixteen live rows are still unmeasured (`R1-01`…`R1-18` less the withdrawn `R1-15`, plus `F0.VER.19`…`21`); four of them decide how a row reads (`R1-04` Landlock, `R1-16` cgroup hooks, `R1-18` no TPM under WSL2, `R1-12` hardware curves). The register must be empty at GATE F0.
