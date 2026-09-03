# STATE — live project status

> **Update this file at the end of every working session.** It is the first thing the next session reads.
> Last updated: **2026-08-17** · Phase: **F0 ready to start — plan complete and executable** · Code written: **none**

## Where we are

**Planning is complete and executable.** The plan (`docs/01_phase5_implementation_plan.md`) is ~3,700 lines, Parts 0 through VIII plus Annexes A–I, reviewed twice with every finding applied: `docs/02_…` for correctness, `docs/03_…` for executability. **No product code exists and the Cargo workspace has no members** — that is task `F0.REPO.01`.

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
| Detection catalogue: 15 detectors, 8 new red-flag classes, 16 benign twins | Plan Annex G, Annex C, §4.13 |
| `warn` verdict and suppression rules (`I-26`) across policy, engine and UI | Plan F1/F7/F8, `01_permission-model.md` |
| Tier L2 made real: Landlock + cgroup connect hooks, both without a reboot | Plan §2.2.1, F3.3 |
| `layers.toml`, `budgets.toml` with directions and profiles, `docs/adr/00_template.md`, `docs/design/02_aisme-run.md` | repo root, `docs/` |
| **Actionability review**: 12 points, 35 findings, all applied | `docs/03_challenge_accionabilidad.md` |
| **Annex H** — the `xtask` command surface: 68 commands, each with its owning task and gate level | Plan Annex H |
| **Annex I** — the control-plane protocol: 12 methods, three authorization classes, error model | Plan Annex I |
| `EventKind` taxonomy with reserved ranges; AISME-PL grammar, backend matrix and precedence | Plan §F1.1.1, Annex B §B.0/B.9/B.10 |
| Test-asset formats; the verification backlog (20 rows, 4 blocking); the reference trace | Plan §4.14, §F0.4, `F0.ASSET.02` |
| **ADR-04** (Tauri v2 + uniffi) and **ADR-05** (multiplatform detection scope) | `docs/adr/` |
| **Threat model**: ranked adversaries, trust boundaries, collected non-goals | `docs/security/01_threat-model.md` |
| Phase Entry/Exit contracts and the seven-item freeze list | Plan §3.7.1 |

## Next up

**One owner question is open**: `Q-11` — AISME-PL rule precedence, **strictest-verdict-wins** (implemented, order-independent, fails safe) versus most-specific-wins. The safe default is in place; answering it either confirms Annex B §B.10 or triggers one edit there.

**Phase F0.** Ordered; task IDs from Plan Part III.

1. **The four `[BLOCKING]` verifications of §F0.4, in week 1** — `F0.VER.04` (Landlock), `F0.VER.16` (cgroup connect hook), `F0.VER.18` (WSL2 TPM), `F0.VER.12` (hardware curves). They do not confirm claims, they decide what plan rows say, and three phases plus a High/High risk rest on them. `F0.WSL.01` is where three of the four are measured.
2. **`F0.WSL.01`** — probe the stock WSL2 kernel: `CONFIG_BPF_LSM`, **Landlock presence and ABI**, the cgroup connect hook, cgroup v2, systemd, and whether a TPM exists. Three of the four blocking verifications are measured here.
3. `F0.ASSET.01` / `F0.ASSET.02` — corpus manifests and the empty corpus tree; **record the reference trace** in observe-only mode, before any enforcement exists.
4. `F0.REPO.01` / `F0.REPO.05` — populate the Cargo workspace with each crate **in its §3.1 layer** (`layers.toml` is the source), dependency direction correct from the first commit.
5. `F0.REPO.03` — `xtask`: the argument surface of **all 68 Annex H commands**, each unimplemented one exiting 3 with its owning task; working `build-ebpf`, `dist`, `vm *`, `verify-*`, `gate --level`.
6. `F0.GATE.04`…`F0.GATE.08` — budget gate, forbidden-dependency gate, dependency-direction gate, doc-drift gate, `verify-docs`. **All exist before F1 code lands.** All run locally (`I-27`).
7. `F0.VM.01` / `F0.VM.02` / `F0.WSL.02` — VM images and the kernel matrix with the expected tier asserted per kernel, including WSL2 with and without systemd.
8. `F0.DOC.01` — write the **eleven** seed memories from Plan §7.4 (fact, why it matters, source — transcribe, do not reconstruct).
9. `F0.VER.01…20` — the remaining sixteen verification rows of §F0.4, any order. **Every row has a recorded outcome at GATE F0.**

Already in place, not F0 work: `F0.REPO.00` (repository), `F0.SEC.01` (`docs/security/01_threat-model.md`), `ADR-04` and `ADR-05`, `docs/adr/00_template.md`.

**Then F1, and treat it as the highest-leverage phase in the plan.** It ends with the interface freeze (§3.2), after which four tracks run in parallel against contracts that cannot move. An interface defect found in F1 costs hours; the same defect found in F6 invalidates three tracks. Do not compress it.

## Blocked

Nothing.

## Decisions taken, ADRs owed

All ten open questions were answered by the owner on 2026-08-17 (`docs/02_…` §Owner answers). The ones that need an ADR written to record them:

| Decision | ADR to write |
|---|---|
| `.aisme/scope.toml` is untrusted input and may only **narrow** a session's scope | with the F7 patch |
| Grants and suppression rules are **per-machine, never synced** | with the F7 patch |
| A grant is **not** a declassification; egress stays separately gated | with the F7 patch |
| Hardware attestation is **P-256** wherever a hardware key exists; Ed25519 only in software; `key_hw` recorded and shown | with the F5 patch |
| **Zero hosted-CI cost** — every gate local, nothing on push | recorded as `I-27`; ADR optional |
| `aisme run` is the documented default onboarding path | with the F8 patch; see `docs/design/02_aisme-run.md` when written |

**ADR-04** (Tauri v2 + `uniffi` fallback) and **ADR-05** (multiplatform detection scope) are now written. No ADR is owed.

## Notes for whoever picks this up

- **Read Plan §3.1–3.2 before writing any code.** The layering rules (`A-01`…`A-06`) and the trait catalogue are the architecture. `aisme-core` must never learn what OS it is on — that single rule is what makes one engine serve Linux, WSL2, Android, iOS and the SDK.
- **F2 is a walking skeleton, not a feature phase.** Its out-of-scope list is as binding as its task list. If it grows features it becomes F3 with extra steps and the whole risk-transfer benefit is lost.
- **Plan Part II is the most valuable artefact here.** It exists specifically to stop the research's rejected designs from being re-implemented by a well-meaning contributor. Read it before writing kernel code. The precedence rule is in Plan §7.6.
- **Windows is served by WSL2** (ADR-02). The native driver spec now lives in **Annex F** marked `[POST]` — do not implement it. Keep the `Sensor`/`Enforcer`/`Adjudicator` trait boundaries (§3.2); they are what makes that decision cheaply reversible.
- **The hardest unsolved problems**, both with documented fallbacks so neither can block the MVP: prompt delivery on headless/GUI Linux (`docs/design/01_permission-model.md` §7.3) and F4 tier-D offset resolution on stripped BoringSSL.
- **The benign corpus (§4.8.2) matters as much as the red team corpus.** A product that blocks `npm ci` is dead on arrival. Milestone M5 is the real go/no-go for exactly this reason.
- The permission model note is now `SPEC` (`docs/design/01_permission-model.md`) and carries the `warn` verdict and suppression rules. F1, F7 and F8 implement it.
- **Two primitives make tier L2 real and were missing from the plan**: Landlock (in-kernel file deny) and `BPF_CGROUP_INET*_CONNECT` (in-kernel network deny). Both work without a reboot and without BPF-LSM, which matters because WSL2 — the Windows strategy — is L2 by default. Confirm with `F0.WSL.01`/`F0.VM.02` (`R1-04`, `R1-16`).
- **Every gate runs locally** (`I-27`). Do not propose GitHub Actions, self-hosted runners or scheduled cloud jobs. `.github/` does not exist and `verify-docs` fails if a push-triggered workflow appears.
- **The report's R1 register is the F0 verification backlog.** Eighteen claims are asserted and unmeasured; four of them decide how a row reads (`R1-04` Landlock, `R1-16` cgroup hooks, `R1-18` no TPM under WSL2, `R1-12` hardware curves). The register must be empty at GATE F0.
