# STATE — live project status

> **Update this file at the end of every working session.** It is the first thing the next session reads.
> Last updated: **2026-08-17** · Phase: **pre-F0 (applying the challenge patches)** · Code written: **none**

## Where we are

**Planning is complete, structurally reviewed, and challenged end to end.** The plan (`docs/01_phase5_implementation_plan.md`) is ~2,900 lines, Parts 0 through VIII plus Annexes A–F. **No product code has been written and the Cargo workspace has no members yet** — that is task `F0.REPO.01`.

Two reviews shaped it. `ADR-03` fixed three structural defects (a circular dependency between the kernel phase and the policy language, horizontal layering that deferred all integration risk to week 10, an under-specified interface layer) and renumbered the phases **once**; **task IDs freeze at F0 start**. Then `docs/02_challenge_ampliacion_sistema.md` challenged all 34 points of the system, producing 209 numbered findings, an R1 register of 18 unverified claims, an R2 register of 13 claims that fell, and ten owner decisions (Q-01…Q-10, all answered).

**We are now applying that report's patches, one commit per point.** See "Next up".

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
| **ADR-02: Windows driver deferred, WSL2 is the Windows strategy** — applied across plan, README, invariants | `docs/adr/02_*.md` |

## Next up

**Phase 0 — apply the challenge patches** (in progress). Each closed point in `docs/02_challenge_ampliacion_sistema.md` has a §3 that is an unapplied patch; they are applied in point order, one commit per point. Done so far: renames (Q-04/06/07), P-01 README, P-02 CLAUDE.md, P-03 workspace and `layers.toml`, P-04 `budgets.toml`, P-05 AGENTS.md, P-07 invariants, P-08 permission model, P-09/P-10 ADRs and research. Remaining: P-06 (this file), P-11…P-34 (the plan itself).

**Then phase F0.** Ordered; task IDs from Plan Part III.

0. `F0.REPO.00` — **done**: the owner initialised the repository before the patches (`b8b7a27`).
1. **`F0.WSL.01`** — probe the stock WSL2 kernel: `CONFIG_BPF_LSM`, **Landlock presence and ABI**, cgroup v2, systemd, and whether a TPM exists. **Do this first**: it decides whether WSL2 reaches L2 or L3, whether the L2 row reads as written (`R1-04`), and it confirms `R1-18` (no TPM ⇒ software-signed forensics for Windows users).
2. `F0.REPO.01` / `F0.REPO.05` — populate the Cargo workspace with each crate **in its §3.1 layer**, dependency direction correct from the first commit.
3. `F0.REPO.03` — `xtask` orchestrator: `build-ebpf`, `verify-budgets`, `verify-layering`, `vm up`.
4. `F0.GATE.04`…`F0.GATE.08` — budget gate, forbidden-dependency gate, **dependency-direction gate**, doc-drift gate, `verify-docs`. **All must exist before F1 code lands**, or the invariants become retrofits nobody enforces. All run locally (`I-27`); there is no hosted CI.
5. `F0.VM.01` / `F0.VM.02` / `F0.WSL.02` — VM images and the kernel matrix, including WSL2 with and without systemd.
6. `F0.SEC.01` — threat model doc recording the `H-05`/`H-06`/`H-12` anti-goals, the OWASP Agentic Top-10 mapping (Annex G §G.3) and the relationship to the agent's own sandbox (§G.4).
7. `F0.DOC.01` — write the ten seed memories (Plan §7.4). They record facts already paid for.
8. `F0.VER.01…18` — one task per R1 register entry, each with its verification command. **The R1 register must be empty at GATE F0.**

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

Still owed from the plan: **ADR-04** (Tauri v2 + `uniffi` fallback) and **ADR-05** (multiplatform detection scope / AI Sentinel sensor architecture).

## Notes for whoever picks this up

- **Read Plan §3.1–3.2 before writing any code.** The layering rules (`A-01`…`A-06`) and the trait catalogue are the architecture. `aisme-core` must never learn what OS it is on — that single rule is what makes one engine serve Linux, WSL2, Android, iOS and the SDK.
- **F2 is a walking skeleton, not a feature phase.** Its out-of-scope list is as binding as its task list. If it grows features it becomes F3 with extra steps and the whole risk-transfer benefit is lost.
- **Plan Part II is the most valuable artefact here.** It exists specifically to stop the research's rejected designs from being re-implemented by a well-meaning contributor. Read it before writing kernel code. The precedence rule is in Plan §7.6.
- **Windows is served by WSL2 now** (ADR-02). The native driver spec now lives in **Annex F** marked `[POST]` — do not implement it. Keep the `Sensor`/`Enforcer`/`Adjudicator` trait boundaries (§3.2); they are what makes that decision cheaply reversible.
- **The hardest unsolved problems**, both with documented fallbacks so neither can block the MVP: prompt delivery on headless/GUI Linux (`docs/design/01_permission-model.md` §7.3) and F4 tier-D offset resolution on stripped BoringSSL.
- **The benign corpus (§4.8.2) matters as much as the red team corpus.** A product that blocks `npm ci` is dead on arrival. Milestone M5 is the real go/no-go for exactly this reason.
- The permission model note is now `SPEC` (`docs/design/01_permission-model.md`) and carries the `warn` verdict and suppression rules. F1, F7 and F8 implement it.
- **Two primitives make tier L2 real and were missing from the plan**: Landlock (in-kernel file deny) and `BPF_CGROUP_INET*_CONNECT` (in-kernel network deny). Both work without a reboot and without BPF-LSM, which matters because WSL2 — the Windows strategy — is L2 by default. Confirm with `F0.WSL.01`/`F0.VM.02` (`R1-04`, `R1-16`).
- **Every gate runs locally** (`I-27`). Do not propose GitHub Actions.
