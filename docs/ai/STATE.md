# STATE — live project status

> **Update this file at the end of every working session.** It is the first thing the next session reads.
> Last updated: **2026-08-17** · Phase: **pre-F0 (planning complete)** · Code written: **none**

## Where we are

**Planning is complete and has been through a full structural review.** `docs/PHASE5_IMPLEMENTATION_PLAN.md` is ~2,900 lines, Parts 0 through VIII plus Annexes A–F. The repository skeleton, README, CLAUDE.md and the LLM working docs exist. **No product code has been written and the Cargo workspace has no members yet** — that is task `F0.REPO.01`.

The review (`ADR-0003`) found and fixed three structural defects: a circular dependency between the kernel phase and the policy language, horizontal layering that deferred all integration risk to week 10, and an under-specified interface layer. Phases were renumbered **once** as a result; **task IDs freeze at F0 start**.

The next session starts phase **F0**.

## Done

| Item | Where |
|---|---|
| Four research documents analysed and challenged | `docs/research/` + `extracted/` (plain text, LLM-readable) |
| 19 architectural findings `H-01`…`H-19` with corrections | Plan Part II |
| Corrected topology, resource invariants, degradation model | Plan §2.21–2.23 |
| **Software architecture**: layering + dependency rules, trait catalogue, event lifecycle, concurrency, error model, versioning | Plan §3.1–3.6 |
| **Walking-skeleton delivery strategy** and phase order | Plan §3.7 + `ADR-0003` |
| Development phases F0–F11 with task IDs and gates | Plan Part III |
| Exhaustive test plan: Ring-0 injection, budget certification, crypto interception, correlation ground truth, IRR, red team + benign corpus, chaos, Sentinel | Plan Part IV |
| Deployment: builds, self-contained packaging, SBOM/supply chain, install/uninstall, mobile distribution, OTel conventions, runbooks | Plan Part V |
| Folder structure, LLM state/memory protocol, risk register, critical path, milestones | Plan Parts VI–VIII |
| Annexes: ontology, AISME-PL, red flag catalogue, capability matrix, glossary, Windows spec | Plan Annexes A–F |
| **ADR-0003: walking skeleton, interface freeze, layered architecture** | `docs/adr/0003-*.md` |
| Repository skeleton, README, CLAUDE.md, AGENTS.md, invariants.md | repo root + `docs/ai/` |
| Permission model design note (multiplatform prompt delivery) | `docs/design/permission-model.md` |
| **ADR-0002: Windows driver deferred, WSL2 is the Windows strategy** — applied across plan, README, invariants | `docs/adr/0002-*.md` |

## Next up — phase F0

Ordered. Task IDs from Plan Part III.

1. **`F0.WSL.01`** — probe whether the stock WSL2 kernel ships `CONFIG_BPF_LSM=y`. **Do this first**: it decides whether WSL2 reaches tier L2 or L3, which affects the F3 gate and the installer copy.
2. `F0.REPO.01` / `F0.REPO.05` — populate the Cargo workspace with each crate **in its §3.1 layer**, dependency direction correct from the first commit.
3. `F0.REPO.03` — `xtask` orchestrator: `build-ebpf`, `verify-budgets`, `verify-layering`, `vm up`.
4. `F0.CI.04` / `F0.CI.05` / `F0.CI.06` / `F0.CI.07` — budget gate, forbidden-dependency gate, **dependency-direction gate**, doc-drift gate. **All four must exist before F1 code lands**, or the invariants become retrofits nobody enforces.
5. `F0.VM.01` / `F0.VM.02` / `F0.WSL.02` — VM images and the kernel matrix, including WSL2 with and without systemd.
6. `F0.SEC.01` — threat model doc recording the `H-05`/`H-06`/`H-12` anti-goals.

**Then F1, and treat it as the highest-leverage phase in the plan.** It ends with the interface freeze (§3.2), after which four tracks run in parallel against contracts that cannot move. An interface defect found in F1 costs hours; the same defect found in F6 invalidates three tracks. Do not compress it.

**Also early, not blocking:** write the seed memories listed in Plan §7.4 — they capture facts already discovered that would otherwise be re-learned expensively.

## Blocked

Nothing.

## Open decisions needing an ADR

| # | Question | Leaning |
|---|---|---|
| 1 | Is a repo-provided `.aisme/scope.toml` trusted input? | Narrow-only, never widen — same monotonicity principle as `H-12` |
| 2 | Do `Always` permission grants sync across paired devices? | No — per-machine; syncing grants is a lateral-movement vector |
| 3 | Is `aisme run` the documented default onboarding path? | **Yes** — it now solves three problems at once: prompt delivery on headless Linux, prompt delivery in WSL2, and session identity |
| 4 | Tauri v2 mobile maturity | Proceed; `uniffi` fallback pre-specified (ADR-0019, to be written) |
| 5 | Does an `Always` grant on a secret file imply taint declassification? | No — reading is granted, egress stays separately gated |

ADRs still to write: **ADR-0019** (Tauri v2 + uniffi fallback) and **ADR-0020** (multiplatform detection scope / AI Sentinel sensor architecture). Both are referenced by the plan.

## Notes for whoever picks this up

- **Read Plan §3.1–3.2 before writing any code.** The layering rules (`A-01`…`A-06`) and the trait catalogue are the architecture. `aisme-core` must never learn what OS it is on — that single rule is what makes one engine serve Linux, WSL2, Android, iOS and the SDK.
- **F2 is a walking skeleton, not a feature phase.** Its out-of-scope list is as binding as its task list. If it grows features it becomes F3 with extra steps and the whole risk-transfer benefit is lost.
- **Plan Part II is the most valuable artefact here.** It exists specifically to stop the research's rejected designs from being re-implemented by a well-meaning contributor. Read it before writing kernel code. The precedence rule is in Plan §7.6.
- **Windows is served by WSL2 now** (ADR-0002). The native driver spec now lives in **Annex F** marked `[POST]` — do not implement it. Keep the `Sensor`/`Enforcer`/`Adjudicator` trait boundaries (§3.2); they are what makes that decision cheaply reversible.
- **The hardest unsolved problems**, both with documented fallbacks so neither can block the MVP: prompt delivery on headless/GUI Linux (`docs/design/permission-model.md` §7.3) and F4 tier-D offset resolution on stripped BoringSSL.
- **The benign corpus (§4.8.2) matters as much as the red team corpus.** A product that blocks `npm ci` is dead on arrival. Milestone M5 is the real go/no-go for exactly this reason.
- The permission model note is still `DRAFT`. It needs to become the F7/F8 specification, and its open questions resolved, before F7 starts.
