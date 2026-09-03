# ADR-0003 — Walking skeleton delivery, interface freeze, and layered architecture

**Status**: **Accepted** 2026-08-17
**Supersedes in part**: the original Part III phase ordering

## Context

A full review of the plan before F0 started found three structural defects. None were visible while writing the phases in isolation; all three would have cost weeks once implementation began.

**1. A circular dependency.** The Linux phase (then F2) included `F2.PT.01` — "path trie in BPF" — and the LSM enforcement hooks. But AISME-PL, the language that compiles *into* that trie, was defined in F7, five phases later. The kernel phase would have been built against an invented placeholder policy format and then rewritten when the real compiler arrived. The same applied to the causal-graph ontology, defined in F5 but needed by F3, F4, F9 and F10.

**2. Horizontal layering.** The order built each layer fully across the whole system before proving any path end to end: all of core, then all Linux probes, then all TLS capture, then correlation, then compression, then enforcement, then UI. Nothing worked end to end until roughly week 10. Every integration assumption — ring buffer semantics, the sync-enforcement/async-adjudication split, the hot/cold process boundary, the trait composition — sat unvalidated behind six weeks of accumulated work.

**3. Under-specified interfaces.** The plan named four traits in a single code block in F1 and then described five sensing mechanisms and five prompt-delivery mechanisms as if they were separate subsystems. For a system that must serve Linux, WSL2, Android, iOS and an embeddable SDK from one engine, the trait layer *is* the architecture, and it was the least specified part of the document.

## Decision

### 1. Move the policy model and ontology into the core phase

`AISME-PL` and its compiler move from F7 to **`F1.PL.01`–`F1.PL.05`**. The causal-graph ontology and taint algebra move from F5 to **`F1.ON.01`–`F1.ON.04`**. F7 retains the policy *surface* — default rule sets, grants, red-flag detectors, learning mode — which genuinely depends on everything below it.

### 2. Insert a walking skeleton as F2

One vertical slice through every layer, working, in week 4.5: one tracepoint → ringbuf → hot loop → correlation against one synthetic ToolCall → one real compiled policy rule → `seccomp_unotify` → terminal prompt → verdict → WAL → `forensicd` → CLI output.

Deliberately narrow: one probe, one rule, one adjudicator. No UI, no LLM, no compression, no Merkle. **Its entire value is risk removal**, and its exit criterion is a demo rather than a checklist: an engineer types `aisme run -- bash`, the terminal asks whether to allow reading a protected file, and the syscall obeys the answer.

### 3. Formalize the architecture as five layers with a trait catalogue

Plan §3.1–3.6 add what was missing: layering with enforced dependency direction (rules `A-01`…`A-06`), the full trait catalogue, the end-to-end event lifecycle, the concurrency and ownership model, the error and degradation model, and the versioning contracts between the five independently deployable artifacts.

The central insight recorded there: the system does not have five sensing subsystems and five prompt mechanisms. It has **`Sensor`, `Enforcer` and `Adjudicator`, with fifteen implementations between them.**

### 4. Make the interface freeze a milestone

The L1 traits freeze at GATE F1 (week 3.5). After that they change only by ADR.

### 5. Renumbering, applied once

Old F2 → **F3**. New **F2** = walking skeleton. Old F11 (SDK) → **F9**, matching its dependency position. Old F9 (mobile control plane) → **F11**. Old F3 (Windows, deferred by ADR-0002) → **Annex F**, task IDs retagged `F3.*` → `WIN.*`. F4–F8 unchanged.

Permitted because no code exists. **Task IDs freeze at F0 start** (`I-23`).

## Consequences

**Good.**
- Integration risk moves from week 10 to week 4.5, when there is almost nothing to throw away.
- Four tracks run genuinely in parallel after F2, because each codes against frozen traits on top of a working system and can test with `MockSensor`/`NullEnforcer` without the other tracks existing.
- The circular dependency is gone: F3 compiles real policy from day one.
- Every phase after F2 is demoable. Progress becomes observable rather than inferred from task lists.
- Budget gates start measuring real code in week 4.5 instead of stubs until week 10.
- Critical path: 11 weeks, down from 11–12, with far lower variance — the variance reduction matters more than the week.

**Costs.**
- F1 grows from 2 to 2.5 weeks, and F2 adds a week that produces almost no features. This is the price of the risk transfer and it is worth paying: an interface defect found in F1 costs hours; the same defect found in F6 invalidates three tracks.
- One renumbering churn, absorbed now while it is free.

**Risks.**
- **The skeleton could be over-scoped.** If F2 grows features it becomes F3 with extra steps and the risk-transfer benefit is lost. The scope table in F2 lists what is explicitly *out*, and that list is as binding as the task list.
- **The freeze could be treated as advisory.** If traits drift silently after F1, parallel tracks desynchronize invisibly. Mitigated by making the freeze an ADR-gated boundary and by the `verify-layering` CI gate.

## Follow-up actions

- [x] Plan Part III rewritten: §3.1–3.7 architecture, restructured phases, renumbering note.
- [x] F1 absorbs ontology (`F1.ON.*`), policy model (`F1.PL.*`), trait catalogue (`F1.PA.*`).
- [x] F2 walking skeleton specified with explicit out-of-scope list.
- [x] Windows moved to Annex F; §4.3 marked deferred.
- [x] Critical path, milestones and risk-register phase owners updated.
- [x] Deduplication: red flags → Annex C only; budgets → §2.22 + `budgets.toml` only; capability matrix → Annex D only; session protocol → `docs/ai/AGENTS.md` only.
- [ ] `F0.CI.06` — implement the dependency-direction gate.
- [ ] `F0.CI.07` — implement the doc-drift gate between §2.22 and `budgets.toml`.
- [ ] Write ADR-0019 (Tauri v2 + uniffi fallback) and ADR-0020 (multiplatform detection scope).
