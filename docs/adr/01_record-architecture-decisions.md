# ADR-01 — Record architecture decisions

**Status**: Accepted · **Date**: 2026-08-17

## Context

This project is built largely by LLM agents working across sessions with no shared memory. The dominant failure mode in that setting is not writing bad code — it is **re-litigating settled decisions**, or worse, silently re-implementing a design that was analysed and rejected months earlier because the reasoning was never written down.

The project already has a concrete instance of this risk: eighteen designs from the original research (`docs/research/`) were rejected, cut, corrected or deferred during architecture review, and one requirement absent from the research was added (`H-19`). Those live as findings `H-01`…`H-19` in Part II of the implementation plan. Without a durable record and an explicit precedence rule, a future contributor reading the research documents would reasonably conclude that the plan had *omitted* something and "fix" it — reintroducing, for example, a kernel-blocking FUSE-RPC path that can deadlock the machine.

## Decision

1. **Architecture decisions are recorded as ADRs** in `docs/adr/NN_slug.md`, numbered sequentially, never deleted. Superseded ADRs are marked `Superseded by ADR-NN` and kept.
2. **Findings `H-01`…`H-19` in the implementation plan have ADR force.** Contradicting one requires a new ADR that argues the case explicitly. It may not be done silently, and it may not be done in a pull request comment.
3. **An ADR is required for:** anything affecting the resource invariants, the security invariants, a kernel-space mechanism, the policy or wire formats, a cross-platform contract, or the addition of a dependency that runs in `agentd` or in kernel space.
4. **An ADR is not required for:** implementation detail inside a settled boundary, refactors, tests, or documentation.
5. ADRs are short. Context, decision, consequences. If it needs ten pages it is a design note in `docs/design/`, and the ADR references it.

## Consequences

**Good.** A contributor arriving cold can reconstruct *why*, not just *what*. Rejected designs stay rejected. The precedence rule (plan over research, ADR over plan) is unambiguous and mechanical.

**Cost.** Every architectural change carries a small documentation tax. This is deliberate — the tax is the point, because it forces the reasoning to be articulated before the code exists.

**Risk.** ADRs rot if the code moves and nobody updates them. Mitigation: the definition of done in `docs/ai/AGENTS.md` §2 requires, for any task touching an architectural boundary (Decision 3), that the relevant ADR was re-read and is still true, or that a superseding ADR was written.

## Numbering

ADRs are numbered **strictly in order of creation**: `NN_slug.md`, two digits, following the project's Rule 4. The slug never begins with a hyphen (`01_record-architecture-decisions.md`, never `01_-record-…`). Numbers are never reused and never reserved in advance — the earlier scheme that reserved `0001`–`0018` for the `H-xx` findings was abandoned the day it was written, because `ADR-02` and `ADR-03` were real decisions that needed the next free numbers.

An ADR that formalizes a Part II finding says `Formalizes H-xx` in its header. **The H number and the ADR number are unrelated.**

`ADR-04` (Tauri v2 for the mobile client, with a `uniffi` fallback) and `ADR-05` (multiplatform detection scope and the AI Sentinel sensor architecture) are referenced by the plan and should be written next.
