# ADR-0001 — Record architecture decisions

**Status**: Accepted · **Date**: 2026-08-17

## Context

This project is built largely by LLM agents working across sessions with no shared memory. The dominant failure mode in that setting is not writing bad code — it is **re-litigating settled decisions**, or worse, silently re-implementing a design that was analysed and rejected months earlier because the reasoning was never written down.

The project already has a concrete instance of this risk: nineteen designs from the original research (`docs/research/`) were rejected or corrected during architecture review. Those live as findings `H-01`…`H-19` in Part II of the implementation plan. Without a durable record and an explicit precedence rule, a future contributor reading the research documents would reasonably conclude that the plan had *omitted* something and "fix" it — reintroducing, for example, a kernel-blocking FUSE-RPC path that can deadlock the machine.

## Decision

1. **Architecture decisions are recorded as ADRs** in `docs/adr/NNNN-title.md`, numbered sequentially, never deleted. Superseded ADRs are marked `Superseded by ADR-NNNN` and kept.
2. **Findings `H-01`…`H-19` in the implementation plan have ADR force.** Contradicting one requires a new ADR that argues the case explicitly. It may not be done silently, and it may not be done in a pull request comment.
3. **An ADR is required for:** anything affecting the resource invariants, the security invariants, a kernel-space mechanism, the policy or wire formats, a cross-platform contract, or the addition of a dependency that runs in `agentd` or in kernel space.
4. **An ADR is not required for:** implementation detail inside a settled boundary, refactors, tests, or documentation.
5. ADRs are short. Context, decision, consequences. If it needs ten pages it is a design note in `docs/design/`, and the ADR references it.

## Consequences

**Good.** A contributor arriving cold can reconstruct *why*, not just *what*. Rejected designs stay rejected. The precedence rule (plan over research, ADR over plan) is unambiguous and mechanical.

**Cost.** Every architectural change carries a small documentation tax. This is deliberate — the tax is the point, because it forces the reasoning to be articulated before the code exists.

**Risk.** ADRs rot if the code moves and nobody updates them. Mitigation: the session protocol in `docs/ai/AGENTS.md` makes ADR review part of the definition of done for any task touching an architectural boundary.

## Numbering

`0001`–`0018` are reserved for the ADRs that formalize findings `H-01`…`H-18` — to be backfilled as each area is implemented, so the reasoning sits next to the code rather than only in a planning document. `ADR-0019` (Tauri v2 for the mobile client, with a `uniffi` fallback) and `ADR-0020` (multiplatform detection scope and the AI Sentinel sensor architecture) are already referenced by the plan and should be written next.
