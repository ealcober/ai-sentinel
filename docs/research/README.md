# Research sources

The four documents in this directory are the **original research input** for the project, written in Spanish. They were the starting point, not the specification.

| File | Covers |
|---|---|
| `Arquitectura Monitorización Sesiones IA.docx` | The ontological problem, AI-session discovery heuristics, eBPF vs. ETW/minifilter comparison, CoT extraction, boundary tracing, the proposed AOCP standard, monitor self-protection |
| `Diseño AI Sessions Manager.docx` | Hooking stripped BoringSSL, heuristic offset scanning, SSL-pinning defeat, causal correlation between cloud inference and local events |
| `Diseño Motor Seguridad IA.docx` | Active enforcement (BPF-LSM, minifilters), causal provenance graph, Merkle immutability, OTel integration, anti-evasion hardening, deployment blueprint |
| `Plan MVP Seguridad IA y Gestión de Permisos.docx` | The Phase 5 blueprint: low-latency architecture, Inverted Call Model, Observer LLM, SAC compression, UI and Circuit Breaker |

`extracted/` contains plain-text extractions of each document. **Use these** — LLMs cannot read `.docx` directly, and the extractions include the tables, which carry a lot of the technical detail.

## How to read these

> **These documents have been superseded by [`docs/PHASE5_IMPLEMENTATION_PLAN.md`](../PHASE5_IMPLEMENTATION_PLAN.md).**

The research is strong on diagnosis and on the choice of fundamental primitives — Ring-0 as the trust boundary, eBPF/Aya, minifilters, GC-free Rust, the provenance graph, Lamport-ordered correlation. Those decisions were adopted.

Nineteen specific designs in these documents were analysed and **rejected or corrected**, each recorded as a finding `H-01`…`H-19` in Part II of the implementation plan, with the reasoning. Among them: the FUSE-RPC blocking mechanism, in-process DuckDB, JSON on the hot path, `/proc/self/maps` spoofing, SSL-pinning defeat, the single-channel Inverted Call Model, the OTel trace mapping, and the applicability of Semantic-Anchor Compression.

**If something in these documents contradicts a finding in the plan, the plan wins.** These files are kept for provenance and for the material the plan did adopt — not as an implementation reference.
