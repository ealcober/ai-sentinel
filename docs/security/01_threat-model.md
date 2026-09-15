# Threat model

> Assembled from material that exists across the plan, so it can be read as a whole. It **cites rather than restates**: where a decision is argued elsewhere, this document points at the argument.
>
> Produced by `F0.SEC.01`. Reviewed against the plan's `[CUT]` markers and declared anti-goals by `verify-docs`.

## 1. Assets, in priority order

1. **The user's source code, secrets and intent.** Prompts and chain-of-thought are the user's private data (`I-08`); credentials are what an exfiltration takes.
2. **The integrity of the machine.** Files, processes, persistence, egress.
3. **The forensic record.** Tamper-evident, not immutable (`I-18`) — its value is that an auditor can tell whether it was altered.
4. **The user's attention.** Over-alerting is an attack on the product's usefulness, and `I-15` already weights a false positive as heavily as a miss. A guardrail nobody keeps installed protects nothing.

## 2. Adversaries, ranked, with what is in scope for each

**A1 — The misaligned agent.** *Primary.* Hallucination, over-eager tool use, a misread instruction. No intent, unbounded capability, and it holds legitimate credentials. It is the reason enforcement must be deterministic (`I-20`) and the reason a denial is not enough on its own: an agent routes around a denial (`DT-05`).

**A2 — Content that instructs the agent.** *Primary.* Indirect prompt injection through a file the agent reads, a web page it fetches, or an MCP tool description it trusts. The agent is the attacker's remote hand and it has the user's permissions. `DT-02` and `DT-03` exist for this adversary; `H-12` hardens the Observer against being the second victim.

**A3 — A hostile AI application** on mobile, or a hostile host embedding the SDK. *Secondary.* It owns its SDK instance and its attestation key, so it can sign whatever it likes — which is why the per-install key proves *which install* spoke, never that it told the truth. What catches it is cross-checking declared intent against observed flows (`F9.SDK.09`).

**A4 — A human attacker with root on the machine.** **Out of scope for prevention. In scope for evidence.** They can stop the daemon, rewrite the log and re-sign it with the local key. `H-17` states this plainly: what survives them is **external root anchoring**, because rewriting history then requires compromising the SIEM too.

**A5 — An APT implant engineered to detect and evade eBPF.** **Out of scope.** `H-05` argues it: the cost of contesting such an adversary is enormous, the benefit marginal, and the techniques it would require — rewriting another process's memory to hide — are what would make this product a rootkit and end its compliance story. This is a deliberate boundary, not an oversight.

> **Why the ranking is the most important thing in this document.** Several of the plan's design decisions read as gaps if you do not know which adversary they are against. Not defeating certificate pinning (`H-06`), not hiding from the monitored process (`H-05`), accepting that A4 wins on prevention — each is correct against A1 and A2 and would be wrong against A5. The scope is what makes them discipline rather than naivety.

## 3. Trust boundaries

| Boundary | What crosses | What checks it |
|---|---|---|
| Kernel → `agentd` | `RawEvent` over a ring buffer | Fixed layout, wire version, fuzzed decode path (`T4.2.12`); drops counted, never silent |
| `agentd` → `forensicd` | The WAL, append-only, offset-addressed | Segment header with wire version and schema hash; either process may restart independently |
| Engine → control plane | JSON-RPC over UDS or the relay | Three authorization classes (Annex I.1); the **human-principal** test is what separates the user from the agent |
| **Session → host, deferred** `[RISK]` | A file the agent writes that the *host* executes later — `.claude/settings.json`, `.vscode/tasks.json`, `.mcp.json`, `.git/config` | **Nothing, today.** `DT-14` detects it; `F3.EN.11` is the task that would deny it |
| Device → device | Ciphertext only | Noise `XX` on a software X25519 static; every remote `ALLOW` signed by a hardware P-256 key (`I-06`); the relay is blind (`I-07`) |

## 4. Attack surface

Enumerated, each with what defends it:

- **The ring-buffer decode path** — fuzzed 8 h nightly (`T4.2.12`); no panic, no OOB, no unbounded allocation.
- **The policy compiler** — static validation, deterministic output, a grammar (Annex B §B.0) rather than an inferred format.
- **The Observer's input** — attacker-controlled by construction: structured, fenced, schema-constrained output, severity monotonic, and it may propose only tightening rules (`H-12`, `I-04`).
- **The offset scanner** — a sacrificial seccomp-jailed process with a time limit; disassembling untrusted input never happens inside `agentd` (`H-07`).
- **The pairing handshake** — constant-time, indistinguishable failures (Annex I.2), or it becomes an oracle.
- **The SDK transport** — per-install key authentication; loopback on iOS because App Groups cannot span vendors.
- **Host-executed configuration the agent can write** `[RISK]`. AISME supervises a cgroup and a process tree. A file the agent writes inside its own workspace and the IDE, the shell or the next `git` invocation executes **tomorrow** is outside both — the write is supervised, the execution is not, because it happens after the session ends and in the host's process tree. Measured 2026-09-15: a supervised session creates all four of the files above inside its declared scope, and the scope cannot refuse them because Landlock rules only *grant*. Three of the seven July 2026 sandbox escapes in `docs/research/01` are this shape, with no agent involvement at the moment of execution, and the CHAINDROP worm is it in the wild. **This is honest scope today and it is stated here rather than left to be inferred**: a product that says it supervises a session without saying where the session ends is making a claim it does not hold.
- **The prompt itself.** `I-05`: a prompt is an attack surface. If a tired user can be induced to click Allow on `/etc/shadow`, the architecture is decorative — which is why three groups are never promptable and never suppressible.

## 5. Non-goals

Collected from the eight places they otherwise live. AISME does **not**:

- Prevent a human attacker with root from tampering (§2 A4) — it makes tampering *evident*, and anchoring is what carries that off-machine.
- Defend a machine whose kernel is already compromised.
- Prevent the user from disabling it. `aisme disable` exists, is auditable, and is human-principal-only (`F7.PS.08`).
- Modify, patch, hook or hide from an observed process (`I-01`, `I-02`, `H-05`, `H-06`).
- Defeat certificate pinning or degrade any pre-existing security guarantee (`I-03`, `H-06`).
- Observe **native Windows processes** — WSL2 coverage is the WSL2 VM (`ADR-02`).
- Observe another application's files or processes **on mobile** — the app sandbox is the boundary (`ADR-05`, Annex D).
- Let the Observer LLM authorize anything, ever (`I-04`).
- Collect third-party network traffic for its corpora (§4.14.1, tier 3 `[CUT]`).
- Let a suppression rule remove a record or weaken enforcement (`I-26`).
- Supervise what the **host** does with a file after the session ends — see the trust-handoff row in §3 and §4. The boundary is the session's process tree and cgroup; execution outside it, later, by the IDE or the shell, is `F3.EN.11`'s to deny at the write and nobody's to observe at the run.

## 6. Mappings

- **OWASP Top 10 for Agentic Applications** → Annex G §G.3.
- **Relationship to the agent's own sandbox** → Annex G §G.4. In short: an agent's sandbox is configured by files the agent can write and is escapable; AISME sits outside it and is not configurable by the agent. Neither is a substitute for the other, and the product says so.
