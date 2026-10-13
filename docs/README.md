# Documentation index

Every document in this directory, in the order it was written. The number is fixed at creation and
never changes, so a citation stays valid for the life of the project.

**Where to start:** [`01_phase5_implementation_plan.md`](01_phase5_implementation_plan.md) is the
plan and the definitive reference. [`ai/STATE.md`](ai/STATE.md) is the live position — what is done,
what is next, what is blocked. [`CHANGELOG.md`](CHANGELOG.md) is every change with its commit.

## The plan, and the three reviews that sealed it

| | |
|---|---|
| [01_phase5_implementation_plan.md](01_phase5_implementation_plan.md) | **The plan.** Parts 0–VIII and Annexes A–I: the task tables, the 19 `H-xx` findings, the budgets, the protocol, the policy grammar |
| [02_challenge_ampliacion_sistema.md](02_challenge_ampliacion_sistema.md) | Correctness review — 209 findings with their patches, all applied, and the owner's ten decisions |
| [03_challenge_accionabilidad.md](03_challenge_accionabilidad.md) | Executability review — 35 findings: can a stranger execute this plan without asking anybody? |
| [04_final_coherence_seal.md](04_final_coherence_seal.md) | The seal — 134 findings, the host probe, and the register of claims that could not be verified |

## Phase amplifications

Each takes a skeleton of points to Challenge, Verification, Implementation, Tests and Documentation
**before** any code is written, so that implementing it requires no further decision.

| | |
|---|---|
| [05_challenge_ampliacion_f2.md](05_challenge_ampliacion_f2.md) | Phase F2, the walking skeleton — thirteen points |
| [06_challenge_ampliacion_policy_object.md](06_challenge_ampliacion_policy_object.md) | The policy object: why the double buffer cannot use BTF maps at the pinned toolchain, measured |
| [07_challenge_coherencia_estado_y_host.md](07_challenge_coherencia_estado_y_host.md) | Coherence between the recorded state and the host it was measured on |
| [08_challenge_artefactos_trackeados.md](08_challenge_artefactos_trackeados.md) | 890 build artefacts in the index, and the one-line rule that replaced naming them |
| [09_challenge_ampliacion_f2_enforcement.md](09_challenge_ampliacion_f2_enforcement.md) | F2's enforcement half: seccomp, Landlock, and what each can and cannot decide |
| [10_challenge_cierre_f2.md](10_challenge_cierre_f2.md) | The first F2 closing plan |
| [11_challenge_ampliacion_recomendaciones.md](11_challenge_ampliacion_recomendaciones.md) | Two recommendations amplified, one of which fell under its own measurement |

## Measurements, closing plans, and this release

| | |
|---|---|
| [12_investigacion_guardarrailes_sesiones_ia.md](12_investigacion_guardarrailes_sesiones_ia.md) | Eleven host measurements, `M1`–`M11`: tool composition, syscall density, seccomp perturbation, Yama's grant model, and the two bypasses they found |
| [14_plan_de_cierre_f2_y_campo.md](14_plan_de_cierre_f2_y_campo.md) | What F2 owes, and what the field record adds to it |
| [15_decisiones_abiertas_y_cierre_de_f2.md](15_decisiones_abiertas_y_cierre_de_f2.md) | The open decisions, separated into what blocks the phase and what does not |
| [16_atribucion_y_carga_del_sensor.md](16_atribucion_y_carga_del_sensor.md) | The attribution rule and the sensor load, verified against kernel source |
| [17_plan_de_cierre_de_f2.md](17_plan_de_cierre_de_f2.md) | **The live closing plan.** Seven items, each amplified and each with its owner |
| [18_preparacion_para_publicacion.md](18_preparacion_para_publicacion.md) | Preparing this repository for public release |

There is no `13`. It was a stub superseded before it was ever committed, and the gap is the honest
record of a file that never existed here.

## Field research

Dated, sourced, with a register of what could not be verified. These are the documents the roadmap
decisions cite.

| | |
|---|---|
| [research/01_incidentes_y_defensas_de_agentes_ia.md](research/01_incidentes_y_defensas_de_agentes_ia.md) | 32 dated incidents and the defensive state of the art, with ten decisions and their evidence |
| [research/02_hooks_de_agentes_como_fuente_de_intencion.md](research/02_hooks_de_agentes_como_fuente_de_intencion.md) | Agent hooks as a source of intent: eleven vendors compared, and how far a hook can be trusted |
| [research/03_atribucion_de_procedencia_y_tracepoints.md](research/03_atribucion_de_procedencia_y_tracepoints.md) | Attributing kernel events to activities, verified against kernel source |

## Design, decisions and security

| | |
|---|---|
| [design/01_permission-model.md](design/01_permission-model.md) | The permission and suppression model, and the four answers a prompt offers |
| [design/02_aisme-run.md](design/02_aisme-run.md) | The session launcher, step by step |
| [adr/](adr/) | Architecture decision records, `00`–`10`. Each states its context, its decision, and what it costs |
| [security/01_threat-model.md](security/01_threat-model.md) | Assets, ranked adversaries, trust boundaries, and the collected non-goals |

## Working documents for development LLMs

| | |
|---|---|
| [ai/AGENTS.md](ai/AGENTS.md) | The session protocol and the definition of done |
| [ai/STATE.md](ai/STATE.md) | **The live state.** Done, next, blocked, and the decisions taken |
| [ai/invariants.md](ai/invariants.md) | The constraints that may not be broken, `I-01`–`I-28` |
| [ai/memory/](ai/memory/) | Durable facts that were expensive to discover, one per file |
| [ai/handoff/](ai/handoff/) | Notes left mid-flight, so the next session does not start from zero |
