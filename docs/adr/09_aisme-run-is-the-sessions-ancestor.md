# ADR-09 — `aisme run` supervises its own child instead of `exec`ing it

**Status**: Accepted · **Date**: 2026-09-15
**Raised by**: `F2.WS.11`'s measurement, closing F2 · **Supersedes in part**: `F2.WS.08`'s
`exec`-not-`fork` decision

## Context

`aisme run` `exec`ed the supervised command, so the session's supervisor was `aisme-agentd`: a
**sibling** of the session, reached over the control socket, which read each trapped `openat`'s
path argument out of the target with `process_vm_readv`.

**That supervises the first process of a session and nothing it forks.** Measured on this host,
`kernel.yama.ptrace_scope = 1`:

| target | a sibling supervisor's `process_vm_readv` |
|---|---|
| the process that called `PR_SET_PTRACER`, after `execve` | permitted |
| **a process it forked** | **`EPERM`** |
| the same, from an **ancestor**, with no grant at all | **permitted, at depth 1, 2 and 3** |

Through the product: `aisme run --trap-openat -- cat /etc/hostname` delivered 4 opens and denied 0,
while `… -- sh -c 'cat /etc/hostname'` denied **13**, every one the grandchild's and every one *"the
path argument could not be read"*. **Every real agent forks**: across 17 sessions and 13 686 tool
calls, **91.1 %** of what an agent does is run a subprocess, and one such call expands into 1 713
`openat` across 58 programs.

The kernel refuses the unprivileged alternative on purpose, and not only through Yama. An
unprivileged `fanotify` listener may create a group and mark a directory, and then reports `pid=0`
for every process but itself. **There are two ways to observe a process tree on Linux: own it, or
hold a capability.**

GATE F2 passed anyway, which is worse than failing: its guest daemon runs as `uid 0`, where
`CAP_SYS_PTRACE` makes Yama irrelevant, while `deploy/systemd/aisme-agentd.service` runs as
`User=aisme` with an empty `CapabilityBoundingSet=`. The gate measured a configuration the product
does not ship.

## Decision

**`aisme run` forks the supervised command and remains its parent for the life of the session.**

- The **child**, in order and with nothing fallible after the filter: `PR_SET_PDEATHSIG(SIGKILL)`,
  the Landlock write scope, the seccomp filter when the session asked for one, the listener handed
  up over a socketpair, then `execve`.
- The **parent** answers the notifications. It is the session's ancestor, so it reads each held
  open's path argument with no capability and no `PR_SET_PTRACER` anywhere. It performs the
  validated `openat2` and the `ADDFD`, exactly as `I-28` requires and with the same adapter code.
- **The daemon still decides.** The parent asks it over `decideOpen` once per held open; the daemon
  holds the compiled policy, the adjudicator and the WAL. A session that decided what governs it
  would be deciding whether to be enforced.
- `registerSession` **carries no descriptor**. `PR_SET_PTRACER` and `SO_PEERCRED`-based ptrace
  grants leave the session path entirely and are deleted, because a grant left in place is a grant
  someone will rely on.
- The whole `fork` sequence lives in `aisme-linux` (L2), because `unsafe` is forbidden in L4's
  product edges and one auditable adapter function is what the adapter layer is for.

**`CAP_SYS_PTRACE` on `aisme-agentd` is rejected**, and for the project's own reason rather than a
preference: `docs/06` point 3 refused the daemon a writable policy-map descriptor because it would
leave `CapabilityBoundingSet=` decorative — *"the capability gone and the authority kept"*.
`CAP_SYS_PTRACE` is broader than what was refused there. A separate privileged supervisor process
was also rejected: it works, and it still puts the capability somewhere.

## Consequences

**Good.** Supervision reaches every descendant at any depth, with **no component holding any
capability** — measured: `sh -c 'cat /etc/hostname'` goes from 2 delivered and 13 denied to 6
delivered and 0 denied, and three shells deep to 10 delivered and 0 denied. GATE F2 can be re-run
against the configuration that ships. It also restores what `docs/design/02_aisme-run.md` steps 8
and 9 already assumed — a process that outlives `exec` — which F2 had to move into the daemon one
piece at a time.

**Costs.** `aisme run` is now an intermediary in the process tree, and the exit status has to be
reproduced by hand rather than inherited. One control-plane round trip per held open: T1 is
budgeted at 400 µs target and 1 000 µs hard, and was 46.6 µs p99 before this. `aisme run` must be
single-threaded at the fork, which is checked rather than assumed.

**Risks.** *The intermediary could be killed, freeing the child.* It does not: `PR_SET_PDEATHSIG`
survives `execve` and fires, measured, and the test
`killing_the_supervisor_kills_the_command` pins it. *The child could run before the parent's loop
exists.* It cannot matter: a trapped syscall blocks in the kernel until somebody answers it, and if
the parent dies the listener closes and every held syscall gets `ENOSYS` — measured at 297 361
refusals in one run. *The parent could be confined by what it applies to the child.* The ruleset and
the filter are applied after the fork, and a test asserts a session reading **outside** its own
scope is answered, which only the unconfined parent can do.

**Reversal cost.** Low, and deliberately so. The adapter's notification loop takes callbacks, so
the caller can move back to the daemon without the adapter changing; `decideOpen` is additive and
`registerSession` would regain its descriptor. What must be preserved to keep it cheap: the loop
stays behind `serve_notifications_with`, and the decision stays in the daemon.

## Follow-up actions

- [ ] Re-run GATE F2's five enforcement lines against the shipped configuration and record the
      output in `STATE.md` (`F2.WS.10`'s gate block).
- [ ] `F2.WS.11`'s second half: zero notification traffic, observed through `sys_exit_openat`.
- [ ] Move the terminal adjudicator into `aisme run`, which design step 8 asks for and which this
      makes possible. It is `F8.UA.01`'s and deliberately not done here.

## Sources

- `docs/11_challenge_ampliacion_recomendaciones.md` point 1 — the amplified recommendation and the
  five measurements behind it.
- `docs/12_investigacion_guardarrailes_sesiones_ia.md` — the nine measurements, including the
  `fanotify` result that closes the unprivileged alternative.
- `docs/06_challenge_ampliacion_policy_object.md` point 3 — the refusal `CAP_SYS_PTRACE` is
  measured against.
