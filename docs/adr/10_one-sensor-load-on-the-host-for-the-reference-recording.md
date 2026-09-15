# ADR-10 — Load the sensor once on the owner's host, for the reference recording only

**Status**: Proposed · **Date**: 2026-09-15
**Raised by**: the owner, on `docs/15` point 2 · **Narrows**: `I-12`

## Context

`I-12` reads: *"No kernel-touching test ever runs on a host OS. Snapshot-restored disposable VMs
only, for every developer and every local gate run (`I-27`)."* It has no exceptions today, and that
is its value: an invariant nobody has to remember the shape of.

`F0.ASSET.02` owes a reference recording — a real Claude Code session on this repository, captured
with `aisme run` in observe-only mode into `tests/fixtures/reference-trace/`. Plan `:1360` places it
**before** GATE F2, so F2 does not close without it.

Three facts were measured on 2026-09-15 and together they leave no way to produce that recording
inside a VM or through the seccomp path.

**A guest cannot host the session.** The recording is specified as *"an actual working session, not
a script"*. That needs the agent, its credentials and the repository inside the guest. Putting a
developer's API credentials into a disposable VM to make a test fixture is the exact handoff
`docs/research/01` documents being exploited (Part II §4, §6), and it trades a recording for a
credential-exposure path.

**The seccomp path cannot carry a working session.** Under `--trap-openat` every write-mode open is
denied — that is `Q-13`'s reproducible subset, documented and deliberate, not a defect. Measured
twice: `sh -c 'cat X >/dev/null'` is refused at the redirection, and `rm` outside the scope fails
before it starts. An agent that cannot write a file is not an agent session, so a recording made
this way would record a crippled process. It would also perturb what it measures: **+17 µs per
open** (`docs/12` M7), on a workload whose defining property is open density (M2: 1,713 `openat` in
one `Bash` call).

**Observe-only mode records nothing without the sensor.** Measured: the WAL of an observe-only
session carried the hook's declaration and **zero** `FileOpen` records. There is no seccomp path when
no filter is installed, and `platform::probe()` reports no ring buffer and no BTF on any host because
those probes are `F3.LD.01`'s and unwritten (`crates/aisme-agentd/src/platform/mod.rs:49`) — so the
composition does not attempt a load even where one would succeed.

Not verified, and it is the first thing this decision buys: **whether the sensor loads on this
kernel at all.** `aisme-agentd --load-sensor` has never been run on this host. It needs `CAP_BPF` or
root.

## Decision

**One narrow, expiring exception to `I-12`**, for `F0.ASSET.02` and nothing else.

What is permitted, on the owner's host, out of band:

1. `aisme-agentd --load-sensor`, run by hand under `sudo`, to learn whether the sensor loads on this
   kernel and to record the answer verbatim in `docs/ai/STATE.md` — `ACCEPTED` with its capabilities,
   or `REFUSED` with the kernel's own words. Either outcome is a measurement.
2. If it is `ACCEPTED`: the sensor attached for the duration of **one** observe-only session, to
   produce `tests/fixtures/reference-trace/`.

What is **not** permitted, and stays exactly as `I-12` says:

- No BPF program is loaded by `cargo test`, by any `cargo xtask` gate, or by any pre-commit hook, on
  any host, ever.
- `platform::probe()` is not changed to report the sensor present on a host. That probe is
  `F3.LD.01`'s work, and the test that holds it —
  `nothing_measured_means_no_bpf_load_is_attempted_on_the_host`
  (`crates/aisme-agentd/src/platform/mod.rs:450`) — stays exactly as it is. **If that test ever needs
  changing, this exception has grown beyond what was agreed.**
- No second recording. A re-record needs this ADR superseded, not re-read.

**This exception expires when the recording exists**, and the follow-up below is how it is closed.

The program loaded is an observe-only tracepoint on `sys_enter_openat`. It goes through the kernel's
verifier like any `bpftrace` one-liner, and `H-05` forbids `bpf_probe_write_user` outright, so it
cannot modify the processes it observes. `I-01` and `I-02` already forbid modifying an observed
process by any means, and `T4.5.06` tests it.

## Consequences

**Good.** `F0.ASSET.02` becomes producible, and with it GATE F2 and the close of the phase. The
fixture is recorded in the mode its specification names — observe-only, perturbing nothing — rather
than through a path that would deny the agent every write. And `--load-sensor`'s answer on a 7.1
kernel is a measurement this project does not otherwise have, since the matrix tops out at 7.0.

**Costs.** `I-12` stops being an invariant with no exceptions and becomes one with a named,
dated, expiring exception. That is a real loss: the next person to want a shortcut has a precedent to
point at. The mitigation is that the exception names one command, one session and one asset, and
says in as many words which test must not change.

**Risks.**

- *The exception creeps.* Caught by the rule above: `probe()` and its test are the tripwire, and any
  change to them means this grew.
- *The load destabilises the host.* It is a verified, observe-only tracepoint and the sensor detaches
  itself (`--load-sensor` stops immediately — *"this is a question, not a session"*). The ordinary
  risk of running a profiler.
- *The recording carries something it should not.* The trace format was built for this: entries carry
  `args_hash`, never paths — *"the arguments themselves are not in the trace, because a fixture is
  committed and a path is data"*. The manifest's hash check is `F0.ASSET.02`'s own done-condition.

**Reversal cost.** Near zero while the exception is narrow: nothing in the product changes, no
capability is granted to any component, no code path is added. Undoing it means deleting this file
and re-recording in a guest if one ever becomes able to host a session. What keeps it cheap is that
`probe()` is untouched, so the shipped composition never attempts a host load whatever this ADR says.

## Follow-up actions

- [x] **Done, 2026-09-15 — the offsets hold on 7.1.5.** The format file reports `filename` at
      **offset 24**, `flags` at **32** and `mode` at **40**, which is exactly what the program
      compiles in. The recording may proceed on this kernel. The same output also shows a field the
      VM matrix has never seen — `field:__data_loc char[] __filename_val; offset:48; size:4;` — the
      kernel's **own captured copy** of the filename, beside the user pointer the program
      dereferences. It is not used and is recorded as an open question, not as a change: reading a
      copy the kernel made beats dereferencing a user pointer that can change or fault, and whether
      it is available below 7.1 decides whether it can ever be more than a fast path.
- [ ] **First, and cheaper than the load:** read
      `/sys/kernel/tracing/events/syscalls/sys_enter_openat/format` on this host and compare
      `filename`, `flags` and `mode` against the 24/32/40 the program compiles in
      (`crates/aisme-ebpf/src/main.rs:87`). Those offsets are an ABI detail of a **format file** and
      are verified only **in the guest**, by `cargo xtask vm probe`; the VM matrix tops out at 7.0
      and this host runs 7.1.5. A wrong offset does not fault — it yields a pointer that is not the
      filename, and the recording fills with nonsense that looks like data. The file needs the same
      privilege as the load, which is why it shares the one `sudo` rather than preceding it. **If
      they differ, stop**: the offsets become an `F0.VER` row measured on 7.1 and the recording waits.
      (`docs/16` point 2)
- [ ] Run `sudo aisme-agentd --load-sensor` on the owner's host; paste the output verbatim into
      `docs/ai/STATE.md`. (`F0.ASSET.02`)
- [ ] If `ACCEPTED`: record `tests/fixtures/reference-trace/` from one observe-only session, with the
      hook installed in `~/.claude/settings.json` and nowhere else. (`F0.ASSET.02`)
- [ ] Mark this ADR **Superseded by nothing — expired** on the commit that lands the fixture, so the
      exception is visibly closed rather than silently standing.
- [ ] `docs/ai/invariants.md`: link `I-12` to this ADR, so the invariant and its one exception are
      read together.

## Sources

- `docs/ai/invariants.md` — `I-12`, `I-01`, `I-02`.
- `docs/12_investigacion_guardarrailes_sesiones_ia.md` — M2 (1,713 `openat` per `Bash` call), M7
  (+17 µs per trapped open).
- `docs/research/01_incidentes_y_defensas_de_agentes_ia.md` — Part II §4 and §6, on credentials and
  agent configuration as the exploited handoff.
- `crates/aisme-agentd/src/platform/mod.rs:49` and `:450` — why a host reports no sensor, and the test
  that holds it.
- Plan `:1360` — `F0.ASSET.02`, and where the recording sits relative to GATE F2.
