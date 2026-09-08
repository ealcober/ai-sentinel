# Handoff — F2, the walking skeleton, mid-flight

**Written 2026-09-08 at commit `34ba389`.** Everything below was measured, not
remembered; where a number appears, the command that produced it is named.

---

## 1. Read these, in this order, before touching anything

The order is not decorative — each file assumes you have read the one before it.

1. **`CLAUDE.md`** — the rules and the forbidden patterns. Its "single most
   important rule" (findings `H-01`…`H-19` beat the research documents) is the
   one people break by trying to be helpful.
2. **`docs/ai/AGENTS.md`** — the working contract. Read **§2-bis** (push every
   commit) and **§3-bis** (the verification rules) closely: §3-bis is nine rules,
   each paid for by a defect that reached a commit or a VM in the last two days.
3. **`docs/ai/STATE.md`** — what is actually done, what is blocked, what is next.
   Trust it over your assumptions; it was corrected on 2026-09-07 precisely
   because it had stopped being true.
4. **`docs/ai/invariants.md`** — `I-01`…`I-28`. `I-12` (no kernel test on a host)
   and `I-27` (zero hosted-CI cost) are the two you will bump into first.
5. **`docs/01_phase5_implementation_plan.md`** — the plan. Find your task by its
   `F<phase>.<block>.<task>` ID. F2's task table is around line 1619.
6. **`docs/05_challenge_ampliacion_f2.md`** — F2 amplified point by point, and
   the record of which of its own claims fell and with what measurement.
7. **`docs/06_challenge_ampliacion_policy_object.md`** — the six points that
   specify the rest of `F2.WS.04`. Points 3 to 6 are unimplemented and are
   written to be executed without deciding anything.
8. Skim **`docs/ai/memory/`** — facts that were expensive to discover.
   `seccomp-unotify-toctou`, `wsl2-import-mechanics` and
   `cloud-images-are-the-kernel-matrix` are the ones this phase touches.

---

## 2. The rules that will bite you if you skip them

Beyond `CLAUDE.md`, these are the ones learned the hard way here:

- **Push every commit, immediately.** Standing owner instruction; `AGENTS.md`
  §2-bis. Confirm with `git rev-list --left-right --count origin/main...HEAD`
  reading `0 0` before you report anything as done.
- **Verify the effect of an edit, never its report.** A script printing `ok`
  proved it ran, not that it changed anything — an anchor that drifted matches
  nothing and still reports success. Confirm with `grep`, a compile, or a test.
- **No pipe between a command and `$?`.** `cmd | tail` makes `$?` tail's status.
  Use `cmd > file 2>&1; echo $?`.
- **Never rewrite a file by line range.** A splice by index deleted 716 lines of
  a working file here. Edit by anchor.
- **Run it, do not read it.** Reading missed a guard that announced a refusal and
  then ran the command anyway, a loop spinning a core flat out, and an error
  message blaming a cause it had not measured.
- **See a guard fail before trusting it.** Three gates in this repository were
  reporting compliance they had never checked, including the one enforcing the
  owner's hardest rule.
- **Predict before you measure.** Write down what each possible result will mean,
  *then* run the command. Several predictions in this repository fell; each one
  is recorded with its measurement, which is the point.
- **The owner's hardest rule**: zero GitHub cost. No workflow, no action, ever —
  not even a manually dispatched one. `verify-docs` fails on the existence of one.

---

## 3. Where development actually is

**F0 and F1 are closed on their gates.** F1's gate froze the L1 traits
(`ADR-03`, scoped by `ADR-08`: the freeze binds trait signatures, and a
`#[non_exhaustive]` type may still grow additively).

**F2 is in flight.** Measured at commit `34ba389`:

| Gate | Result |
|---|---|
| `cargo test --workspace` | **272 passed** |
| `verify-layering`, `verify-docs`, `verify-budgets` | exit 0 |
| `verify-backlog` | exit 2 — the documented `SKIP`; `F0.VER.12` needs hardware this host lacks |
| `gate --level commit` | `GATE PASSES` |

### F2's eleven tasks

| Task | State |
|---|---|
| `F2.WS.01` `BpfSensor` | **Done and kernel-verified.** `--load-sensor` reports `ACCEPTED`, `ringbuf: true` on 6.8; 5.4 refuses naming `AISME_EVENTS` and `BPF_MAP_TYPE_RINGBUF`, which is the stated refusal the task requires |
| `F2.WS.02` hot loop | **Done and connected.** `aisme-agentd --run <wal-dir> [--serve-ipc <sock>] [--ticks N]` drives sensors → engine → the real WAL. Verified end to end over a real socket: three declarations accepted, three records read back by `aisme-core::wal::replay` |
| `F2.WS.03` `declareToolCall` | **Done and connected.** One new Annex I method; the correlation token never crosses it, watched on all three streams |
| `F2.WS.04` policy | **Half.** The policy file compiles through the real compiler, `BpfTrieBackend` lowers it, and the three maps exist on a real kernel. **Publication is unimplemented** — `docs/06` points 3–6 |
| `F2.WS.05` `SeccompEnforcer` | Not started |
| `F2.WS.06` `TerminalAdjudicator` | Not started |
| `F2.WS.07` `forensicd` tail | Not started — `crates/aisme-forensicd/src/main.rs` is 9 lines |
| `F2.WS.08` `aisme run` | Not started — `crates/aisme-cli/src/main.rs` is 10 lines |
| `F2.WS.09` latency | Not started |
| `F2.WS.10` slice with no kernel | **Partial.** `vm run --with-dist` was committed under this ID because no task row owns the transport; the task itself — the whole slice on `MockSensor` — is not done |
| `F2.WS.11` Landlock | Not started |

**Beware a trap:** grepping the repository for a task ID counts *mentions*, not
implementations. `F2.WS.05` and `F2.WS.11` appear in comments as future work.

### What is blocked

Nothing hard-blocks progress. One thing is unimplemented with its cause measured:

**`F2.WS.04`'s publication.** `BPF_MAP_TYPE_ARRAY_OF_MAPS` exists at the pinned
`aya-ebpf 0.2.1` only as a BTF map, and this toolchain's BTF is unreadable to
`aya-obj 0.3.0`: `unexpected BTF type id 45`
(`aya-obj-0.3.0/src/btf/btf.rs:104`), measured on 6.8 and 5.4. A second object
does **not** help — `crates/aisme-ebpf-policy` reproduces the failure in one
command and its `README` says so. The mechanism that survived is in `docs/06`:
two legacy `LpmTrie`s and an index, already declared and loading. What remains
is points 3 to 6.

---

## 4. Next steps, in order

1. **`docs/06` point 3** — `aisme-loaderd` gains its own composition root
   (`A-05` is checked on every L3 engine now), compiles and lowers the policy,
   pins the three maps under `/sys/fs/bpf/aisme/` and **exits**, so `CAP_BPF` is
   not resident. Passing the map fd to `agentd` with `SCM_RIGHTS` is refused and
   the reason is written down: it would leave `CapabilityBoundingSet=`
   decorative.
2. **Point 4** — the five-step publish, whose **order is the property**: read the
   index, clear and fill the *idle* trie, write the generation, write the index
   last. Everything before that last write is invisible.
3. **Point 5** — the generation reaches `agentd`, the WAL header and
   `getCapabilities`. It names a live defect: `WalSink` is given
   `PolicyGeneration(0)` today and every segment records it — a placeholder
   written as a value.
4. **Point 6** — the three tests, each seen failing: the torn-read run, the
   `EPERM` privilege negative, the in-VM publication.
5. Then `F2.WS.07` (`forensicd` tails the WAL that already exists) and
   `F2.WS.08` (`aisme run`), which together unlock most of GATE F2.

---

## 5. Decisions waiting for the owner

- **Move the `aya` or `bpf-linker` pin?** It would remove the blocker entirely
  and restore `ARRAY_OF_MAPS` — and with it the structural no-torn-read that
  `docs/06` point 4 now has to argue for. `F0.VER.01` pinned both against a
  measured MSRV, so it is a change with its own validation, not a step inside
  `F2.WS.04`.
- **Enable the pre-commit hook?** `git config core.hooksPath .githooks`. It no
  longer waits on anything: `doctor` reports 15 of 15 and `gate --level commit`
  exits 0. The only question left is whether to pay the gate on every commit.
- **Perf-buffer fallback for 5.4 inside F2?** `docs/05` point 1 says no and hands
  it to `F3.PT.*`. A scope decision the owner may reverse.
- **Trademark** for *AISME* and *AI Sentinel*, and the **commercial-edition
  question**, which the DCO requires deciding before the first external
  contribution is merged (`ADR-06`).

---

## 6. How to run things

```bash
cargo xtask gate --level commit          # what the hook would run
cargo xtask build-ebpf                   # both BPF objects
cargo xtask vm run ubuntu-24.04 --with-dist -- /usr/lib/aisme/aisme-agentd --load-sensor
cargo xtask vm probe --all               # the seven-image tier matrix
cargo xtask bench-hotloop --events 200000
./target/debug/aisme-agentd --run /tmp/wal --serve-ipc /tmp/sock --ticks 8000
```

`vm run --with-dist` builds the product binaries **statically**
(`-C target-feature=+crt-static`) because this host's glibc is 2.43 and every
guest's is older — a dynamically linked binary built here runs on no image in
the matrix. It stages them with a `sha256` manifest and the guest re-hashes
each one before running anything.

**Never run a kernel-touching test outside a VM** (`I-12`).

---

## 7. Two habits worth copying

**Write the prediction before the measurement, including what each possible
result will mean.** Several predictions here fell — the tracepoint offsets held,
the BTF fallback did not — and the fallen ones are the reason the design is
where it is. A prediction that falls is worth more than one that was never made.

**When a point's claim does not survive contact with the source, stop and say
so.** `docs/06` exists because point 1 refuted the plan the other five points
were about to assume. Four claims of `docs/05` point 2 fell the same way. That
is the process working, not the process failing.
