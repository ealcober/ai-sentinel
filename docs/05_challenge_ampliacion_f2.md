# Challenge–amplification: F2, the walking skeleton

> **Status**: complete — thirteen points, closed one at a time, in order
> **`Q-13`**: answered 2026-09-07 (point 5); its consequence is point 13, a measurement
> **Skeleton**: plan §F2 (`F2.WS.01` … `F2.WS.11` and GATE F2)
> **Entry**: GATE F1 passed on 2026-09-07; the L1 traits of §3.2 are frozen
> **Rule that governs this phase**: *F2 is a walking skeleton, not a feature phase. Its
> out-of-scope list is as binding as its task list.*

## How to read this

Every point below is amplified in five sections — **Challenge**, **Verification**,
**Implementation**, **Tests**, **Documentation** — and is written in the declarative future, so
whoever implements it decides nothing and only executes. A point closes with a paragraph saying
what was verified against what, which claim of the skeleton fell, and what stays open.

Nothing here touches the repository. Where the amplification finds a decision that is not
mine to take — a safety property that the skeleton's shape would weaken — it is raised as a
**question to the owner** rather than resolved, and the point says so.

Three constraints apply to every point and are not repeated in each:

- **`I-12`**: no kernel-touching test runs on a host OS. Every real-kernel line of GATE F2 runs
  inside a disposable VM through `cargo xtask vm`.
- **`I-27`**: every gate is local. Nothing added here triggers on push.
- **The interface freeze**: `F2` may not change an L1 trait signature. Where a point needs one,
  it says so and the change becomes an ADR, not a patch.

---

## Point 1 — `F2.WS.01`: `BpfSensor`, one tracepoint, real ring buffer

**Done when:** events reach `agentd` with the correct `RawEvent` layout.

### 1. Challenge

*Is this the best solution?* The tracepoint choice is already settled by measurement rather than
taste: `F0.VER.03`'s disassembly showed glibc issues `openat` for `open()` and never `openat2`,
so `sys_enter_openat` is the one probe that sees `cat` and `sh`. Attaching an LSM hook instead
would be F3's shape and would prove a seam F2 does not need yet.

*Is it coherent with the specs?* Two frictions, both real:

1. **A tracepoint gives the path as a user-space pointer.** Reading it with
   `bpf_probe_read_user_str` yields *the string the caller asked for*, which is not the file the
   kernel will open: it is neither canonical nor stable against a concurrent rename. The memory
   `seccomp-unotify-toctou` states the rule for decisions — never decide from user memory — and
   F2 respects it by not deciding here (enforcement is seccomp and Landlock). But the *record*
   must not silently claim a canonical path it does not have.
2. **The ring buffer needs kernel ≥ 5.8.** The matrix has 5.4 and 5.10 (`F0.VM.02`), and 5.4
   lacks `BPF_MAP_TYPE_RINGBUF`. Annex D.1 already says the fallback is the perf buffer at L1.

*Can it be simplified?* Yes, in one place: the sensor will not carry its own session-filtering
logic in user space. A `BPF_MAP_TYPE_HASH` keyed by `tgid`, written by `aisme run` when it opens
a session, is §3.3 step 1 and costs one lookup; filtering in user space would move the whole
firehose across the ring boundary to be discarded.

### 2. Verification

Safe, clear, compliant — with one addition that makes it so rather than assuming it:

- The event will carry a **new wire flag**, `FLAG_PATH_UNRESOLVED = 1 << 1`, set by the BPF
  program on every path copied from user memory. The wire is append-only (§3.6) and a flag bit
  consumes no offset, so this is not a layout change and not a freeze violation. Without it, a
  consumer reading `FilePayload::path` cannot tell a canonicalized path from a requested one, and
  `F3.PT.03`'s canonicalization would silently overwrite the distinction — an absence read as a
  value (general rule 9).
- Where `BPF_MAP_TYPE_RINGBUF` is unavailable, `BpfSensor::start` will return
  `ErrorKind::Unsupported` naming the kernel version and the missing map type. It will **not**
  fall back to a perf buffer in F2: the perf-buffer path is a second transport with its own
  ordering and copy semantics, and shipping it untested inside a risk-removal phase would add
  the risk the phase exists to remove. `F3.PT.*` owns the fallback.
- The program is GPL-2.0-only (`crates/aisme-ebpf`, `ADR-06`): a tracepoint program calling
  `bpf_probe_read_user_str` and `bpf_ringbuf_reserve` uses `gpl_only` helpers, and the verifier
  enforces the declaration at load.

### 3. Implementation

- `crates/aisme-ebpf/src/main.rs` will gain one `#[tracepoint]` program, `sys_enter_openat`,
  which will: read `tgid`; look it up in `AISME_SESSIONS` (`HashMap<u32, u64>`, tgid → session
  id) and `return 0` on a miss; `bpf_ringbuf_reserve` a `RawEvent`; fill `ts_ns`
  (`bpf_ktime_get_boot_ns`), `seq` (a per-CPU counter), `session_id`, `pid`, `tgid`, `ppid`,
  `uid`, `kind = FileOpen`, `outcome = Observed`, `wire_version`; copy the path with
  `bpf_probe_read_user_str` into `FilePayload::path`, set `path_len`, set `FLAG_PATH_UNRESOLVED`,
  and set `FLAG_TRUNCATED` when the copy filled the array; then `submit`. On reserve failure it
  will bump a per-CPU drop counter that `F2.WS.02` turns into a `DropNotice`.
- `crates/aisme-linux` will gain `BpfSensor`, implementing `Sensor`: `start` loads the embedded
  object with `aya` (`include_bytes!` of the artefact `cargo xtask build-ebpf` produces),
  attaches the tracepoint, opens the ring buffer, and pins nothing; `poll` drains into the
  caller's `EventBatch` without allocating, returning within the budget; `capabilities` reports
  what it probed; `health` returns `Detached { reason }` when the link is gone (the watchdog
  proper is `F3.LD.03`); `stop` drops the links.
- `aisme-linux` will take `aya` as its first dependency, justified in `Cargo.toml` against
  `DEP.SUP.06`: it is the loader, it is what `F0.REPO.02` pinned the toolchain against, and the
  alternative is hand-rolled `bpf(2)` syscalls in a security product.
- `aisme-agentd::platform` will name `BpfSensor` behind `cfg(target_os = "linux")` — the only
  module allowed to (`A-05`) — and will keep composing `MockSensor` when the sensor reports
  `Unsupported`, so the daemon still starts (`I-19`).

### 4. Tests

**Existing to change:** `crates/aisme-core/tests/event_producers.rs` — the `PRODUCED` coverage
will remain satisfied by the mock catalogue, but the test's doc comment will name `BpfSensor` as
a second producer so the reader knows the set grew.

**New:**

- `tests/probes/ebpf` gains a verifier test for the new program, run through
  `cargo xtask vm probe --all`: the program must load on every matrix kernel that has ring
  buffers (5.10 upward) and be rejected with a stated reason on 5.4.
- In-VM integration (`cargo xtask vm run`): open a known path from inside a session and assert
  one `RawEvent` arrives with `kind = FileOpen`, `tgid` matching, `FLAG_PATH_UNRESOLVED` set, and
  the path bytes equal to what was requested.
- A negative: a process **outside** the session map opens the same path and produces no event —
  the session filter is what keeps the non-session overhead at the §2.22 budget.
- A drop test: fill the ring by refusing to poll and assert the drop counter rises and a
  `DropNotice` follows, with the count matching.

### 5. Documentation

- `docs/ai/STATE.md`: a Done row naming the tracepoint, the flag and the ring-buffer requirement.
- `docs/CHANGELOG.md`: one line under Added.
- Plan §F2's scope table: the Sensor row will name `FLAG_PATH_UNRESOLVED` so the distinction is
  visible where the scope is read.
- Plan §F1.1's `RawEvent` block: the new flag will be listed with the other `flags` bits.
- `docs/ai/memory/`: a new file if the in-VM measurement contradicts the assumption that a
  tracepoint's `args[1]` is the path pointer on every matrix kernel — it is an ABI detail worth
  keeping if it bites.

**Closing.** Verified against `docs/01_phase5_implementation_plan.md:1611` (the task row),
`:1596` (the scope row naming `sys_enter_openat`), Annex D.1's ring-buffer row, and
`docs/ai/memory/seccomp-unotify-toctou.md:7`. One claim of the skeleton needed narrowing rather
than falling: "Events reach `agentd` with correct `RawEvent` layout" is not sufficient as a
done-condition, because a path copied from user memory is not the path the kernel opens; the
point adds `FLAG_PATH_UNRESOLVED` and its test so the record cannot claim more than it knows.
Open: whether 5.4 should get the perf-buffer fallback in F2 — this point says no and hands it to
`F3.PT.*`, which is a scope decision the owner may reverse.

---

## Point 2 — `F2.WS.02`: the hot loop wired, end to end

**Done when:** zero allocations in steady state, verified by `dhat`.

### 1. Challenge

*Is this the best solution?* The loop already exists and is measured: `aisme-core::engine::Engine`
does drain → classify → intern → risk → detect → sink, and `bench-hotloop --events 5000000`
reports 0 allocations and 0 drops. What F2 adds is one stage the skeleton names and F1 does not
have — **canonicalize** — plus the real sensor at one end and the real WAL at the other.

*Is it coherent with the specs?* One friction, and it is structural rather than cosmetic:
canonicalizing a path is I/O (`readlink`, `openat2(RESOLVE_NO_SYMLINKS)`, `/proc/self/fd`), and
`aisme-core` has no I/O by rule `A-01`. Putting it inside `Engine::tick` would put a syscall in
L1 and break the rule the whole layering exists for; leaving it to the consumer would let two
consumers canonicalize differently, which is worse.

*Can it be simplified?* Yes: the loop does not need to know how a path is resolved, only that
something resolves it. One L1 trait, one L3 implementation, one bounded cache — and `F5.CO.04`
already promises "canonical path matching with a bounded resolution cache", so this is that
component arriving early rather than a new one.

### 2. Verification

Safe and clear, with two properties made explicit so they are not assumed:

- **The resolver is fallible and says so.** A path that cannot be resolved — the file was
  unlinked between the syscall and the drain, a `/proc` entry vanished — must arrive as
  *unresolved*, keeping `FLAG_PATH_UNRESOLVED`, never as a guess. `F2.WS.01`'s flag is what makes
  this expressible; without it the loop would have to choose between a wrong canonical path and
  dropping the event.
- **The cache is bounded and its evictions are counted.** An unbounded resolution cache is a slow
  memory leak on a daemon with a 50 MB budget, and a silent one: the interner's shape
  (`F1.EV.04`) already solves this, so the resolver will reuse it rather than invent a second
  policy.
- The plan says "verified by `dhat`". The measurement that exists is a counting global allocator
  (`F1.RT.03`), which answers the same question exactly and needs no dependency and no second
  global allocator. That deviation is already recorded in the `F1.RT.05` row's neighbourhood;
  this point restates it rather than quietly diverging.

### 3. Implementation

- `aisme-core` will gain `trait PathResolver { fn resolve<'a>(&mut self, raw: &'a [u8], out: &'a mut [u8]) -> Option<usize>; }`
  — bytes in, bytes out, no allocation, `None` when the path cannot be resolved. It is **not** one
  of the three §3.2 traits and therefore not part of the freeze; it will be documented as an
  internal ingest hook so a later reader does not mistake it for a platform trait.
- `Engine::tick` will take `&mut dyn PathResolver`. The signature change is F2's, before F2's own
  gate, and touches no §3.2 trait.
- `crates/aisme-linux` will implement `RealpathResolver`: `openat2` with `RESOLVE_NO_MAGICLINKS`
  where available, `realpath(3)` semantics otherwise, an LRU keyed by `(dev, ino)` sized from
  `budgets.toml`, and a counter per outcome (hit, miss, unresolved).
- `aisme-agentd` will compose sensor → engine → WAL sink, replacing `CountingSink` with the real
  `WalSink` from `F2.WS.07`, and will run the loop on the `LocalSet` of `F1.RT.02`.
- The `MockSensor` path keeps working with a `NullResolver` that returns the input unchanged, so
  `F2.WS.10`'s no-kernel run measures the same code.

### 4. Tests

**Existing to change:** `crates/aisme-core/tests/hot_loop_allocations.rs` — it will pass a
`NullResolver` and keep asserting zero allocations, so the new stage is inside the measured
region rather than beside it. `crates/aisme-core/src/engine.rs`'s unit tests take the same
parameter.

**New:**

- Resolver unit tests in `aisme-linux`: a symlink chain resolves to its target; a relative path
  resolves against the session's cwd; an unlinked file resolves to `None` and the event keeps
  `FLAG_PATH_UNRESOLVED`; a `/mnt/c` path under WSL2 resolves without hanging (the 9p caveat of
  §2.16.1 is a real one and `T4.6.07` will own it properly).
- A cache test: N distinct paths through a cache of M < N evict exactly N − M times and never
  grow the allocation.
- An end-to-end in-VM test: `openat` of a symlink produces one event whose canonical path is the
  target and whose `FLAG_PATH_UNRESOLVED` is **clear**.

### 5. Documentation

- Plan §F2's scope table: the Hot loop row will name the resolver as the stage that turns a
  requested path into a canonical one, and name `F5.CO.04` as the task that widens it.
- Plan §F1.RT.03's row: a sentence recording that the zero-allocation measurement is a counting
  allocator, not `dhat`, with the reason — the same correction already made for `rkyv`.
- `docs/ai/STATE.md`, `docs/CHANGELOG.md`: the usual rows.

**Closing.** Verified against the plan's `F2.WS.02` row (`:1613`), the scope table's Hot-loop row
(`:1600`), `A-01` as `xtask/src/rules.rs:62` enforces it, and the existing measurement in
`crates/aisme-core/tests/hot_loop_allocations.rs`. The skeleton's phrase "verified by `dhat`"
falls: the property is measured by a counting allocator and will stay that way, for the reasons
recorded when `F1.RT.03` closed. Open: nothing blocking; the `/mnt/c` resolution behaviour is a
known unknown that `T4.6.07` measures rather than this point.

---

## Point 3 — `F2.WS.03`: `agentsim` emits one synthetic `ToolCall` with a hidden token

**Done when:** ground-truth scoring is possible from day one.

### 1. Challenge

*Is this the best solution?* The format and the replayer exist (`F1.SIM.01`, `F1.SIM.02`) and
already keep the token on a stream the engine never reads. What is missing is the **live**
path: at F2 the declared tool call has to reach `agentd` while the actions happen, or correlation
has nothing to match against.

*Is it coherent with the specs?* The gap is that Annex I has no method for "a tool call is
starting". Three candidates:

1. **The cooperative JSONL tail** — explicitly out of scope for F2 (the scope table lists only
   the one tracepoint).
2. **The SDK** — F9, and a much larger surface.
3. **The control-plane socket** — already exists (`F1.IPC.01`), already authenticates by peer
   identity, and is the channel `aisme run` will use anyway.

*Can it be simplified?* Yes, and the simplification is the honest one: F2 adds **one** method,
`declareToolCall`, to Annex I rather than inventing a private side channel that would later have
to be removed. The protocol is frozen at GATE F8a, not now, so adding it here is in time.

### 2. Verification

Safe, clear, compliant, with one property that must be stated or the whole measurement is void:

- **The correlation token never crosses the socket.** `agentsim` will send
  `declareToolCall { toolcall_id, tool_name, params_hash, declared_targets[] }` — and will write
  the token only to its ground-truth stream. If the token reached `agentd`, the correlation
  engine could join on it and the precision/recall numbers of §4.6 would measure nothing. A test
  will assert the socket bytes contain no token.
- **A declared tool call is not an authorization.** `declareToolCall` will be
  `AnyAuthenticated` and will create no grant, change no verdict and carry no scope. It is an
  observation the agent volunteers, and `DT-04` exists precisely because a declaration may be a
  lie.
- **Rate and bound.** The method will be rejected beyond a per-session rate (a declaration
  storm is a cheap denial of service against the correlation window); the refusal is a
  **result**, not an error, per Annex I.2.

### 3. Implementation

- `aisme-proto::rpc`: add `Method::DeclareToolCall` (`"declareToolCall"`), `AuthClass::AnyAuthenticated`,
  idempotent = no. Annex I.1's table gains the row.
- `aisme-agentd::ipc`: handle it by pushing a `SemanticPayload`-carrying `RawEvent`
  (`kind = ToolCall`) into the same ring the sensor feeds, so the correlate step sees one stream
  and the WAL records the declaration next to the actions it caused.
- `aisme-agentsim`: `--declare <socket>` will send the declaration for every `toolcall` entry of
  the trace as it replays, at the entry's own time, keeping the token on stderr as it does today.
- The synthetic tool call of the skeleton will be exactly the trace's first entry, so F2 needs no
  new fixture.

### 4. Tests

**Existing to change:** `crates/aisme-agentsim/src/replay.rs`'s "the token goes to the scorer"
test gains a third writer — the socket — and asserts the token is absent from it too.

**New:**

- A protocol test: `declareToolCall` from a peer inside a session cgroup is accepted (an agent
  may declare its own work), and creates no grant.
- A rate test: declarations beyond the bound return `{"outcome":"rate_limited"}` as a result,
  and the accepted ones are unaffected.
- An end-to-end scoring test on `MockSensor`: one declared tool call, three actions, and a scorer
  that joins on the ground-truth stream reports precision 1.0 and recall 1.0 — the day-one
  scoring the task's done-condition asks for.

### 5. Documentation

- Plan Annex I.1: the new method row, its class, and the sentence that it authorizes nothing.
- Plan §F2's task row: `F2.WS.03` will name the transport, since "emits" is currently silent
  about it.
- `docs/design/02_aisme-run.md`: step 3 already registers the session over the socket; a line
  will note that the same socket carries declarations.

**Closing.** Verified against the plan's `F2.WS.03` row (`:1615`), the F2 scope table (which
excludes the cooperative sensor), Annex I.1's method list, and `crates/aisme-agentsim/src/replay.rs`
as it stands. Nothing of the skeleton fell; what was missing was named: the task said "emits"
without a channel, and this point fixes the channel as one new Annex I method with an explicit
prohibition — the token does not cross it — plus the test that proves the prohibition. Open: the
rate bound's value, which will be set from the reference workload's 200 tool calls/hour rather
than guessed.

---

## Point 4 — `F2.WS.04`: one rule, compiled by the real compiler, published to a real BPF map

**Done when:** the policy generation counter increments; no torn read.

### 1. Challenge

*Is this the best solution?* The seam being proven is *compile → artefact → atomic publish*, and
the plan is explicit in "Why each seam matters" that **kernel-side evaluation is F3's**: at F2 the
sensor is a tracepoint and enforcement is seccomp plus Landlock, so nothing in the kernel reads
the map. Publishing to a map nobody reads looks wasteful until one asks what the alternative
proves: a user-space double buffer would prove the compiler produces bytes, not that it produces
bytes a BPF map will accept, and the map's key layout, value size and `BPF_ANY` update semantics
are exactly where a compiler's output meets reality.

*Is it coherent with the specs?* Yes, with one omission to fix: `PL-04` requires "atomic
publication with a generation counter; readers never lock, never see a torn policy", and neither
`F1.PL.*` nor this row says *how*. Updating an `LPM_TRIE` entry by entry is not atomic — a reader
mid-update sees half a policy — so the mechanism must be named here rather than discovered in F3.

*Can it be simplified?* Yes: `BPF_MAP_TYPE_ARRAY_OF_MAPS` with two inner tries and one generation
index is the standard shape and needs no new invention. Publish into the idle inner map, then a
single `bpf_map_update_elem` on the outer map swaps it; the swap is one word.

### 2. Verification

Safe, clear, compliant, with three properties pinned:

- **The swap is the only mutation a reader can observe.** Filling the idle trie touches a map no
  program is looking up; the outer array's update is a single element write. That is what makes
  "no torn read" a property rather than a hope.
- **The generation counter is monotonic and published with the policy**, not beside it: the
  generation lives in the same swap (a second array element written before the swap, read after),
  so a reader that sees generation N sees policy N. `PolicyGeneration` (`F1.PL.03`) is already
  the type.
- **The compiler is the real one.** `F2.WS.04` will call `aisme_core::policy::compile_with` on
  AISME-PL text, not a hand-built `CompiledPolicy`. A skeleton that published a struct literal
  would prove nothing about the pipeline it exists to prove.
- The map is created and updated by `aisme-loaderd` (`CAP_BPF`), never by `agentd`
  (`CapabilityBoundingSet=`), which is `F1.RT.07`'s split doing its job.

### 3. Implementation

- The F2 policy source will live at `deploy/policy/skeleton.aisme` and will be exactly the
  scope table's three rules plus the write scope: `deny /etc/shadow`, `escalate ~/.aws/**`,
  default allow, and the `F2.WS.11` scope rule. It will be a file, not a string in code, so the
  gate compiles what an operator would.
- `aisme-linux` will gain `BpfTrieBackend`, implementing `PolicyBackend` (`F1.PL.03`) with
  `BackendKind::BpfTrie`: `lower` will turn a `CompiledPolicy` into a set of
  `(prefix_len, path_bytes) → verdict` entries and refuse — per `F1.PL.08` — every rule whose
  keys it cannot express, naming them.
- `aisme-loaderd` will create `AISME_POLICY` (`ARRAY_OF_MAPS`, 2 inner `LPM_TRIE`s) and
  `AISME_POLICY_META` (`ARRAY`, `[generation, active_index]`), fill the idle trie, write the
  generation, then swap. It will return the new `PolicyGeneration` over the handoff socket.
- `agentd` will hold the generation it was told and include it in `getCapabilities` and in every
  WAL segment header (`F1.RT.05` already carries the field).

### 4. Tests

**Existing to change:** none — `F1.PL.*`'s suites already cover compilation; this point adds the
publication path beside them.

**New:**

- A backend test on the host, no kernel: `BpfTrieBackend::plan` on the skeleton policy accepts
  the three path rules and rejects nothing; a policy with a `taint_any` key is rejected with the
  §B.9 message.
- An in-VM publication test: publish generation 1, read the meta array, publish generation 2, and
  assert the active index flipped and the generation rose by one.
- **The torn-read test, which is the point of the task**: a reader loop in user space samples the
  meta array and the active trie a million times while a writer republishes in a tight loop;
  every sample must be internally consistent (generation N with policy N). Sampling from user
  space is weaker than sampling from a BPF program, and the test will say so in its own comment
  — the kernel-side version arrives with `F3.PT.02`.
- A negative on the split: `agentd` attempting the same update fails with `EPERM`, which is the
  test that `F1.RT.07`'s empty capability set is real.

### 5. Documentation

- Plan `F2.WS.04`'s row: the double-buffer mechanism named, so F3 inherits it rather than
  reinventing it.
- Plan §B.2 `PL-04`: the same sentence, since that is where the requirement is stated.
- `docs/ai/memory/`: a new durable note if the in-VM run shows `ARRAY_OF_MAPS` behaving
  differently on any matrix kernel — inner-map replacement semantics changed across releases and
  that is exactly the kind of fact this project keeps.

**Closing.** Verified against the plan's `F2.WS.04` row (`:1616`), the "Why each seam matters"
table that scopes kernel-side evaluation out of F2, §B.2 `PL-04`, and `F1.PL.03`'s
`PolicyBackend` as implemented. Nothing of the skeleton fell; one silence was filled: "published
atomically" had no mechanism anywhere in the plan, and this point fixes it as an array-of-maps
double buffer with the generation inside the same swap. Open: whether the F2 policy file lives at
`deploy/policy/` — the Part VI tree has no policy directory yet, so the tree gains one when this
point is implemented.

---

## Point 5 — `F2.WS.05`: `SeccompEnforcer` — and the question the owner has now answered (`Q-13`)

**Done when:** a denied `openat` returns `-EACCES` to the caller.

### 1. Challenge

*Is this the best solution?* For the escalate class at L2 there is no alternative:
`seccomp_unotify` is the only mechanism that can hold a syscall while a human is asked, and
`H-01`'s correction is the reason the whole design uses it instead of a blocking kernel callback.

*Is it coherent with the specs?* **Here the skeleton and a domain rule collide**, and the
collision is the most valuable thing this amplification found.

The rule (`docs/ai/memory/seccomp-unotify-toctou.md`, and `H-01`): *never decide from user memory
read in a notification*. A `seccomp_unotify` notification carries the syscall's **arguments**,
and for `openat` the path is a pointer into the target's address space. Between the supervisor
reading that pointer and the kernel resolving the path, the target — or a thread of it — can
change what the string points to. Deciding *allow* on the string the supervisor read is a
classic TOCTOU: the syscall proceeds against a different file.

`F3.EN.12` exists precisely to close this: *"escalate-class opens at L2 are resolved by the
supervisor and delivered with `SECCOMP_IOCTL_NOTIF_ADDFD`: the target receives the fd the
supervisor validated and never re-resolves the path"*. But `F3.EN.12` is in F3, and `F2.WS.05` is
in F2 — so the walking skeleton, as written, would demonstrate an allow decision that is
TOCTOU-vulnerable, in the phase whose entire purpose is to prove the seams are sound.

*Can it be simplified?* Two ways, and they differ in what they cost:

- **(a) Pull `F3.EN.12` into F2.** `ADDFD` is one ioctl and a `pidfd_getfd`-shaped dance; the
  supervisor opens the path itself, validates it, and hands the descriptor back. F2 grows by
  perhaps a day and the seam is proven correctly.
- **(b) Keep F2's allow path narrow.** F2 answers `deny` with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`
  never used for allow: an *allow* is delivered as `CONTINUE`, which re-executes the syscall and
  therefore re-resolves the path — the very race. To stay safe without `ADDFD`, F2 would have to
  treat every escalate-class *allow* as a **deny with a stated reason**, which makes the
  headline demo ("the terminal asks, you answer, the syscall obeys") impossible.

### 2. Verification

The skeleton as written is **not** 100 % safe, the point stopped and asked (`Q-13`), and the owner
has answered: **the mechanism of `F3.EN.12` enters `F2.WS.05`.** What follows is the decision as
taken, with the reasoning kept because a decision without its reasoning is re-litigated in six
months.

**Why no weaker answer survives the threat model.** An *allow* delivered with
`SECCOMP_USER_NOTIF_FLAG_CONTINUE` makes the kernel **re-resolve the path after the decision**:
the human authorizes `~/.aws/credentials` and the agent obtains a different file. That does not
weaken the escalate class, it removes it, and it is precisely what `H-01` and
`docs/ai/memory/seccomp-unotify-toctou.md` forbid.

**Why freezing the session is not the cheap alternative.** The obvious mitigation — hold the rest
of the session with the cgroup freezer while the human answers — does not close the race, and
saying so here stops it being proposed later. The attack does not need the *bytes of the path* to
change: renaming a directory component or swapping a symlink changes what the same string
resolves to, and any process on the machine can do that, inside the session or not. The freezer
is also out of F2's scope. Only a descriptor the supervisor opened and validated survives.

**The decision, with the two limits that make it small and fail-closed:**

1. On *allow*, the supervisor opens the file itself and answers with
   `SECCOMP_IOCTL_NOTIF_ADDFD`, so the target receives the descriptor the supervisor validated
   and never re-resolves anything. `SECCOMP_ADDFD_FLAG_SEND` (kernel ≥ 5.14) is used where it
   exists — it adds the descriptor and returns it as the syscall's value in one step — and the
   two-step `ADDFD` then `RESP` where it does not. Both are safe with respect to *our* decision:
   the notified thread is blocked throughout.
2. On *deny*, `-EACCES` and no descriptor. **`CONTINUE` is never used to permit a syscall that
   carries a path.**
3. **Limit one — only what F2 can reproduce faithfully.** `openat` for reading, `O_CLOEXEC`.
   Any escalate-class open whose flags this subset cannot reproduce exactly (`O_CREAT`,
   `O_TRUNC`, `O_APPEND`, `O_DIRECTORY`, and the `open`/`openat2` entry points) is **denied with
   the reason stated**, never allowed. A descriptor that does not mean what the caller asked for
   is worse than a refusal.
4. **Limit two — only when the target's uid is the supervisor's.** Opening a file with
   credentials the target does not have would be a privilege escalation served by the guard
   itself. In F2 both are the same user; where they are not, the answer is a deny with the reason.
   Credential-matched opening is `F3.EN.12`'s widening.
5. `SECCOMP_IOCTL_NOTIF_ID_VALID` before every response, and the classic filter installed with
   the escalate class defaulting to `EACCES`, so a supervisor that dies denies rather than allows.

**This becomes an invariant, not a habit.** The rule is the kind this project does not leave to
memory:

> **`I-28` — A decision that permits a path-bearing syscall is delivered as a validated
> descriptor, never by re-executing the syscall.** Where the kernel cannot deliver one, the
> escalate class degrades to *deny* and the degradation is declared (`I-16`, `I-19`).

**What the decision does to `F3.EN.12`.** It stops being "close a hole F2 left" and becomes
widening: the full flag matrix, `open` and `openat2`, directory opens, credential-matched
opening, and the story for kernels without `ADDFD`. Its plan row will say so.

**One consequence that must be measured, not assumed** — it is large enough to be its own point
and is amplified as **Point 13**: `ADDFD` arrived in kernel 5.9, and §2.23 annotates its own
capability field as `seccomp_unotify: bool, // kernel >= 5.9 (CONTINUE >= 5.5)`. The plan
therefore already meant *the decidable form* by that field, while `F0`'s probe measured the
notifier (`SECCOMP_GET_NOTIF_SIZES`, present since 5.0) and reported `yes` on 5.4.

### 3. Implementation

- `crates/aisme-linux` will gain `SeccompEnforcer` implementing `Enforcer`: `publish` installs the
  classic filter for the escalate class from `aisme run` before `exec` (it cannot be installed
  later without a window); `suspend`/`resume` return `Unsupported` at F2 with the reason (the
  freezer is F3); `respond` answers the outstanding notification; `tier` is `Partial`.
- The notification loop runs on `agentd`'s control thread, never the hot loop: a human's answer
  takes seconds and the hot loop's budget is microseconds.
- The allow path, in order: `ID_VALID` → read the request → check `flags` against the F2 subset
  (deny with reason if outside) → check the target's uid against the supervisor's (deny with
  reason if different) → obtain the target's cwd via `pidfd` → `openat2` with
  `RESOLVE_NO_MAGICLINKS` → evaluate the *opened* file against the compiled policy → `ADDFD`
  (with `SEND` where available) → respond.
- `aisme-core::capability::CapabilitySet` gains `seccomp_addfd: bool`, and
  `aisme-core::tier::degradations` gains its sentence: *no `SECCOMP_IOCTL_NOTIF_ADDFD`: an
  escalate-class allow cannot be delivered as a validated descriptor; the class degrades to deny
  (T1 allow lost)*.
- Every answer is recorded as a `VerdictIssued` event carrying `decided_by`, the channel, and
  whether the target received a validated descriptor — so the WAL distinguishes a permitted open
  from a re-executed one.

### 4. Tests

**New, and the first two are written before the enforcer:**

- **The TOCTOU test, in both of its forms.** (i) A target that rewrites the path buffer between
  the syscall and the supervisor's read must receive the descriptor for the file the supervisor
  validated, not the swapped one. (ii) A second process that `rename`s a directory component
  between the decision and the response must not change which file the target receives. Form (ii)
  is the one the freezer would not have caught, and it is the reason the decision is what it is.
- A flags test: `O_CREAT`, `O_TRUNC`, `O_DIRECTORY` and an `openat2` entry are each denied with
  their stated reason, and the denial names the flag rather than saying "unsupported".
- A credentials test: a target running as another uid is denied with the reason, and no
  descriptor is delivered.
- A supervisor-death test: kill `agentd` with a notification outstanding; the syscall fails
  closed.
- A stale-notification test: the target dies before the answer; `ID_VALID` catches it and the
  supervisor does not answer into a reused id.
- A degradation test on a kernel without `ADDFD`: the escalate class denies, the capability
  banner names the lost function, and `aisme run` still works.
- In-VM, the gate's own line: `cat /etc/shadow` inside a session returns `-EACCES` and the WAL
  carries the deny with its rule id.

### 5. Documentation

- Plan `F2.WS.05`'s row: the `ADDFD` mechanism, the two limits, and the reference to `I-28`.
- Plan `F3.EN.12`'s row: rewritten as the widening, naming what F2 already did.
- `docs/ai/invariants.md`: `I-28`, with its test named.
- Plan §2.23's `Capabilities` block: `seccomp_addfd` beside `seccomp_unotify`, and the annotation
  corrected so the two versions are not conflated again.
- `docs/ai/memory/seccomp-unotify-toctou.md`: a line recording that `F2.WS.05` is where the rule
  first becomes code, and that the directory-rename form is why a freezer does not substitute.
- `docs/ai/STATE.md`: `Q-13` moved from open to answered, with the date and the answer.

**Closing.** Verified against the plan's `F2.WS.05` row (`:1617`), `F3.EN.12` (`:1711`), `H-01`,
`docs/ai/memory/seccomp-unotify-toctou.md:7`, §2.23's capability annotation, and the kernel
versions of `ADDFD` (5.9) and `SECCOMP_ADDFD_FLAG_SEND` (5.14). `Q-13` is **answered**: the
mechanism moves into F2, bounded to read-only `openat` at matching credentials, with everything
outside that subset denied and stated. Two claims fell in the process — the skeleton's silence
about the allow path, which would have shipped a full bypass of the escalate class in the phase
whose purpose is removing risk; and the tempting mitigation of freezing the session, which the
directory-rename form of the attack walks straight through. What remains open is not a decision
but a measurement, and it has its own point: whether `ADDFD` exists on each matrix kernel, and
what that does to the L2- boundary (**Point 13**).

---

## Point 6 — `F2.WS.06`: `TerminalAdjudicator`, and the unattended answer

**Done when:** a human answers in the terminal and the syscall obeys; `AISME_TERMINAL_ANSWER=<d|1|s|a>`
is accepted for unattended gates and recorded as such in the WAL.

### 1. Challenge

*Is this the best solution?* Yes, and for a reason the permission model states plainly: when a
session is started as `aisme run -- <cmd>`, **we own the terminal**, so the prompt goes where the
developer is already looking — over SSH, in tmux, in a container, and in WSL2 where the daemon is
in Linux and the desktop is Windows. No desktop stack has to be guessed (`§7.3`).

*Is it coherent with the specs?* The prompt's shape is already specified — four answers
(`[d] deny`, `[1] allow once`, `[s] allow this session`, `[a] always`), the stated intent line,
the deterministic severity line, and `deny` as both the default action and the default focus. The
adjudicator's contract is already frozen (`Adjudicator`, `F1.PA.01`): channel `Terminal`, budget
10 s focused / 20 s unfocused (§2.20.5), ceiling `LOCAL`.

*Can it be simplified?* One simplification and one refusal:

- **Simplify**: the terminal adjudicator does not need its own timeout machinery. The ladder
  (`F1.PA.03`) already applies the channel budget and the timeout default; the adjudicator only
  has to return a verdict or not return one.
- **Refuse to simplify**: `AISME_TERMINAL_ANSWER` must not be "read the variable and answer".
  An environment variable that answers security prompts is an authorization bypass wearing a
  convenience hat, and the agent being supervised **inherits the environment of the session**.

### 2. Verification

Not safe as literally written; three constraints make it so, and they are not optional:

- **The variable is read once, in `aisme run`, before `exec` — never by the adjudicator from the
  ambient environment.** `aisme run` captures it, strips it from the child's environment (the
  same hygiene step that strips `LD_PRELOAD`, `docs/design/02_aisme-run.md` §4), and passes the
  answer to `agentd` as a session property. Otherwise a supervised agent could set the variable
  for its own children and answer its own prompts.
- **It may not answer above `Severity::Medium`, and never for an `I-05` group.** A canned answer
  is a `Policy`-channel answer in everything but name, so it inherits `GrantCeiling::POLICY`'s
  limits: `[a] always` from a variable does not create a grant at all. The three never-promptable
  groups are unreachable by construction (`F1.PL.04` refuses to compile them promptable), but the
  ceiling is checked anyway, because a defence that depends on another defence having worked is
  one defence.
- **Every canned answer is recorded as canned.** The `VerdictIssued` event will carry
  `channel = Policy` and `decided_by` naming the rule, plus a flag in `DecisionPayload` saying the
  answer came from the environment. A WAL that cannot distinguish "a human said yes" from "a
  variable said yes" is a forensic record with a hole in it, and this is the plan's own phrase —
  *recorded as such in the WAL* — made precise.

### 3. Implementation

- `crates/aisme-cli` (or `aisme-agentd`'s TTY module, decided at implementation time by where the
  controlling terminal lives — `aisme run` owns it) will gain `TerminalAdjudicator` implementing
  `Adjudicator`: `channel` → `Terminal`; `budget` → `AdjudicationChannel::Terminal.budget(true)`;
  `notify` → one line for a `warn`, never blocking; `ask` → draws the §7.3 prompt on the
  controlling TTY and reads one keystroke in raw mode; `max_grant` → `GrantCeiling::LOCAL`.
- The prompt will be drawn **exactly** as §7.3 shows it, including the risk line fed by `DT-09`'s
  deterministic score (`F1.DT.02`) and never by an Observer opinion (`I-04`, `H-12`).
- Timeout is the ladder's: if the read does not complete within the budget, `ask` yields nothing
  and `AdjudicatorLadder` applies the session default, which for the escalate class is `deny`.
- `aisme run` will capture `AISME_TERMINAL_ANSWER`, strip it from the child environment, and pass
  it in the session-open call; `agentd` will store it per session and answer with it through a
  `CannedAdjudicator` inserted **below** `TerminalAdjudicator` in the ladder, so a real terminal
  always wins when one exists.
- `DecisionPayload` will gain one flag bit (`ANSWER_FROM_ENVIRONMENT`) in its existing `pad0`
  byte — append-only, no offset moves.

### 4. Tests

**Existing to change:** `crates/aisme-core/src/ladder.rs`'s tests gain a rung for the canned
adjudicator, asserting the terminal outranks it.

**New:**

- A prompt-rendering test against the §7.3 text: the four answers, the intent line, the severity
  line, and `deny` as the default focus. Rendering is pure; the TTY is not needed.
- A keystroke test with a pseudo-terminal: each of `d`, `1`, `s`, `a` produces the matching
  verdict; an unknown key redraws rather than defaulting; EOF is a deny.
- A timeout test: no key within the budget yields the session default, and the WAL records the
  timeout as the reason.
- **The bypass tests**, which are the point of the verification section: (i) a child that sets
  `AISME_TERMINAL_ANSWER=a` in its own environment does not affect its own prompts; (ii) a canned
  `a` on a `High` severity is refused and falls through to the next rung; (iii) a canned answer
  never creates a grant; (iv) the WAL entry for a canned answer is distinguishable from a human's.
- An in-VM gate rehearsal: `AISME_TERMINAL_ANSWER=d cargo xtask vm run -- aisme run -- sh -c 'cat ~/.aws/credentials'`
  denies, exactly as GATE F2's fourth line requires.

### 5. Documentation

- Plan `F2.WS.06`'s row: the three constraints, since "accepted for unattended gates" currently
  reads as unconditional.
- `docs/design/01_permission-model.md` §7.3: a subsection for the unattended answer with its
  ceiling and its recording, so the prompt spec and its bypass live together.
- `docs/design/02_aisme-run.md` §4: `AISME_TERMINAL_ANSWER` added to the **stripped** list with
  the reason.
- Plan §F1.1's `DecisionPayload`: the new flag.

**Closing.** Verified against the plan's `F2.WS.06` row (`:1618`),
`docs/design/01_permission-model.md` §7.3's prompt, §2.20.5's budgets, `F1.PA.03`'s ladder as
implemented, and §4 of the `aisme run` note. The skeleton's claim that
`AISME_TERMINAL_ANSWER` is "accepted for unattended gates" survives but not unconditionally: as
written it would let a supervised agent answer its own prompts, so the variable is captured once
by `aisme run`, stripped from the child, capped at `Medium`, barred from creating grants, and
recorded as canned. Open: which crate owns the TTY — `aisme-cli` and `agentd` are both defensible
and the choice follows where `aisme run`'s process lives, which `F2.WS.08` settles.

---

## Point 7 — `F2.WS.07`: `forensicd` tails the WAL by offset

**Done when:** kill `forensicd` mid-stream; it resumes with zero loss.

### 1. Challenge

*Is this the best solution?* The format is done (`F1.RT.05`): fixed 320-byte records behind a
segment header, replay that stops at a torn tail and returns the offset **before** it. What F2
adds is the file: writing, rotating, fsyncing, and a reader that follows.

*Is it coherent with the specs?* Two gaps in the skeleton, both about the word *resumes*:

1. **Where the resume point lives.** "Resumes with zero loss" needs the reader's offset to
   survive the kill. If it lives only in memory, a kill loses it; if it is written without
   ordering, a crash between the write and the work leaves it ahead of what was processed.
2. **What the writer promises.** The plan says "`fsync` policy configurable" and nothing more.
   A reader can only resume from what the writer durably wrote, so the two are one property.

*Can it be simplified?* Yes: the reader's checkpoint is written **after** the work it accounts
for, never before, and it may be stale but never ahead. A stale checkpoint re-reads records —
which is why `forensicd`'s consumers must be idempotent by record `seq`, and that is a cheaper
property to hold than exactly-once delivery.

### 2. Verification

Safe and clear once three rules are fixed:

- **Checkpoint after work, fsync the checkpoint, then continue.** The failure mode becomes "some
  records are processed twice", which the `seq` is there to absorb, rather than "some records are
  never processed", which loses evidence (`I-17`: a gap must appear as a gap; here there must be
  no gap at all).
- **The writer's default is `fsync` per batch, not per record.** Per record is a syscall per event
  on the T-tel path; per batch bounds the loss window to one batch, and a batch is what the WAL
  is appended in. The knob exists for an operator who wants per-record; the default is stated.
- **A torn tail is not an error, and a foreign wire is.** `F1.RT.05` already separates them, and
  `forensicd` will act accordingly: on a torn tail it waits for the writer to finish the record;
  on a foreign wire it skips the segment, warns, and does **not** parse (§3.6).

### 3. Implementation

- `aisme-agentd` will gain `WalSink` implementing `EventSink`: it appends `RawEvent` records to
  the current segment, rotates at `SEGMENT_BYTES` writing a fresh header (wire version, schema
  hash, segment number, first `seq`, policy generation), and fsyncs per batch by default.
- `crates/aisme-forensicd` will gain the tailer: open the newest segment, `replay` from the
  checkpoint, process, checkpoint, then follow the file (poll at a bounded interval — inotify is
  an optimisation F5 can add and a dependency F2 does not need).
- The checkpoint is `<state-dir>/forensicd.offset`, written as `segment,offset` and fsynced,
  written **after** the batch it accounts for.
- At F2 "process" is one printed line per event, which is the skeleton's Surface row. DuckDB,
  Parquet, Merkle and OTLP stay out (the scope table forbids them).

### 4. Tests

**New:**

- Round trip: write N events, tail them, and assert the printed `seq`s are `0..N` with no gap.
- **The kill test, which is the done-condition**: write, kill `forensicd` mid-stream with
  `SIGKILL`, restart, and assert every record appears at least once and none is missing. Run it
  fifty times at random kill points, because a resume bug that appears once in ten runs is the
  kind this test exists to find.
- A torn-tail test: truncate the segment inside a record, tail it, assert the reader waits and
  then reads the record once the writer completes it.
- A foreign-wire test: a segment with a bumped wire version is skipped with both versions named
  and nothing from it is printed.
- A rotation test: writing past `SEGMENT_BYTES` opens a new segment whose header's `first_seq` is
  the next record's, and the tailer follows across the boundary.

### 5. Documentation

- Plan `F2.WS.07`'s row: the checkpoint-after-work rule and the per-batch fsync default, since
  "resumes with zero loss" is a property of both.
- Plan §F1.RT.05's row: the same two sentences, where the format is defined.
- `docs/ops/`: the first runbook entry — where the WAL and the checkpoint live, and what to do
  when a segment is refused as foreign.

**Closing.** Verified against the plan's `F2.WS.07` row (`:1619`), `F1.RT.05` as implemented in
`crates/aisme-core/src/wal.rs`, and §3.6's rule for the `agentd`↔`forensicd` pairing. Nothing of
the skeleton fell; two silences were filled — where the resume point lives and when it is written
— and the ordering chosen (checkpoint after work) makes the failure mode duplicate delivery
rather than lost evidence, which is the only acceptable direction for a forensic record. Open:
the fsync default is stated here as per batch; if the 72 h soak of §4.4 shows the batch window
costs more than the loss window is worth, the knob moves and the plan row moves with it.

---

## Point 8 — `F2.WS.08`: `aisme run -- <cmd>` establishes session identity and scope

**Done when:** the session's own process tree is correctly attributed.

### 1. Challenge

*Is this the best solution?* It is the *only* one that gives identity without inference: we own
the process from before its first syscall (`H-18`), so nothing has to be guessed from a binary
catalogue or a lineage heuristic. Everything else in session discovery exists for sessions
nobody started this way.

*Is it coherent with the specs?* The nine steps are already written in
`docs/design/02_aisme-run.md` §3, and F2 owns steps 1, 2, 7 and the parts of 3 and 8 that the
skeleton needs. Two frictions:

1. **Creating the session cgroup needs a delegated subtree.** `F1.RT.07` delegates one to
   `aisme-agentd` (`Delegate=yes`, `DelegateSubgroup=sessions`), and `aisme run` is a *user*
   process that is not in it. It therefore cannot `mkdir` there itself; it must ask.
2. **The order is load-bearing.** Steps 4–6 happen before `exec` "so there is no window in which
   the child runs unsupervised". A skeleton that placed the child in the cgroup after `exec`
   would prove the seam and hide the race.

*Can it be simplified?* Yes: `aisme run` does not need to create anything. It asks `agentd` to
open a session, receives the cgroup path and the policy generation, moves **itself** into the
cgroup, and then `exec`s — the child inherits membership by fork semantics, which is the plan's
own phrasing ("place itself in it, so the tree is captured by construction").

### 2. Verification

Safe and clear, with three properties pinned and one refusal:

- **Refuse to start when `agentd` is unreachable.** The `aisme run` note calls this "the one
  failure this command must not have": running an agent unsupervised while appearing supervised.
  F2 will implement the refusal, not defer it, because the demo it enables is exactly the
  situation where someone would be tempted to continue.
- **The session id is `agentd`'s to mint**, never the client's: a client-chosen id is a client
  that can join another session.
- **Scope narrows, never widens.** `--scope` and `.aisme/scope.toml` may only narrow what
  detection found (`F7.PS.07`'s owner decision); F2 implements the narrowing rule even though the
  scope file's full handling is F7's, because implementing it later would mean shipping a widening
  path first.
- **Placement before `exec`, verified by the test rather than by the comment**: the child's
  `/proc/<pid>/cgroup` is read in the test and must equal the session's.

### 3. Implementation

- `aisme-proto`: one new method, `openSession { scope[], profile } -> { session_id, cgroup_path, generation }`,
  class **local peer** (a remote device may not open a session on a workstation), non-idempotent.
  Annex I.1 gains the row. `closeSession { session_id }` joins it, idempotent.
- `aisme-agentd`: `openSession` creates `<delegated>/sessions/<id>` inside its own subtree,
  registers `tgid → session_id` in `AISME_SESSIONS` when the caller reports its pid, and answers.
  `closeSession` removes the cgroup and flushes.
- `crates/aisme-cli` gains `aisme run`: resolve scope (flags → `.aisme/scope.toml` narrowing →
  VCS root), call `openSession`, write its own pid into `cgroup.procs`, install the seccomp
  filter (`F2.WS.05`) and the Landlock ruleset (`F2.WS.11`), strip the environment per §4, and
  `exec`. On exit it calls `closeSession` and prints the one-line summary.
- The `AISME_SESSIONS` map write is `loaderd`'s or `agentd`'s, never the CLI's: the CLI has no
  capability and the map is the kernel's view of who is supervised.

### 4. Tests

**New:**

- Attribution, in-VM: `aisme run -- sh -c 'cat /etc/hostname'` produces events whose `session_id`
  is the opened session's and whose `tgid` is the child's, and a `sh` started **outside**
  produces none.
- Depth: `aisme run -- bash -c 'python -c "import subprocess; subprocess.run([\"git\",\"status\"])"'`
  keeps every descendant in the session cgroup — the lineage the correlation gate will need
  (`T4.6.03` widens this to depth 8).
- Order: the child's first `openat` is already attributed; a test reads
  `/proc/<child>/cgroup` from a stopped child (`ptrace`-stop or a self-`SIGSTOP` shim) and asserts
  membership before `exec` completes.
- Refusal: with `agentd` down, `aisme run` exits non-zero, prints why, and **does not** run the
  command. A test asserts the command did not run, not merely that the exit code was non-zero.
- Scope narrowing: a `.aisme/scope.toml` that widens beyond detection is refused with the reason;
  one that narrows is honoured.

### 5. Documentation

- Plan `F2.WS.08`'s row: the ask-`agentd`-to-create shape, since "establishes session identity
  and scope" does not say who creates the cgroup and the delegation makes it non-obvious.
- Annex I.1: `openSession` / `closeSession`.
- `docs/design/02_aisme-run.md`: §3's table gains the method names, and §6's open item — a shell
  that later launches the agent — gains the note that F2 leaves it open deliberately.

**Closing.** Verified against the plan's `F2.WS.08` row (`:1620`), `docs/design/02_aisme-run.md`
§3–§5, `F1.RT.07`'s delegated subtree as shipped in `deploy/systemd/aisme-agentd.service`, and
`F7.PS.07`'s narrowing decision. Nothing fell; one silence was filled — the CLI cannot create the
cgroup and must ask, which changes the protocol rather than the CLI's privileges — and one
degradation was pulled forward: refusing to start when `agentd` is unreachable is implemented in
F2 rather than deferred, because the phase's demo is exactly when someone would want to continue
anyway. Open: §6 of the run note (a shell that later launches the agent broadens the scope) stays
open, by the note's own instruction that it needs a real session to judge.

---

## Point 9 — `F2.WS.09`: latency instrumentation for the tiers that exist at this shape

**Done when:** measurable, even if unoptimized.

### 1. Challenge

*Is this the best solution?* The task is already scoped honestly by the plan — "the tiers present
at this shape: T1, T2, T-tel, and the Landlock deny cost" — which is the right list, because at
F2 there is no in-kernel decision and therefore **no T0 to measure**.

*Is it coherent with the specs?* One naming problem, and it matters more than it looks: Annex H
assigns `cargo xtask bench-t0` to `F2.WS.09`. A command called `bench-t0` that reports something
other than T0 is a measurement nobody can compare against §2.22's T0 rows, and the plan is
explicit that "a CPU or latency figure without its tier is not a figure".

*Can it be simplified?* Yes. One command, four named measurements, each labelled with what it is
and what it is not — rather than four commands or one number pretending to be T0.

### 2. Verification

Safe and clear with three rules:

- **`bench-t0` at F2 prints, in its own output, that T0 is not measured here and names `F3` as
  the phase that measures it.** A gate whose output can be pasted into a report must not let the
  reader infer a T0 figure that does not exist.
- **Every figure carries its tier.** At F2 that is `L2` when Landlock applied and `L2-` when
  `F0.VER.04`'s capability was absent — the same string the capability banner shows.
- **Percentiles, not means.** §2.22 states p99 and p95; a mean hides exactly the tail these
  budgets exist to bound. The bench will record every sample and report p50/p95/p99/p999 with the
  sample count, because a p999 over 100 samples is not a p999.

### 3. Implementation

- `cargo xtask bench-t0 --syscalls N` will run inside a VM (`I-12`) and measure four things:
  **T-tel** (tracepoint → event visible in the hot loop), **T1** (escalate-class notification →
  supervisor's answer, no human: the canned path of `F2.WS.06`), **T2** (notification → human
  answer, driven by a scripted TTY), and the **Landlock deny cost** (a denied write versus the
  same write in a session without the ruleset, both measured, the difference reported).
- Timing uses `CLOCK_MONOTONIC` in user space and the event's own `ts_ns` (boot-monotonic) for
  the kernel-side leg; the two clocks are normalized by `F1.ON.03`'s `ClockDomain`, which exists
  for exactly this.
- The report is written to `target/budget/skeleton-latency.toml` so `verify-budgets` reads it as
  an artefact, in the shape `F1.RT.06` established — a measurement is a file some run produced.
- The command prints, verbatim: `T0 is not measured at this shape: at F2 the sensor is a
  tracepoint and enforcement is seccomp plus Landlock, so no decision is taken in kernel. F3
  measures T0.`

### 4. Tests

**New:**

- A self-test of the harness on `MockSensor`: injected known delays are recovered within the
  timer's resolution, so the harness is calibrated before it measures anything real.
- A percentile test on a synthetic distribution with a known p99.
- An in-VM smoke run at `--syscalls 1000` asserting all four figures are present, each with its
  tier, and that the artefact is written and readable by `verify-budgets`.
- A negative: with Landlock unavailable, the deny-cost figure is **absent** rather than zero, and
  the tier reads `L2-`.

### 5. Documentation

- Plan `F2.WS.09`'s row: the four measurements, named.
- Plan Annex H's `bench-t0` row: a note that at F2 it measures T1/T2/T-tel/Landlock and that T0
  arrives with F3, so the name does not mislead a reader of the command table.
- `budgets.toml`: keys for the four figures under a `latency` section that already exists,
  with the F2 profile's ceilings drawn from §2.22's T1/T2 rows.

**Closing.** Verified against the plan's `F2.WS.09` row (`:1621`), §2.22's latency rows,
Annex H's `bench-t0` ownership (`xtask/src/annex_h.rs:74`), and `F1.ON.03`'s clock normalization.
The skeleton's row survives; what fell is the *name*: `bench-t0` at F2 measures no T0, and the
command will say so in its own output rather than leaving a reader to infer a figure that does
not exist. Open: the F2 ceilings for T1 and T2 — §2.22 states them for the finished product, and
whether an unoptimized skeleton must already meet them is a judgement the first measurement will
inform.

---

## Point 10 — `F2.WS.10`: the whole slice on `MockSensor`, with no kernel at all

**Done when:** the gate runs the full path in milliseconds.

### 1. Challenge

*Is this the best solution?* It is the seam §3.2 promises — "the whole engine is testable without
any kernel" — turned into a gate. Its value at F2 is not speed: it is that every later phase can
run the *whole* product path on any machine, so a correlation or policy regression is caught by
`cargo test`, not by a VM boot.

*Is it coherent with the specs?* Yes, and the pieces exist: `MockSensor`, `NullEnforcer`,
`PolicyAdjudicator`, `MemorySink`, `CountingSink` (`F1.PA.02`). What F2 adds is that the *slice*
— sensor → loop → policy → adjudication → WAL → tail → one printed line — runs with the mock
substituted only at the two ends that touch the kernel.

*Can it be simplified?* One trap to avoid rather than a simplification: `test-skeleton` must not
become a second implementation of the slice. If the gate wires its own engine, its own policy and
its own adjudicator, it proves that *the test* works. It will therefore call the same composition
root as the daemon, with one substitution — the platform's sensor and enforcer — which is what the
composition root exists for (`F1.PA.06`).

### 2. Verification

Safe and clear, with two properties named:

- **The substitution point is the composition root, not the test.** `platform::sensors()` will
  take the capability set and return `MockSensor` when nothing is present — which it already does
  — so `test-skeleton` runs the daemon's own composition on a machine with no BPF.
- **The mock path must exercise the *same* policy artefact.** The skeleton policy file is
  compiled by the real compiler in both runs; only the backend differs (`BpfTrieBackend` in the
  VM, a user-space evaluator on the mock path). Otherwise the gate would prove a policy nobody
  ships.

### 3. Implementation

- `cargo xtask test-skeleton` will: compile `deploy/policy/skeleton.aisme` with
  `aisme_core::policy::compile_with`; build the composition from a `CapabilitySet` with nothing
  present; feed a fixed trace through `MockSensor` containing an `openat` of `/etc/shadow`, one of
  `~/.aws/credentials` and one of an allowed path, plus the declared `ToolCall` of `F2.WS.03`;
  evaluate each against the compiled policy; answer the escalation through a canned adjudicator;
  append to a temporary WAL; tail it with `forensicd`'s reader; and assert the printed line.
- It runs in-process where it can and as a child process where the WAL and the tailer need two
  processes, because "resumes with zero loss" is a two-process property.
- Runtime budget: the command asserts its own wall clock is under one second and prints it, so
  "in milliseconds" is measured rather than claimed.

### 4. Tests

`test-skeleton` **is** the test; what it must assert is the list:

- the deny is a deny, with `decided_by = "shadow-deny"`;
- the escalate reached the adjudicator and the answer was obeyed;
- the allowed open produced an event and no decision;
- the WAL contains all three in `seq` order with no gap;
- the tailer printed one line per event after a kill and restart mid-stream;
- the correlation joined the three actions to the declared tool call, scored against the hidden
  token, with precision and recall 1.0;
- and the whole run allocated nothing in the hot loop, reusing `bench-hotloop`'s counter.

### 5. Documentation

- Plan `F2.WS.10`'s row: "runs the daemon's own composition, substituting only the platform ends".
- `docs/ai/AGENTS.md`: `test-skeleton` added to the commands a session runs before claiming F2
  work is done.

**Closing.** Verified against the plan's `F2.WS.10` row (`:1622`), §3.2's first consequence, and
`F1.PA.02`/`F1.PA.06` as implemented. Nothing fell; the trap named — a gate that reimplements the
slice proves only itself — is the reason the point fixes the substitution point at the composition
root. Open: nothing.

---

## Point 11 — `F2.WS.11`: one Landlock ruleset before `exec`, and zero notification traffic

**Done when:** a write outside the workspace fails with `-EACCES` **and produces zero
notification traffic**; observed via the syscall-exit tracepoint with `inferred_from = sys_exit`.

### 1. Challenge

*Is this the best solution?* Yes, and it is the task that makes L2 a real tier rather than a
euphemism: Landlock denies **in kernel**, before the syscall completes, with no supervisor in the
path. `F0.VER.04` measured it holding — ABI 7 on the WSL2 host, ABI 1/2/4/8 across the matrix, a
write outside the allowed path returning `EACCES` under a real ruleset.

*Is it coherent with the specs?* The subtle part is the second half of the done-condition, and it
is the most interesting sentence in F2: **zero notification traffic**. A Landlock denial produces
no `seccomp_unotify` notification, so the supervisor never hears about it — which is the whole
performance argument for L2 (§2.2.1: everything trapping to the supervisor "would be a disaster")
and simultaneously an observability hole: a denial nobody records is a denial nobody can audit.
The plan's answer is `sys_exit_openat` with `inferred_from = sys_exit`: we learn of the denial
from the syscall's *return value*, not from a decision we made.

*Can it be simplified?* No — and the alternative is worth naming so nobody proposes it later:
adding a notification for denied writes would restore the traffic the tier exists to avoid, and
inferring denials from the enter-tracepoint alone cannot distinguish a denial from a failure for
any other reason. The exit tracepoint carrying the errno is the cheap, honest signal.

### 2. Verification

Safe and clear, with four properties that must be explicit:

- **`inferred_from = sys_exit` must be on the wire**, or the record claims an observation it did
  not make. A new flag, `FLAG_INFERRED_FROM_EXIT = 1 << 2`, will be set on events synthesised
  from an exit tracepoint. Together with `F2.WS.01`'s `FLAG_PATH_UNRESOLVED` this keeps two
  distinct honesties separate: *we did not resolve this path* and *we did not observe this
  decision, we inferred it*.
- **An `EACCES` is not necessarily ours.** A write can fail with `EACCES` for ordinary permission
  reasons. The event will therefore be recorded as *an access denial consistent with the session's
  ruleset*, and the enforcement attribution will be made only when the path lies outside the
  declared scope — which is knowable from the compiled policy, in user space, without asking the
  kernel who denied it. Where it is ambiguous, the record says ambiguous.
- **ABI gating with a stated reason.** Landlock ABI 0 (5.4, 5.10 in the matrix) means the ruleset
  is skipped, the tier is reported `L2-`, and the capability banner says which function was lost —
  `docs/design/02_aisme-run.md` §5 already specifies this behaviour, and `F1.PA.05`'s state
  machine already carries the sentence.
- **The ruleset is applied before `exec` and is inherited.** A Landlock domain cannot be widened
  by the child; that is the property that makes it worth applying early, and the test will prove
  it by attempting to widen from inside.

### 3. Implementation

- `crates/aisme-linux` will gain `LandlockEnforcer` (the F2 subset of `F3.EN.09`): compile the
  session's write scope from `CompiledPolicy` into a ruleset — `PATH_BENEATH` with
  `WRITE_FILE|MAKE_REG|MAKE_DIR|REMOVE_FILE` for the workspace, nothing outside — and
  `landlock_restrict_self` in `aisme run` after the seccomp filter and before `exec`.
- ABI is probed with `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, the
  same call `F0.VER.04` used; features above the measured ABI are skipped and named.
- `crates/aisme-ebpf` will gain the `sys_exit_openat` tracepoint program, enabled only for
  sessions, emitting a `FileOpen` event with `outcome = Denied`, `FLAG_INFERRED_FROM_EXIT`, and
  the errno in `FilePayload::flags`' spare bits when the return is negative.
- `agentd` will join the exit event to the enter event by `(tgid, seq)` in the correlate step and
  keep one record, not two, with the errno attached.

### 4. Tests

**New:**

- In-VM, the done-condition: `aisme run -- sh -c 'touch /tmp/outside'` fails with `EACCES`, the
  WAL contains exactly one denial record with `FLAG_INFERRED_FROM_EXIT`, and **the notification
  counter is zero** — the second half of the condition, which needs its own assertion or it will
  not be checked.
- In-VM, the positive: a write **inside** the workspace succeeds and produces no denial.
- Inheritance: a child of the session cannot widen the domain; an attempt to
  `landlock_restrict_self` with a broader ruleset does not restore access.
- ABI gating, on 5.10 in the matrix: the ruleset is skipped, the tier reads `L2-`, the banner
  names the lost function, and the run still works.
- Ambiguity: a write to a path outside the scope that would also fail on ordinary permissions is
  recorded as ambiguous rather than attributed to AISME.

### 5. Documentation

- Plan `F2.WS.11`'s row: the ambiguity rule and the new flag.
- Plan §F1.1's `RawEvent` block: `FLAG_INFERRED_FROM_EXIT`.
- `docs/ai/memory/landlock-l2-file-deny.md`: a line recording that F2 is where the measured
  capability first becomes enforcement, with the task id.
- `docs/design/02_aisme-run.md` §3, step 5: the F2 subset named, so a reader knows what is
  implemented and what is `F3.EN.09`'s widening.

**Closing.** Verified against the plan's `F2.WS.11` row (`:1623`), §2.2.1's argument for why L2
cannot trap everything, `F0.VER.04`'s measurement (`docs/reports/01_f0-verification.md`), and
`docs/design/02_aisme-run.md` §5's degradation table. Nothing of the skeleton fell; two silences
were filled — how a denial nobody was notified about gets recorded honestly (a wire flag, not a
guess) and what happens when an `EACCES` might not be ours (recorded as ambiguous) — and one
alternative was named and rejected so it is not proposed later: notifying on denied writes would
restore exactly the traffic the tier exists to avoid. Open: nothing blocking; `F3.EN.09` widens
this to the never-promptable classes and the AISME self-protection paths.

---

## Point 12 — GATE F2: the six lines, and the one thing none of them can do yet

**The gate, as the plan writes it:**

```bash
cargo xtask test-skeleton              # full slice against MockSensor, no kernel
cargo xtask vm run -- aisme run -- sh -c 'cat /etc/hostname'   # real kernel, allowed
cargo xtask vm run -- aisme run -- sh -c 'cat /etc/shadow'     # real kernel, denied -EACCES
AISME_TERMINAL_ANSWER=d cargo xtask vm run -- aisme run -- sh -c 'cat ~/.aws/credentials'
cargo xtask vm run -- aisme run -- sh -c 'touch /tmp/outside'  # Landlock deny, zero notifications
cargo xtask verify-budgets --profile skeleton                  # measuring real code now
cargo xtask bench-t0 --syscalls 100000                         # baseline recorded
```

### 1. Challenge

*Is this the best gate?* The shape is right: it is a demo, not a checklist, and its exit criterion
is stated as one — an engineer types `aisme run -- bash`, the terminal asks, they answer, the
syscall obeys.

*Is it coherent with what exists?* **Four of these lines cannot run today, for a reason nobody has
written down**: `cargo xtask vm run` executes a command *inside the guest*, and the guest has no
AISME binaries. Today `vm` boots a distribution cloud image with a NoCloud seed and runs shell
commands; `cargo xtask dist` builds the workspace on the **host**. Nothing carries the artefacts
across, and `aisme run` inside the guest would be `command not found`.

The second gap is smaller and also unwritten: `verify-budgets --profile skeleton` needs an
artefact for `profiles.skeleton.agentd_rss_mb`, and the artefact must come from a run **inside**
the VM at the skeleton's shape — the idle artefact of F1 was written on the host.

*Can it be simplified?* Yes, and cheaply. The binaries are small (`aisme-agentd` is 665 KB
stripped today, and §2.22 budgets 10 MB); the seed ISO already carries files into the guest.

### 2. Verification

Safe and clear once the transport is named. Three properties:

- **The guest runs the binaries the host built, and the gate says which.** Every certification
  figure in this project carries the hash of what produced it (§2.22's reference-trace rule); the
  same applies here: the run records the `sha256` of each binary it staged, so a latency figure
  can never be attributed to a build nobody can identify.
- **No network in the guest for this.** The seed ISO is already the transport for the probe
  scripts; adding a package fetch would make the gate depend on a mirror (`F0.WSL.02` measured
  what that costs) and `I-27`'s zero-cost rule is about more than GitHub.
- **The artefacts come out the same way they went in.** The guest writes
  `target/budget/skeleton*.toml` to a directory the host reads after the run — the same
  "a measurement is a file some run produced" rule `F1.RT.06` established.

### 3. Implementation

- `cargo xtask vm run` gains `--with-dist`: it runs `dist`, stages the release binaries and the
  skeleton policy into the seed ISO under `/opt/aisme/`, and prepends a guest-side step that
  copies them to `/usr/lib/aisme/`, installs the two systemd units from `deploy/systemd/`, and
  starts `aisme-loaderd` then `aisme-agentd` before running the command.
- The staged manifest (`name`, `sha256`, `size`) is printed by the host and written into the
  guest at `/opt/aisme/manifest.toml`, so both sides can name what ran.
- Results come back the way the probe logs already do — the guest writes to `/dev/console` and
  `vm` captures it — plus a `budget` block the host extracts into `target/budget/`.
- `cargo xtask verify-budgets --profile skeleton` then reads that artefact exactly as it reads
  the idle one.
- The four `vm run` lines of the gate become one xtask helper each so the gate block stays
  readable, but the plan's block is kept verbatim: the helpers are what `vm run` does, not new
  commands.

### 4. Tests

**New:**

- A staging test: `--with-dist` on an image, then `sha256sum` inside the guest equals the host's
  manifest for every binary.
- A no-network assertion: the guest's run performs no package installation; the probe script's
  existing `apt` path is not taken for this command.
- An artefact test: the skeleton profile's artefact is produced in the guest and read on the host,
  and `verify-budgets --profile skeleton` reports a number rather than a skip.
- The gate itself, as a rehearsal before it is a gate: each of the six lines run once, with its
  output pasted into `docs/CHANGELOG.md` as GATE F1's was.

### 5. Documentation

- Plan GATE F2's block: `--with-dist` added to the four `vm run` lines, since without it the
  block is not runnable.
- Plan §F2's task table: a note on `F2.WS.10` and `F2.WS.09` that their artefacts come from the
  guest.
- `docs/ai/STATE.md`: the gate's output when it passes, and the binary manifest's hashes with it.
- `docs/ops/`: how to run the gate by hand, since it is the phase's demo and someone will want to
  show it.

**Closing.** Verified against the plan's GATE F2 block (`:1637`), `xtask/src/vm.rs`'s `vm run`
implementation (a guest-side shell command, nothing staged), `xtask/src/tooling.rs:80`'s `dist`
(a host-side build), and `F1.RT.06`'s artefact convention. **One claim of the skeleton falls
outright**: the gate as written cannot run, because four of its six lines invoke `aisme run`
inside a guest that has no AISME binaries and nothing in the tooling carries them there. The fix
is `vm run --with-dist` plus a staged manifest with hashes, specified above. Open: whether the
guest should run the daemons under the shipped systemd units (specified here, and it exercises
`F1.RT.07`'s split) or as plain processes — the units are the honest choice and cost one more
step in the seed script.

---

## Point 13 — the capability `ADDFD` names, and what it does to the L2- boundary

This point exists because `Q-13`'s answer surfaced it (Point 5), and it is a measurement rather
than a decision, so it is amplified separately instead of being smuggled into a task row.

**The claim to test:** `seccomp_unotify` as `F0`'s probe measures it is **not** the capability
the plan means by that name, and the tier derived from it may be wrong on the oldest matrix
kernel.

### 1. Challenge

*Is the current probe the best one?* No, and the evidence is in the plan's own annotation.
§2.23 declares the field as `seccomp_unotify: bool, // kernel >= 5.9 (CONTINUE >= 5.5)`. The
notifier interface itself landed in 5.0; `SECCOMP_USER_NOTIF_FLAG_CONTINUE` in 5.5;
`SECCOMP_IOCTL_NOTIF_ADDFD` in **5.9**. The plan's `>= 5.9` therefore means the *decidable* form —
the one that can deliver a validated descriptor — which is exactly what `I-28` now requires and
what Point 5 pulled into F2.

`F0`'s probe measures `SECCOMP_GET_NOTIF_SIZES` (present since 5.0) and reported `seccomp_unotify:
yes` on all seven matrix images, including 5.4. That is a true statement about the notifier and a
false one about what the tier needs.

*Is it coherent with the specs?* Annex D.1 puts `seccomp_unotify (T1)` at `kernel ≥ 5.9` in the
L2- column. `aisme-core::tier::tier_of` derives L2- from `seccomp_unotify && cgroup_v2_freeze`. If
the field means the notifier, 5.4 is L2-; if it means the plan's `≥ 5.9`, 5.4 is **L1** — which is
what the plan expected before any of this was measured, and what my first correction to that row
overturned with a probe that was too permissive.

*Can it be simplified?* Yes, and the simplification is also the honest fix: **two fields, each
measured by the thing it names.**

### 2. Verification

Safe and clear, with the discipline this project applies to any capability:

- **`seccomp_unotify` and `seccomp_addfd` become separate fields.** One says a syscall can be
  trapped; the other says a decision can be delivered safely. Conflating them is what produced a
  tier that overstated what the machine can enforce.
- **The probe feature-tests, never version-tests.** A kernel version is a proxy; a backport makes
  it wrong in one direction and a vendor kernel in the other. The probe will install a filter in
  a short-lived child, take one notification, and attempt `SECCOMP_IOCTL_NOTIF_ADDFD`,
  distinguishing `ENOTTY`/`EINVAL` (absent) from `EBADF`/`EFAULT` (present, wrong arguments) — the
  same shape as `F0.VER.04`'s Landlock probe, which asked the syscall rather than `uname`.
- **The tier follows the capability that enforcement needs.** `tier_of` will read
  `seccomp_addfd`, because L2-'s promise is "escalate/deny via seccomp — every watched path
  decision traps", and a trap that can only ever answer *deny* is not that promise.
- **Nothing is asserted before it is measured.** The prediction below is written first, as
  `F0.VER`-style rows are.

**Prediction, written before the run.** `ADDFD` will be **absent on 5.4** (Ubuntu 20.04) and
**present on 5.10, 5.15, 6.1, 6.8 ×2 and 7.0**. The matrix tiers will therefore read
**L1**, L2-, L2, L3, L2, L3, L2 — one change, on the first row, restoring the plan's original
expectation. If instead `ADDFD` is present on 5.4 (a backport), the row stays L2- and §2.23's
`>= 5.9` annotation is what is imprecise; either way one document is corrected by the
measurement, and this point says which in advance.

### 3. Implementation

- `xtask/src/vm.rs`'s tier probe gains the `ADDFD` feature test and prints `seccomp_addfd: yes|no`
  beside the two it already prints, then derives the tier from
  `addfd && freeze` for L2- rather than from `unotify && freeze`.
- `aisme-core::capability::CapabilitySet` gains `seccomp_addfd`; `tier_of` uses it; `degradations`
  gains the sentence from Point 5.
- `aisme-agentd::platform::probe` reports both fields once `F3.LD.01` gives it a real probe; until
  then it reports neither present, as it does today.
- `cargo xtask vm probe --all` is re-run over the seven images and the result recorded in
  `docs/reports/01_f0-verification.md` beside the tier table, with the prediction and the outcome.

### 4. Tests

**Existing to change:** `crates/aisme-core/src/tier.rs`'s unit tests — the `caps_for` helper sets
`seccomp_addfd` alongside `seccomp_unotify` for L2- and above, and one new case pins the
distinction: a kernel with the notifier but **without** `ADDFD` is **L1**, not L2-.

**New:**

- A `degradations` case naming the lost function when `ADDFD` is absent.
- The in-VM feature test itself, which is the probe: it must answer the same way twice on the same
  image, and must not leave the child process behind.

### 5. Documentation

- Plan §2.23: the two fields, with the version each one means, so the annotation cannot be read
  as one capability again.
- Plan Annex D.1: the L2- row cites `SECCOMP_IOCTL_NOTIF_ADDFD` explicitly rather than
  "seccomp_unotify (T1) | kernel ≥ 5.9".
- Plan's `F0.VM.02` row and `docs/reports/01_f0-verification.md`: the re-measured tiers, with the
  lesson stated once — a capability probed by its weakest interface reports a tier the product
  cannot deliver.
- `docs/ai/memory/`: a durable note if 5.4 turns out to carry a backport, because that is exactly
  the kind of fact a version check would have got wrong.

**Closing.** Verified against §2.23's annotation, Annex D.1's L2- row, `aisme-core::tier::tier_of`
as implemented, `xtask/src/vm.rs`'s current probe (which asks `SECCOMP_GET_NOTIF_SIZES`), and the
kernel versions of the three seccomp features. Nothing is claimed yet: this point ends with a
**prediction and a measurement to run**, not a correction, because the correction it expects would
be the third time this row moves and it will move on evidence. Open, and deliberately so, until
`vm probe --all` runs with the new feature test.

---

## Summary of what this amplification changed

| # | Point | What the amplification added or corrected |
|---|---|---|
| 1 | `F2.WS.01` | `FLAG_PATH_UNRESOLVED` on the wire; ring buffer required, perf fallback refused in F2 with the reason |
| 2 | `F2.WS.02` | `PathResolver` as an L1 ingest hook so canonicalization is not I/O in `aisme-core`; `dhat` → the counting allocator, restated |
| 3 | `F2.WS.03` | `declareToolCall` as one new Annex I method; the token proven not to cross it |
| 4 | `F2.WS.04` | Atomic publication given a mechanism: array-of-maps double buffer, generation inside the same swap |
| 5 | `F2.WS.05` | **`Q-13` answered**: `ADDFD` enters F2, bounded to read-only `openat` at matching credentials; everything outside the subset denied and stated; `CONTINUE` never permits a path-bearing syscall (**`I-28`**) |
| 6 | `F2.WS.06` | `AISME_TERMINAL_ANSWER` constrained: captured by `aisme run`, stripped from the child, capped at `Medium`, never a grant, recorded as canned |
| 7 | `F2.WS.07` | Checkpoint after work and fsync it; per-batch fsync as the writer's default |
| 8 | `F2.WS.08` | `openSession`/`closeSession`: the CLI asks `agentd` to create the cgroup, because the subtree is delegated to the daemon |
| 9 | `F2.WS.09` | `bench-t0` at F2 measures no T0 and says so in its own output; four named figures, each with its tier |
| 10 | `F2.WS.10` | The gate runs the daemon's own composition; only the platform ends are substituted |
| 11 | `F2.WS.11` | `FLAG_INFERRED_FROM_EXIT`; an ambiguous `EACCES` is recorded as ambiguous, not attributed |
| 12 | GATE F2 | **The gate cannot run as written**: `vm run --with-dist` and a staged, hashed manifest are required to put the binaries in the guest |
| 13 | *(from `Q-13`)* | `seccomp_unotify` and `seccomp_addfd` split; the tier's L2- boundary follows the one enforcement needs; prediction written, measurement pending |

**`Q-13` is answered** (point 5): the `ADDFD` mechanism enters `F2.WS.05`, bounded, with `I-28`
recording the rule. Everything in this document is now executable as written, with one measurement
outstanding — point 13's `ADDFD` feature test across the matrix, whose prediction is on record.
