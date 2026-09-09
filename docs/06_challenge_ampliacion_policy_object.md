# Challenge-amplification — the policy BPF object

> **Status**: six points written; **points 1 to 5 implemented**. Outstanding: point 6 — the three
> guest tests and `cargo xtask test-policy-publish`. The publication path has never executed:
> `I-12` keeps it out of a host, so point 6 is what will prove it runs
> **Scope**: the half of `F2.WS.04` that `docs/05_challenge_ampliacion_f2.md` §4.6 left blocked:
> atomic publication of a compiled policy into real BPF maps, with a generation counter.
> **Method**: `/challenge-ampliar` — five sections per point, written in the declared future so
> whoever implements it decides nothing and only executes.

## How to read this

The compiled half of `F2.WS.04` is done and tested: `deploy/policy/skeleton.aisme` compiles
through the real compiler, and `aisme-linux::BpfTrieBackend` lowers it to LPM keys. What is
blocked is publication. `docs/05` §4.6 recorded three measurements showing that
`BPF_MAP_TYPE_ARRAY_OF_MAPS` — which exists at the pinned `aya-ebpf 0.2.1` only as a BTF map —
cannot be added to the sensor's object without the whole object ceasing to load, and named the
fallback: a **second object** the loader owns.

This document amplifies that fallback point by point. Its first point is not the object: it is
the measurement that decides whether the fallback is even the right shape.

**The points:**

1. Read the actual BTF failure before designing around it. **Closed** — it refuted the
   second-object fallback, so points 2 to 6 are written against the mechanism that survived.
2. The maps: two legacy `LpmTrie`s and a meta array, in the sensor's own object.
3. Creation and ownership: who loads, who holds them open, and what the privilege split costs.
4. The publish, and the torn-read argument that `ARRAY_OF_MAPS` gave for free.
5. The handoff: how the generation reaches `agentd`, the WAL header and `getCapabilities`.
6. The tests: the torn-read run, the privilege negative, and the in-VM publication.

---

## Point 1 — Read the actual BTF failure before designing around it

**Done when:** the failure that blocks `F2.WS.04` is named by its own error, not by a wrapper.

### 1. Challenge

*Is this the best next step?* It is the only honest one. `docs/05` §4.6 concludes that "aya cannot
parse the BTF this toolchain emits", and the evidence for that conclusion is the string
`error parsing BPF object: BTF error`. That string names nothing. In `aya-obj 0.3.0`,
`ParseError::BtfError` is declared `#[error("BTF error")]` (`obj.rs:969`) and wraps a `BtfError`
reachable only through `source()`; the inner type has at least seven distinct variants —
`InvalidHeader`, `InvalidTypeInfo`, `InvalidRelocationInfo`, `UnknownBtfType`,
`UnknownBtfTypeKind`, `InvalidStringOffset` and a file-parse wrapper (`btf/btf.rs:32–68`). The
sensor formats the failure with `e.to_string()` (`crates/aisme-linux/src/sensor.rs:160`), which
prints only the top of the chain.

So the blocker's diagnosis rests on a message that cannot distinguish "this BTF is malformed" from
"this BTF contains a type kind aya does not know" from "the header is not BTF at all". Those three
have different fixes, and only one of them makes a second object the answer.

*Is it coherent with the specs?* It is the repository's own rule, newly written and immediately
broken by the person who wrote it: `docs/ai/AGENTS.md` §3-bis says **never state a cause you did
not establish**, and "aya cannot parse the BTF" is a cause asserted from a message that does not
carry it. §3-bis also says a check that produces no result must say so — an error type whose
`Display` discards its own reason is that failure inside a library rather than inside a probe.

*Can it be simplified?* Yes, and the simplification removes work rather than adding it. The whole
of points 2 through 6 assumes a second object loads. If the inner error turns out to be, say, an
unknown type kind produced by `bpf-linker 0.11`, then **no** object built by this toolchain with
BTF maps will load, a second object is not a fallback at all, and points 2–6 would be five points
of design resting on a refuted premise. One measurement, taken first, either confirms the fallback
or replaces it.

### 2. Verification

Safe, clear and compliant, with the boundary stated:

- **The measurement runs in a guest, never on this host.** Loading a BPF object touches the
  kernel, and `I-12` allows no kernel-touching test on a host OS. `cargo xtask vm run <image>
  --with-dist` already stages the product's own loader, so the run costs one boot and no new
  tooling.
- **Nothing about the sensor's verified object changes to take this measurement.** The object that
  loads `ACCEPTED` on 6.8 stays exactly as it is; the probe object is built and loaded separately,
  so a failed measurement cannot regress `F2.WS.01` the way the first attempt did.
- **The error chain is printed, not summarised.** The diagnostic will walk `source()` to the end
  and print every link, because a wrapper that hides its cause is precisely what made this point
  necessary. This is a change to how failures are reported, which is safe by construction: it adds
  information and removes none.

### 3. Implementation

- `crates/aisme-linux/src/sensor.rs` will gain a small free function, `error_chain(&dyn
  std::error::Error) -> String`, which walks `source()` and joins the links with `: `. `start`
  will use it in place of `e.to_string()`, so **every** load failure — not only this one — names
  its own cause from now on. The existing "a cause only where one was established" logic stays.
- `crates/aisme-agentd`'s `--load-sensor` will gain a sibling, `--load-policy-probe`, which loads
  a **second, minimal object** containing only the two policy maps and no programs, and reports
  `ACCEPTED` or `REFUSED` with the full chain. It will live in `platform/`, where naming an
  adapter is legal (`A-05`, now checked on every L3 engine).
- The probe object will be a new crate, `crates/aisme-ebpf-policy`, built by
  `cargo xtask build-ebpf` beside the existing one, with its own `rust-toolchain.toml` pinned to
  the same nightly. It will declare `AISME_POLICY` (`ArrayOfMaps<LpmTrie<[u8; 200], u8, 1024>, 2>`)
  and `AISME_POLICY_META` (`Array<u64, 2>`) as `#[btf_map]`, a `license` section, and **no
  programs at all** — the question is whether the maps load, and a program would add a second way
  to fail.
- `xtask`'s `build-ebpf` will build it with `RUSTFLAGS="-C link-arg=--btf"` and
  `[profile.release] debug = 2`, the pairing measured on 2026-09-07 to be the only one that emits
  a `.BTF` section at all.
- The prediction will be written before the run, naming what each inner error means for points
  2–6, exactly as `docs/05` point 13's was.

### 4. Tests

**Existing to change:** none. The sensor's tests do not exercise the error path, and the change to
`start`'s message is additive.

**New:**

- A host unit test for `error_chain`: a two-link error chain formats as `outer: inner`, and a
  single error with no source formats as itself. It will be built from `std::io::Error` sources so
  it needs no kernel and no aya.
- A guest run of `--load-policy-probe` on **6.8 and 5.4**, recorded with its full output in this
  document and in `docs/CHANGELOG.md`. The 5.4 row is expected to differ and is a measurement, not
  a failure: BTF-defined maps need 5.2, and `ARRAY_OF_MAPS` needs 4.12, so 5.4 should manage both
  — if it does not, that is a finding naming the kernel.
- A negative that keeps the first attempt's mistake from returning: `--load-sensor` will be run in
  the same guest boot, and must still report `ACCEPTED` with `ringbuf: true`. The policy probe
  cannot be allowed to regress the sensor a second time, and the way to know is to ask in the same
  breath.

### 5. Documentation

- `docs/05_challenge_ampliacion_f2.md` §4.6: the sentence "aya cannot parse the BTF" will be
  replaced by what the inner error actually says, with the lesson kept — a conclusion drawn from a
  wrapper's `Display` is a cause asserted rather than established, and the rule against it was
  written in the same session it was broken.
- `docs/ai/STATE.md`'s blocker: rewritten to name the real obstruction, whichever it turns out to
  be, and to say whether the second object remains the fix.
- `docs/ai/memory/`: a durable note if the inner error is a toolchain pairing fact — the kind of
  thing that costs a day to rediscover and a line to record.
- Plan `F2.WS.04`'s row will not change in this point; it changes in point 4, when the mechanism
  is settled.

### 6. The measurement, and the fallback it refutes (2026-09-07)

`--load-policy-probe` and `--load-sensor`, in the same guest boot, on both ends
of the matrix:

| Image | `--load-policy-probe` | `--load-sensor` |
|---|---|---|
| ubuntu-24.04 (6.8) | **REFUSED** — `BTF error: unexpected BTF type id 45` | `ACCEPTED`, `ringbuf: true` |
| ubuntu-20.04 (5.4) | **REFUSED** — same error | `REFUSED` — `failed to create map AISME_EVENTS: Invalid argument (os error 22)` |

**The point achieved what it was for: the cause has a name.** `UnexpectedBtfType
{ type_id: 45 }` (`aya-obj` `btf/btf.rs:104`) is aya's BTF resolver following a
type reference and finding something it did not expect there — a structural
mismatch between the BTF `bpf-linker 0.11` (LLVM 21) emits and what `aya-obj
0.3.0` reads. The 5.4 sensor row shows the same improvement working on an
unrelated failure: it now names the map and the errno instead of stopping at
"map error".

**Two claims fell, one of them the whole shape of the plan.**

`docs/05` §4.6 said the obstruction was one object carrying two map-section
styles. It is not: this object carries **only** `.maps`, has no programs, and
fails identically. Mixing was a consequence — adding BTF maps to the sensor's
object made that object need BTF parsing, and BTF parsing is what fails.

And my own prediction, written before the run, said the second object would
load. **It does not, so the second-object fallback is refuted**, not confirmed:
it moves the maps without touching the reason they cannot be read. Points 2
through 6 as drafted rest on it, and are therefore rewritten before they are
written, which is exactly why this point came first.

**What replaces it**, and what it costs. The mechanism must not need a BTF map,
so the double buffer becomes **two `LpmTrie` maps declared with `#[map]`** in
the sensor's own legacy `maps` section — the style already proven to load on
every matrix kernel — plus an `Array<u64, 2>` holding `[generation,
active_index]`. Publication fills the idle trie and then writes one element of
the array. **What is lost is the single-word outer-map swap**: a reader now
reads the index, then looks up in the trie that index names, which is two
lookups rather than one and needs its own argument that a reader cannot straddle
a swap. That argument is point 4's, and it is a real cost of this route rather
than a detail — `ARRAY_OF_MAPS` gave it for free.

**One thing left alone deliberately.** The pairing could also be fixed from the
toolchain end — a newer aya that reads this BTF, or a bpf-linker built against
the LLVM aya expects. `F0.VER.01` pinned both against a measured MSRV, and
moving either is a change with its own validation, not a step inside `F2.WS.04`.
It is recorded as the alternative and left to the owner.

**Closing.** Verified against `aya-obj 0.3.0`'s `obj.rs:969` (the wrapper that discards its
cause), `btf/btf.rs:32–68` (the seven inner variants it hides),
`crates/aisme-linux/src/sensor.rs:160` (`e.to_string()`, which prints only the top link), and
`docs/ai/AGENTS.md` §3-bis (the rule this violates). **One claim of the blocker falls before any
design rests on it**: `docs/05` §4.6 states that aya cannot parse this toolchain's BTF, and the
evidence offered cannot support that or any other specific cause. Nothing about the second-object
fallback is refuted yet — it is simply not yet *established*, which is a different thing and the
reason this point exists. Open, and deliberately so, until the guest run reports the inner error.

---

## Point 2 — The maps: two legacy `LpmTrie`s and a meta array

**Done when:** the policy maps exist on every matrix kernel that loads the sensor, and the sensor
still loads.

### 1. Challenge

*Is this the best solution?* It is the one that survived point 1. `ARRAY_OF_MAPS` would have been
better and is unavailable: it exists at `aya-ebpf 0.2.1` only as a BTF map, and BTF is what fails
(`unexpected BTF type id 45`). What remains is the map style already proven to load on all seven
matrix kernels — `#[map]`, the legacy `maps` section, which `aya-obj` parses at `obj.rs:1073`.

Two `LpmTrie`s and an index is not a workaround for a missing type; it is the same double buffer
with the swap moved from the map layer to the value layer. What changes is who does the
indirection: `ARRAY_OF_MAPS` made the kernel resolve `outer[active] → trie` in one lookup, and
here a reader resolves `meta[1] → which trie` and then looks up in that trie. **Two lookups where
there was one**, and the reason it still works is that both are on the reader's side and neither
can observe a half-written map.

*Is it coherent with the specs?* Yes, and it removes a coupling. §B.2 `PL-04` asks for "atomic
publication with a generation counter; readers never lock, never see a torn policy" — it does not
ask for `ARRAY_OF_MAPS`, which was this document's word, not the plan's. `F2.WS.04`'s row asks
that "the policy generation counter increments; no torn read". Both are met by an index swap.

The maps will live in **`crates/aisme-ebpf`**, the sensor's own object, and not in a second one.
Point 1 measured that a separate object buys nothing — the obstruction was never the sharing — and
a second object would mean a second load, a second failure mode, and two places where a kernel can
refuse. `crates/aisme-ebpf-policy` therefore becomes a **probe**, not a product artefact: it stays
in the tree as the thing that reproduces the BTF failure in one command, and its `README` will say
so, because deleting the reproduction of a live blocker is how the blocker gets rediscovered.

*Can it be simplified?* One simplification will be taken and one refused. Taken: the two tries will
be **one map with a doubled key space** — no. That is the tempting one and it is wrong: a shared
trie cannot be filled without a reader seeing entries of the next policy under the current
generation, which is precisely the torn read. Two maps, refused simplification, and the reason
recorded here so nobody re-proposes it. Taken instead: the meta array will hold **two `u64`s and
nothing else**, so a reader's second lookup is a fixed offset rather than a search.

### 2. Verification

Safe, clear and compliant, with three properties pinned:

- **The tries are sized once and never grown.** `LpmTrie<[u8; 200], u8, 1024>` at
  `BPF_F_NO_PREALLOC` (which `map_constructors!` sets for this type at
  `aya-ebpf-0.2.1/src/maps/lpm_trie.rs:38`). 1024 entries × 201 bytes of key is ~206 KB per trie,
  ~412 KB for both — read against the 50 MB daemon budget, this is the kernel's memory and not
  `agentd`'s, and `verify-budgets` will gain no row for it because it is not the daemon's RSS.
  What *will* be recorded is the refusal: a policy with more than 1024 prefixes will be rejected
  at lowering time with the count, never silently truncated.
- **The key is the one `BpfTrieBackend` already produces.** `TrieEntry` is `#[repr(C)]`
  `{ prefix_len: u32, path: [u8; 200], verdict: u8 }` and `aya_ebpf::maps::lpm_trie::Key<K>` is
  `{ prefix_len: u32, data: K }` (`lpm_trie.rs:24`). The first two fields are the key and the third
  is the value, which is why `TrieEntry::key_bytes` already exists and returns exactly
  `4 + 200` bytes. No new layout is invented in this point.
- **The sensor's program does not read them.** Kernel-side evaluation is F3's (plan `:1638`), so
  the tracepoint will not gain a lookup. Adding one would put a policy decision in a program whose
  verdict cannot deny anything, which is worse than useless: it would make the map look load-bearing
  when it is not.

### 3. Implementation

- `crates/aisme-ebpf/src/main.rs` will gain three `#[map]` statics beside the four it has:
  `AISME_POLICY_A` and `AISME_POLICY_B`, both `LpmTrie<[u8; 200], u8>` with
  `with_max_entries(1024, 0)`, and `AISME_POLICY_META`, an `Array<u64>` with
  `with_max_entries(2, 0)`. Each will carry a doc comment naming what it is for and stating that
  nothing in this object reads it until F3.
- The names will be exactly `AISME_POLICY_A`, `AISME_POLICY_B`, `AISME_POLICY_META`, because
  user space looks them up by name and a rename is a silent break.
- `crates/aisme-linux/src/policy.rs` will gain `POLICY_TRIE_ENTRIES: usize = 1024` and
  `BpfTrieBackend::lower` will refuse an image exceeding it with a `LowerError` naming the count
  and the bound — the same shape as the existing over-long-prefix refusal.
- `crates/aisme-ebpf-policy` will keep its object and gain a `README.md` stating that it exists to
  reproduce the BTF failure of point 1 in one command, that it is not shipped, and what would make
  it obsolete (a toolchain pairing whose BTF `aya-obj` reads).

### 4. Tests

**Existing to change:** `crates/aisme-linux/src/policy.rs`'s
`lowering_the_shipped_policy_yields_prefix_keys_with_their_verdicts` will additionally assert the
image fits `POLICY_TRIE_ENTRIES`, so the shipped policy is known to be publishable and not merely
lowerable.

**New:**

- A host test that a synthetic policy of `POLICY_TRIE_ENTRIES + 1` prefixes is **refused** by
  `lower` with both numbers in the message. Silent truncation here would publish a policy that
  denies less than the one the operator wrote, which is the dangerous direction.
- A host test pinning the key layout against `aya_ebpf`'s: `size_of::<TrieEntry>() - 1` equals
  `4 + 200`, and `TrieEntry::key_bytes()[..4]` is the `prefix_len` in native byte order. It will
  cite `lpm_trie.rs:24` in a comment so a future reader knows what it is pinned *to*.
- An in-VM test through `--load-sensor`: after the maps are added, the sensor must still report
  `ACCEPTED` with `ringbuf: true` on 6.8, and the refusal on 5.4 must still name
  `AISME_EVENTS` — not one of the new maps. If 5.4 starts failing on `AISME_POLICY_A` instead,
  that is a finding about `LPM_TRIE` on that kernel and it is named as such rather than folded
  into the existing row.

### 5. Documentation

- Plan `F2.WS.04`'s row: the mechanism named — two tries plus an index, not `ARRAY_OF_MAPS` — so
  F3 inherits what exists rather than what was once planned.
- Plan §B.2 `PL-04`: a sentence that the generation is published *in* the same array as the index,
  read after it, and that this is what "never a torn policy" means here.
- `docs/ai/memory/`: a durable note recording that `ARRAY_OF_MAPS` is unavailable at this pin and
  why, so the next person to want it finds the measurement instead of repeating it.

**Closing.** Verified against `aya-ebpf-0.2.1/src/maps/lpm_trie.rs:24` (the `Key<K>` layout this
key must match) and `:38` (the legacy constructor and its `BPF_F_NO_PREALLOC`),
`crates/aisme-linux/src/policy.rs`'s `TrieEntry` as implemented, `aya-obj-0.3.0/src/obj.rs:1073`
(the legacy `maps` section this style lands in), and plan `:1638` (kernel-side evaluation is F3's).
Nothing of point 1's conclusion fell. One simplification was considered and **refused with its
reason**: a single trie with a doubled key space would let a reader see the next policy's entries
under the current generation, which is the torn read the whole point exists to prevent. Open: the
1024-entry bound, which is stated here and will be measured against the reference workload's policy
when one exists — until then it is a bound with a refusal, not a bound with evidence.

---

## Point 3 — Creation and ownership: who loads, who holds, and what the split costs

**Done when:** the maps outlive the loader and `agentd` cannot write them.

### 1. Challenge

*Is this the best solution?* The tension is real and worth stating plainly. `F1.RT.07` splits
privilege: `aisme-loaderd` holds `CAP_BPF` (`deploy/systemd/aisme-loaderd.service:29`) and
`aisme-agentd` holds **none** (`CapabilityBoundingSet=` at
`deploy/systemd/aisme-agentd.service:32`). A BPF map is owned by an fd; when the last fd closes,
the map is destroyed. So a loader that creates the maps and exits destroys them, and a loader that
stays alive to hold them is a privileged process that never drops.

Three shapes were weighed:

1. **The loader stays resident.** Simple, and it keeps `CAP_BPF` alive for the machine's uptime —
   the opposite of what the split is for.
2. **Pin the maps to `bpffs`.** `/sys/fs/bpf/aisme/…` holds a reference, so the loader exits and
   the maps live. This is what pinning exists for, and it is how `bpftool` and every production
   loader do it.
3. **Pass the fd to `agentd` over the control socket** with `SCM_RIGHTS`. Elegant, and it gives
   `agentd` a *writable* fd to a policy map — which is exactly the authority the split removes.

*Is it coherent with the specs?* (2) is, and (3) is not. `F2.WS.05`'s and `F3`'s reason for the
split is that the long-running daemon must not be able to change what the kernel enforces. Handing
it a writable map fd would make `CapabilityBoundingSet=` decorative: the capability would be gone
and the authority would remain. **The plan's `F1.RT.07` will be cited for this in the code**, not
paraphrased.

*Can it be simplified?* Yes, in one place that matters: `agentd` will not open the maps at all in
F2. It has no reason to — it neither publishes (that is the loader) nor evaluates (that is F3) —
so the simplest correct thing is that it never holds a policy-map fd of any kind, readable or not.
What it needs is the **generation number**, which is a `u64` and travels over the socket.

### 2. Verification

Safe, clear and compliant, with the boundary stated where someone will look for it:

- **Pinning is under one directory, created by the loader, mode 0700, owned by root.**
  `/sys/fs/bpf/aisme/` will hold `policy_a`, `policy_b` and `policy_meta`. A world-writable pin
  path would hand the authority back to anyone on the machine, which is the same defect as (3) by
  another route.
- **The loader is not resident.** It will create, pin, publish and exit. `bpffs` holding the
  reference is what makes that possible, and the unit already carries `Type=oneshot` and
  `RemainAfterExit=yes` so systemd's model matches what the process does. `units.rs` enforces
  both, so a unit that quietly loses either one fails a test rather than a machine.
- **`agentd` is proven unable to write.** Not asserted — tested. The negative in point 6 will have
  `agentd` attempt an update on the pinned map and require `EPERM`, which is the test that
  `CapabilityBoundingSet=` is real rather than written.
- **`bpffs` may not be mounted.** On a minimal container or an unusual image `/sys/fs/bpf` is
  absent. The loader will mount it when it can and, when it cannot, will **fail with the reason**
  rather than falling back to staying resident: a silent fallback would turn the privilege split
  off on exactly the machines whose configuration is unusual.

### 3. Implementation

- `crates/aisme-loaderd` will gain `src/platform.rs` — its own composition root, which `A-05`'s
  extended check already requires of every L3 engine — naming `aisme_linux` behind
  `cfg(target_os = "linux")`, and `src/policy.rs` with the load-pin-publish sequence.
- It will take `aisme-core` (the compiler) and, behind the Linux target, `aisme-linux` and `aya`,
  each justified in `Cargo.toml` against `DEP.SUP.06` as the sensor's are.
- `aisme-loaderd --publish <policy-file> [--bindings k=v]` will parse and compile the file with
  `aisme_core::policy::{parse, compile}`, lower it with `BpfTrieBackend`, load the sensor's object,
  pin the three maps, publish, and print the resulting `PolicyGeneration`. Compilation failure will
  print every `CompileError` with its position and exit non-zero **before** any map is touched.
- `deploy/systemd/aisme-loaderd.service` will gain the `--publish` invocation — `Type=oneshot`
  and `RemainAfterExit=yes` are already there and already checked. `--publish` joins the flag list
  in `units.rs`'s `check_loaderd` in **this same change**: that list is empty today because the
  binary parses no arguments, and a unit passing a flag the binary does not parse is refused by a
  test (`check_exec_start`).

### 4. Tests

**Existing to change:** `crates/aisme-loaderd/src/units.rs`'s checker and its tests — the two new
directives join the set it verifies, and its existing "shown failing on each way it could rot"
test gains the two new ways.

**New:**

- A host test that `--publish` on a policy with a deliberate syntax error prints the position and
  exits non-zero, and that it does so **without** attempting to load anything. It will assert on
  the absence of a load attempt by running with no `CAP_BPF` and requiring the compile error rather
  than a permission error: a compile error that arrives *after* a permission error would mean the
  order is wrong.
- An in-VM test that the maps survive the loader's exit: publish, confirm the process is gone, then
  read `/sys/fs/bpf/aisme/policy_meta` from a second process and find the generation.
- An in-VM negative that a missing `bpffs` produces a named failure and no resident process.

### 5. Documentation

- Plan `F1.RT.07`'s row: pinning named as the mechanism that lets the loader exit, since "minimal
  privileged loader" currently implies residency to a reader who knows how map lifetime works.
- `docs/design/`: a short note on the pin layout — path, mode, owner — because it is an interface
  between two processes and interfaces belong in writing.
- `deploy/systemd/aisme-loaderd.service`'s own comments: why `oneshot` is correct here.

**Closing.** Verified against `deploy/systemd/aisme-loaderd.service:29` (`CAP_BPF`),
`deploy/systemd/aisme-agentd.service:32` (the empty bounding set), `crates/aisme-loaderd/src/units.rs`
as implemented, and `xtask/src/rules.rs`'s `A-05` check as extended on 2026-09-07 to every L3
engine. **One design was considered and rejected on a specification, not a preference**: passing
the map fd to `agentd` with `SCM_RIGHTS` would leave `CapabilityBoundingSet=` decorative — the
capability gone and the authority kept. Open: whether the pin path is `/sys/fs/bpf/aisme/` or a
per-session subdirectory; F2 has one policy for the machine, so the flat path is correct now and
`F3.PT.02` will say if that changes.

---

## Point 4 — The publish, and the torn-read argument `ARRAY_OF_MAPS` gave for free

**Done when:** a reader that sees generation N sees policy N, and never half of one.

### 1. Challenge

*Is this the best solution?* This is the point that pays for point 1's outcome, so the cost is
stated first. With `ARRAY_OF_MAPS`, "no torn read" was structural: a reader looked up
`outer[active]` and the kernel handed it a trie, so the only mutation observable was one element of
the outer array, and an element write is atomic. With two named tries and an index, a reader does
**two** lookups — `meta[1]` for the index, then the trie that index names — and between them the
publisher may swap. That interleaving has to be argued, not assumed.

The argument: the publisher only ever writes the **idle** trie, and only ever swaps **after** it is
complete. So a reader that reads index `i` and then looks up in trie `i` sees either the policy
that was active when it read the index, or — if a swap happened in between — a *complete* older
policy, because the trie it is reading is the one the publisher has stopped writing. It never sees
a partially filled trie, because the partially filled one is the one it is not reading. **The
window is staleness, not tearing**, and staleness is bounded by one publication.

That is weaker than `ARRAY_OF_MAPS` in one specific way and it must be said: a reader can act on
the previous policy for the length of one lookup. For a policy that only ever *tightens*, that is
harmless; for one that loosens, a decision could deny something the operator just allowed, one
lookup late. Denying late is the safe direction, and `PL-04` asks for no torn read rather than no
staleness — but the difference is real and is recorded here rather than discovered in F3.

*Is it coherent with the specs?* Yes. `PL-04` (plan `:3310`) asks that readers "never lock, never
see a torn policy". Neither lookup takes a lock, and neither can observe a half-written trie.

*Can it be simplified?* Yes, and it removes the remaining ambiguity: the **generation and the
index will be one write, not two**. `meta` holds two `u64`s, and a publisher that wrote generation
then index would leave a window where a reader sees the new generation and the old policy. Instead
the two will be packed: `meta[0]` is the generation, `meta[1]` is the index, and the publisher
writes **`meta[1]` last**. A reader that wants both reads `meta[1]` first, then `meta[0]`, and if
it needs them consistent it re-reads `meta[1]` and retries when it changed — the standard seqlock
shape, stated here so F3 does not invent a different one.

### 2. Verification

Safe, clear and compliant, with the sequence pinned because the order *is* the property:

1. Compile and lower on the host side; refuse before touching a map if anything fails.
2. Read `meta[1]` to learn the active index; the idle one is `1 - active`.
3. **Clear** the idle trie, then fill it entry by entry.
4. Write `meta[0] = generation + 1`.
5. Write `meta[1] = idle`. **This write is the publication**; everything before it is invisible.

- **Step 3 is why two tries are needed and one is not.** Clearing and refilling the *active* trie
  is the torn read; this is where the refused simplification of point 2 would have failed.
- **The generation is monotonic and never reused.** It will be read from `meta[0]` and incremented,
  so a restarted loader continues rather than restarting at 1 — a generation that went backwards
  would make a WAL segment header ambiguous about which policy was in force.
- **A failed fill leaves the active policy untouched.** If step 3 fails partway, step 5 never runs
  and the machine keeps enforcing the last complete policy. The failure will be reported with the
  entry that failed and the generation that was *not* published.

### 3. Implementation

- `crates/aisme-loaderd/src/policy.rs` will implement the five steps in that order, with the order
  itself commented as the property rather than as a description of the code.
- The idle trie will be cleared by deleting the keys it holds; `aya::maps::LpmTrie` exposes
  iteration and `remove`, so a full rebuild does not need map recreation and therefore does not
  need a new fd or a new pin.
- `PolicyGeneration` (`aisme_core::policy`) will be the type at every boundary; the `u64` in the
  map is its wire form, and the conversion will live in one function so the two cannot drift.
- The published generation will be printed on stdout as the last line, so `vm run` captures it and
  a script can read it.

### 4. Tests

**Existing to change:** none.

**New:**

- **The torn-read run, which is the point of the task.** In a guest: one process republishes in a
  tight loop while another samples `meta[1]`, then looks up a key that has a *different* verdict in
  the two policies, a million times. Every sample must be internally consistent — the verdict it
  reads must belong to a policy that was complete. The test will state in its own comment that
  sampling from user space is weaker than sampling from a BPF program, and that the kernel-side
  version arrives with `F3.PT.02`; it measures the publisher, not the reader path F3 will have.
- A guest test that a failed fill leaves the active policy in force: publish generation 1, then
  publish a policy whose 1025th entry is refused, and assert `meta` still reads generation 1 and
  the original index.
- A guest test that the generation survives a loader restart: publish, exit, publish again, and
  assert 1 then 2 rather than 1 then 1.

### 5. Documentation

- Plan §B.2 `PL-04`: the five-step order written out, since "atomic publication" names a property
  and not a mechanism, and F3 will otherwise choose its own.
- Plan `F2.WS.04`'s row: the staleness window named — one lookup, in the safe direction — because
  a reader of the row should not have to derive it.
- `docs/ai/memory/`: the seqlock shape for `meta`, so F3's reader is written against the same one.

**Closing.** Verified against plan `:3310` (`PL-04`'s wording), `aisme_core::policy::PolicyGeneration`
as implemented, and point 1's measurement, which is what makes this mechanism necessary rather than
chosen. **One weakening is recorded rather than hidden**: two lookups admit a one-lookup staleness
window that `ARRAY_OF_MAPS` did not, harmless when a policy tightens and a late deny when it
loosens. Open: whether F3's kernel-side reader takes the seqlock retry or accepts the staleness —
this point specifies the publisher and names the reader's choice without making it.

---

## Point 5 — The handoff: the generation reaches `agentd`, the WAL and `getCapabilities`

**Done when:** every WAL segment says which policy was in force, and the daemon can be asked.

### 1. Challenge

*Is this the best solution?* The field already exists and is already written: `SegmentHeader`
carries `generation: PolicyGeneration` (`crates/aisme-core/src/wal.rs:54`) and `WalSink::create`
takes one. What it is given today is `PolicyGeneration(0)` — a placeholder that means "nobody
told me", written as if it meant generation zero. That is an absence read as a value, in code I
wrote, and this point is where it stops.

*Is it coherent with the specs?* `F1.RT.05`'s header exists precisely so a forensic reader knows
which policy produced a decision. A WAL whose every segment says 0 answers that question wrongly
rather than not at all, which is worse: a reader has no way to tell the placeholder from a real
first generation.

*Can it be simplified?* Yes. `agentd` needs one `u64` and no map access (point 3), and the socket
that carries it already exists. Rather than a new method, `getCapabilities` — which already answers
"what is this engine" — will carry `policy_generation`. Annex I's row will say it may be absent,
because before the first publication there is no generation and saying so beats reporting 0.

### 2. Verification

- **Absent is not zero.** `PolicyGeneration` will be `Option<PolicyGeneration>` where it travels,
  and `WalSink::create` will take an `Option`; a segment opened before any publication will record
  a generation of `u64::MAX` in the header with `SegmentHeader::UNKNOWN_GENERATION` naming it, or —
  preferably, if the header's reserved space allows — a flag bit. The choice will be made by
  reading `SegmentHeader::encode` before the implementation, not guessed here.
- **The daemon does not poll.** The loader publishes and then tells `agentd` once, over the socket
  it already speaks; `agentd` holds the number and stamps it on every segment it opens from then on.
- **A restart is honest.** `agentd` restarting without a publication has no generation to report,
  and will say absent rather than remembering a stale one from a file.

### 3. Implementation

- `aisme-proto::rpc` will gain `Method::SetPolicyGeneration`, `AuthClass::LocalPeer`, idempotent —
  telling the daemon the same number twice is the same as once. Annex I.1 gains the row, and the
  existing test that every `Method` appears in Annex I.1 will enforce it.
- `aisme-agentd` will hold `Option<PolicyGeneration>` behind the same channel shape the
  declarations use, and `run_slice` will pass it to `WalSink` when a segment rolls.
- `getCapabilities` will gain `policy_generation`, present only when known.
- `aisme-loaderd --publish` will call `setPolicyGeneration` after step 5, and will **not** fail the
  publication if the daemon is absent: publishing is the privileged act and telling the daemon is
  a courtesy, so a missing socket is a warning and an exit code of 0.

### 4. Tests

**Existing to change:** `crates/aisme-agentd/src/wal.rs`'s round-trip test will assert the
unknown-generation encoding rather than `PolicyGeneration(7)` alone, so the placeholder has a test
of its own.

**New:**

- A host test that a segment opened with no generation encodes as unknown and decodes as unknown —
  and specifically **not** as 0.
- A host test of `setPolicyGeneration` through `serve_line`: accepted from a local peer, refused
  from a peer that is not, and reflected in the next `getCapabilities`.
- A guest test end to end: publish generation 1, read `getCapabilities`, open a segment, and find
  1 in its header.

### 5. Documentation

- Plan Annex I.1: the new method row and the `policy_generation` field of `getCapabilities`.
- Plan `F1.RT.05`'s row: that the header's generation may be unknown, and how that is encoded.
- `docs/CHANGELOG.md` and `docs/ai/STATE.md`: the usual rows.

**Closing.** Verified against `crates/aisme-core/src/wal.rs:54` (the field), `crates/aisme-agentd/src/wal.rs`
(`PolicyGeneration(0)` as the value it is given today), and Annex I.1's method table with the test
that guards it. **One defect of my own is named rather than carried forward**: the WAL currently
records generation 0 for every segment, which is a placeholder written as a value — the same
absence-as-value this project treats as a defect everywhere else. Open: whether unknown is a
sentinel or a flag bit, which `SegmentHeader::encode`'s reserved space decides.

---

## Point 6 — The tests: the torn-read run, the privilege negative, the in-VM publication

**Done when:** the three properties this document rests on are each shown failing when broken.

### 1. Challenge

*Is this the best solution?* The three tests are named across points 2 to 5, and gathering them
here is not duplication: they share a harness — a guest with the binaries staged, which
`vm run --with-dist` now provides — and each of them is a **negative** as much as a positive.
`AGENTS.md` §3-bis says a guard nobody has seen fail is a guard nobody has seen work, and all three
of these guard properties that would otherwise be assertions in a document.

*Is it coherent with the specs?* Yes, and it fills a hole. `F2.WS.04`'s done-condition is "the
policy generation counter increments; no torn read" — two properties, and the plan names no test
for either. This point is where they get one.

*Can it be simplified?* The torn-read run cannot be simplified without losing its meaning: fewer
samples make a rare interleaving invisible, and a single-threaded version tests nothing. The other
two can share one guest boot with it, which is the simplification taken.

### 2. Verification

- **The torn-read run states its own weakness.** Sampling from user space cannot observe what a BPF
  program would; it measures the publisher's ordering, not the reader path F3 will have. The test's
  comment will say so, and `F3.PT.02` will own the kernel-side version.
- **The privilege negative must fail for the right reason.** `agentd` attempting the update must
  produce `EPERM`, not `ENOENT`: a test that passes because the map is missing proves nothing about
  capabilities. It will assert on the errno, and it will first confirm the map exists by reading it.
- **A million samples is a number, not a ritual.** It will be reported with the elapsed time and the
  number of swaps observed, so a run where the publisher never swapped is visibly not a test.

### 3. Implementation

- `cargo xtask test-policy-publish` will be the entry point, running the three inside one guest via
  `vm run --with-dist`, and it will be added to Annex H with `F2.WS.04` as its owning task.
- The sampler and the publisher will be two invocations of `aisme-loaderd`, so the thing under test
  is the shipped binary and not a test-only reimplementation of it.
- Output will be the three results and the numbers behind them, in the marked block `vm run`
  already captures.

### 4. Tests

This point *is* the tests. What it adds beyond points 2–5's list:

- A **self-check of the harness**: the run asserts that at least one swap was observed during
  sampling, so a publisher that silently stopped republishing fails the test rather than passing it
  with a clean million.
- A **negative of the negative**: a variant that runs the update as the loader, which must succeed,
  so the `EPERM` result is known to come from the capability set and not from something else about
  the map.

### 5. Documentation

- Plan Annex H: the new command and its task.
- Plan `F2.WS.04`'s row: the two done-conditions each pointing at the test that shows them.
- `docs/ai/STATE.md`: the numbers when it first passes, with the swap count beside the sample
  count.

**Closing.** Verified against `F2.WS.04`'s done-condition as the plan states it (`:1622`),
`AGENTS.md` §3-bis (the rule that a guard must be seen failing), and `vm run --with-dist` as
implemented on 2026-09-07, which is what makes a three-part guest test cost one boot. Nothing of
the skeleton fell here. Open: the sample count, which is written as a million and will be reduced
if a boot takes longer than the gate's budget — with the reduction recorded and the swap-count
self-check keeping it honest at any size.

---

## What this document changed

| Point | What it settled |
|---|---|
| 1 | The blocker's cause is `UnexpectedBtfType { type_id: 45 }`, not mixed sections; the second-object fallback is **refuted**, and every load failure now reports its whole chain |
| 2 | Two legacy `LpmTrie`s and a meta array in the sensor's own object; a single shared trie is refused, with its reason |
| 3 | The loader pins to `bpffs` and exits; `agentd` never holds a policy-map fd, because `SCM_RIGHTS` would leave the capability gone and the authority kept |
| 4 | The five-step publish, `meta[1]` written last, and the one-lookup staleness window recorded as the price of losing `ARRAY_OF_MAPS` |
| 5 | The generation reaches the WAL and `getCapabilities`; **unknown stops being encoded as 0** |
| 6 | The three properties each get a test that has been seen to fail |

**Still open for the owner:** moving the `aya` or `bpf-linker` pin would remove point 1's
obstruction entirely and restore `ARRAY_OF_MAPS` — and with it the structural no-torn-read that
point 4 now has to argue for. `F0.VER.01` pinned both against a measured MSRV, so it is a change
with its own validation rather than a step inside `F2.WS.04`.
