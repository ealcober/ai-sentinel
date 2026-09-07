# Challenge-amplification — the policy BPF object

> **Status**: in progress — point 1 closed
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

1. Read the actual BTF failure before designing around it.
2. The object: what it declares, and why it is separate.
3. Creation and ownership: `aisme-loaderd`'s composition root, and who holds the maps open.
4. The atomic publish: fill the idle trie, write the generation, swap.
5. The handoff: how the generation reaches `agentd` and the WAL.
6. The torn-read test, and the privilege-split negative.

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
