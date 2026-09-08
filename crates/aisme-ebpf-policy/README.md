# `aisme-ebpf-policy` — a reproduction, not a product artefact

This crate builds a BPF object containing **only** BTF-defined maps
(`ArrayOfMaps` and `Array`) and **no programs**. Nothing ships it and nothing
loads it in production.

It exists to reproduce, in one command, the obstruction that decided the shape
of `F2.WS.04`:

```bash
cargo xtask build-ebpf
cargo xtask vm run ubuntu-24.04 --with-dist -- /usr/lib/aisme/aisme-agentd --load-policy-probe
```

Measured on 2026-09-07, on both ends of the kernel matrix:

```
load-policy: REFUSED (Unsupported)
  error parsing BPF object: BTF error: BTF error: unexpected BTF type id `45`
```

`UnexpectedBtfType { type_id: 45 }` (`aya-obj-0.3.0/src/btf/btf.rs:104`) is
aya's BTF resolver following a type reference into something it does not
expect — a structural mismatch between the BTF `bpf-linker 0.11` (LLVM 21)
emits and what `aya-obj 0.3.0` reads. It is **not** a consequence of an object
carrying two map-section styles: this object carries only `.maps`, has nothing
to mix with, and fails identically.

That is why `BPF_MAP_TYPE_ARRAY_OF_MAPS` — which exists at the pinned
`aya-ebpf 0.2.1` only as a BTF map — cannot be the policy double buffer, and
why the shipped mechanism is two legacy `LpmTrie`s and an index in
`crates/aisme-ebpf` instead. The cost of that substitution is written down in
`docs/06_challenge_ampliacion_policy_object.md` point 4: one lookup of
staleness where `ARRAY_OF_MAPS` gave a structural guarantee.

**What would make this crate obsolete:** a toolchain pairing whose BTF
`aya-obj` reads — a newer `aya`, or a `bpf-linker` built against the LLVM that
`aya` expects. `F0.VER.01` pinned both against a measured MSRV, so moving
either is a change with its own validation. When that happens, run the command
above: if it reports `ACCEPTED`, `ARRAY_OF_MAPS` is available again and point 4
can drop its staleness argument.

**Do not delete this crate while the blocker is live.** Deleting the
reproduction of a live obstruction is how the obstruction gets rediscovered
from scratch.
