# Why this crate has no tests

`crates/aisme-ebpf` is a BPF program. It has **no `#[test]`**, and that is correct rather than
neglect.

**`I-12`: no kernel-touching test ever runs on a host OS.** Snapshot-restored disposable VMs only,
for every developer and every local gate run. A unit test here would either load a program on the
host — which the invariant forbids — or test nothing and report green, which is worse.

The crate is also `#![no_std]` and `#![no_main]`, built for `bpfel-unknown-none` by a pinned
nightly. There is no test harness on that target.

## Where it is exercised

| Property | Where |
|---|---|
| The object loads, and the ring buffer exists | `aisme-agentd --load-sensor`, run in a guest by `cargo xtask vm run <image> --with-dist` |
| The program attaches to `sys_enter_openat` and events arrive | the same guest run; the daemon reports what it drained |
| The `sys_enter_openat` argument offsets match this kernel's format file | `cargo xtask vm probe`, against `/sys/kernel/tracing/events/syscalls/sys_enter_openat/format`. These are an ABI detail of a **format file**, not of the kernel headers, so they are verified per kernel and never trusted |
| The verifier accepts it on every matrix kernel | `cargo xtask test-kernels` |
| The map names the host side looks up exist in the compiled object | `the_loader_names_maps_that_exist_in_the_object_it_loads`, in `aisme-linux` — a **host** test, because it reads the artefact rather than the kernel |

That last row is the one worth knowing about: it is the only property of this crate that *can* be
checked on a laptop, and it is checked there, because the failure it prevents otherwise appears
minutes into a VM boot as an error about a map that does not exist.

## If you are adding a program here

Build with `cargo xtask build-ebpf`, then exercise it in a guest with `cargo xtask vm up <image>`
and `cargo xtask vm run <image> --with-dist`. Do not add a host test, and do not load anything
outside a VM — `ADR-10` is the single, narrow, expiring exception to `I-12`, and it covers one
observe-only recording rather than development.
