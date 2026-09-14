---
name: seccomp-args-are-32-bit
description: A seccomp notification's descriptor and flag arguments are 32-bit values in 64-bit slots — truncate and reinterpret, never range-check
type: domain
---

A `seccomp_notif`'s `data.args` is `[u64; 6]`, and the kernel leaves a 32-bit argument in its slot **without sign-extending it**. `AT_FDCWD` is `-100`, and it arrives as `0x0000_0000_ffff_ff9c`.

So `i32::try_from(args[0] as i64)` **fails** on the commonest `openat` in the system. Measured, not reasoned: the first version of `aisme-linux`'s allow path wrote exactly that with `.unwrap_or(0)` and refused every plain `open` as "relative to a directory descriptor" — because the fallback turned `AT_FDCWD` into descriptor **0**. An absence read as a value, in the conversion written to avoid one.

**Why it matters:** the failure is silent in the direction that looks safe. A supervisor that refuses every open is obviously broken in a test and *looks* fail-closed in production, so it survives review; and had the fallback been any other number it would have resolved paths from the wrong directory instead.

**How to apply:** read these arguments as `args[n] as i64 as i32` and put the conversion in the notification type rather than in each caller — `Notification::dirfd()` and `Notification::open_flags()` — so there is one place to get it right. A range check is the wrong tool: the value is not out of range, it is in a wider slot. The regression is pinned by `a_descriptor_argument_is_truncated_and_not_range_checked`, which also asserts `i32::try_from` still fails on it, so the test stops pinning anything the day that changes.

**Source:** `F2.WS.05`, measured 2026-09-15

Related: [[seccomp-unotify-toctou]]
