---
name: an-interrupted-wait-is-not-a-timeout
description: poll returns EINTR on any caught signal and Linux never restarts it — a wait that treats that as the budget expiring fails closed on a person who was about to answer
type: domain
---

`poll(2)` returns `-1`/`EINTR` whenever a **caught** signal arrives, and Linux **never** restarts it — not even when the handler was installed with `SA_RESTART`. `select` and `poll` are the documented exception to restartability; `read` on a regular descriptor is not.

Measured on 2026-09-15 in `TerminalAdjudicator`: a budget of **300 ms** was given up on in **4.4 ms**. The wait treated `rc <= 0` as *the budget ran out*, which is an absence read as a value — the interruption and the expiry are different facts and only one of them means nobody answered.

**Why it matters here:** the escalate class's timeout default is **deny**. A signal arriving while the prompt is on screen refused a developer who was about to type. And the signal is one the product generates itself: `agentd` reaps children, so `SIGCHLD` is ordinary traffic, not an exotic condition.

**How to apply:** a bounded wait is written against a **deadline**, never against a single duration handed to one `poll` call. On `EINTR`, recompute what is left and resume; the deadline still bounds the loop, so there is no way to spin. The `read` that follows the wait is the same class and is resumed the same way rather than being read as an answer of none.

**How it was found, and the lesson about the test:** as a **flake** — the budget test passed alone and failed in the workspace run, because only under parallel load did another test's child exit and deliver a signal. A test that is green alone and red in the suite is evidence of a real defect far more often than it is evidence of a bad test. The regression test delivers `SIGCONT` to the waiting thread with `pthread_kill`, which makes it deterministic: a handler is installed so the signal is *caught* (an ignored or defaulted signal does not interrupt anything), and the thread is named so it cannot land on another test's.

**Source:** `F2.WS.06`, measured 2026-09-15

Related: [[a-path-is-a-spelling]]
