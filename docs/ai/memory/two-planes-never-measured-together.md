---
name: two-planes-never-measured-together
description: A per-component measurement can be exactly right and mean nothing — AISME's intent plane cost 1 ms alone and deadlocked the moment a session existed
type: domain
---

`F2.WS.03` measured `aisme declare` at **1 ms per call** and the figure was correct. It was taken with **no session registered**. The first time the intent plane and the enforcement plane ran in the same session, they deadlocked:

| | result |
|---|---|
| a declaration, alone | 1 ms |
| a declaration from inside a supervised session, no socket budget | **never returned** |
| the same, with a 100 ms budget | **103 ms each, 1 of 5 landed** |
| the same, once the daemon served connections concurrently | **9–22 ms, 5 of 5 landed** |

The process tree named the fault exactly: `aisme run` in `recv_wait_event`, the shell in `do_wait`, `aisme declare` in `unix_stream_data_wait`. The daemon accepted connections serially and `aisme run` holds one open for the session's whole life, so the hook queued behind it and was never reached.

**Why it matters:** every component was measured and every measurement was right. What was never measured is the **composition**, and the composition is the product. A benchmark of a piece in isolation answers a question nobody is asking.

**How to apply:** when two subsystems are specified to run in the same session, the measurement that counts is the one with both running. Before trusting a per-component figure, ask what else is holding a resource at the time the figure was taken — a socket, a lock, a descriptor, the terminal.

**The second half of the lesson, found the same way:** fixing the accept loop moved the freeze one level down rather than removing it. The generation cell was locked across the whole request, and a request can block for ten seconds because `decide_open` calls the adjudicator on the serving thread. Concurrency does nothing for a handler that holds a shared lock while it waits for a person. That is why `a_blocked_adjudication_does_not_freeze_the_daemon` asserts on a **second caller's latency** and not on the first one's answer.

**Source:** `F0.ASSET.02` and `F2.WS.03`, measured 2026-09-15

Related: [[a-path-is-a-spelling]], [[an-interrupted-wait-is-not-a-timeout]]
