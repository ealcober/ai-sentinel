---
name: ios-extension-memory-ceiling
description: NEPacketTunnelProvider is OS-killed near 50 MB
type: platform-limit
---

`NEPacketTunnelProvider` is OS-killed near 50 MB.

**Why it matters:** The flow table is the main consumer, and the forensic store must never live in the extension. An extension that grows past the ceiling is terminated by the OS, which reads as AISME failing rather than as iOS enforcing a limit.

**How to apply:** Keep the flow table bounded and evict; put the forensic store in the containing app, not the extension. `budgets.toml` carries `mobile.ios_extension.rss_mb` and `os_terminations`, whose hard value is **0**.

**Source:** §2.20.7, `budgets.toml`

Related: [[ios-app-groups-same-team]]
