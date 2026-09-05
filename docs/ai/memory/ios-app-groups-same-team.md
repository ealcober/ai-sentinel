---
name: ios-app-groups-same-team
description: iOS App Groups are scoped to one developer team, so cross-vendor IPC is loopback or nothing
type: platform-limit
---

App Groups are scoped to one developer team.

**Why it matters:** A third-party app can never join ours, so cross-vendor IPC on iOS is loopback or nothing. Any design that assumes a shared container between AI Sentinel and someone else's AI app is unbuildable.

**How to apply:** The AI Sentinel SDK talks to the on-device engine over loopback, not a shared container. Do not specify an App Group as the SDK transport on iOS.

**Source:** `F9.SDK.05`

Related: [[ios-extension-memory-ceiling]]
