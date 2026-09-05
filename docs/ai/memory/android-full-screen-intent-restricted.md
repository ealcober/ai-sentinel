---
name: android-full-screen-intent-restricted
description: Android 14 restricts USE_FULL_SCREEN_INTENT to calling and alarm apps
type: platform-limit
---

Android 14 restricts `USE_FULL_SCREEN_INTENT` to calling and alarm apps.

**Why it matters:** Mobile prompts are heads-up notifications with action buttons; asking for the entitlement invites review rejection, and a rejected build ships nothing.

**How to apply:** Deliver adjudication prompts as heads-up notifications with action buttons. Do not request the full-screen-intent entitlement. Mobile denies first and grants retroactively, which is a platform constraint rather than a design preference.

**Source:** `01_permission-model.md` §7.4

Related: [[ios-extension-memory-ceiling]]
