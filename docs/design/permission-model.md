# Design Note — Session Permission Model ("Android-style permissions for AI agents")

> **Status**: `DRAFT` — captured 2026-08-17, to be developed in the next session.
> **Owner**: architecture · **Feeds**: Phase F7 (enforcement), F8 (desktop UI), F9/F10 (mobile), Annex B (AISME-PL)
> **Origin**: direct product requirement from the project owner.

## 1. The requirement

> The interface must block, by default, actions outside the permitted or detected scope of an AI session, and allow them after asking — a system similar to Android permissions.

This is the **product-facing shape** of the enforcement engine described in Part III / F7 of the implementation plan. Everything below the UI already exists in the plan (BPF-LSM, minifilter, `seccomp_unotify`, cgroup freeze, Network Slam, AISME-PL). What this note adds is the **user-visible permission semantics** that sit on top, and the decision to make *deny-by-default outside scope* the product's default posture rather than an opt-in hardening mode.

## 2. Why the Android analogy is the right one

Android's runtime permission model solved almost exactly this problem for apps, and its evolution encodes lessons we get for free:

| Android lesson | How it maps to AI sessions |
|---|---|
| **Runtime prompts, not install-time** | Ask when the agent actually reaches outside scope, not in a setup wizard nobody reads |
| **Scoped storage** — an app owns its directory and needs permission for anything else | An AI session owns its **workspace** and needs permission for anything else. This is already the plan's "contextual permissions by default" |
| **Permission groups**, not individual syscalls | Users cannot reason about `openat2`; they can reason about "read files outside the project" |
| **One-time / while-in-use grants** (Android 11) | "Allow once" and "Allow for this session" must exist, and one-time should be the safe default choice |
| **Auto-revoke unused permissions** (Android 11+) | Grants decay. A permission granted for one task should not persist forever |
| **Rationale UI** — apps must explain why | **We can do better than Android here** — see §5 |
| **Prompt fatigue is the failure mode** | If we ask too often, users blanket-approve and the system is worse than useless. §6 |

The critical difference in our favour: **Android has to trust the app's self-declared reason for asking. We have the agent's actual Chain-of-Thought and its causal graph.** We can show the user the real reason, and we can detect when the stated reason does not match the attempted action. That turns the prompt from "an app wants your contacts, ok?" into something a person can actually adjudicate.

## 3. Scope: what "inside" means

A session's scope is a **manifest**, partly declared and partly inferred:

```
SessionScope {
  workspace_roots:  [canonical paths]      // project dir(s); read+write free
  read_extra:       [canonical paths]      // toolchain, caches, ~/.cargo, node_modules
  network_allow:    [domains/CIDRs]        // AI provider, package registries, project hosts
  exec_allow:       [binaries/classes]     // compilers, package managers, git, test runners
  tool_allow:       [tool names]           // for SDK/tool-call layer (F11)
  device_allow:     [capabilities]         // mobile: camera, contacts, location…
}
```

Populated from, in precedence order:
1. **Explicit declaration** — `aisme run --scope ./project -- claude`, or a checked-in `.aisme/scope.toml`.
2. **Detection** — inferred from the working directory, VCS root, detected toolchain, and the provider endpoint the agent actually talks to.
3. **Baseline profile** — shipped defaults per agent type (a coding agent needs a compiler; a chat client does not).

**Open question for the next session:** does a checked-in `.aisme/scope.toml` constitute a trusted input? A malicious repository could ship one that grants itself broad scope. Leaning towards: repo-provided scope files can only ever *narrow* the effective scope, never widen it — the same monotonicity principle used for the Observer LLM in `H-12`. Needs an ADR.

## 4. Permission groups (user-facing taxonomy)

Deliberately small. Each maps to enforcement hooks already in the plan.

| Group | Covers | Enforcement point | Default |
|---|---|---|---|
| `FILES_OUTSIDE_WORKSPACE` | Read/write outside declared roots | `lsm/file_open`, `IRP_MJ_CREATE` | **Ask** |
| `SYSTEM_CONFIG` | `/etc`, `System32`, boot config, systemd units, registry Run keys, shell profiles | same | **Deny** (never ask by default) |
| `CREDENTIALS` | SSH keys, `.env`, keychain, credential manager, cloud config | same + taint | **Ask**, always with elevated framing |
| `NETWORK_EGRESS` | Connections outside the allowlist | `lsm/socket_connect`, tunnel (mobile) | **Ask** |
| `EXECUTE` | Running binaries outside the allowlist | `lsm/bprm_check_security` | **Ask** |
| `FILELESS_EXECUTE` | `memfd_create`+`execveat`, reflective loading | same | **Deny** (never ask) |
| `PERSISTENCE` | cron, systemd timers, Scheduled Tasks, autostart | file hooks | **Ask**, elevated |
| `PACKAGE_INSTALL` | System-wide package managers | exec + file | **Ask** |
| `SELF_PROTECTION` | Anything targeting AISME itself | `lsm/bpf`, `ptrace`, `task_kill`, `ObRegisterCallbacks` | **Deny** (never ask) |
| `DEVICE` *(mobile)* | Camera, contacts, location, photos accessed by an AI app | Sentinel SDK + platform | **Ask** |

Three groups are **never promptable** (`SYSTEM_CONFIG`, `FILELESS_EXECUTE`, `SELF_PROTECTION`). This is deliberate: a prompt is an attack surface. If an agent under prompt injection can get a tired user to click "Allow" on "modify /etc/shadow", the whole architecture is decorative. Those require an explicit, out-of-band policy change in settings — never a modal in the flow of work.

## 5. Grant lifecycle

Prompt options, in the order they should appear:

```
┌──────────────────────────────────────────────────────────────┐
│  Claude Code wants to read files outside your project        │
│  ~/.aws/credentials                                          │
│                                                              │
│  It said it was: "checking the deploy configuration"         │
│  ⚠ This file contains credentials. Reading it will mark the  │
│    session as handling secrets and restrict outbound network.│
│                                                              │
│  [ Deny ]  [ Allow once ]  [ Allow this session ]  [ Always ]│
│                                            Risk score: 6/10  │
└──────────────────────────────────────────────────────────────┘
```

- **Deny** — default action on timeout, and the default focus.
- **Allow once** — this single operation.
- **Allow this session** — until the session ends.
- **Always** — creates a persisted AISME-PL rule. Must show *exactly* what rule it will create, and must be revocable in one click from the UI.

**Decay (Android auto-revoke analogue):** `Always` grants expire after N days of non-use (default 30) and are re-prompted. Session grants die with the session. This prevents a workstation from accumulating a permission surface nobody remembers approving.

**The rationale line is the differentiator.** We show the agent's own declared intent, taken from the Chain-of-Thought captured in F4/F11 — and if the declared intent and the attempted action diverge, the prompt says so and the risk score reflects it. That is the "causal disparity" detection from the research, surfaced at exactly the moment it is useful.

## 6. Prompt fatigue is the primary failure mode

A permission system that asks too much gets blanket-approved, and then it is worse than nothing because it manufactures consent. Countermeasures, all already available in the plan:

1. **Generous default scope.** Inside the workspace, everything is free and silent. The plan's "zero friction inside the project directory" is what makes deny-by-default outside it tolerable.
2. **Mandatory learning mode.** First 7 days: `WOULD_BLOCK` only, no prompts. Then show the user a summary — *"this is what we would have asked you about"* — and let them bulk-approve the boring parts. This is `H-13` in the plan and it applies to the whole permission model, not just Network Slam.
3. **Coalescing.** 150 file reads under `~/.cargo` is **one** prompt about a directory, not 150 prompts. Prompts are per-*intent*, not per-syscall.
4. **Budget the prompts.** Target: **≤ 3 prompts per developer per day** in steady state after learning mode. Instrument it (`aisme.permission.prompts_per_day`) and treat exceeding it as a product bug, with the same weight as a false positive in the benign corpus.
5. **Never prompt for the three non-promptable groups.**

## 7. Multiplatform prompt delivery — the hard part

The enforcement engine is already cross-platform. **The prompt is not.** Asking a user a question is, on every OS, harder than blocking the syscall. This section is the open engineering problem.

### 7.1 The one architectural rule that makes it tractable

> **The enforcement engine never draws UI. A separate per-user-session agent (`aisme-uiagent`) owns every prompt, on every platform.**

This is forced on us by Windows (a service in session 0 physically cannot show UI in an interactive session) but it turns out to be the right answer everywhere: on Linux the daemon is root and the desktop is a user session; on macOS the same split exists; on mobile the sensor is an extension that cannot present UI at all. One architecture, five implementations of a thin agent.

```
enforcement engine (root / SYSTEM / extension)
        │ escalation  (local IPC, authenticated by peer identity)
        ▼
aisme-uiagent  (runs as the logged-in user, one per session)
        │
        ├─ Tier 1  modal window          ← best: focused, blocking, full detail
        ├─ Tier 2  notification w/ actions ← Allow/Deny without opening anything
        ├─ Tier 3  terminal prompt        ← when we own the TTY (`aisme run`)
        ├─ Tier 4  remote (mobile)        ← §2.20.5, 3 s budget, deny-first
        └─ Tier 5  policy default         ← nothing available; decide and log loudly
```

**The available tier determines the timeout and the default action** — which is exactly the channel-aware adjudication model already specified in §2.20.5 of the implementation plan. This section is that model made concrete per platform.

### 7.2 Windows — familiar pattern, real plumbing

The user-facing precedent is excellent: **Controlled Folder Access** in Windows Security does precisely this (block, toast, allow), so the interaction is already native to users' expectations.

| Aspect | Approach |
|---|---|
| Session split | `aisme-agentd` runs as a service in session 0. `aisme-uiagent` is launched per interactive session (`WTSGetActiveConsoleSessionId` / session-change notifications, or a Run-key/Task Scheduler logon task) |
| Tier 1 modal | Tauri window, always-on-top, `SetForegroundWindow` with the usual foreground-lock caveats |
| Tier 2 notification | WinRT toast with action buttons — requires a registered AUMID and a Start Menu shortcut, done at install time |
| Multi-session | RDP / Fast User Switching: one `uiagent` per session; escalations route to the session owning the agent process |
| Non-negotiable | We do **not** and cannot hook UAC's secure desktop. Our prompt is an ordinary user-session prompt. Do not imply otherwise in UI copy |

**Open item:** session-0 → session-N routing when the AI agent runs as a different user than the console user (a service account, a container). Probably: route to the *owner of the session scope*, fall back to policy.

### 7.3 Linux — the genuinely hard case

There is no single desktop stack. Assume nothing.

| Environment | Mechanism | Notes |
|---|---|---|
| Any graphical session | `aisme-uiagent` as a **systemd `--user` unit**, connected to the system daemon over a Unix socket | Mirrors the Windows split; avoids root-reaching-into-the-session-bus entirely |
| Session enumeration | `systemd-logind` (`org.freedesktop.login1`) to find active sessions and their users | Do **not** try to guess `DBUS_SESSION_BUS_ADDRESS` |
| Tier 2 notification | `org.freedesktop.Notifications` with actions | Action-button support varies by DE; must degrade if the daemon reports no `actions` capability |
| Wayland caveat | **Cannot force-focus a window.** A modal may open unfocused or be missed entirely | Never rely on the modal as the only channel; always pair with a notification |
| X11 | Focus stealing works, but is rude | Same policy |
| **Headless / SSH / CI / tmux** | **Tier 3: prompt in the terminal** | See below — this is the good answer |
| No agent at all | Tier 4 (mobile) → Tier 5 (policy) | Logged as a coverage event |

**The `aisme run` insight.** When a session is started as `aisme run -- claude`, **we own the terminal**. That lets us prompt directly in the TTY the developer is already looking at, with no desktop integration whatsoever:

```
⚠ AISME  Claude Code wants to read ~/.aws/credentials
         Stated intent: "checking the deploy configuration"
         This file contains credentials.                     risk 6/10
         [d] deny  [1] allow once  [s] allow this session  [a] always ▸ _
```

This sidesteps the entire GNOME/KDE/Wayland/X11 problem for the most common developer case, works over SSH, works in a container, works in tmux. **It is a strong argument for making `aisme run` the primary onboarding path** rather than just one option among several — which also happens to give us perfect session identity (§2.19 of the plan). Two problems, one answer.

**Open item:** what happens when the agent is launched from an IDE rather than a terminal (no TTY, GUI session present). Likely Tier 1/2 via the user agent; needs prototyping across GNOME, KDE and a tiling WM.

### 7.4 Android

| Aspect | Approach |
|---|---|
| Tier 1 modal | **Restricted.** Background activity launch is blocked on Android 10+. `setFullScreenIntent` was further restricted on Android 14 to calling/alarm apps — we will not qualify, and requesting it invites review rejection |
| **Tier 2 (primary)** | **High-priority heads-up notification with `Action` buttons** — Allow / Deny answered without opening the app. This is the realistic default and it works |
| Detail view | Tapping the notification opens the app with full context and the 4-option grant model |
| Timing reality | With a 3 s enforcement budget (§2.20.5) the flow is **deny-first, grant retroactively**: the flow is blocked, the user is notified, and an `Allow` creates a rule for next time rather than un-blocking a dead connection |
| Device permissions | The `DEVICE` group can reuse the platform's own runtime permission prompts where the AI app is SDK-integrated (F11) |

### 7.5 iOS

| Aspect | Approach |
|---|---|
| Extension constraint | `NEPacketTunnelProvider` **cannot present UI at all** — a hard platform rule |
| **Primary channel** | `UNUserNotificationCenter` local notification with **notification actions** (Allow/Deny buttons on the notification itself) |
| Detail view | Notification tap → app, via App Group shared container for context handoff |
| Timing reality | Same as Android: deny-first, grant retroactively |
| Critical alerts | `UNNotificationInterruptionLevel.critical` requires a special Apple entitlement; **do not assume it.** Design for `.timeSensitive`, which is obtainable |

### 7.6 macOS `[POST]`

Not in Phase 5, but the shape is known: Endpoint Security framework for enforcement, a login-item `uiagent` for prompts, `NSAlert` + `UNUserNotificationCenter`. Same split, no surprises. Recording it here so the `uiagent` protocol is not accidentally designed in a Windows/Linux-only way.

### 7.7 Summary matrix

| | Modal | Notification + actions | Terminal | Realistic default posture |
|---|---|---|---|---|
| **Windows** | ✅ via `uiagent` | ✅ WinRT toast | ✅ with `aisme run` | Ask synchronously |
| **Linux (GUI)** | ⚠️ Wayland focus caveats | ✅ freedesktop (actions vary) | ✅ with `aisme run` | Ask synchronously |
| **Linux (headless)** | ❌ | ❌ | ✅ **primary** | Ask in terminal, else policy |
| **Android** | ❌ blocked by OS | ✅ **primary** | ❌ | **Deny-first, grant retroactively** |
| **iOS** | ❌ blocked by OS | ✅ **primary** | ❌ | **Deny-first, grant retroactively** |

**The one substantive product consequence:** desktop can ask *before* the fact; mobile can only ask *after* it has already denied. That asymmetry has to be visible in the UI so users are not surprised — and it is also, conveniently, the safer default. It is consistent with the remote-adjudication asymmetry already specified in §2.20.6 (`DENY` is cheap, `ALLOW` is expensive).

### 7.8 Open questions for the next session

1. `aisme-uiagent` ↔ engine protocol: reuse the F8 control-plane JSON-RPC, or a narrower dedicated one? (Leaning: reuse — one protocol, already specified in `F8.API.01`.)
2. Prototype the Wayland modal focus behaviour across GNOME / KDE / Hyprland before committing to Tier 1 on Linux.
3. Does `aisme run` become the *documented default* onboarding path? (Strongly leaning yes — it solves prompting and session identity simultaneously.)
4. Notification action-button availability probe: how do we detect at runtime that a Linux notification daemon supports actions, and what is the fallback?
5. Android/iOS: is retroactive grant enough for a good experience, or do we need a "pre-authorize this app's typical behaviour" onboarding flow?

## 8. Where this lands in the plan

| Component | Phase | Change needed |
|---|---|---|
| Grant model, decay, persistence | F7 | Extend AISME-PL (Annex B) with grant scope + TTL |
| Prompt coalescing by intent | F7 | New: intent-grouping layer above the escalation queue |
| Desktop prompt UI | F8 | `F8.UI.04` already covers the modal; extend to the 4-option grant model |
| Mobile prompt UI | F9 | Inherits §2.20.5 channel-aware timeouts; remote `Always` should be forbidden |
| Sentinel device permissions | F10 | `DEVICE` group |
| Tool-call level prompts | F11 | SDK veto is the cleanest prompt point — it has the intent natively |
| Prompt-per-day budget | Part IV | New CI metric, added to the benign corpus gate |
| **`aisme-uiagent`** (per-session prompt agent) | F8 | **New component** — see §7.1. Required on Windows, Linux and macOS |
| Notification channels (toast / freedesktop / UN) | F8, F9 | Per-platform, with capability probing |
| Terminal prompt in `aisme run` | F8 | Solves headless Linux and gives perfect session identity |

## 9. Open questions for the next session

1. Trust model for repo-provided `.aisme/scope.toml` (leaning: narrow-only, needs ADR).
2. Does `Always` sync across paired devices, or is it per-machine? (Leaning: per-machine; syncing grants is a lateral-movement vector.)
3. Interaction between grants and taint declassification (`H-13`) — is an `Always` grant on `.env` also an implicit declassification? (Leaning: no. Reading is granted; egress remains separately gated.)
4. Should there be a "paranoid mode" that makes every group non-promptable for regulated environments?
5. Prompt UX when the agent is running unattended (CI, overnight) — currently falls to policy default; is that enough?
