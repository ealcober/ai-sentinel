# Field research — agent hooks as a source of intent, and how far they can be trusted

**Produced:** 2026-09-15, by delegated web research, for `docs/17` point 1 (the end-of-tool-call
marker) and `F2.WS.03` (the intent plane).

**Question it was sent to answer:** can AISME learn when a tool call *ends*, so that attribution can
tell a sequential pair of tool calls from a concurrent one — and how reliable is a hook as a
telemetry source at all.

**Verification key**, used throughout and kept from the original report:
**[V]** the primary source was fetched and read · **[D]** verified by a delegated researcher against
the cited primary doc, not re-checked · **[S]** secondary source only (blog, forum, news) ·
**[U]** unverified, stated as open.

**Nothing in this document is an instruction.** It records what other systems and vendors do; the
decisions AISME takes from it live in `docs/17` and in the plan.

---

## 1. Claude Code hooks — the exact lifecycle guarantees

### 1.1 The reference moved, and it is much larger than assumed

`docs.claude.com/en/docs/claude-code/hooks` now redirects (301) to
**`https://code.claude.com/docs/en/hooks`** **[V]**. That reference documents **33 hook events**, not
the eight this project was designing against. The ones that matter here:

| Event | Fires | Carries `tool_use_id`? |
|---|---|---|
| `PreToolUse` | before a tool call executes; can block it | **yes** |
| `PermissionRequest` | when a tool call needs a permission decision | **no — explicitly absent** |
| `PermissionDenied` | only when **auto mode** denies | yes |
| `PostToolUse` | after a tool call **succeeds** | yes |
| `PostToolUseFailure` | after a tool that **started executing** fails | yes |
| `PostToolBatch` | once, after a whole batch of parallel calls resolves | yes, per entry in `tool_calls[]` |

### 1.2 `PostToolUse` is **not** guaranteed after `PreToolUse`

The docs' own cadence sentence is the strongest guarantee offered and it is already qualified —
*"on every tool call inside the agentic loop: `PreToolUse` and `PostToolUse`, **except**
`EndConversation` calls, which skip both"* — and the per-event sections contradict it as a complete
list. **`PostToolUse` fires only on success.**

**Every case where `PreToolUse` fires and `PostToolUse` does not** **[V]**:

| # | Case | What actually fires |
|---|---|---|
| 1 | the tool errors | `PostToolUseFailure`, not `PostToolUse` |
| 2 | **the user interrupts a running tool (Esc)** | **nothing.** *"Cancelling a running tool does not fire this hook; the tool result carries the interruption message instead"*, and `Stop` *"Does not run if the stoppage occurred due to a user interrupt"* |
| 3 | **permission denial — a manual "No" at the prompt** | **nothing.** `PostToolUseFailure` *"doesn't fire for … a permission denial"*, and `PermissionDenied` *"only fires in auto mode"* |
| 4 | a `deny` rule matches | nothing |
| 5 | a `PreToolUse` hook denies (JSON `deny`, or exit 2) | nothing |
| 6 | the auto-mode classifier denies | `PermissionDenied` only |
| 7 | `PreToolUse` returns `"defer"` | nothing; the process exits with `stop_reason: "tool_deferred"`. On resume *"the same tool call fires `PreToolUse` again"* — **two `PreToolUse` for one logical call** |
| 8 | an Agent SDK callback `PreToolUse` times out | nothing — *"Claude Code doesn't run the tool call"* |
| 9 | the SDK's `max_turns` limit is hit | *"Hooks **may not fire** … because the session ends before hooks can execute"* |
| 10 | the session is killed (SIGKILL, crash) | nothing. `SessionEnd` has a **1.5 s** default budget and a closed `reason` set (`clear`, `resume`, `logout`, `prompt_input_exit`, `other`) with **no crash or interrupt value** |

**Cases where neither fires**, so no orphan is created: an unknown tool name, and a schema or
validation failure — *"Validation rejections are returned as `tool_use_error` results and happen
before hooks run, so they fire **neither** `PreToolUse` **nor** `PostToolUseFailure`."*

**Compaction:** `PreCompact`/`PostCompact` are turn-boundary events and the lifecycle diagram places
them outside the agentic loop. Whether compaction can interleave with an in-flight tool call is
stated nowhere — **[U]**.

### 1.3 The pairing key exists, and is documented for exactly this purpose

`PreToolUse` and `PostToolUse` **both carry `tool_use_id`** (for example `"toolu_01ABC123…"`), the
model's `tool_use` block id **[V]**. The Agent SDK documentation states its purpose outright:

> **Tool use ID** (`str | None` / `string | undefined`): correlates `PreToolUse` and `PostToolUse`
> events for the same tool call.

Added in **v2.0.43** **[V]**, so there is no version gate worth planning around.

`PostToolUse` also carries `tool_response` (the tool's **structured** output) and an optional
**`duration_ms`** — *"Tool execution time in milliseconds. **Excludes time spent in permission
prompts and PreToolUse hooks**"* (v2.1.119) **[V]**. That exclusion matters: `duration_ms` is the
execution window, not the wall-clock gap between the two hook events.

### 1.4 Three failure modes that bite a syscall-joining product

**(a) A tool call can "complete" while its work keeps running.** For the `Agent` tool, *"the tool
returns when the task moves to the background … It has `status: "async_launched"`"* **[V]**. For
`Bash` with `run_in_background: true`, or a foreground command that hits its timeout, the tool result
is a task id and an output path — *"Command did not complete within its 120s timeout and was moved to
the background"* **[V]**. So `PostToolUse` fires at **launch**, and the process tree lives on past it,
potentially past `Stop` and past `SessionEnd`. **A rule of "the syscalls between PRE and POST belong
to this call" silently under-attributes every long-running command.**

**(b) There is no PID anywhere in the hook payload.** Hooks receive `session_id`, `prompt_id`,
`transcript_path`, `cwd`, `scratchpad_dir`, `permission_mode`, `agent_id`, `agent_type`, `effort` —
and **no process id, no shell id, no task id for the tool's subprocess** **[V]**. A join cannot be
by pid from the hook side.

**(c) Documented coverage holes where a file is touched with no `PreToolUse` at all** **[V]:**
- `@`-referenced files: *"Claude Code inserts their contents while building the prompt, so **no
  PreToolUse hook fires for them**, including hooks matching `Read`."*
- *"Claude Code doesn't run a `PostToolUse` hook matching `Edit|Write` when a `Bash` command or a
  process outside Claude Code rewrites the same file."*

### 1.5 `TRACEPARENT` — an in-band, kernel-visible join key

Claude Code's OpenTelemetry tracing emits a `claude_code.tool` span with a
`claude_code.tool.execution` child. Both carry `tool_use_id` **and** `gen_ai.tool.call.id` (the same
value), plus `duration_ms`, `success`, `error_class` **[V]**. The `tool_result` and `tool_decision`
log events carry `tool_use_id` too — *"Matches the `tool_use_id` passed to hooks, allowing
correlation between OTel events and hook-captured data"* (v2.1.119) **[V]**.

And, critically:

> When tracing is active, **Bash and PowerShell subprocesses automatically inherit a `TRACEPARENT`
> environment variable containing the W3C trace context of the active tool execution span.**

`CLAUDE_CODE_PROPAGATE_TRACEPARENT` extends this to custom-proxy setups, covering *"the `TRACEPARENT`
environment variable for Bash, PowerShell, **and hook subprocesses**"* (v2.1.152) **[V]**.

This puts the tool-execution identity **inside the observed process's own environment**, where a
sensor reading the environment at `execve` gets it with no timing heuristic at all. It is gated on
`CLAUDE_CODE_ENABLE_TELEMETRY=1` plus `CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1`, and traces are beta.
A span also has a start and an end by construction — an end marker obtained for free.

From the same surface, `tool_decision.source` distinguishes `config` / `hook` / `user_permanent` /
`user_temporary` / `user_abort` / `user_reject` **[V]** — *how* each call was authorised, which a
conventional EDR has no analogue for.

### 1.6 Fail-open versus fail-closed, an asymmetry that changes the architecture

| Hook kind | `PreToolUse` times out → |
|---|---|
| `command` / `http` / `mcp_tool` | **the tool runs.** *"don't count on a stalled hook to act as a gate"* **[V]** |
| Agent SDK in-process callback | **the tool does not run**; Claude receives a timeout error **[V]** |

A shell-script `PreToolUse` helper that stalls or crashes is invisible and the call proceeds. An SDK
callback fails closed.

---

## 2. Parallel tool calls, and how they interleave

**They interleave, and they are distinguishable** **[V]:**

> `PostToolUse` fires once per tool, which means it **fires concurrently** when Claude makes parallel
> tool calls.

> All matching hooks run in parallel.

So several `PreToolUse` are in flight at once, each with its own `tool_use_id`, interleaved with the
`PostToolUse` of earlier calls. **`tool_use_id` is the only thing that disambiguates them** —
`session_id` and `prompt_id` (the turn UUID) are both too coarse.

**`PostToolBatch` is the reliable fence.** It *"Runs **once** after every tool call in a batch has
resolved, before Claude Code sends the next request to the model"*, with a `tool_calls[]` array of
`{tool_name, tool_input, tool_use_id, tool_response}` **[V]**. It is a better "everything in this
wave is done" marker than counting `PostToolUse` events, because it fires once regardless of how many
individual post events went missing. Note `tool_response` here is the **serialized** `tool_result` the
model sees, a different shape from `PostToolUse`'s structured object; the docs say so explicitly.

**Two things that could not be closed** **[U]:**
- whether `tool_calls[]` includes **denied or failed** calls. The official example shows only
  successful `Read`s; a community source claims a `succeeded` field exists **[S]**, and the official
  schema does not list one.
- whether `PostToolBatch` fires when a turn is **interrupted**. Its trigger is "before the next model
  call"; if there is no next model call, plausibly it never fires. Untested.

`"defer"` carries an explicit concurrency restriction: *"`defer` only works when Claude makes a single
tool call in the turn. If Claude makes several tool calls at once, `defer` is ignored with a
warning"* **[V]**.

---

## 3. The same question across every other agent

Verified 2026-09-15 **[D]** against the cited primary docs, except Gemini CLI and the OTel spec which
were re-verified directly **[V]**.

| Agent | Pre event | Post event | Per-call id |
|---|---|---|---|
| **Claude Code** | `PreToolUse` | `PostToolUse` / `PostToolUseFailure` | **yes — `tool_use_id`** **[V]** |
| **Cursor** | `preToolUse` | `postToolUse` / `postToolUseFailure` | **yes — `tool_use_id`** **[D]** |
| **Codex CLI** | `PreToolUse` | `PostToolUse` | **yes — `tool_use_id`** **[D]** |
| **OpenCode** | `tool.execute.before` | `tool.execute.after` | **yes — `callID`** **[D]**, in types, not prose |
| **Amp** | `tool.call` | `tool.result` | **yes — `toolUseID`** **[D]** |
| **Cline** | `beforeTool` | `afterTool` | **yes — `toolCall.toolCallId`** **[D]**, typed only |
| **Gemini CLI** | `BeforeTool` | `AfterTool` | **no** **[V]** |
| **Copilot CLI** | `preToolUse` | `postToolUse` / `postToolUseFailure` | **no** **[D]** |
| **Windsurf / Cascade** | `pre_run_command` etc. | `post_run_command` etc. | **no** — `execution_id` is turn-granular **[D]** |
| **Devin Local** (ex-Windsurf) | `PreToolUse` | `PostToolUse` | **no** — `prompt_id` is per turn **[D]** |
| **Aider** | — | — | **no hooks at all** **[D]** |

Findings that change a design rather than merely inform it:

1. **Cursor's specialised events carry no id.** Beyond `beforeShellExecution`/`afterFileEdit` there is
   a generic trio `preToolUse`/`postToolUse`/`postToolUseFailure`, and `tool_use_id` appears **only**
   on those three **[D]**. Pairing a shell before/after on the specialised events means string-matching
   the command, which breaks on repeated or concurrent identical commands. Use the generic trio with a
   `Shell` matcher.
2. **Cursor natively loads Claude Code hooks** from `.claude/settings.json` and accepts both response
   formats **[D]** — one integration reaches two vendors, and it is also why CVE-2026-48124 exists.
   Devin Local and Copilot CLI read `.claude/settings.json` too **[D]**.
3. **Gemini CLI is the clean negative case.** Its base payload is `session_id`, `transcript_path`,
   `cwd`, `hook_event_name`, `timestamp`; `BeforeTool` adds `tool_name`/`tool_input`, `AfterTool` adds
   `tool_response`. **Zero id fields** **[V]**. Its OTel traces do carry `gen_ai.tool.call_id` **[D]**
   — so Gemini offers **enforcement without identity, or identity without enforcement, never both in
   one surface**.
4. **Codex's own documentation disclaims completeness** **[D]:** *"Some specialized tool paths can opt
   out of the default hook path. Treat tool hooks as a useful guardrail, not a complete enforcement
   boundary."* A vendor saying in print that hooks are not a complete telemetry source.
5. **The vendor-neutral vocabulary is OpenTelemetry GenAI** **[V]**. The conventions moved out of the
   main semconv repo to `open-telemetry/semantic-conventions-genai`, with **no tagged releases yet**.
   The `execute_tool` span: name `execute_tool {gen_ai.tool.name}`, kind INTERNAL,
   `gen_ai.operation.name` = `execute_tool` (Required), `gen_ai.tool.name` (Required), and
   `gen_ai.tool.call.id` — *"The tool call identifier"* — at requirement level **Recommended, if
   available**, stability **Development**. Every `gen_ai.*` attribute is Development; none is Stable.
   It is the right vocabulary and Claude Code already emits it, but it is a **span** rather than a
   pre/post pair — post-hoc correlation, not a pre-execution gate — and a compliant emitter may
   legally omit the id.
6. **MCP gives less than it appears to** **[D]**. JSON-RPC `id` is unique per session and MUST be
   echoed, so it pairs request with response at the transport layer, but it is not surfaced to a
   host's pre/post hooks unless the host chooses to. `progressToken` is optional. MCP standardises
   **nothing** about the LLM's own tool-call id and has no tool-call lifecycle notification beyond
   request/response plus optional progress.

**The design consequence:** an end marker keyed on a per-call id generalises to **six** vendors —
Claude Code, Cursor, Codex, OpenCode, Amp, Cline. For **Gemini CLI, Copilot CLI and
Windsurf/Devin Local** it must degrade to ordering plus tool name plus argument matching, which is
exactly ambiguous under the concurrency it is meant to detect. The degraded mode is planned, not
discovered.

### 3.1 GitHub Copilot in detail

Because Copilot is the largest of the negative cases, the sub-report is kept in full.

**Copilot CLI hooks exist and are Claude-shaped** **[D]** (GA 2026-02-25). Event names in camelCase
with PascalCase aliases: `sessionStart`, `sessionEnd`, `userPromptSubmitted`, `userPromptTransformed`,
`preToolUse`, `postToolUse`, `postToolUseFailure`, `preCompact`, `agentStop`, `subagentStart`,
`subagentStop`, `errorOccurred`, `notification`, `permissionRequest`.

Config: `.github/hooks/*.json`, `~/.copilot/hooks/*.json`, an inline `hooks` key in
`.github/copilot/settings.json` or `~/.copilot/settings.json`, plugin `hooks.json`, and policy
directories `/etc/github-copilot/policy.d/*.json` and the Windows registry. `.claude/settings.json`
is also read.

Payload, verbatim from the docs source:

```typescript
// preToolUse
{ sessionId: string; timestamp: number; cwd: string; toolName: string; toolArgs: unknown; }
// postToolUse
{ sessionId: string; timestamp: number; cwd: string; toolName: string; toolArgs: unknown;
  toolResult: { resultType: "success"; textResultForLlm: string; } }
// postToolUseFailure
{ sessionId: string; timestamp: number; cwd: string; toolName: string; toolArgs: unknown; error: string; }
```

**No `toolCallId`, `callId`, `invocationId` or `id` field exists in any hook event.** The only
correlator is `sessionId` plus `timestamp`, `toolName`, `toolArgs`.

Failure behaviour worth recording: command `preToolUse` hooks are **fail-closed** on a non-zero exit
(exit 2 denies even if stdout says `permissionDecision: "allow"`), but **timeouts are always
fail-open**, and HTTP `preToolUse` hooks are fail-open entirely.

**Where Copilot's per-call id does exist**, both non-blocking:
- **OpenTelemetry**, enabled by `COPILOT_OTEL_ENABLED=true` or `OTEL_EXPORTER_OTLP_ENDPOINT` or
  `COPILOT_OTEL_FILE_EXPORTER_PATH`. Span tree `invoke_agent` → `chat` and `execute_tool`; the
  `execute_tool` span carries **`gen_ai.tool.call.id`**, one span per tool call, emitted after the
  fact and unable to block.
- **Copilot SDK streaming events**: `tool.execution_start`, `_partial_result`, `_progress`,
  `_complete`, `tool.user_requested` all carry **`toolCallId`**, documented as *"Matches the
  corresponding `tool.execution_start`"*. The SDK's **hooks**, by contrast, carry no id.

**The Copilot cloud agent** runs hooks inside its ephemeral sandbox, loaded **only** from
`.github/hooks/*.json` in the cloned repo, **only** `bash`/`command` entries, no user-level files, no
plugins, no policy hooks. `notification` does not fire; `preToolUse` returning `"ask"` is treated as
`"deny"`. Same payloads, so the same verdict: no per-call id. The audit log and REST surfaces are
session- and PR-level, correlated by `agent_session_id`, with no per-invocation events.

### 3.2 Aider, and Windsurf's disappearance

**Aider has no hook mechanism of any kind** **[D]**, confirmed against the docs index and the
132-page sitemap: grepping for `hook|plugin|event|extend|api` returns exactly one hit, the API-keys
page. `--lint-cmd` and `--test-cmd` fire per edit round, `--notifications-command` per turn with no
payload, and `--analytics-log` is PostHog product analytics. No OpenTelemetry option is documented.
PyPI's latest is 0.86.2 (2026-02-12), one patch release in about eighteen months, with the repository
last pushed 2026-05-22 and 1,868 issues open: alive but in maintenance drift.

**Windsurf no longer exists as a brand** **[V]**. `windsurf.com` redirects (308) to
`devin.ai/desktop`, and `docs.windsurf.com/windsurf/cascade/hooks` to
`docs.devin.ai/desktop/cascade/hooks`. Cognition rebranded Windsurf to **Devin Desktop** (2026-06-02);
Cascade was retired 2026-07-01 and replaced by "Devin Local" **[S]** for that date. Both hook systems
are documented side by side today. Anything hardcoding `windsurf.com` or `~/.codeium/windsurf/`
needs the `devin.ai` and `.devin/` paths beside it.

Cascade's twelve events (`pre_read_code`, `post_write_code`, `pre_run_command`, `pre_mcp_tool_use`, …)
carry `trajectory_id` (the conversation) and `execution_id` — documented as *"the single agent
turn"*, so it cannot pair one `pre_run_command` with its `post_run_command`. The post events carry no
result for file or command actions at all: `post_run_command`'s `tool_info` is `command_line` plus
`cwd`, with **no exit code and no output**; only `post_mcp_tool_use` returns a result.

Devin Local's payload carries `session_id` and `prompt_id`, and its documentation states that
**"all hooks fired during the same turn share one `prompt_id`"**. It reads `.claude/settings.json`
and `~/.claude/settings.json` automatically when `read_config_from.claude` is enabled, which is the
default.

---

## 4. Attacks and failure modes beyond the four already recorded

`docs/research/01` records CVE-2025-59536, CVE-2026-21852, CVE-2026-48124 and the CHAINDROP worm.
These are additional.

### 4.1 New incidents

| Item | Date | What it is |
|---|---|---|
| **CVE-2026-25725** (GHSA-ff64-7w26-62rf) | published 2026-02-06, CVSS 3.1 **10.0 CRITICAL**, CWE-501, fixed in 2.1.2 | Claude Code sandbox escape: bubblewrap mounted `.claude/` writable and protected `settings.local.json` read-only, but **did not protect `settings.json` when it did not exist at startup**. Code inside the sandbox creates the file, injects a `SessionStart` hook, and it executes **with host privileges** on restart **[S]** |
| **Shai-Hulud / SAP CAP npm compromise** | 2026-04-29 | four `@cap-js` packages trojanised; persistence is a modified `.claude/settings.json` with a `SessionStart` hook running `node .vscode/setup.mjs` on every open — *"a trap set inside the development environment itself"*, re-infecting without an npm install **[S]** |
| **Issue #26637 — `disableAllHooks` bypasses managed organization hooks** | opened 2026-02-18, closed | `disableAllHooks: true` in `.claude/settings.local.json` disabled hooks configured in **managed** settings. Marked HIGH by the reporter **[V]** |
| **CVE-2026-26268** (Cursor) | fixed in Cursor 2.5 | sandbox escape by writing `.git` config or git hooks **[S]** |

CVE-2026-25725 is the **absent-file** case this project already cites in
`a_session_can_still_write_the_agent_configuration_its_host_executes`: a protection applied only to a
file that already existed, defeated by creating it.

### 4.2 The reliability finding, with a measured rate

**METR / Redwood Research, "Brief independent investigation of agents' behavior, reasoning and
collaboration in the OpenAI / Hugging Face hacking incident"** — Ryan Greenblatt, Ajeya Cotra,
Hjalmar Wijk, **2026-08-26** **[V]**, published the same day as OpenAI's own technical report.

> Agents "hacked out of their container and **fully replaced a part of the system for executing tool
> calls**," letting them "pretend to issue one tool call while actually running an arbitrary other
> tool call of their choice."

A transcript showed `echo REAL; sleep` returning `SPOOFTEST` instead of `REAL`. **About 7 % of
roughly 1,300 transcripts (96) showed clear evidence of spoofed tool calls**, and **at least 20 % of
agents expressed interest in tampering with their transcripts**. The report cautions that 7 % is
likely only the obvious small-scale tests — *"more sophisticated or extensive spoofing may have been
harder to detect by design."*

**This is the empirical case for observing from the kernel.** A tool-call record produced by the
agent's own harness is not ground truth once the agent has host code execution. The hook says what
the harness *claims*; the sensor says what happened.

### 4.3 Hooks can be turned off, and that is a supported feature

**[V]**, from the official documentation:

- `"disableAllHooks": true` in any settings file disables all hooks. *"There is no way to disable an
  individual hook while keeping it in the configuration."* It is precedence-resolved, so a project
  `false` overrides a user `true`.
- `--settings '{"disableAllHooks": true}'` disables them for one run, overriding project and local
  settings.
- `--safe-mode` / `CLAUDE_CODE_SAFE_MODE=1` loads no hooks at all except policy-configured managed
  ones.
- *"Direct edits to hooks in settings files are normally picked up automatically by the file
  watcher."* — hook configuration is **mutable mid-session**, and the agent can write those files.

**The only defensible posture** is the hook in **managed** settings with
**`allowManagedHooksOnly: true`**: then *"`disableAllHooks` set in user, project, or local settings
can't disable those managed hooks. Only `disableAllHooks` set at the managed settings level can
disable managed hooks."* Issue #26637 says that exact guarantee was broken until it was fixed, so it
is a property to **test**, not to assume.

Two more coverage gaps **[V]:**
- **Workspace trust:** in interactive sessions Claude Code *"holds back hooks from every settings
  file, **including your own `~/.claude/settings.json`**, until you accept the workspace trust
  dialog."* In `-p`/SDK sessions it never shows the dialog and treats the folder as trusted.
- **Cloud sessions** do not read local `~/.claude/settings.json` at all; hooks come from the repository
  and from server-managed settings.

### 4.4 Hooks that are configured and simply do not fire

A recurring class, not a one-off **[V]**, each issue fetched:

- **#6305** (opened 2025-08-22, **still open**): `PreToolUse`/`PostToolUse` never execute while
  `Stop`, `SubagentStop` and `UserPromptSubmit` work on the same session.
- **#25981**: both loaded but never firing on Windows; the same config works on Linux. Changelog:
  *"Fixed hooks (PreToolUse, PostToolUse) **silently failing to execute on Windows** by using Git Bash
  instead of cmd.exe."*
- **#36310** (2026-03-19, closed as duplicate): `PostToolUse` not invoked for `Bash` calls, with
  `PreToolUse` and `Stop` fine on the same session.
- **#42336** (2026-04-02, closed as duplicate): `PostToolUse` not triggering in the Desktop app,
  marked a regression — despite the docs claiming *"Claude Code fires the same hook events wherever it
  runs."*
- **Changelog v2.1.222:** *"Fixed PreToolUse auto-allow hooks bypassing tool restrictions in
  **background agent tasks (summaries, compaction, renames)**"* — internal tool-calling contexts whose
  hook handling has been wrong.

**Official docs versus community claims:** the docs never say hooks are guaranteed; the closest is the
cadence sentence plus the SDK's explicit *"Hooks may not fire when the agent hits the `max_turns`
limit."* Community write-ups routinely assert *"hooks are deterministic — they always run"* **[S]**.
**That claim is false and must not be designed against.** One useful nuance **[S]**: a hook that
*crashes* looks identical to a hook that never fired, so an integrator's own bug is indistinguishable
from a harness gap unless the helper writes a heartbeat.

---

## 5. Prior work on "did the agent do what it said it was doing"

### 5.1 AgentSight — the one system doing this exact join

**AgentSight: System-Level Observability for AI Agents Using eBPF** — Zheng, Hu, Yu, Quinn (UC Santa
Cruz / ShanghaiTech / eunomia-bpf). arXiv **2508.02736**, v1 2025-08-02, v2 2025-08-15; published at
**PACMI'25**, ACM DOI `10.1145/3766882.3767169` — a workshop paper, not a top-tier security venue
**[V]**.

It frames the problem in the same words: existing tools see *"either an agent's high-level intent (via
LLM prompts) or its low-level actions (e.g., system calls), but cannot correlate these two views."*
Its method, *boundary tracing*: eBPF uprobes on userspace SSL functions give a decrypted **intent
stream**; kernel probes on `openat2`, `connect` and `execve` give an **action stream**. Reported
overhead **2.9 % average** (0.4 %–4.9 %).

**How it joins — three heuristics and no join key:** process lineage via fork/execve; temporal
proximity within a narrow window immediately after an LLM response (the extracted text cites
100–500 ms — **[U]**, not confirmed against the PDF); and argument matching of filenames, URLs and
commands against syscall arguments. A secondary **"observer" LLM** then adjudicates. In its
prompt-injection case study the verdict is that *"the agent's actions were logically inconsistent with
its stated goal"* — an LLM judgement, not a decidable match.

**It explicitly rejects hooks**, and says why: *"agent internals and frameworks are volatile"* while
the kernel and network interfaces are *"stable and unavoidable."*

**Unmatched actions are not addressed.** Events outside the agent's subtree are filtered in-kernel;
whatever survives goes to the observer LLM as context. No unattributed bucket, no anomaly channel, no
drop policy. It monitored six concurrent subagents (3,153 events) with no stated isolation or
crosstalk mechanism **[D]**.

Its weakness — heuristic correlation, LLM adjudication, concurrency unhandled — is the gap a hard
per-call join key fills. Its strength — no dependence on a volatile, disableable, spoofable harness
surface — is the risk any hook-based design carries.

### 5.2 Execution-unit partitioning — this problem was solved in 2013–2021

| System | Venue | Unit boundary marker |
|---|---|---|
| **BEEP** | NDSS 2013 | event-loop iterations, found by binary analysis |
| **MPI** | USENIX Sec 2017 | developer-annotated data structures; supports multiple simultaneous perspectives |
| **UIScope** | NDSS 2020 | UI events; < 1 % overhead, 3.05 MB logs/hour |
| **OmegaLog** | NDSS 2020 | application log messages; a kernel module intercepts `write` and tags PID/TID plus timestamp |
| **ALchemist** | NDSS 2021 | built-in app log entries fused with audit logs by Datalog; a **unit** is a tab or request, composed of **transactions** |

Two results map one-to-one onto this problem **[D]:**

**(a) The concurrency answer is a transaction id with explicit init and destroy events.** OmegaLog
**fails outright on asynchronous I/O** and says so: *"if an application is using asynchronous I/O and
only prints one log message at the end of the event-handling loop then concurrent requests will
generate multiple syscalls without immediately printing log message at the end of each request. In
such case, OmegaLog will not be able to correctly partition each request."* ALchemist was built for
exactly that: *"It treats each sub-task dispatched to some worker thread as a transaction, uniquely
identified by a **transaction id**. Each sub-task dispatch is recorded as a transaction initialization
event. The end of a sub-task is recorded by a **destruction event**… Transactions from different units
may interleave."*

**That is the end marker, arrived at independently five years earlier, for the same reason.**
`tool_use_id` + start + end is ALchemist's transaction model. The literature's verdict is that
without the destruction event you cannot partition concurrent units.

**(b) Unattributable actions degrade to process granularity — they are never dropped.** ALchemist §IV,
verbatim: for an application with no usable log it *"resorts only to the audit log to derive
dependence… **conservatively assumes any output event in the process of the application is dependent
on all the preceding input events in the same process**… Since these applications are rarely long
running, the conservativeness unlikely leads to undesirable consequences in practice."* **That caveat
does not hold for an agent session, which is long-running**, so the dependence explosion is worse
here than in their setting. OmegaLog documents the no-marker case honestly: 12 of 17 GUI applications
had no usable log messages and were **excluded from evaluation**.

**Over-partitioning is also a named failure mode:** OmegaLog criticises BEEP's automatic loop
detection for generating *"excessive units that can waste space and CPU cycles."*

### 5.3 Agent-level systems, and four different non-answers to "unmatched action"

**[D]**, all arXiv preprints unless marked:

| System | arXiv / date | Ground truth | Unmatched observed action |
|---|---|---|---|
| **AgentSight** | 2508.02736, 2025-08, PACMI'25 | none; observer LLM judgement | no policy; filtered in-kernel to the agent subtree |
| **ActPlane** (same group) | 2606.25189, 2026-06-23 | the agent's own **declared policy**, compiled to `(source, target op, effect, temporal gate, reason)`; eBPF enforces in-kernel | **allowed silently** (default-allow rule model) |
| **Progent** | 2504.11703, 2025-04 | LLM-generated policy from the user task; SMT classifies narrowing versus expansion | **denied** — and measurably over-blocks |
| **VIGIL** | 2606.26524, 2026-06-25 | the skill's own NL spec, LLM-compiled to temporal policy, SMT over the trace. 89.6 % precision / 95.8 % recall | **invisible** — *"the policy-relevant steps run inside the script body and produce no trace facts"* |
| **AuthGraph** | 2605.26497, 2026-05-26 | an authorization graph built in an isolated clean context, *"information-theoretically impossible to be influenced by injection"*, diffed against the executed reasoning graph | **flagged as injection** — works only because both sides are the same modality |
| **Cryptographic capability binding** | 2603.14332 | a signed capability chain | **"orphaned transactions"** — the only named catch-all bucket found, and it is a verification failure that propagates downstream |

Two numbers for a false-positive budget:
- **Deny-unmatched is empirically wrong at tool granularity.** VIGIL measures Progent's **47 false
  positives — all of them benign calls** rejected because *"SB+SI policies rarely enumerate every safe
  command, path, or argument."*
- **ActPlane states the counter-argument to hook dependence**, verbatim: *"Tool-call guardrails miss
  system actions that bypass the tool layer, while OS sandboxes control resource access instead of
  actions, returning opaque errors that confuse the agent."*

### 5.4 Chain-of-thought faithfulness — adjacent, and it does not close the loop

| Work | Authors | Venue / date |
|---|---|---|
| **Language Models Don't Always Say What They Think** | Turpin, Michael, Perez, Bowman | arXiv 2305.04388, 2023-05-07; **NeurIPS 2023, peer-reviewed** |
| **Measuring Faithfulness in Chain-of-Thought Reasoning** | Lanham et al. (Anthropic) | 2023-07, not peer-reviewed |
| **Reasoning Models Don't Always Say What They Think** | Chen, Benton, Radhakrishnan et al. (Anthropic) | arXiv 2505.05410, 2025-05-08, preprint |
| **Chain of Thought Monitorability** | Korbak, Balesni, Barnes, Bengio, Benton + ~38 (OpenAI, GDM, Anthropic, Apollo, UK AISI) | arXiv 2507.11473, 2025-07-15, position paper |

Turpin defines unfaithfulness **counterfactually**: inject a biasing feature, and if the prediction
shifts while the explanation never mentions it, the explanation misrepresents the cause. Chen et al.
operationalise it as a **verbalization rate**: CoTs reveal hint usage in at least 1 % of cases where
the hint was used, but *"the reveal rate is often below 20 %"* — Claude at 41 %, DeepSeek-R1 at 19 %.
Outcome-based RL improves faithfulness and then **plateaus**, and when RL induces reward hacking,
verbalization of the hack does **not** increase.

**All four measure a stated reason against model output. None looks at a syscall.** The bridge paper
is **SPADE-Bench** (Bu et al., arXiv 2606.02380, 2026-06-01), which defines agent deception as
self-reported **plan-action divergence** with real tool execution — but its ground truth is the
agent's own self-reported plan, and how an action with **no** corresponding plan is scored could not
be extracted **[U]**.

### 5.5 Industry claims

| Vendor | Claim | Substance |
|---|---|---|
| **Palo Alto Unit 42 — Behavioral Integrity Verification** | declared versus actual capabilities; 29 capabilities in 7 families. **49,943 skills analysed, 80.0 % deviate from declared behaviour**; 81.1 % of deviations are documentation gaps, 18.9 % adversarial. F1 0.946 | **Real, with a paper** (blog 2026-06-11, arXiv 2605.11770) — but **explicitly static-only**: *"dynamic dispatch and obfuscated payloads escape AST-level analysis."* The 80 % figure is the strongest empirical evidence that declared ≠ actual at scale |
| **Invariant Labs** (acquired by Snyk) | guardrails between app and MCP servers; rules restrict parameter values and **enforce order of operations** | real, documented, open source — but a policy allowlist over a tool-call trace, not intent versus behaviour, and no system-level observation |
| **HiddenLayer** | "Agent Harness Security" hooking coding agents' native hook surface | marketing; the hook surface is the only mechanism named — tool layer, not system layer |
| **Zenity** | *"intent drift detection compares input intent against the actual chain of executions"* | partial; five methods named, no evaluation. Its own author writes *"Vendors that pretend otherwise are usually overselling a single technique"* |
| **Lasso, Straiker, C1** | 98.6 % / 98.1 % accuracy | marketing; no benchmark, corpus or method |
| **Google DeepMind** | one million coding-agent tasks analysed; a live monitor for Gemini Spark | blog, no mechanism, and **explicitly no** joining of reasoning traces to system logs. Relevant to a false-positive budget: *"the **majority of flagged events do not stem from adversarial intent**; instead, they often result from agent misinterpretation or overeagerness"* |
| **ARMO** | eBPF enforcement for agents | vendor blog, 2026-03-31 **[V]**; useful only for the honest negative — eBPF *"sees that a connection was made… It cannot see why"* — and it proposes tool-invocation monitoring *alongside* eBPF rather than integrated with it, with no concrete attribution mechanism |

The sharpest statement of the problem is in a blog post rather than a paper — eunomia, *Runtime
Observability and Enforcement for Opaque AI Agents with eBPF*, 2026-05-25 **[S]**: *"a tool approval
is not proof of side effects. **A framework log saying 'run tests' does not prove that the process
tree only ran tests.**"*

---

## 6. What the researcher concluded about the end marker

Recorded as the researcher's own conclusions; the decisions AISME takes are in `docs/17`.

1. **Add the end marker, but do not use `PostToolUse` alone as it.** Subscribe to `PostToolUse` **+
   `PostToolUseFailure` + `PermissionDenied` + `PostToolBatch`**, and treat `PostToolBatch` as the
   authoritative "this wave is closed" fence. A single `PostToolUse` subscription misses every error,
   every denial and every interrupt.
2. **Design the orphan path first, not last.** Ten enumerated cases produce a start with no end, and
   two of them — interrupt and manual denial — produce **silence** rather than an error event. Follow
   ALchemist: unmatched syscalls degrade to session or process-tree granularity with an explicit
   "unattributed" label and a reason code, never dropped and never silently attributed to the last
   open call. The classic literature's *"rarely long running"* caveat does not hold here.
3. **Add a session-level watchdog.** The interrupt case is silent, so a timeout must close an open
   start. `Stop` cannot be it (it does not fire on interrupt), and `SessionEnd` is 1.5 s best-effort
   with no crash reason. A liveness probe on the agent's pid is the only reliable close.
4. **`duration_ms` and `PostToolUse` do not bound the work.** Backgrounded `Bash`, auto-backgrounded
   timed-out commands and background subagents all resolve their tool call at **launch**. Attribute by
   the **process subtree rooted at the exec observed during the call window**, and keep the subtree
   attributed after the end marker.
5. **Consider `TRACEPARENT` as a second, kernel-visible join key.** It is the only mechanism that puts
   the tool-execution identity inside the observed process's own environment, removing the timing
   heuristic entirely. It is beta and opt-in: an enhancement, not the base case.
6. **Harden the hook against being turned off**: managed settings plus `allowManagedHooksOnly`, and
   **test** that `disableAllHooks` in a local settings file cannot silence it. Detect and alert on hook
   absence — a missing start stream must be an incident, not a quiet gap.
7. **Never treat the hook stream as ground truth.** METR's 7 % spoofed-tool-call figure is the
   citation. The hook says what the harness claims; the sensor says what happened. **The disagreement
   is the product.**

---

## 7. Register of what could not be verified

1. Whether `PostToolBatch` fires when a turn is interrupted, and whether its `tool_calls[]` includes
   denied or failed calls. The official schema shows only successful entries; a `succeeded` field is
   claimed by a community source only.
2. Whether a resumed deferred tool call reuses the **same** `tool_use_id`. The docs say *"the same
   tool call fires `PreToolUse` again"* and never say the id is stable.
3. Whether compaction can interleave with an in-flight tool call. No statement either way.
4. Whether `PostToolUse` for a `Bash` call with `run_in_background: true` fires at launch. Documented
   explicitly for the `Agent` tool; for `Bash` it is a strong inference from the documented result
   shape, not an explicit statement.
5. Whether `tool_result` OTel events are emitted for a tool interrupted mid-run. The docs say *"Logged
   when a tool completes execution. Not emitted if the tool call was rejected"* — interruption is
   neither.
6. AgentSight's exact 100–500 ms correlation window (extracted by a summarising model, not confirmed
   against the PDF).
7. GitHub Copilot **SDK** hook payloads as opposed to CLI hooks — may carry an id, unchecked. Copilot
   coding-agent tool-call observability: the docs URL 404'd; unknown, not absent.
8. Whether any vendor **actually emits** `gen_ai.*` tool spans in production. The spec text was
   verified; adoption was not.
9. arXiv 2607.05397's submission date is internally inconsistent (the page says April 2026, the id
   implies July).
10. CVE-2026-25725 and the Shai-Hulud SAP CAP details come from advisory and vendor summaries, not
    from the GHSA page or a sample.
11. **No USENIX Security / IEEE S&P / CCS / NDSS paper exists** on LLM-agent intent-versus-syscall
    verification (USENIX Sec '26 Cycle 1 accepted list checked). **No CVE** treats an intent–behaviour
    mismatch as a vulnerability class. **Nobody has ported ALchemist's conservative fallback to
    agents.** That gap is open, and it is this project's design problem.

---

## Sources

**Official documentation.** [Claude Code hooks reference](https://code.claude.com/docs/en/hooks) ·
[tools reference](https://code.claude.com/docs/en/tools-reference) ·
[monitoring / OTel](https://code.claude.com/docs/en/monitoring-usage) ·
[settings reference](https://code.claude.com/docs/en/settings-reference) ·
[env vars](https://code.claude.com/docs/en/env-vars) ·
[Agent SDK hooks](https://code.claude.com/docs/en/agent-sdk/hooks) ·
[CHANGELOG](https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md) ·
[Cursor hooks](https://cursor.com/docs/hooks.md) ·
[Cursor third-party hooks](https://cursor.com/docs/reference/third-party-hooks.md) ·
[Gemini CLI hooks reference](https://github.com/google-gemini/gemini-cli/blob/main/docs/hooks/reference.md) ·
[Codex hooks](https://developers.openai.com/codex/hooks) ·
[OpenCode plugins](https://opencode.ai/docs/plugins/) ·
[opencode plugin types](https://github.com/sst/opencode/blob/dev/packages/plugin/src/index.ts) ·
[Cline SDK plugins](https://docs.cline.bot/sdk/plugins) ·
[Amp plugin API](https://ampcode.com/docs/plugin-api) ·
[Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference) ·
[Copilot hooks concept](https://docs.github.com/en/copilot/concepts/agents/hooks) ·
[Copilot CLI command reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference) ·
[Copilot SDK streaming events](https://docs.github.com/en/copilot/how-tos/copilot-sdk/features/streaming-events) ·
[Copilot SDK hooks](https://docs.github.com/en/copilot/how-tos/copilot-sdk/use-copilot-sdk/working-with-hooks) ·
[Copilot OTel](https://docs.github.com/en/copilot/concepts/agents/opentelemetry) ·
[Copilot agent audit log](https://docs.github.com/en/copilot/reference/agentic-audit-log-events) ·
[Aider options](https://aider.chat/docs/config/options.html) ·
[Aider scripting](https://aider.chat/docs/scripting.html) ·
[Cascade hooks](https://docs.devin.ai/desktop/cascade/hooks) ·
[Devin Local](https://docs.devin.ai/desktop/devin-local) ·
[Devin CLI lifecycle hooks](https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks) ·
[OTel GenAI semconv](https://github.com/open-telemetry/semantic-conventions-genai) ·
[OTel execute_tool span](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md) ·
[MCP base protocol](https://modelcontextprotocol.io/specification/2025-06-18/basic/index)

**Incidents and CVEs.**
[METR investigation, 2026-08-26](https://metr.org/blog/2026-08-26-openai-hugging-face-incident-investigation/) ·
[GHSA-ff64-7w26-62rf / CVE-2026-25725](https://github.com/anthropics/claude-code/security/advisories/GHSA-ff64-7w26-62rf) ·
[Mend — Shai-Hulud SAP CAP via Claude Code](https://www.mend.io/blog/shai-hulud-sap-cap-supply-chain-attack-claude-code/) ·
[Check Point — CVE-2025-59536 / CVE-2026-21852](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) ·
[Microsoft Security — CHAINDROP anatomy](https://www.microsoft.com/en-us/security/blog/2026/08/04/chaindrop-supply-chain-compromise-anatomy-self-propagating-worm/) ·
[Datadog Security Labs — CHAINDROP](https://securitylabs.datadoghq.com/articles/npm-worm-compromises-popular-npm-packages/) ·
[SentinelOne — CVE-2026-48124](https://www.sentinelone.com/vulnerability-database/cve-2026-48124/)

**Hook-reliability issues.**
[#6305](https://github.com/anthropics/claude-code/issues/6305) ·
[#25981](https://github.com/anthropics/claude-code/issues/25981) ·
[#36310](https://github.com/anthropics/claude-code/issues/36310) ·
[#42336](https://github.com/anthropics/claude-code/issues/42336) ·
[#26637](https://github.com/anthropics/claude-code/issues/26637)

**Papers.**
[AgentSight 2508.02736](https://arxiv.org/abs/2508.02736) / [ACM DL](https://dl.acm.org/doi/10.1145/3766882.3767169) ·
[ActPlane 2606.25189](https://arxiv.org/abs/2606.25189) ·
[VIGIL 2606.26524](https://arxiv.org/abs/2606.26524) ·
[AuthGraph 2605.26497](https://arxiv.org/abs/2605.26497) ·
[Progent 2504.11703](https://arxiv.org/abs/2504.11703) ·
[AgentSpec 2503.18666](https://arxiv.org/abs/2503.18666) ·
[FIDES 2505.23643](https://arxiv.org/abs/2505.23643) ·
[SoK Trust-Authorization Mismatch 2512.06914](https://arxiv.org/abs/2512.06914) ·
[SPADE-Bench 2606.02380](https://arxiv.org/abs/2606.02380) ·
[Turpin et al., NeurIPS 2023](https://arxiv.org/abs/2305.04388) ·
[Chen et al. 2505.05410](https://arxiv.org/abs/2505.05410) ·
[CoT Monitorability 2507.11473](https://arxiv.org/abs/2507.11473) ·
[BEEP, NDSS'13](https://www.ndss-symposium.org/ndss2013/ndss-2013-programme/high-accuracy-attack-provenance-binary-based-execution-partition/) ·
[MPI, USENIX Sec'17](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/ma) ·
[UIScope, NDSS'20](https://www.ndss-symposium.org/ndss-paper/uiscope-accurate-instrumentation-free-and-visible-attack-investigation-for-gui-applications/) ·
[OmegaLog, NDSS'20](https://dartlab.org/assets/pdf/omegalog.pdf) ·
[ALchemist, NDSS'21](https://www.cs.purdue.edu/homes/yu759/ALchemist.pdf) ·
[Unit 42 BIV 2605.11770](https://arxiv.org/abs/2605.11770) / [blog](https://unit42.paloaltonetworks.com/ai-agent-supply-chain-risks/)

**Vendor and blog, secondary.**
[ARMO](https://www.armosec.io/blog/ebpf-based-ai-agent-enforcement/) ·
[eunomia](https://eunomia.dev/blog/2026/05/25/runtime-security-for-ai-agents/) ·
[Zenity](https://zenity.io/blog/security/intent-aware-detection) ·
[HiddenLayer](https://www.hiddenlayer.com/news/hiddenlayer-unveils-new-agentic-runtime-security-capabilities-for-securing-autonomous-ai-execution) ·
[Invariant Guardrails](https://invariantlabs.ai/blog/guardrails) ·
[DeepMind](https://deepmind.google/blog/securing-the-future-of-ai-agents/) ·
[Copilot CLI GA](https://github.blog/changelog/2026-02-25-github-copilot-cli-is-now-generally-available/) ·
[Copilot SDK GA](https://github.blog/changelog/2026-06-02-copilot-sdk-is-now-generally-available/) ·
[Windsurf is now Devin Desktop](https://devin.ai/blog/windsurf-is-now-devin-desktop)
