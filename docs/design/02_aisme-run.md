# Design Note — `aisme run`

> **Status**: `SPEC` · **Owner**: architecture
> **Feeds**: `F2.WS.05`, `F2.WS.06`, `F2.WS.08`, `F2.WS.11`, `F3.EN.09`, `F3.EN.12`, `F4.CO.04`, `F7.PS.07`, `F8.CLI.01`
> **Why this note exists**: `aisme run` is defined across seven tasks in five phases and is the
> documented default onboarding path. Without one specification it drifts.

## 1. What it is

```bash
aisme run [--scope <path>...] [--profile <name>] -- <command> [args...]
```

It launches a command as a supervised AISME session. It is the **preferred** session-discovery
path (`H-18`) because it gives perfect identity for free: we own the process from before its first
syscall, so nothing has to be inferred.

## 2. Why it is the default onboarding path

It solves three problems that would otherwise need three mechanisms:

1. **Session identity.** No heuristic, no binary catalogue, no lineage guessing.
2. **Prompt delivery where there is no desktop.** We own the terminal, so the adjudication prompt
   goes where the developer is already looking — over SSH, in a container, in tmux, and in WSL2,
   where the daemon is in Linux and the desktop is Windows.
3. **Scope declaration.** The workspace is an argument rather than a detection.

## 3. What it does, in order

| # | Step | Task |
|---|---|---|
| 1 | Resolve the session scope: `--scope` flags, then `.aisme/scope.toml` **narrowing only**, then detection (VCS root, toolchain), then the baseline profile for the detected agent | `F7.PS.07` |
| 2 | Create the session cgroup and place itself in it, so the tree is captured by construction | `F2.WS.08` |
| 3 | Register the session with `agentd` over the control-plane socket, receiving the compiled policy generation | `F8.CLI.01` |

The same socket carries **`declareToolCall`** (`F2.WS.03`): an agent volunteers that a tool call is starting, so correlation has something to match against while the actions happen. It authorizes nothing — no grant, no verdict, no scope — and the correlation token never travels on it, because an engine that could join on the token would make §4.6's precision and recall measure the join rather than the correlator. Beyond `DECLARATIONS_PER_MINUTE` per connection the answer is the result `rate_limited`, not an error.

| 4 | Install the seccomp filter for the escalate class, passing everything else | `F2.WS.05` (`Q-13`); `F3.EN.12` widens it |
| 5 | Apply the Landlock ruleset compiled from the session policy — deny writes outside scope, deny the never-promptable classes, deny AISME's own files | `F2.WS.11`, `F3.EN.09`, `F3.EN.11` |

**Steps 4 and 5 run in the opposite order to their numbers, and the reason is measured.** `landlock_add_rule` needs an `O_PATH` descriptor for each allowed directory, so building the ruleset *under* a filter that traps every `openat` sends the session's own setup to the supervisor to be answered — and `I-28` forbids permitting an `O_PATH` open, so the supervisor would have to refuse it. The filter is also irreversible, and anything that can still fail belongs above it. The numbering is the order of the *concerns*, not of the calls. What matters for both is only that they are before `exec`.

**F2's subset of step 5** is the write scope: one ruleset built from the session's declared scope, handling every write-shaped right the running ABI knows. The never-promptable classes and AISME's own files are `F3.EN.09` and `F3.EN.11`, and they need the daemon's policy rather than the invocation's scope.
| 6 | Set the environment: export the key-log variables for known runtimes pointing at the `agentd` socket; strip variables that would defeat observation | `F4.CO.04` |
| 7 | `exec` the command. Landlock and the cgroup are inherited; nothing the child does can relax them | — |
| 8 | Serve terminal adjudication on the controlling TTY for the life of the session | `F2.WS.06` |
| 9 | On exit: close the session, release the cgroup, flush the WAL, print a one-line summary | — |

**Step 9 is `agentd`'s, not this command's, and `exec` is the reason.** From step 7 this process *is* the supervised command, so it has no "on exit" of its own: the summary is printed before `exec` and the cgroup is released by the daemon, which waits on `poll` of `cgroup.events` for the kernel to say the session is empty and then removes the directory. That is why **every** session registers, not only a filtered one — an unregistered session is one whose cgroup nothing will ever remove.

Steps 4–6 happen **before** `exec`, so there is no window in which the child runs unsupervised.

**F2 implements steps 1 (one scope, from `--scope` or the working directory), 2, 7 and the
summary of 9 — printed before `exec`, because `exec` has no after.** The remaining steps belong
to the tasks named beside them, and `crates/aisme-cli/src/run.rs` carries an empty `pre_exec`
hook where steps 4 and 5 attach. Releasing the cgroup on exit is not F2's: the process that
created it is the supervised command by then, so release belongs to whoever outlives the session
(`docs/09` point 6).

## 4. Environment hygiene

**Set**: `SSLKEYLOGFILE` and, for Node-family runtimes, `NODE_OPTIONS=--tls-keylog`, both pointing
at a 0600 socket owned by `agentd`. Keys are consumed in memory and never written to a file (`I-08`).
`AISME_SESSION_ID` for cooperative adapters and the SDK.

**Stripped**, with the removal recorded in the session log: `LD_PRELOAD`, `LD_AUDIT`,
`DYLD_INSERT_LIBRARIES` — they are an observation-defeating vector and a `DT-13` signal if the
agent sets them later.

**Never touched**: anything else. `aisme run` does not rewrite a developer's environment.

## 5. Degradation

| Missing | Behaviour |
|---|---|
| No TTY (IDE-launched, CI) | Terminal adjudication unavailable; the ladder falls to `aisme-uiagent`, then policy default. Stated at startup, not discovered at the first prompt |
| No Landlock (`L2-`) | Step 5 is skipped, the tier is reported as `L2-`, and the trap-volume cost is stated once |
| No cgroup v2 | No T2 freeze; escalations resolve by timeout. Reported in the capability banner |
| `agentd` unreachable | **Refuse to start** and say why. Running the agent unsupervised while appearing supervised is the one failure this command must not have |

## 6. Open

- Behaviour when the command is itself a shell that later launches the agent: the session covers
  the whole tree, which is correct but may be broader scope than the user intended. Needs a real
  session to judge.
