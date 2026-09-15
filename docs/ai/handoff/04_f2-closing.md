# Handoff — F2, at its gate

**Written 2026-09-15.** Every number below was produced by a command named beside it. Where
something is unproven, it says so.

---

## 1. Where F2 is

**Ten of eleven tasks are done.** `F2.WS.11` is half: its Landlock write scope is measured, and the
second half of its done-condition — zero notification traffic, observed through `sys_exit_openat`
with `inferred_from = sys_exit` — is owed and sits behind the decision in §3.

**GATE F2 has been run and every line passes.** Its output is in `STATE.md`, verbatim. It does not
close the phase, and §3 is why.

What the skeleton does today, on this machine:

```bash
aisme-agentd --run <wal> --serve-ipc <sock> --policy deploy/policy/skeleton.aisme
aisme run --trap-openat -- cat /etc/hostname   # read, exit 0,  0 asked
aisme run --trap-openat -- cat /etc/shadow     # EACCES, exit 1, 0 asked  ← nobody was prompted
aisme run --trap-openat -- cat ~/.aws/credentials  # 1 asked, and the answer decides
aisme run --scope $W -- sh -c 'touch /tmp/x'   # EACCES in kernel, no supervisor woken
```

The middle line is the one worth understanding. **A compiled `deny` cannot be answered away**: no
prompt exists, so no answer can go wrong and no timeout has to expire. An escalation that denies on
timeout is strictly weaker — it depends on nobody answering.

## 2. Start here

1. `cargo xtask doctor` — the host, measured rather than read.
2. `cargo xtask test-skeleton` — the whole slice with no kernel, ~80 ms. If this fails, nothing
   below is worth doing.
3. `docs/ai/STATE.md` → *Blocked*, then *GATE F2*. Read them in that order; the gate's output only
   makes sense after the blocker.
4. `docs/10_challenge_cierre_f2.md`, "Step N, as executed" — one section per step, each recording
   what fell and with which measurement.

## 3. The one decision that is the owner's, and everything waiting on it

**An unprivileged supervisor can read the memory of the session's first process and of nothing it
forks.** Yama keys the `PR_SET_PTRACER` exception to the declaring task; it survives `execve` and is
not inherited. Isolated with a **sibling** supervisor, which is the only topology that tests it —
an *ancestor* is permitted by a different Yama rule and reports success whatever the grant does:

| target | sibling supervisor's `process_vm_readv` |
|---|---|
| the declaring process, after `exec` | permitted |
| a process it forked | `EPERM` |

Through the product: `aisme run --trap-openat -- cat /etc/hostname` delivers 4 opens and denies 0,
while `… -- sh -c 'cat /etc/hostname'` denies **13**, all the grandchild's, all *"the path argument
could not be read"*. **Every real agent forks.**

**GATE F2 passes anyway, and that is the sharp end of it.** The guest daemon runs as `uid 0`, where
`CAP_SYS_PTRACE` makes Yama irrelevant; `deploy/systemd/aisme-agentd.service` runs as `User=aisme`
with an empty `CapabilityBoundingSet=`. So the gate measures a configuration the product does not
ship — worse than a failing gate, which at least says something is wrong.

The three options and what each costs are in `docs/10`, "Step 2, as executed". They are: give
`agentd` `CAP_SYS_PTRACE`; split a small privileged supervisor out as `aisme-loaderd` already is for
`CAP_BPF`; or have `aisme run` stop `exec`-ing and stay as the session's parent, which makes it the
tree's ancestor and also restores design steps 8 and 9 that both assume it outlives `exec`.

**Waiting on it:** the second half of `F2.WS.11`, the re-run of GATE F2's five enforcement lines
against the shipped configuration, and the phase itself.

**Also owed and also the owner's:** `F0.ASSET.02`'s reference-trace recording — see `STATE.md` →
*Next up*, item 2. Observe-only mode records nothing on a host, and the specified mechanism cannot
produce the ground-truth correlation token the format requires, because a kernel sensor sees an
`openat` and not the intent behind it.

## 4. What this phase kept getting wrong, so the next one does not

**Four separate checks reported a property they did not test.** They are worth reading together,
because the pattern is one thing and not four:

1. GATE F2's guest lines carried no `--trap-openat`, so three of them would have passed with
   nothing enforced.
2. The shipped policy's escalate rule read `~/.aws/**`. A tilde is a shell expansion, so the rule
   matched nothing any process ever opens — and the gate that existed to exercise the escalate path
   never exercised it. The compiler refuses that form now, which is the fix: **one guard where every
   policy passes, not a correction in each rule that has one.**
3. `test-skeleton` asserted `Escalate` for the string `~/.aws/credentials` — which the policy
   matched only because the gate handed it that exact string, and which no kernel produces.
4. The first GATE F2 script reported `PASS` while answering only *deny*, never reading the `asked`
   column, and running the Landlock line under a seccomp filter that could have been the one
   denying.

The rule that catches all four: **an assertion that cannot fail is not an assertion.** Ask of every
check what input would make it fail, and if the answer is "none", it is decoration.

## 5. Two host facts that cost an afternoon each

Both are in `docs/ai/memory/`, and both look obvious afterwards.

- **A Landlock write scope must grant the non-storage character devices.** Denying `/dev/null`
  breaks every redirect in every supervised session, on a command that writes nothing anywhere.
- **A `PATH_BENEATH` rule on a non-directory takes only file rights.** A directory-only right such
  as `MAKE_REG` makes `landlock_add_rule` answer `EINVAL`, which refuses the *whole* ruleset — so
  the session fails to start instead of being confined.
