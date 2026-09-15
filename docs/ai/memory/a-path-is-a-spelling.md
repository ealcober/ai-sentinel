---
name: a-path-is-a-spelling
description: A rule matched against the path a caller typed is defeated by any other spelling of the same file — decide on what the descriptor names
type: domain
---

A policy that denies a file by path is defeated by a symbolic link to it. Measured on 2026-09-15 against a policy denying one file, in a session under `--trap-openat`:

| how it was asked for | result |
|---|---|
| its real name | denied |
| a symlink pointing at it | **the secret was read** |
| `/proc/self/root/<real name>` | denied |

The third is denied by accident rather than by the rule: `RESOLVE_NO_MAGICLINKS` makes the supervisor's own open fail on a magic link. **It does not stop an ordinary symlink**, which is why one spelling was caught and the other was not.

**Why it matters:** `docs/05` §5.3 already specified the right order — *"`openat2` with `RESOLVE_NO_MAGICLINKS` → evaluate **the opened file** against the compiled policy → `ADDFD`"*. The implementation evaluated the **requested spelling** and then opened it. Inverting those two steps is the entire defect, and it is invisible in every test that asks for a file by its real name.

**How to apply:** **locate, then decide, then open.** Open the requested path with `O_PATH` — which never blocks and reads nothing, so a file the policy is about to refuse is not opened for real, and a FIFO cannot hang the supervisor. Read `/proc/self/fd/<n>` to learn what the descriptor names. Decide on **that**. Then reopen **through the descriptor**, not through the string, so nothing is resolved a second time and the file the policy judged is the file the target receives — which is `I-28`, and re-resolving the string here gives it away after paying for it.

**The class is measured and it is large.** A 2026 study collected 1,709 real-world command denylists containing 13,332 rules and found **69.0–98.6 % of them fragile**: an equivalent command reaching the same goal is not blocked. The same shape appears in the field as reaching a denied binary through `/proc/self/root`, as non-standard `.git` directory names defeating path rules, and as a file named `curl` dropped in the project directory. A rule matched against a spelling is in that 69–98 %. A rule matched against what the descriptor names is not, because the spellings collapse before the decision.

**Source:** `F2.WS.05`, measured 2026-09-15; `docs/research/01_incidentes_y_defensas_de_agentes_ia.md` Part III §1

Related: [[one-syscall-is-not-one-door]], [[seccomp-unotify-toctou]]
