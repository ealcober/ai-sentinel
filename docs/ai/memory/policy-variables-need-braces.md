---
name: policy-variables-need-braces
description: A policy variable is `${name}` — `$name` without braces compiles as a literal path segment and the rule silently matches nothing
type: domain
---

`aisme_core::policy`'s substitution syntax is **`${name}`**. The compiler is careful about the case it recognizes: *"an unbound variable is an error, never an empty string"* (`crates/aisme-core/src/policy/compile.rs:26`), and `aisme-agentd --policy` with `${nowhere}` refuses to start, naming the variable and the rule.

**`$name` without braces is not a variable.** It is not rejected either. It compiles as an ordinary literal, so `match = { path_under = "$workspace" }` produces a rule that matches a directory literally called `$workspace` — which no machine has. The rule is in the compiled policy, it is counted in `N rule(s) in force`, and it decides nothing.

**Why it matters:** the two spellings differ by two characters and fail in opposite directions. The guarded one stops the daemon; the unguarded one produces a policy that *reports* the right number of rules while one of them is inert. Measured on the shipped `deploy/policy/skeleton.aisme`, whose write-scope rule carried `"$workspace"`: `aisme-agentd --policy` accepted it and printed `3 rule(s) in force`.

**How to apply:** write `${name}`, and never trust the rule count as evidence a rule works. A rule is verified by evaluating a path against the compiled policy and asserting the verdict — which is what `the_shipped_policy_keeps_all_three_of_its_rules` does in `crates/aisme-agentd/src/main.rs`. The same test is why the `path_glob` rule is asserted and not just the `path_under` ones: lowering to the BPF trie keeps only prefixes (`crates/aisme-linux/src/policy.rs:157`), so a glob is the rule most likely to be dropped somewhere and least likely to be noticed.

**And a variable needs something to bind to, which means a session.** The defect had a second half that the spelling hid: the daemon compiled its policy **once at startup**, with no bindings at all, before any session existed. Correcting `$workspace` to `${workspace}` alone would have turned a silently inert rule into a daemon that refuses to start. The compilation moved to the session registration — `${workspace}` from the scope that session declared, `${home}` from the peer's uid — which is what `Bindings`' own documentation said all along: *"what `${…}` variables resolve to for **one session**"*.

**Both bindings come from the system, never from the session.** A session that could name its own `${home}` would point every credential rule at a directory it had just created. The uid is written by the kernel into `SO_PEERCRED`; the scope is the operator's own `--scope`, which is the same trust position widening the scope already has.

**Source:** `F2.WS.05` and `F2.WS.11`, measured 2026-09-15

Related: [[seccomp-unotify-toctou]], [[a-path-is-a-spelling]]
