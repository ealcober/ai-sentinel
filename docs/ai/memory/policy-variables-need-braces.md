---
name: policy-variables-need-braces
description: A policy variable is `${name}` — `$name` without braces compiles as a literal path segment and the rule silently matches nothing
type: domain
---

`aisme_core::policy`'s substitution syntax is **`${name}`**. The compiler is careful about the case it recognizes: *"an unbound variable is an error, never an empty string"* (`crates/aisme-core/src/policy/compile.rs:26`), and `aisme-agentd --policy` with `${nowhere}` refuses to start, naming the variable and the rule.

**`$name` without braces is not a variable.** It is not rejected either. It compiles as an ordinary literal, so `match = { path_under = "$workspace" }` produces a rule that matches a directory literally called `$workspace` — which no machine has. The rule is in the compiled policy, it is counted in `N rule(s) in force`, and it decides nothing.

**Why it matters:** the two spellings differ by two characters and fail in opposite directions. The guarded one stops the daemon; the unguarded one produces a policy that *reports* the right number of rules while one of them is inert. Measured on the shipped `deploy/policy/skeleton.aisme`, whose write-scope rule carried `"$workspace"`: `aisme-agentd --policy` accepted it and printed `3 rule(s) in force`.

**How to apply:** write `${name}`, and never trust the rule count as evidence a rule works. A rule is verified by evaluating a path against the compiled policy and asserting the verdict — which is what `the_shipped_policy_keeps_all_three_of_its_rules` does in `crates/aisme-agentd/src/main.rs`. The same test is why the `path_glob` rule is asserted and not just the `path_under` ones: lowering to the BPF trie keeps only prefixes (`crates/aisme-linux/src/policy.rs:157`), so a glob is the rule most likely to be dropped somewhere and least likely to be noticed.

**Source:** `F2.WS.05`, measured 2026-09-15

Related: [[seccomp-unotify-toctou]]
