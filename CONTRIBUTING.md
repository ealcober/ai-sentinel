# Contributing

## Sign your work — the DCO

This project uses the [Developer Certificate of Origin](https://developercertificate.org/). Every commit carries:

```
Signed-off-by: Your Name <your.email@example.com>
```

`git commit -s` adds it. By signing you certify that you wrote the contribution or have the right to submit it under the file's licence.

**There is no CLA and no copyright assignment.** You keep your copyright. The consequence is deliberate and worth understanding: the project cannot be relicensed later without the agreement of everyone who has contributed.

## Licence of your contribution

Your contribution is licensed under the licence of the file you are changing — see [`LICENSE.md`](LICENSE.md). New files carry an SPDX header on the first line:

```rust
// SPDX-License-Identifier: Apache-2.0
```

`cargo xtask verify-docs` fails on a source file with no SPDX header, and on a header that disagrees with the licence map.

## Before you open a pull request

This repository is built to be worked on by both people and LLM sessions, and the same rules apply to both. They are in [`CLAUDE.md`](CLAUDE.md); the ones that most often surprise a new contributor:

1. **Read the plan first.** `docs/01_phase5_implementation_plan.md` Part II contains nineteen findings `H-01`…`H-19`. Each records a design that was analysed and rejected, cut, corrected or deferred, with the reasoning. **If your change contradicts one, the finding wins** — argue it in an ADR rather than implementing around it.
2. **One task ID per change.** Work is tracked by the plan's `F<phase>.<block>.<task>` identifiers. Your commit subject names one: `<area>(<task-id>): <what changed>`.
3. **Edit surgically; never regenerate a file.** Keep existing comments and their reasoning. A rewrite silently loses what nobody is looking at. If a comment becomes false, rewrite it and say so in the commit.
4. **Every gate runs locally.** There is no hosted CI and no workflow triggers on push (`I-27`). Run `cargo xtask gate --level commit` before you push and `--level pr` before you ask for a merge.
5. **Never run a kernel-touching test outside a disposable VM** (`I-12`). `cargo xtask vm up <name>`.
6. **Report what happened.** Paste gate output rather than summarising it. A failed step is reported as failed.
7. **Add a changelog line.** Every closed task adds one to `docs/CHANGELOG.md` in the same commit.

## Reporting a vulnerability

Do not open a public issue. See [`SECURITY.md`](SECURITY.md).
