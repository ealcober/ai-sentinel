# Preparing the repository for public release as `AI-SENTINEL-EALCOBER`

Seven points, amplified until executing them requires no further decision. Each is **Challenge**
(is it the best answer, is it coherent with the specs, can it be simplified), **Verification** (is it
safe, clear and compliant — and where it is not, it asks rather than resolving), **Implementation**,
**Tests**, **Documentation**, and a **Closing** paragraph saying what was verified against what,
which claim of the skeleton fell, and what stays open.

**The rename is last by construction.** Publishing under a new name is cheap; publishing a repository
that contradicts itself is not. Points 1–6 fix what a first visitor would see; point 7 moves it.

## The order, and what was measured

| # | Point | Verdict going in |
|---|---|---|
| 1 | The README states a project state that is no longer true | **blocking** |
| 2 | Three things must leave the repository before it is public | **blocking** |
| 3 | A contributor on-ramp that does not exist yet | required by the ask |
| 4 | Discovery vocabulary — the repository is findable by nobody | required by the ask |
| 5 | Secrets, and the 90 MB of history behind them | **one decision is the owner's** |
| 6 | Test coverage: what the ask means once the stubs are excluded | smaller than it looks |
| 7 | The rename and the publication procedure | last |

Measured on 2026-10-14, before any point was written:

- **387 tests pass, 0 fail**, `gate --level commit` at `7 PASS · 0 FAIL · 1 SKIP · 1 PENDING`. The
  project works.
- **No secret is in any tracked file.** Four files matched a secret-shaped pattern and all four are
  false positives: `libc::passwd` (a C struct), `/etc/passwd` (a path in a policy test), and a prose
  mention of *sudoers*. No `.env`, `.pem`, `.key`, `id_rsa` or `credentials` file is tracked, and none
  ever was in any commit on any branch.
- **No path from the owner's machine and no email address** appears in a tracked file.
- **`sdk.html` is tracked**: 691 KB, in the repository root, a scraped copy of a GitHub Docs page.
- **The history carries 1,781 `/target/` paths** and six blobs over 16 MB, the largest 41.2 MB.
  `.git` is **90 MB** for 264 tracked files.
- **The workspace declares no `description`, `keywords` or `categories`.** Only `license` and
  `repository`.

---

## 1. The README states a project state that is no longer true

**Done when:** a first-time visitor reads what the project is and what works today, and nothing on
the page is contradicted by the repository.

### 1. Challenge

*Is this the best solution?* The README is well written and in correct English — that part of the ask
is already satisfied, and saying so is more useful than pretending otherwise. What is wrong is not
the prose, it is a **fact**:

> **Status: pre-implementation.** … no product code exists yet.

There are 19 workspace members, 387 passing tests, a daemon that enforces a compiled policy from a
seccomp supervisor, a Landlock write scope measured denying in kernel, and a benchmark reporting
46.6 µs p99 for a held syscall. A reader who believes that line will not look at the code, and a
reader who looks at the code will stop believing the page. **For a repository about honesty of
coverage, a stale status line is the worst possible first sentence.**

*Is it coherent with the specs?* It contradicts the project's own rule 5 — *"documentation describes
what the system does **today**"* — and `I-19`'s spirit: never imply a capability you do not have, and
by symmetry never deny one you do.

Second defect, same class: the **documentation map** lists `docs/01`–`docs/04`. There are **16**
numbered documents. Twelve are invisible to a visitor, including the two field studies and the plan
that closes the current phase.

*Can it be simplified?* Yes, and the simplification is the point: the status line becomes **one
table** of what is implemented and measured versus what is specified and not built. That is shorter
than a paragraph of hedging and it is checkable.

### 2. Verification

Safe and clear, with three properties:

- **Every number on the page is reproducible by a command in the page.** 387 tests, the gate's
  output, the latency figures: each is followed by the command that produces it. A README with
  unreproducible numbers is a marketing page.
- **The phase vocabulary stays.** `F0`…`F11` is how the plan, `STATE.md` and every commit subject
  refer to position. The README says where the project is in those terms, not in a new invented
  scale.
- **It must not overclaim in the other direction.** The engine is a walking skeleton: one syscall
  class, one policy, no correlation engine, no mobile app, no UI. The table says so per row. The
  current README's honesty sections are **good and stay** — scope, mobile limits, WSL2's missing TPM.

**Nothing here is unclear enough to ask about.**

### 3. Implementation

- The status block becomes a short table with three columns — *capability*, *state*, *evidence* —
  with one row per thing a visitor would ask about: kernel enforcement (seccomp + Landlock, measured),
  the intent plane (`aisme declare`, measured at 1 ms), the policy compiler (working, three rules),
  the WAL and the forensic tail (working), the correlation engine (specified, not built), mobile
  (specified, not built), the UI (specified, not built), the Windows driver (`[POST]`, `ADR-02`).
- The *evidence* column cites the command: `cargo test --workspace`,
  `cargo xtask gate --level commit`, `cargo xtask bench-t0`.
- The documentation map gains the twelve missing documents, grouped so the list stays readable:
  **the plan and its three reviews** (01–04), **phase amplifications** (05–11, 14–17), **field
  research** (`docs/research/01`–`03`), **design and ADRs**, **working documents**. It does not list
  every file — it names the groups and links the index of each.
- The `## Documentation map` table keeps its current rows; new rows are appended, and the stale
  sentence *"Original research documents (Spanish) and extracted text"* is corrected, because
  `docs/research/` now holds three field studies written in English.
- One sentence is added where the README introduces the engine: that it supervises **off-the-shelf
  agents** through their own hook interface, naming Claude Code, Cursor, Codex, Copilot CLI and Gemini
  CLI. That is the single most useful fact for a visitor and it appears nowhere today.

### 4. Tests

**Existing, changed:** `cargo xtask verify-docs` already checks `NN_slug.md` naming, that every `§`
reference resolves, and that each `<task-id>` citation resolves to its row. It does **not** check the
README's documentation map against the files on disk.

**New:** `verify-docs` gains one check — **every numbered document under `docs/` is linked from the
README's documentation map, and every link in that map resolves**. It fails in both directions, which
is the point: a document nobody links is a document nobody reads, and a link to a deleted file is a
page that lies. The check is a dozen lines in `xtask/src/docgate.rs` beside the checks already there.

**Not added, deliberately:** nothing asserts the *prose* is accurate. A gate cannot read English.
What it can check is that the status table's commands exist as `xtask` subcommands, and that is folded
into the existing Annex H check rather than given its own.

### 5. Documentation

`README.md` — the status block, the documentation map, the research sentence, and the one sentence
about supervising off-the-shelf agents. `docs/ai/STATE.md` gains nothing: it is already the live
position and the README now points at it rather than restating it.

### Closing

Verified against `README.md`'s own status line, the 16 files in `docs/` against the 4 the map cites,
and the measurements at the head of this document. **One claim of the skeleton fell:** the ask was to
check the README *"está en correcto inglés"*, and it is — the defect is factual, not linguistic, which
is a better outcome than the ask assumed and a worse one to leave standing. Open: nothing.

---

## 2. Three things must leave the repository before it is public

**Done when:** the repository root holds only what the project's own rules admit, and no third-party
content is redistributed.

### 1. Challenge

*Is this the best solution?* Three findings, and the first is not untidiness, it is a licence problem.

**`sdk.html` — 691 KB, tracked, in the root.** It is a scraped copy of
`docs.github.com/.../copilot-sdk/hooks/pre-tool-use`, kept from the research pass. Publishing it
**redistributes GitHub's documentation**, which is not ours to relicense — and this repository ships
an Apache-2.0 `LICENSE` plus a `NOTICE` that enumerates attribution obligations. A 691 KB HTML dump
of somebody else's docs sitting beside them is the kind of thing that makes a licence file
unbelievable. It also violates the project's own rule that the root admits only `README.md` and the
instruction files.

**The research citations do the same job properly.** `docs/research/02` cites that exact page by URL
with its findings extracted. The scrape is redundant *and* the cited form is the correct one.

*Is it coherent with the specs?* The root rule is explicit. `verify-docs` enforces it for `.md` files
and does not look at anything else, which is why a 691 KB `.html` slipped past.

*Can it be simplified?* It is already a deletion. The only question is whether to purge it from
**history** too, and that belongs to point 5.

Two smaller findings, both verified:

- **`crates/aisme-ebpf-policy` has 52 lines of real code and no tests**, and
  **`tests/probes/ebpf` likewise**. They are not stubs: they are the second BPF object and the guest
  probe. Point 6 owns them.
- **Twelve of the sixteen numbered documents have Spanish filenames** — `challenge_ampliacion`,
  `investigacion`, `atribucion`, `decisiones_abiertas`, `plan_de_cierre` — while every document's
  *content* is English, as `CLAUDE.md` requires. For a public repository this reads as unfinished.

### 2. Verification

**The deletion is safe and the renaming is not, and the difference is why one happens now and the
other is asked about.**

- `sdk.html` is referenced by **no** tracked file (checked). Deleting it breaks nothing.
- Renaming twelve documents would break **every cross-reference between them**, and `verify-docs`
  checks `§` references and task-id citations but **not** inter-document links — so the breakage would
  be silent. It would also rewrite twelve files' worth of git history for a cosmetic gain, and rule 6
  says reorganising is not refactoring: it would need its own commit touching nothing else, with the
  test suite compared before and after.

**This is the one question in this point, and it is the owner's:** rename the twelve documents to
English slugs, or leave them? My recommendation is **leave them for now and do it as its own commit
after publication**. The reasons: the content is English so a reader loses nothing; `git mv` preserves
history and can be done any time; and doing it in the same pass as the rename of the repository
doubles the surface of a change whose point is to be boring. If you want them renamed first, say so
and it becomes its own numbered point with the link-checking that makes it safe.

### 3. Implementation

- `git rm sdk.html`, with the reason in the commit: third-party documentation, redundant with
  `docs/research/02`'s citation of the same page, and not ours to redistribute.
- `verify-docs`'s root-directory check widens from *"no `.md` in the root except the allowed ones"* to
  **any file in the root that is not on an explicit allow-list**. The allow-list is the one the rules
  already imply: `README.md`, `CLAUDE.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE*`, `NOTICE`,
  `CITATION.cff`, `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `budgets.toml`, `layers.toml`,
  `deny.toml`, and the directories. A new file in the root then fails the gate instead of shipping.
- Nothing is renamed in this point.

### 4. Tests

**New:** the widened root check in `xtask/src/docgate.rs`, with its allow-list in one place so adding
a legitimate root file is one edit and an accident is a `FAIL`. It is the test that would have caught
`sdk.html` the day it was committed.

**Not added:** a check that no tracked file is third-party content. That cannot be automated honestly
— a licence scanner would flag every quoted paragraph in the research documents. What replaces it is
the root allow-list plus the human rule already in `CONTRIBUTING.md`.

### 5. Documentation

`CONTRIBUTING.md` gains two lines: the repository root is allow-listed and the gate enforces it; and
third-party documentation is **cited, never copied**. `docs/CHANGELOG.md` records the deletion with
its reason.

### Closing

Verified that `sdk.html` is tracked (`git ls-files --error-unmatch`), that it is 691 KB of
`docs.github.com` HTML (its `<title>` and `og:url`), and that no tracked file references it. **One
claim of the skeleton fell:** the ask treated organisation as a tidiness question, and the root held a
licence problem. Open, and the owner's: whether to rename the twelve Spanish document slugs, which
this point deliberately does not do.

---

## 3. A contributor on-ramp

**Done when:** somebody who has never seen the project can build it, run it, see it enforce something,
and find a first task sized for a weekend.

### 1. Challenge

*Is this the best solution?* The ask is a *suggested next steps* section, and the honest version of
that is not a wish list — it is **tasks that are already specified and that a stranger can finish**.
This project has an unusual advantage: `docs/01`'s task table gives every item an ID, a
done-condition and its dependencies, and `docs/17` names what the current phase still owes. A
contributor section that points into that is worth more than invented ideas.

What is missing is the step **before** it. `CONTRIBUTING.md` exists and covers the DCO, but a visitor
cannot currently answer "does this run on my machine?" without reading the plan. The first thing the
section needs is `cargo xtask doctor` — which already exists, already measures 15 prerequisites, and
already names what each unblocks.

*Is it coherent with the specs?* Yes, and one project rule shapes it strongly: **`I-27`, zero hosted
CI.** A contributor cannot rely on a pipeline to tell them whether their change is good; they run the
gate locally. The section must say that, because a contributor who expects CI will be confused by its
absence and might helpfully add a workflow file — which `verify-docs` would reject, and which would
be their first experience of the project.

*Can it be simplified?* Yes: three tiers, not a catalogue. *Try it* → *fix something small* →
*take a specified task*. And every entry names its done-condition, because a task without one is an
invitation to guess.

### 2. Verification

- **Every suggested task must be real and currently open.** A contributor who picks something already
  done loses an evening and does not come back. The list therefore cites task IDs from `docs/17` and
  `docs/01` and states where to check it is still open (`docs/ai/STATE.md`), rather than restating a
  status that will drift.
- **No task may need the owner's hardware.** The TPM, iOS and Android rows of `F0.VER.12` are
  `UNVERIFIED` for lack of devices; they are not suggested to a stranger.
- **The kernel rule must be stated before anybody writes a kernel test.** `I-12` — no kernel-touching
  test on a host, snapshot VMs only — is the rule most likely to be broken in good faith, and
  `cargo xtask vm up` is how it is obeyed.
- **The honesty rules must be visible**, because they are what this project is: no claim without a
  measurement, a `FAIL` fixed before commit and never declared around, an absence recorded as an
  absence.

**Nothing here is unclear enough to ask about.** The content is a selection from documents that
already exist.

### 3. Implementation

A `## Contributing` section in `README.md`, immediately before `## Licence`, with four parts:

1. **Run it in five minutes** — `cargo xtask doctor`, `cargo test --workspace`,
   `cargo xtask gate --level commit`, and one `aisme run --trap-openat` line that denies something, so
   the first experience is the product working rather than a build log.
2. **How this project decides things** — six bullets, each one line: nothing enters unverified; every
   defect is a numbered point; a `FAIL` is fixed before committing; absence is never read as a value;
   **no hosted CI, every gate runs locally** (`I-27`); no kernel-touching test outside a VM (`I-12`).
   This is the shortest honest summary of `CLAUDE.md` and it prevents the two most likely good-faith
   mistakes.
3. **Good first tasks**, each with its done-condition and where to verify it is still open:
   - the degradation banner asserts absences it never measured (`STATE.md` → *Open, not blocking*) —
     self-contained, no kernel, and the fix is a third state in one enum;
   - `aisme-ebpf-policy`'s 52 lines have no test (point 6);
   - the twelve Spanish document slugs (point 2), which needs a link checker first and is therefore a
     two-part task;
   - `docs/17` point 5's exit tracepoint, for somebody who wants kernel work and has a VM.
4. **The deep end** — the correlation engine (`F5`), the mobile sensors (`F10`/`F11`) and the UI
   (`F8`) are specified in the plan and unbuilt; the task tables say what each owes. This part names
   the phase and links the table rather than describing the work, because the plan already describes
   it better than a README can.

The section says explicitly that **a contributor does not need to read the plan to start** — doctor,
tests, gate, and a first task — and that the plan is where they go when they want to understand why.

### 4. Tests

**New:** `verify-docs` gains a check that **every task ID cited in `README.md` exists in the plan's
task tables**. It reuses the citation resolver already written for `<task-id>` rows, so it is a few
lines rather than a new mechanism, and it fails the day a suggested task is renumbered or deprecated.

**Not added:** a check that a suggested task is still *open*. That state lives in `STATE.md` prose and
a gate cannot read it — which is why the section points the reader at `STATE.md` instead of asserting
openness itself.

### 5. Documentation

`README.md` gains the section. `CONTRIBUTING.md` gains a pointer to it at the top, so the two do not
diverge: the README is the on-ramp, `CONTRIBUTING.md` is the legal and procedural detail.

### Closing

Verified against `cargo xtask doctor`'s 15 checks, `gate --level commit`'s nine members, `docs/17`'s
seven open items, and `STATE.md`'s *Open, not blocking* entry. **No claim of the skeleton fell**, and
one was strengthened: the ask said *"suggested next steps"*, and the project can offer **specified**
next steps with done-conditions, which is a better thing to offer a stranger. Open: nothing.

---

## 4. Discovery vocabulary

**Done when:** somebody searching for what this project does finds it, without the page overclaiming.

### 1. Challenge

*Is this the best solution?* The repository is currently findable by almost nobody, and the
measurement is simple: the workspace declares **no `description`, no `keywords`, no `categories`** —
only `license` and `repository`. GitHub ranks on the description, the topics and the README's first
lines; crates.io ranks on `description`, `keywords` and `categories`. All of them are empty or absent.

And the name works against it. `AISME — AI Sessions Manager & Security Engine` is an acronym nobody
searches for. The new name, `AI-SENTINEL-EALCOBER`, is distinctive but carries no subject terms
either.

*Is it coherent with the specs?* Yes, with one constraint that must not be traded away: the product
names are fixed — `AISME`, `AI Sentinel`, `AI Sentinel SDK`, *never* "AISME Sentinel". Vocabulary work
adds **descriptive** terms around those names; it does not rename the product to chase a search term.

*Can it be simplified?* Yes, and the simplification is also the honest version: **use the words the
field already uses.** The research documents established them — *AI agent security*, *agentic AI*,
*runtime enforcement*, *provenance*, *prompt injection*, *tool-call attribution*, *eBPF*, *seccomp*,
*Landlock*. Those are the terms in the papers and the vendor pages a searcher will have read first.
Inventing vocabulary is what the acronym already did.

### 2. Verification

- **No term may claim a capability the product lacks.** *"Sandbox"* is out: this is not a sandbox and
  the threat model says so. *"Prevents prompt injection"* is out; *"records and contains what an
  injected agent does"* is accurate. The honest-coverage rule applies to the search terms as much as
  to the feature table.
- **The description must survive being read alone**, because that is how it appears in a search
  result list, with no README under it.
- **Topics are a finite list and GitHub caps them at 20.** They will be chosen for the terms a
  searcher types, not for completeness.
- **`keywords` on crates.io is capped at five per crate** and each is ≤20 characters. The workspace
  will carry one set and the publishable crates inherit it.

**Nothing here is unclear enough to ask about.** One thing is worth stating rather than deciding
silently: the project is **not** going to crates.io in this pass — no crate is published, so
`keywords`/`categories` are set because they cost one line each and are needed the day one is, not
because anything depends on them now.

### 3. Implementation

- `Cargo.toml`'s `[workspace.package]` gains `description`, `keywords`, `categories`, `homepage`,
  `documentation` and `readme`, and `repository` is repointed in point 7.
- The `description`, one sentence that stands alone: *"Kernel-level runtime security for autonomous AI
  coding agents: eBPF and Landlock enforcement, tool-call attribution, and tamper-evident
  forensics."* Terms a searcher types, no claim the product does not hold.
- `keywords` — `ebpf`, `security`, `ai-agents`, `observability`, `sandbox`-free alternatives chosen to
  fit the five-slot, 20-character limit: `ebpf`, `ai-agent`, `security`, `landlock`, `seccomp`.
- `categories` from crates.io's fixed list: `os::linux-apis`, `development-tools`.
- **GitHub topics**, to be set on the new repository in point 7: `ai-agents`, `agentic-ai`,
  `ai-security`, `llm-security`, `prompt-injection`, `runtime-security`, `ebpf`, `seccomp`,
  `landlock`, `linux-security`, `observability`, `provenance`, `audit-log`, `claude-code`, `rust`,
  `devsecops`. Sixteen of the twenty allowed, leaving room.
- The README's **first two lines** gain the searched terms without losing the current voice. The
  subtitle becomes *"Kernel-level runtime security and provenance for autonomous AI coding agents —
  eBPF, Landlock and seccomp on Linux, including WSL2."*
- The vendor names go in the README's opening, as point 1 already specifies: somebody searching
  *"Claude Code security"* or *"Cursor agent sandbox"* finds nothing today, and those are the exact
  searches this project answers.

### 4. Tests

**New:** `verify-docs` gains a check that `[workspace.package]` carries a non-empty `description` and
at least three `keywords`, and that the `repository` URL's final path segment equals the repository
directory name. The third clause is the one that matters: it fails the day the repository is renamed
and the manifest is not, which is precisely the failure point 7 risks.

**Not added:** anything that asserts a search ranking. Unmeasurable, and a gate that claimed it would
be decoration.

### 5. Documentation

`README.md`'s subtitle and opening paragraph; `Cargo.toml`'s workspace package block. The topic list
is recorded in point 7's procedure, because it is set through GitHub's interface and not in a file —
and a list of topics that exists only in somebody's memory is a list that will not survive the next
rename.

### Closing

Verified against `Cargo.toml` (only `license` and `repository` present), crates.io's five-keyword and
twenty-character limits, and GitHub's twenty-topic cap. **One claim of the skeleton fell:** the ask
read as a wording exercise, and the measurement shows the fields are not weak but **absent**, which is
a smaller job with a larger effect. Open: nothing.

---

## 5. Secrets, and the 90 MB of history behind them

**Done when:** it is established, not assumed, that publishing leaks nothing — and the history
question is answered deliberately.

### 1. Challenge

*Is this the best solution?* The secret question is **answered and the answer is good**. Measured
across every tracked file and every commit on every branch:

| check | result |
|---|---|
| secret-shaped patterns in tracked files | 4 files, **all four false positives** |
| `.env` / `.pem` / `.key` / `id_rsa` / `credentials` tracked | **none** |
| the same, ever added in any commit | **none** |
| the owner's home or media paths in a tracked file | **none** |
| the owner's email in a tracked file | **none** |

The false positives are worth naming so nobody re-raises them: `libc::passwd` in `ipc.rs:674` is the
C struct the per-session `${home}` binding reads; `/etc/passwd` in `policy_evaluate.rs:40` is a path a
policy test evaluates; and `STATE.md:345` mentions *sudoers* in prose.

*What is not clean is the history.* **1,781 `/target/` paths** existed in commits, and six blobs
exceed 16 MB with the largest at **41.2 MB** — `libcore-*.rlib` under
`crates/aisme-ebpf-policy/target/` and `tests/probes/ebpf/target/`. `.git` is **90 MB** for 264
tracked files. `.gitignore`'s own comment records the cause: *"Naming them one by one is what put 890
build artefacts in the index."*

*Is it coherent with the specs?* The artefacts are gone from the working tree and `verify-docs`
already checks that no build artefact is tracked. Nothing is broken today. What is at stake is what a
*public* clone costs and what the history says about the project.

*Can it be simplified?* The decision can, into one question with two honest answers, and point 7's
new repository is the moment it is cheapest to take.

### 2. Verification

**This point asks rather than resolving, and it is the one real decision in this document.**

**Option A — publish with full history.** Every commit, every message, every measurement in order.
90 MB clone. The history is unusually valuable here: it records the measurements that produced each
decision, and the commit messages are part of the project's argument.

**Option B — publish with a fresh initial commit.** One commit, the current tree, 264 files, a few MB.
The history stays in the private repository. A visitor sees a clean project and **loses the record of
how it got there**.

**Option C — rewrite history to drop the artefacts** (`git filter-repo --strip-blobs-bigger-than`).
Keeps every message, drops the blobs, and **changes every commit hash**. Costs: the private repository
and the public one diverge irreconcilably; every hash cited in a document — and `STATE.md` and the
changelog cite several — becomes wrong; and the project's own rule about not asserting that rewritten
work *"quedó idéntico"* applies to the history itself.

**My recommendation is A.** 90 MB is unremarkable for a clone in 2026 — GitHub's own soft warning is
per-file at 50 MB and the largest blob here is 41.2 MB, so nothing is even warned about. And the
history is the strongest evidence this project has that its claims were measured rather than asserted:
a visitor who reads three commit messages learns more than a brochure could tell them. **C buys a
smaller clone at the price of invalidating citations across the documentation**, which is a bad trade
for a project whose documents cite commits on purpose.

**If you prefer B**, say so: it is defensible if you would rather the public repository start clean,
and it costs one command. **I will not choose between A and B for you** — it decides what the public
record of this work is.

### 3. Implementation

Whatever the answer, these happen first and are not conditional:

- A **pre-publication secret sweep as a recorded command**, not a one-off: a `cargo xtask verify-release`
  that re-runs the five checks in the table above and exits non-zero on any hit. Run before the push,
  and runnable by anybody afterwards. The value is that *"we checked"* becomes *"the check is in the
  tree and here is its output"*.
- `.gitignore` gains `*.html` **in the root only** (`/​*.html`), since the one that got in was a
  scraped page and the root is the only place such a thing has no business being.
- The `deploy/hooks/aisme-hooks.json` file is re-read before publication to confirm it names no path
  specific to this machine. It currently names `~/.claude/settings.json`, which is correct and
  generic.

### 4. Tests

**New:** `cargo xtask verify-release`, with the five checks as named steps so a failure says which
one. Its own test asserts it **fails** on a planted secret-shaped string in a temporary file and
passes on the real tree — a check that cannot fail is decoration, and this is the one place in this
document where a canary is cheap.

**Existing, unchanged:** `verify-docs`'s *"no build artefact is tracked"* check, which is what keeps
the working tree clean and is why this point is about history rather than about the present.

### 5. Documentation

`docs/CHANGELOG.md` records `verify-release` and the measured sweep. `SECURITY.md` gains one line: the
pre-publication sweep is a command in the tree, and what it checks. `docs/ai/STATE.md` records the
history decision once it is taken, with its reason — because the next person to wonder why the public
repository looks the way it does will look there.

### Closing

Verified against every tracked file, every commit on every branch, the four false positives by file
and line, and `git cat-file --batch-check` for the blob sizes. **One claim of the skeleton fell:** the
ask was *"ensure you would not publish my secrets"*, and the measurement shows there are none to
publish — the real exposure is 90 MB of build artefacts in the history, which is an embarrassment
rather than a leak. Open, and the owner's: full history, fresh start, or rewrite.

---

## 6. Test coverage: what the ask means once the stubs are excluded

**Done when:** every module with real code has tests, and the modules that cannot be tested on a host
say so with their reason.

### 1. Challenge

*Is this the best solution?* The ask reads as *"add tests to every module"*, and measuring first makes
it a much smaller and more useful job. Tests and lines per crate, measured:

| crate | tests | lines | reading |
|---|---|---|---|
| `aisme-core` | 133 | 10,272 | well covered |
| `aisme-agentd` | 59 | 5,447 | well covered |
| `xtask` | 39 | 7,154 | covered; it is build tooling |
| `aisme-linux` | 34 | 4,265 | covered; the kernel parts are guest-tested |
| `aisme-ebpf-common` | 30 | 1,854 | well covered — it is the wire format |
| `aisme-agentsim` | 28 | 2,563 | well covered |
| `aisme-cli` | 27 | 1,099 | well covered |
| `aisme-correlate` | 13 | 1,025 | **thin** |
| `aisme-proto` | 8 | 961 | **thin** |
| `aisme-loaderd` | 8 | 757 | **thin** |
| `aisme-forensicd` | 8 | 307 | proportionate |
| `aisme-ebpf` | 0 | 242 | **no host test is possible** (`I-12`) |
| `aisme-ebpf-policy` | 0 | 52 | **a real gap** |
| nine others | 0 | 4–10 each | **stubs**, not gaps |

**Nine crates with zero tests are stubs of 4 to 10 lines** — placeholders for later phases
(`aisme-tls`, `aisme-observer`, `aisme-otel`, `aisme-relay`, `aisme-clientcore`, `aisme-sdkhost`,
`aisme-compress`, `sentinel-core`, `aisme-windows`). Adding tests to them would be adding tests to
`pub fn main() {}`. That is the claim of the ask that falls, and it falls to arithmetic.

*Is it coherent with the specs?* One rule shapes this absolutely: **`I-12`, no kernel-touching test on
a host.** `aisme-ebpf`'s 242 lines are a BPF program; it cannot be unit-tested here and it is
exercised by `cargo xtask vm run` in a guest. Its zero is **correct** and must be *documented* rather
than filled.

*Can it be simplified?* Yes. The job is: one real gap (`aisme-ebpf-policy`), three thin crates, and
edge cases in the paths that already have tests. Not twenty-two crates.

### 2. Verification

- **A test that cannot fail is worse than no test.** Every new test gets its canary — the defect is
  reintroduced and the test must fail — and the canaries run *after* the commit, because undoing them
  is a `git checkout` that takes anything uncommitted with it.
- **No new test may touch the kernel on this host.** `aisme-ebpf-policy`'s test will assert what can
  be asserted without loading: that the object builds, that its maps are the two `LpmTrie`s plus the
  `Array<u64,2>` the publication expects, and that the names match what `aisme-loaderd` looks up. The
  load stays in the guest.
- **Edge cases are chosen by what would bias toward optimism**, per the project's rule 4. A parser
  that accepts something malformed is urgent; one that rejects something valid is not. The list below
  is ordered that way.
- **The thin crates are thin for different reasons** and must not be treated alike: `aisme-proto` is a
  codec, where fuzz-shaped edge cases pay most; `aisme-correlate` is an algorithm, where the
  interesting cases are structural; `aisme-loaderd` is mostly privileged I/O whose real test is in a
  guest.

**Nothing here is unclear enough to ask about.**

### 3. Implementation

**`aisme-ebpf-policy` — the one real gap.** A test module asserting the map set, the map names, the
key and value sizes, and that `Array<u64,2>`'s two slots are the generation and the active index in
that order. These are the facts `aisme-loaderd` depends on and currently nothing checks: a renamed map
would fail at publication time in a guest rather than at `cargo test` on a laptop.

**`aisme-proto` — the codec, edge cases first.** Each of these would bias toward accepting bad input:
a request whose `id` is absent, null, a string, or a float; a method name that is a prefix of a real
one; duplicate keys in one object (last wins, and a test says which); a number beyond `i64`; a string
with an unterminated escape, a lone surrogate, an embedded NUL, or a literal newline inside quotes; a
nesting depth beyond the codec's bound; an empty line and a line of only whitespace; and `ALL`'s
sixteen methods each round-tripping through `as_str` and back. The last is the cheap one that catches a
method added to the enum and forgotten in the table.

**`aisme-correlate` — structural cases.** An empty graph; a single node with no edges; a cycle, which
must be refused rather than walked; two roots; an event whose parent arrives after it; and the
`MAX_ANCESTRY`-equivalent bound reached exactly and exceeded by one. Boundaries get the three values
either side, not one in the middle.

**`aisme-loaderd` — what can be tested unprivileged.** That a policy file that does not exist is named
rather than read as empty; that a policy that parses and does not bind is refused with the variable
named; that a prefix too long for the LPM key is refused rather than truncated into a broader rule
(this one exists in `aisme-linux` and its absence here is a seam); and that `--publish` with no socket
warns and exits **0**, because the privileged act already happened in the kernel.

**`aisme-forensicd`, `aisme-cli`, `aisme-agentd` — edge cases on paths that already have tests.** A
WAL segment truncated mid-record; a cursor past the end; a cursor that does not parse; a zero-length
segment; a path at exactly the payload's capacity and one byte over; a tool name at exactly 64 bytes
and one over; a session id of `0`; two sessions whose ids differ in one bit.

**`aisme-ebpf` — documented, not filled.** A `tests/README.md` in the crate stating that `I-12`
forbids a host test, naming `cargo xtask vm run` as where it is exercised, and listing which
properties the guest run asserts. A zero with a written reason is honest; a zero with nothing beside
it looks like neglect.

**The nine stubs — one line each.** A `//!` module note saying which phase implements the crate and
which task ID owns it. No tests.

### 4. Tests

The whole point is tests, and the counts are the measurement: **387 today**. Each group above states
what it adds, and the suite's total goes in the commit message with the before and after, as every
commit in this project does.

**Existing, changed:** none are expected to change. If one does, it is reported — a new edge case that
forces an existing test to change usually means the existing test was asserting the defect.

### 5. Documentation

`docs/CHANGELOG.md` per group. `crates/aisme-ebpf/tests/README.md` as above. The nine stub notes.
Nothing in the plan changes: these are tests for specified behaviour, not new behaviour.

### Closing

Verified by counting `#[test]` and lines per crate across all twenty-two. **One claim of the skeleton
fell, and it is the ask's own:** *"all modules"* is nine stubs of four lines, one guest-only BPF
program and one real gap — so the job is `aisme-ebpf-policy`, three thin crates and a list of edge
cases, not a sweep. Open: nothing.

---

## 7. The rename and the publication procedure

**Done when:** `AI-SENTINEL-EALCOBER` is public, builds from a fresh clone, and nothing inside it
still points at the old name.

### 1. Challenge

*Is this the best solution?* The rename surface is **four files**, measured: `CITATION.cff`,
`Cargo.toml`, `NOTICE`, and `docs/01_phase5_implementation_plan.md`. That is small enough to do by
hand and verify by grep, which is the right way for something whose failure mode is a dead link.

One thing the ask implies needs separating. `AI-SENTINEL-EALCOBER` is the **repository** name. The
**product** names are fixed by the project's own conventions — `AISME` for the engine, `AI Sentinel`
for the mobile app, `AI Sentinel SDK` for the library — and `verify-docs` has a check for them. The
rename must not silently redefine `AI Sentinel` from *the mobile app* to *the whole project*, because
then the plan, the ADRs and the parity matrix all become wrong about which component is which.

*Is it coherent with the specs?* With that distinction, yes. The README's `## Naming` section exists
precisely to hold it and will say that the repository is named after the project's general idea while
the components keep their names.

*Can it be simplified?* Yes, in one way that reduces risk: **the new repository is created empty and
pushed to, rather than the old one being renamed.** A rename on GitHub leaves a redirect, which sounds
helpful and means the old name keeps working — so a stale reference never fails loudly. A new
repository makes every stale reference fail at once, which is what a gate wants.

### 2. Verification

- **The order is not negotiable.** Points 1–6 land in the private repository first, verified there.
  Publishing is the last act, and the public repository's first commit is a tree that already passes
  its own gates.
- **`I-27` applies to the public repository exactly as it does here**: no workflow file, not one with
  safe triggers, not a manually dispatched one. A public repository attracts helpful pull requests
  adding CI; `CONTRIBUTING.md` must say *no* before one arrives, and `verify-docs` already fails if a
  workflow file appears.
- **The licence set must be checked against reality once more before the push**: `LICENSE-APACHE`,
  `LICENSE-GPL` (eBPF only), `LICENSE-BSD`, the map in `LICENSE.md`, `NOTICE`'s attributions, and
  `ADR-06`. They exist and are dated; what the publication adds is `cargo deny check` passing on the
  tree being published, which the gate already runs.
- **`CITATION.cff` must be re-read, not patched blind.** It carries a repository URL, a title and
  authorship; a citation file that points at a dead URL is worse than none.

**One thing is the owner's and it is not technical:** the repository name embeds your handle
(`-EALCOBER`). That is a deliberate signal of authorship and it also means the project's name is tied
to you rather than to the thing it does, which point 4 notes costs discoverability. I will use the
name you gave. If you would rather the repository be `ai-sentinel` with your handle in the
description and `CITATION.cff` instead, say so before the push — afterwards it is another rename.

### 3. Implementation

In this order, and stopping at the first that disagrees.

**Before the push, in the existing repository:**

1. Points 1–6 committed and pushed. `cargo test --workspace`, `cargo xtask gate --level commit` and
   the new `cargo xtask verify-release` all green.
2. The four files repointed: `Cargo.toml`'s `repository`, `CITATION.cff`'s URL and title, `NOTICE`,
   and the plan's reference. Verified by `git grep -I "AI-SYSTEM-MONITOR"` returning **nothing**.
3. The README's `## Naming` section gains the repository-versus-component distinction.
4. `verify-docs`'s new check — the `repository` URL's last segment equals the directory name — passing
   against the new name.

**The publication itself**, as commands for you to run:

```bash
# 1. The new repository, empty, public. Created in the browser at github.com/new,
#    named AI-SENTINEL-EALCOBER, with NO README, NO .gitignore and NO licence —
#    the tree already has all three and GitHub's versions would conflict.

# 2. Point this working copy at it, keeping the old remote under another name
#    so nothing is lost if you change your mind.
cd "/media/ealcober/DATOS_ACTIVOS/CODE 2026/AI-SYSTEM-MONITOR"
git remote rename origin old-origin
git remote add origin git@github.com:ealcober/AI-SENTINEL-EALCOBER.git

# 3. Push. `-u` sets the upstream so later pushes need no arguments.
git push -u origin main

# 4. Verify the effect, not the report.
git rev-list --left-right --count origin/main...HEAD    # must read 0 0
```

Then, in the repository's settings page: the **description** from point 4, the **topics** from point
4's list of sixteen, and — because `I-27` is a hard rule — **Actions disabled** under
*Settings → Actions → General → Disable actions*, so a contributor's workflow cannot run even if one
is merged by accident.

**If the history decision in point 5 is B (fresh start)**, step 2 is replaced by creating an orphan
branch, committing the tree once, and pushing that; the old history stays under `old-origin`. The
commands differ enough that they will be written out when the decision is taken rather than guessed
at here.

### 4. Tests

**New:** the `repository`-matches-directory check in point 4, which is the only automatable part of a
rename and catches the exact thing that goes stale.

**Manual, and stated as manual:** a **fresh clone into a temporary directory**, then
`cargo xtask doctor`, `cargo test --workspace` and `cargo xtask gate --level commit` in it. This is
the only check that catches a file that is needed and untracked, and nothing in the tree can test it
from inside the tree. It goes in the procedure as a numbered step, not as an afterthought.

### 5. Documentation

`README.md`'s naming section; `CITATION.cff`; `NOTICE`; `Cargo.toml`. `docs/CHANGELOG.md` records the
rename and the publication with the date. `docs/ai/STATE.md` records the new URL, because every
document that cites the repository will be read by somebody who needs to find it.

### Closing

Verified that exactly four tracked files mention `AI-SYSTEM-MONITOR` (`git grep -lI`), that the
product-name convention is checked by `verify-docs`, and that GitHub's rename-redirect behaviour is
what makes a fresh repository the safer route. **One claim of the skeleton fell:** the ask said
*"renombrar"*, and a GitHub rename is the wrong mechanism — it leaves a redirect that keeps stale
references working, so a new empty repository is both simpler and stricter. Open, and the owner's: the
handle in the repository name, and point 5's history decision, which changes step 2.

---

## Whole-document coherence

Read end to end after all seven were closed.

1. **Three of the seven points shrank when measured, and all three in the same direction.** The
   secrets point found nothing to fix; the test point found nine stubs where the ask assumed nine
   modules; the vocabulary point found absent fields rather than weak ones. The ask was right that
   these needed looking at and wrong about what would be found, which is the ordinary outcome of
   measuring first.
2. **The two blocking points are both the same defect**: the README claims a state the repository
   contradicts, and the root holds a file the licence file contradicts. A visitor who notices either
   stops trusting the rest, and this project's whole argument is that it does not overclaim.
3. **Point 2 and point 7 are sequenced and it matters.** Deleting `sdk.html` before the push is
   cheap; after it, the file is in a public history and removing it needs a rewrite. The same is true
   of point 5's decision, which is why both sit before publication rather than after.
4. **Point 3 and point 4 pull in opposite directions and both are satisfied.** The contributor section
   wants precision — task IDs, done-conditions, `I-12`, `I-27` — and the discovery vocabulary wants
   the field's common terms. They live in different sections of the README: the opening is for
   somebody searching, the contributing section is for somebody who already arrived.
5. **Corrected while reading:** the skeleton had point 6 before point 5. Tests are not a precondition
   for the history decision, and the history decision is the only thing in this document with a long
   lead time — it is the owner's and it gates step 2 of the publication. It moved ahead of the tests so
   the question is asked earlier.

**Against the specs**, nothing here contradicts an invariant. Point 3 states `I-12` and `I-27` to
contributors rather than relying on them reading `CLAUDE.md`. Point 6 preserves `I-12` by documenting
`aisme-ebpf`'s zero instead of filling it. Point 7 keeps the product-name convention intact and
separates it from the repository name.

**Two decisions are the owner's and they are independent:** the history (full, fresh or rewritten) and
whether the handle belongs in the repository name. Everything else in this document is executable.
