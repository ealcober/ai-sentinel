# Challenge-amplification — 890 build artefacts in the index

> **Status**: complete — three points, all closed. Points 1 and 2 are implemented; point 3 was the
> owner's and is answered: **history stays**, and the 75 MB stays with it
> **Scope**: `docs/07` point 9, which was recorded and deliberately not fixed while implementing
> points 1–8. It is amplified here because removing 890 files from the index is a reorganisation
> under `CLAUDE.md` rule 6, and because one of its three questions is the owner's and not mine.
> **Method**: `/challenge-ampliar` — five sections per point, in the declared future.

## How to read this

`docs/07` recorded one defect. Measurement split it into three decisions that are genuinely
separate, and conflating them is how a cleanup turns into a history rewrite nobody asked for:

1. **Stop tracking them.** Mechanical, reversible, and the only part that has to happen.
2. **Stop them coming back.** One `.gitignore` line, and the choice of which line matters more
   than it looks.
3. **Reclaim the 75 MB, or not.** A history rewrite. The owner's — **answered on 2026-09-09:
   history stays.**

**The measurement that reshaped the point**, and it refutes what `docs/07` implied: *three code
paths read those directories.* `crates/aisme-linux/build.rs:27`, `xtask/src/vm.rs:54` and
`xtask/src/tooling.rs:228` all name a path inside one of the two trees. `docs/07` said the
artefacts were tracked and said nothing about anyone reading them, which would have made this a
one-line cleanup. It is not.

**What makes it safe anyway, measured rather than argued:** the *sensor's* object is read by the
same function, through the same mechanism, from a directory that is **already ignored** —
`/crates/aisme-ebpf/target` is in `.gitignore` and has been since the file was written. The
pattern being proposed is not new; it is already running for the object that matters most.

---

## Point 1 — Stop tracking the two trees

**Done when:** `git ls-files | grep -c "/target/"` reports 0 and the workspace still builds.

### 1. Challenge

*Is this the best solution?* Measured: **890 tracked files, 445 in each of
`crates/aisme-ebpf-policy/target` and `tests/probes/ebpf/target`, 631 MB on disk.** They entered
in `ccd5632` (2026-09-07), the commit that added `crates/aisme-ebpf-policy`.

Where the error biases is not the size. Every `cargo xtask build-ebpf` rewrites them, so a routine
build produces a diff of over 150 files, and **a real change to a tracked file would be invisible
inside it**. That is what makes this a correctness problem rather than a tidiness one: the review
that would catch a mistake cannot see past the noise. The 631 MB every clone pays is the second
cost, not the first.

Three shapes were weighed:

1. **Leave them.** They are regenerated anyway, so they are never *wrong* — they are noise. Refused
   on the review argument above.
2. **`git rm --cached` the two trees and ignore them.** Removes them from the index and from every
   future commit, leaves history alone, and leaves the files on disk so nothing rebuilds.
3. **Rewrite history to remove them entirely.** That is point 3, and it is a different decision
   with a different blast radius.

(2) is what this point does.

*Is it coherent with the specs?* Yes, and it restores a symmetry the repository already has:
`.gitignore` covers `/target` and `/crates/aisme-ebpf/target`. The two directories at issue are the
ones created **after** that file was written — `crates/aisme-ebpf-policy` in `ccd5632` and
`tests/probes/ebpf`. Nothing chose to track them; the ignore file simply did not grow with them.

*Can it be simplified?* The removal itself cannot be smaller than `git rm -r --cached`. What can be
simplified is the worry: **the files stay on disk**, `--cached` touches only the index, so no
rebuild is needed and nothing that reads them stops working in this working copy.

### 2. Verification

Safe, clear and compliant, with the one thing that actually changes stated plainly:

- **Three paths read into those trees and all three read build outputs.**
  `crates/aisme-linux/build.rs:27` locates
  `../aisme-ebpf-policy/target/bpfel-unknown-none/release/aisme-ebpf-policy`;
  `xtask/src/vm.rs:54` and `xtask/src/tooling.rs:228` name
  `tests/probes/ebpf/target/bpfel-unknown-none/release/aisme-ebpf-verify`. `cargo xtask build-ebpf`
  produces both — measured on 2026-09-09, exit 0, three `PASS` lines.
- **Absence is already handled, and handled well.** `build.rs`'s `locate` (`:35`) emits a
  `cargo:warning` naming the missing object and leaves the `cfg` unset, so `POLICY_OBJECT` is empty
  and `load_policy_maps` returns *"no policy object is embedded; run `cargo xtask build-ebpf` and
  rebuild"*. That is a named degradation, not a crash.
- **The identical arrangement already runs untracked.** `/crates/aisme-ebpf/target` is ignored, its
  object is located by the same `locate` call one block above, and the sensor works. This is the
  measurement that turns "should be safe" into "is already the case for the object that matters
  most".
- **What changes, and it must not be hidden:** a *fresh clone* currently arrives with a prebuilt
  policy object and probe. After this, it arrives without them, and `cargo xtask build-ebpf` is a
  prerequisite rather than an accident of what was committed. That is the documented workflow
  already — `doctor` exists to make that build possible — but it is a real behavioural change for
  anyone who cloned and ran a probe without building.
- **`git rm --cached` is reversible** in one commit and does not touch the working tree. Nothing in
  it is destructive; point 3 is where destructive lives.

### 3. Implementation

- `git rm -r --cached crates/aisme-ebpf-policy/target tests/probes/ebpf/target` — index only, files
  left on disk.
- Nothing in `crates/aisme-linux/build.rs`, `xtask/src/vm.rs` or `xtask/src/tooling.rs` changes.
  They read paths, and the paths are unaffected by what git tracks. **This is stated because the
  temptation to "fix" them at the same time is exactly what `CLAUDE.md` rule 6 forbids:
  reorganising is not refactoring.**
- The commit touches the index, `.gitignore` (point 2) and the documentation, and **nothing else**.

### 4. Tests

**Existing to change:** none. No test asserts anything about what git tracks.

**New:** one check in `xtask/src/docgate.rs`, `no_build_artefacts_are_tracked`, registered in
`verify-docs`: `git ls-files` must contain no path with a `/target/` component. It will report the
count and the first few paths, because "890 files" without an example is not actionable.

It will be **seen failing before the removal**, which is free here: the check is written first, run
against the current index, and its output — the count and the offending paths — goes in the commit
body. That is stronger than a canary, because it fails on the real defect rather than an injected
one.

**Not tested:** that the build still works without them. That is `cargo xtask build-ebpf` and the
existing suite, which run anyway; a test asserting a build works is the build.

### 5. Documentation

- `docs/CHANGELOG.md`: one line, with the count and the size.
- `docs/ai/STATE.md`: the Done row, and `docs/07` point 9 marked closed by reference.
- `CONTRIBUTING.md` will be **read first**: if it tells a new contributor to clone and run
  something that needs an object, it gains the `build-ebpf` step. If it does not, nothing is added
  — inventing a setup section is not this point's work.

**Closing.** Verified against `git ls-files | grep "/target/"` (**890 files, 445 per tree**),
`du -ch` over them (**631 MB**), `git log --diff-filter=A` on the first of them (`ccd5632`),
`.gitignore` (`/target` and `/crates/aisme-ebpf/target`, and neither of the two at issue), and
`crates/aisme-linux/build.rs:19-32`, where the sensor's already-ignored object is located by the
same function. **One claim of the skeleton fell**: `docs/07` point 9 said nothing read these
directories and implied a one-line cleanup; three code paths name them, and the point is safe for a
different reason — the same mechanism already runs untracked for the sensor. Open: nothing in this
point.

---

## Point 2 — Stop them coming back

**Done when:** a `target/` created by a crate added next year is ignored without anyone editing
`.gitignore`.

### 1. Challenge

*Is this the best solution?* The defect is not that two directories were forgotten. It is that
`.gitignore` lists **specific** target directories — `/target`, `/crates/aisme-ebpf/target` — so
every out-of-workspace crate added afterwards is one someone has to remember. Two were added; two
were forgotten. The rule and the failure are the same shape.

Two shapes:

1. **Add the two missing entries.** Fixes today and reproduces the defect the next time a crate is
   added outside the workspace. Refused: it is the fix that does not fix.
2. **One pattern that covers any depth**: `target/` — with no leading slash, gitignore matches a
   directory of that name at any level. It subsumes the two existing entries.

*Is it coherent with the specs?* Yes, and it is what the comment in `.gitignore` already wishes
for: it explains that `crates/aisme-ebpf` is outside the workspace *and therefore has a target of
its own*. That comment is a reason that generalises, written as an exception that does not.

*Can it be simplified?* It is one line. What needs care is not the line but its blast radius: a
bare `target/` also ignores a **source** directory that happened to be called `target`.

### 2. Verification

- **Measured, not assumed:** `git ls-files | grep "/target/\|^target/"` returns 890 paths and every
  one of them is under one of the two build trees. There is no source directory named `target` in
  this repository, so the pattern ignores nothing anyone wants.
- **The two specific entries will be replaced, not kept alongside.** Leaving them would restate the
  general rule as two examples, and the next reader would not know whether the list is exhaustive —
  which is what made this defect possible.
- **The comment survives and is corrected.** It currently explains why `crates/aisme-ebpf` needs
  its own entry. Under the general pattern that reason is no longer about one crate, so the comment
  will say what is true now: a crate outside the workspace builds into its own `target/`, and the
  pattern covers every one of them, present and future.
- **The risk that remains, and it is real:** a future crate that *must* ship a prebuilt artefact
  would now be silently ignored. That is the correct default — a repository should refuse build
  output by default and be told otherwise — and the escape hatch is `git add -f` with a reason in
  the commit. This is recorded rather than left to be discovered.

### 3. Implementation

- `.gitignore`: `/target` and `/crates/aisme-ebpf/target` are replaced by a single `target/`, and
  the existing comment is rewritten to state the general rule rather than the one exception.
- No other ignore entry is touched. In particular `Cargo.lock`'s comment — which explains why the
  lock file **is** committed — stays exactly as it is; it is the kind of reasoning `CLAUDE.md`
  rule 1 exists to protect.

### 4. Tests

**Existing to change:** none.

**New:** none beyond point 1's `no_build_artefacts_are_tracked`, which is the check that would
catch a regression whatever pattern `.gitignore` uses. A test that asserts the *contents* of
`.gitignore` would test the fix instead of the property, and would pass with the files tracked.

### 5. Documentation

- `.gitignore`'s own comment, as described.
- `docs/CHANGELOG.md`: folded into point 1's line; the two are one change.

**Closing.** Verified against `.gitignore` as committed (`/target`, `/crates/aisme-ebpf/target`,
and the comment explaining the second), and against `git ls-files`, which shows no tracked path
containing a `target` component that is not build output. **Nothing of the skeleton fell.** Open:
whether a future crate will ever need to ship a prebuilt artefact — recorded, with `git add -f` as
the deliberate escape, rather than designed for now.

---

## Point 3 — The 75 MB already in history

**Done when:** the owner has decided, and the decision is written down.

### 1. Challenge

*Is this the best solution?* Points 1 and 2 stop the bleeding and change nothing about what is
already committed. Measured: `git count-objects -vH` reports **`size-pack: 74.84 MiB`**, and the
five largest blobs in the whole history are all build artefacts — two 42 MB `libcore` rlibs, two
39 MB rmetas, a 19 MB `libsyn`. The repository is, in packed bytes, mostly these files.

So the question is worth asking and **is not mine to answer**:

1. **Leave history alone.** Every clone downloads ~75 MB once. Nothing breaks, no rewrite, every
   published hash stays valid.
2. **Rewrite history** (`git filter-repo`, or a fresh root). Reclaims most of the 75 MB and
   **changes every commit hash after `ccd5632`**, which invalidates every reference to a commit —
   including the ones written into `docs/05`, `docs/06`, `docs/07`, `STATE.md` and the CHANGELOG,
   which cite hashes as evidence. That is not a side effect; in this repository, commit hashes are
   citations.

*Is it coherent with the specs?* The project's documents cite commits by hash as proof
(`ccd5632`, `34ba389`, `624c507`). A rewrite turns every one of those into a dangling reference,
and `CLAUDE.md` general rule 1 says an unverifiable claim does not belong in the body of a
document. So a rewrite is not only a git operation: it is a documentation migration.

*Can it be simplified?* Only by not doing it. 75 MB is one download; the citations are the whole
record of what was measured and when.

### 2. Verification

**This point does not resolve itself, and the algorithm says to ask rather than decide.** What is
needed from the owner is one answer, and the trade is stated so it can be given in a sentence:

- **Keeping history** costs ~75 MB per clone, once, forever. Nothing else.
- **Rewriting** reclaims most of it and breaks every commit hash cited in `docs/05`, `docs/06`,
  `docs/07`, `docs/ai/STATE.md`, `docs/CHANGELOG.md` and every handoff note. Those citations would
  have to be rewritten or dropped, and a dropped citation is a measurement whose evidence is gone.
- There is no third option that keeps both. A rewrite that preserved hashes would not be a rewrite.

**The recommendation, stated as one and not as a decision:** keep history. The cost is a fixed
75 MB against a record that this project treats as its primary evidence, and points 1 and 2 already
stop it growing.

### 3. Implementation

**Nothing, until the owner answers.** If the answer is "keep", this point closes with that recorded
in `docs/ai/STATE.md` under decisions taken, and an ADR is **not** written — declining to rewrite
history is not an architectural decision.

If the answer is "rewrite", it becomes its own plan, and its first point will be the citation
migration rather than the git command: every hash cited in `docs/`, found by one grep, mapped to
its rewritten equivalent before anything is pushed. That plan will also say who re-clones and when,
because a force-pushed history that someone else already has is how work is lost.

### 4. Tests

None, in either branch. A rewrite is verified by comparing the tree at `HEAD` before and after
(`git diff` between the old and new tips must be empty) and by the full suite passing, not by a
test that asserts a repository is small.

### 5. Documentation

- `docs/ai/STATE.md`, section *"Open decisions needing an ADR"* or *"Open, not blocking"* depending
  on the answer — this point does not choose which, because that depends on the answer.
- If the answer is "keep": one line in *"Decisions taken, and where each is recorded"*, with the
  75 MB and the reason, so nobody re-opens it in six months without the number.

**Answered, 2026-09-09: history stays.** The owner took the recommendation, and the reason is on
the record rather than in a chat: 75 MB once per clone is a smaller price than every commit hash in
`docs/05`, `docs/06`, `docs/07`, `STATE.md` and the CHANGELOG becoming a dangling reference. The
decision is written in `docs/ai/STATE.md` under *Decisions taken*, and **no ADR is written** —
declining to rewrite history is not an architectural decision, and §3 above said so before the
answer arrived.

**Closing.** Verified against `git count-objects -vH` (**`size-pack: 74.84 MiB`**), the five
largest blobs in `git rev-list --objects --all` (all build artefacts, 42 MB and 39 MB at the top),
and the hash citations in `docs/05`, `docs/06`, `docs/07` and `STATE.md`. **Nothing of the skeleton
fell**; the skeleton already said this half was the owner's. Points 1 and 2 were implementable
without the answer and did not wait for it. Open: nothing.
