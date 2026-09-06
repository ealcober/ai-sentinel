# 04 — Final coherence seal

> **Document**: `04_final_coherence_seal.md` · **Date**: 2026-09-03 · **Scope**: the whole repository as of the commit that carries this file · **Method**: three independent read-only audits, one manual pass, one probe of the owner's host. Every finding is applied in the same commit unless §4 says otherwise.

This is the third and last review before implementation. `docs/02` reviewed correctness, `docs/03` reviewed executability; this pass asks one question of every document: **can a session with no human present start `F0` tomorrow and reach GATE F0 without inventing anything?**

## 1. What was checked

| Check | Result |
|---|---|
| Required root and `docs/` files present; every markdown link resolves; every `I-nn`, task ID, `§` reference, ADR number, `BN`/`RF`/`DT`/`T4` ID resolves | Clean after the patch |
| Every `cargo xtask` string in the plan has an Annex H row; every row names a task that exists | 71 rows, clean |
| Every gate command that a phase runs is owned by that phase or an earlier one | Clean after ten owner corrections (§2, `B-01`…`B-05`) |
| Read order identical in `CLAUDE.md` and `AGENTS.md`; write order identical; commit rule consistent | Clean after `S-01`, `S-02`, `C-28`…`C-30` |
| Phase durations sum to the stated totals; milestone weeks follow from the durations | 4.5 · 7.5 · 6.5 · 10.5 · 9.5 · 11.5, verified against the phase table |
| The GATE F0 lines, executed on this host: the `for f … test -f` loop, `grep -qi "read-only"`, the negated `serde_json` check | All exit 0 |
| `budgets.toml`, `layers.toml`, `Cargo.toml` parse | Clean |
| The developer host (the owner's WSL2, kernel `6.18.33.1-microsoft-standard-WSL2`) | **`/dev/kvm` present, VT-x on all 12 CPUs, user not in group `kvm`; no `qemu-system-x86_64`, `virtme-ng`, `clang`, `bpf-linker`, `bpftool`, `strace`, `cargo-deny`, `tpm2-tools`, no nightly toolchain** |

## 2. Findings

134 numbered findings were raised: 10 from the manual pass (`S`), 30 from the F0–F2 executability audit (`A`), 44 from the Parts IV–VIII audit (`B`), 50 from the cross-document audit (`C`). About twenty were raised twice; each is applied once. Every finding carries where it was, why it mattered, and what was done. The full per-finding tables follow.

### 2.1 Manual pass (`S`)

| ID | Where | Why it mattered | Applied |
|---|---|---|---|
| `S-01` | `docs/ai/AGENTS.md` §4 forbade "commit or push without being asked" while `CLAUDE.md` asks for one commit per task | A session obeying one file breaks the other; the safer reading (never commit) leaves tasks unrecorded | Row now forbids pushing only |
| `S-02` | `docs/ai/AGENTS.md` "On finish" listed the changelog fifth; `CLAUDE.md` lists it second | Two write orders for one protocol | Aligned to `CLAUDE.md` |
| `S-03` | `docs/ai/invariants.md` said "every CI runner", "CI-enforced", "fails CI" | Contradicts `I-27`: there is no CI; every gate is local | Three wordings changed to the local gate |
| `S-04` | `ADR-06` and `ADR-07` dated 2026-08-17; `git log` shows both written 2026-09-03 | A decision date that is wrong by two weeks misleads anyone reading history | Dates corrected from git |
| `S-05` | The owner's decision "a grant is not a declassification" existed only in `docs/02` | A decision that lives only in a review is not in the plan an implementer reads | One bullet in §2.14, the taint model |
| `S-06` | `STATE.md` titled a table "ADRs owed" and then said "no ADR is owed" | Direct self-contradiction on the first file a session trusts | Table retitled; every decision now names the plan task or section that records it |
| `S-07` | `F0.VER.01`…`F0.VER.18` had no ID-to-claim mapping; the sixteen non-blocking rows were prose | `verify-backlog` cannot check rows that have no identity; a session cannot know which claim is `F0.VER.07` | Numbering rule stated: `F0.VER.nn` = `R1-nn` of `docs/02` |
| `S-08` | `docs/reports/f0-verification.md` had no shape and no `NN_` prefix | Rule 4; and a checker needs a defined column to read | `docs/reports/01_f0-verification.md`, one row per ID, `Outcome` ∈ {HOLDS, FAILS, WITHDRAWN} |
| `S-09` | **No host prerequisites anywhere.** Measured on the owner's WSL2 host on 2026-09-03: `/dev/kvm` present, VT-x on 12 CPUs, user **not in group `kvm`**; no `qemu`, `virtme-ng`, `clang`, `bpf-linker`, nightly | `F0.VM.01`, `F0.VM.02` and `build-ebpf` stall on the first session with no plan text to point at | `F0.REPO.06` + `cargo xtask doctor` (Annex H, GATE F0); `F0.VER.21` records the KVM outcome with both predictions |
| `S-10` | Plan header, `STATE.md` size and counts stale (1.0.0 / 2026-08-17; ~3,700 lines; 68 commands) | Numbers a reader would check and find wrong | 1.1.0 / 2026-09-03; ~3,850; 69 |

### 2.2 Executability of F0–F2 (`A`)

| ID | Where | Why it mattered | Applied |
|---|---|---|---|
| `A-01` | GATE F0 `test -f` with four operands | `bash: test: too many arguments`, exit 2 — the gate fails with every file present | `for … do test -f … done` |
| `A-02` | GATE F0 `grep -q "read-only"` | Exit 1: the only occurrence is `Read-only` | `grep -qi` |
| `A-03` | GATE F1 `… \| grep -q serde_json && exit 1` | Line status is 1 precisely when `agentd` is clean | `! cargo tree … \| grep -q serde_json` |
| `A-04` | `docs/reports/f0-verification.md` | `verify-docs` rejects an un-numbered file the backlog tells the session to create | `docs/reports/01_f0-verification.md` |
| `A-05` | `STATE.md` headings vs §7.3 | `verify-docs` requires `## Open decisions needing an ADR`; STATE had a different name | Heading restored; extra headings declared permitted |
| `A-06` | Three-way read-order check | Part 0 rule 5 holds no list; a literal check fails | Two-way check; Part 0 points at `CLAUDE.md` |
| `A-07` | `F0.GATE.07` "agree on every value" | `budgets.toml` carries keys with no §2.22 row; two obvious rules give opposite results | Rule stated: table is the human subset; rows added for the machine-only keys |
| `A-08` | `F0.ASSET.02` recorded with `aisme run` in F0 | `aisme run` is `F2.WS.08`; the trace format is `F1.SIM.02` | Schema in F0; recording after `F2.WS.08`, before GATE F2 |
| `A-09` | `[BLOCKING]` rows "ahead of `F0.REPO.01`" | Their commands need `F0.VM.02`; only the WSL2 half is measurable in week 1 | Stated: WSL2 by hand in week 1, VMs as soon as they boot; nothing loads BPF on the host |
| `A-10` | Annex H owners for ten commands | A gate ran a command that exits 3 naming a task in a later phase | Owners moved to the phase whose gate first runs them |
| `A-11` | `F1.PA.07` duplicates `F0.GATE.06` | A session at F1 finds nothing to do | Re-run on real crates, with a planted violation |
| `A-12` | `F0.GATE.03/05/07` have no command | Annex H forbids adding one without a row | Bound inside `verify-layering`, `verify-budgets --drift`, `cargo deny` |
| `A-13` | "lists all 67" | Annex H has 71 rows | 71 |
| `A-14` | Sixteen `F0.VER` rows with no ID | See `S-07`; `F0.VER.15` was withdrawn | Numbering rule; `DEPRECATED` |
| `A-15` | `F0.VER.12` needs a TPM, an iPhone and an Android device | No "cannot measure" branch; withdrawing H-17 for lack of a phone is wrong | `unverified` per platform, exit 2 |
| `A-16` | `F0.VER.04` reads `/sys/kernel/security/lsm` | securityfs is not mounted on stock WSL2 — an absence read as "no LSM" | Mount first; fall back to `/proc/config.gz` |
| `A-17` | No host prerequisites | See `S-09` | `F0.REPO.06`, `doctor` |
| `A-18` | Kernel matrix differs between `F0.VM.02` and §4.2 | A `vm` built from §4.2 omits the ≥ 6.15 kernel | Lists aligned |
| `A-19` | GATE F1 tests two crates | F1 work lands in five | `cargo test --workspace` |
| `A-20` | `F1.IPC.01` JSON-RPC in `agentd` under `I-21` | A session pulls `serde_json` and fails the gate, or moves the server without authority | Constraint stated; codec is `Q-12`, decided at the task |
| `A-21` | `F1.EV.01`'s check in no gate | `bpfel-unknown-none` never built at the freeze | `build-ebpf` in GATE F1 |
| `A-22` | F2 hooks `sys_enter_openat2` | glibc's `open()` issues `openat` (syscall 257, verified by disassembly); the skeleton would see zero events | `openat`; same fix in `F3.OB.03` and the §2.21 diagram |
| `A-23` | `F2.WS.11` needs `sys_exit`, forbidden by the scope table | Contradiction inside F2 | Exit side admitted for `F2.WS.11` only |
| `A-24` | "One hardcoded rule" cannot yield allow, deny and escalate | The gate needs three verdicts | One hardcoded policy with three rules |
| `A-25` | GATE F2 escalation needs a human at a TTY inside a VM | Unattended sessions cannot run the line | `AISME_TERMINAL_ANSWER`, recorded in the WAL |
| `A-26` | §3.7.1 "every Exit artefact appears in an Entry" | False on the table as written | Phase-level check is the gate; artefact-level is a review item |
| `A-27` | F8a and F10 Entries cite F1 deliverables F1 does not produce | Dead references | `F1.IPC.01` + stub + Annex I; `F1.PL.03` |
| `A-28` | `verify-budgets # passes on stubs` | Absent artefacts report "skipped", never "pass" | Comment states the exit contract |
| `A-29` | Memory seed table lacks the `type` the frontmatter requires | Eleven files would be written without a required field | `Type` column filled |
| `A-30` | `wsl2-capabilities` seeded and measured | Two sources for one fact | Seed marked as replaced by `F0.WSL.01` |

### 2.3 Parts IV–VIII and annexes (`B`)

| ID | Where | Why it mattered | Applied |
|---|---|---|---|
| `B-01`…`B-05` | Annex H owners: `verify-budgets`, `bench-hotloop`, `bench-t0`, `test-policy-compiler`, `test-skeleton`, `test-taint`, `test-detect`, `test-correlation`, `test-merkle-tamper`, `sentinel verify-budgets`, `test-a11y` | Exit-3 messages naming the wrong task, or PENDING in the gate that needs the command | Owners corrected; the H.2 example updated |
| `B-06` | `weekly` level has no members; §4.4's 72 h soak has no task | M7 and R-06 rest on a protocol nobody runs | `F7.CB.07`, `bench-soak` |
| `B-07` | `test-battery` (24 h) at `pr` (≤ 60 min) | Cannot fit | `weekly` |
| `B-08` | `win *` rows at `pr` | Four permanent `PENDING WIN` lines for a `[POST]` deliverable | `—` |
| `B-09` | Levels not cumulative; `test-kernels` at `pr` while `commit` runs it; 8 h fuzzing has no command | §4.12 cannot be expressed | Cumulative levels stated; `commit`; `test-fuzz` |
| `B-10` | `T4.5.06`, the release blocker, in no gate | The most important test in the plan never runs | `test-tls --integrity` in GATE F4 |
| `B-11` | No GATE F8a | The protocol freeze and F11's Entry hang on it | GATE F8a and F8b |
| `B-12` | F8a Entry | See `A-27` | — |
| `B-13` | §3.7.1 assertions | See `A-26` | — |
| `B-14` | `verify-docs` claimed seven checks its task never enumerates | A session implements the list and drops the rest silently | All enumerated in `F0.GATE.08` |
| `B-15` | "sixteen classes `RF-01`…`RF-16`" | Annex C has twenty-four | Twenty-four |
| `B-16` | Benign-twin counts contradict each other; `RF-17`, `RF-22` have none | `test-detect --benign-twins` cannot cover them | `BN-17`, `BN-18`; claims narrowed to detector-bearing classes |
| `B-17` | `F0.VER.05/09/14/17` referenced, never bound | See `S-07` | — |
| `B-18` | GATE F4 fixture names not in §4.5.1 | `test-*` exits 2 on an absent fixture | `fx-*` names |
| `B-19` | Corpus `annex-c` used by two gates, defined by none | A gate input with no manifest | Defined as the unfiltered view |
| `B-20` | §4.2 kernel list | See `A-18` | — |
| `B-21` | Four `budgets.toml` keys with no §2.22 row | See `A-07` | Rows added |
| `B-22` | Pass/fail at the `hard` boundary defined three ways | `0/0` entries could never pass | `>` / `<` hard, equality passes |
| `B-23` | Gates cite `target` where `hard` is the blocker | Which number fails is undefined | Gates cite `hard` (target in parentheses) |
| `B-24` | GATE F6 precision has no key | `verify-budgets` refuses a metric with no key | `compressor_precision` |
| `B-25` | F5 budget line without a tier | "A figure without its tier is not a figure" | `--tier l3` and `--tier l2` |
| `B-26` | Five gate numbers no gate reads | Verifier 60 %, mimalloc 1.4, recall 0.80, attribution 99 %, 200 series | `T4.4.18` for the series cap; the rest stay reported, not gated (§4) |
| `B-27` | F9 start stated two ways | One reading makes mobile the critical path (12.5 wks) | GATE F1, everywhere |
| `B-28` | Milestone weeks | 7 / 8 / 10 / 10 do not follow from the durations | 7.5 / 6.5 / 10.5 / 9.5 |
| `B-29` | "3 tracks" | The table has five | Five |
| `B-30` | "six items" in the DoD | `AGENTS.md` has eight | Eight |
| `B-31` | R-15 claims an `L2-` CPU gate that no gate runs | A mitigation that does not exist | Line added to GATE F3 |
| `B-32` | Debian 12 "L2" while R-15 says Landlock may be absent there | Unverified tier | "L2 or L2- per `F0.VER.04`" |
| `B-33` | Part VI tree "cannot drift" and has | Files present in the repo missing from the tree | Added |
| `B-34` | Six detectors with no implementing task | `test-detect --corpus annex-g` cannot run over the catalogue | `F5.DT.09`…`F5.DT.13`; `DT-09`/`DT-15` scenarios authored at `F5.DT.08` |
| `B-35`…`B-37` | Annex I: undeclared authorization classes; `hw_pubkey` required for a device that may have none; no error shape for an unsigned remote `allow` | Tests T4.10.05/06/07/13 have no protocol behaviour to assert | Remote-peer class; `hw_pubkey?`; two error rows |
| `B-38` | `F8.API.01` lists six of twelve methods | Half the protocol unowned | "the twelve methods of Annex I.1" |
| `B-39`…`B-41` | Annex B grammar lacks `assert`, `degrade_open`; `tier` used and reserved; `scope` is not a key; requirement IDs collide with section numbers | The compiler task cites constructs the grammar cannot parse | Grammar extended; `tier` line removed; `scope_rel`; `PL-01`…`PL-08` |
| `B-42` | `F3.RB.01` forbids the only transport 5.4 has | Kernel 5.4 has no event path, or the "never" is false | Perf buffer as the L1 fallback below 5.8 |
| `B-43` | Part V says each DEP table names its phase; none does | Unowned deployment work | Owning phase per block |
| `B-44` | Compressed-context format "frozen" but not in the freeze list | No gate owns that freeze | Eighth row, GATE F6 |

### 2.4 Cross-document contradictions (`C`)

| ID | Where | Why it mattered | Applied |
|---|---|---|---|
| `C-01` | H-19 row: mobile enforcement "impossible" | `ADR-05` ships it | Row restated |
| `C-02` | Control plane and relay "F9" | F9 is the SDK since `ADR-03` | F11 |
| `C-03` | Index vs headings for §2.20 and §4.12 | `F0.GATE.08` asserts they match | Headings aligned to the index |
| `C-04` | "three service tiers" | The table defines four | Four; `F1.PA.05` gains `L2-` |
| `C-05` | Implementations: 15, 20, 22 | The table is 22 | Twenty-two, twenty-one `[MVP]` |
| `C-06`, `C-07` | Tracks: 3, 4, 5; critical path 11 vs 11.5 | The table has five tracks and sums to 11.5 | Five; 11.5, incl. `ADR-03` |
| `C-08` | F9 start | See `B-27` | — |
| `C-09`, `C-10` | `verify-budgets` owner; count | See `A-10`, `A-13` | — |
| `C-11` | Windows driver called "phase F3", Linux engine "F2" | Pre-`ADR-03` numbering | Annex F; F3 |
| `C-12`, `C-13` | RF and BN counts | See `B-15`, `B-16` | — |
| `C-14` | "exactly two places" | See `B-21` | — |
| `C-15` | T2 hard timeout 10 s vs per-channel 20 s | Two definitions | Per channel, §2.20.5 |
| `C-16` | `Verdict` names the policy verdict, a timeout, and a five-state event field | Three meanings, one name; `ADR-07` requires a total order of four | Event field is `Outcome`; timeout yields the channel default |
| `C-17` | Annex B sketch | See `B-39`…`B-41` | — |
| `C-18` | `FILES_OUTSIDE_WORKSPACE` "Ask" vs Landlock deny at L2 | The permission model and the plan disagree on what a write outside scope does at the tier most users run | Plan wins (§7.6): Ask for reads; writes denied in-kernel at L2 with the notice; a grant binds later processes because Landlock cannot widen a running domain — stated in `F7.PS.02`, the model and `RF-06` |
| `C-19` | Flow corpus "captured from real devices" | §4.14.1 makes capture `[CUT]` | Generated, tier 1 |
| `C-20` | §7 numbering skips 7.8; "four document types" lists ten | Broken references | 7.8; "the document types" |
| `C-21` | DoD counts | See `B-30` | — |
| `C-22`, `C-23`, `C-24` | Entries; tree drift; research "in the project root" | Dead references | Fixed |
| `C-25` | Fuzzing 24 h vs 8 h | Two durations | 8 h nightly, 24 h pre-release |
| `C-26` | "Ed25519 signing" in two diagrams | Contradicts H-17 | P-256 (hw) / Ed25519 (sw) |
| `C-27` | Scope statement "in `invariants.md`" | It is not there | README; `I-16` |
| `C-28`…`C-30` | Read order, write order, commit rule | See `S-01`, `S-02`, `A-06` | — |
| `C-31` | "Every commit carries `Signed-off-by`" | None of 48 does | "Every contributed commit"; the owner is the sole copyright holder until the first external merge |
| `C-32` | `.gitignore` says `Cargo.lock` is committed | It does not exist yet | "from `F0.REPO.01` onward" |
| `C-33` | "CI runner", "Graviton CI", "CI runs with" | Contradicts `I-27` | Local wording everywhere |
| `C-34` | STATE date, size, ADR dates | Wrong by two weeks or 150 lines | From git and `wc` |
| `C-35`, `C-36`, `C-37`, `C-38` | STATE: ADRs owed vs none; "when written"; eighteen vs twenty rows; no nightly/weekly fields | Self-contradictions in the first file a session trusts | Section rewritten; fields added to STATE and §7.3 |
| `C-39`, `C-40` | `ADR-02` says artefacts removed; defines L2 as seccomp-only | The tree and H-16 say otherwise | Editor's note extended |
| `C-41`…`C-44` | `ADR-01`/`03` say ADR-04/05 are to be written; `ADR-04` cites a decision `ADR-02` does not contain; `ADR-06` says `cargo-deny` is configured; `CONTRIBUTING` says all nineteen findings reject a design | Stale or false | Fixed |
| `C-45` | `CLAUDE.md` diagram: all `cfg(target_os)` in L2; taint in `aisme-correlate` | Contradicts the composition-root row and `F1.ON.04` | Diagram corrected; taint in `aisme-core` |
| `C-46`, `C-47` | `I-23` scope; `budgets.toml` pointer to Annex F | Wrong citations | Fixed |
| `C-48`, `C-49` | Permission model: SDK "F11"; Windows row unmarked; README "the same" incl. BPF-LSM for WSL2 | WSL2 is L2 by default | `[POST]` row plus a WSL2 row; README states the tier |
| `C-50` | Ten history clauses ("now lives", "were missing", "the earlier text") | Rule 5 | Present tense |

## 3. Decisions taken in this pass, stated as defaults

- **`F0.VER.21` is not `[BLOCKING]`.** Whether KVM is usable changes how fast the matrix runs, not what any plan row says; TCG is the fallback and `I-12` is unchanged.
- **`F0.REPO.06` never installs anything.** `doctor` reports and exits non-zero; installing packages on the owner's machine is the owner's action.
- **`BN-17`/`BN-18` exist** rather than declaring `RF-17`/`RF-22` "their own negatives" (the alternative one audit proposed). Every detector-bearing class now has a twin, which is what `F5.DT.08` and `I-15` assume.
- **`F7.CB.07` owns the 72 h certification harness.** F7 is the last core phase before M7.
- **`Q-12`** (the non-`serde_json` JSON-RPC codec for `F1.IPC.01`) is decided at that task. It is a choice under `I-21`, not a change to it.
- **Five gate numbers stay reported, not gated** (`B-26`): verifier 60 %, mimalloc ratio 1.4, unknown-endpoint recall 0.80, attribution 99 %. Adding keys without a measurement protocol would be a budget nobody can certify.
- **Milestone weeks are non-monotonic by number** (M4 at 6.5, M3 at 7.5). They follow from parallel tracks and are correct; renumbering milestones would break `I-23`.

## 4. Not applied, with the reason

1. **The §8.2 ASCII Gantt** (plan around line 3055) still draws F9 starting after F2. The arithmetic and the prose say GATE F1. Redrawing a fixed-width diagram is a rewrite, not an edit; it is a review item for whoever next touches §8.2.
2. **`DT-09` and `DT-15` scenario cells in Annex G** stay `—`. Their scenarios are authored with their detectors at `F5.DT.08`, which now says so. Inventing an `RF-` number here would be a claim without a scenario file.
3. **Twins for `DT-02`, `DT-07`, `DT-08`, `DT-10`** are not named in Annex G. `F5.DT.08` owns them; the BN table gains rows when they exist.
4. **The `2026-08-17` dates** on `ADR-01`…`ADR-05`, the owner's decisions and the `[0.1.0]` entry are kept. Git shows every commit on 2026-09-03; the harness's memory timestamps show working sessions on 2026-08-17. The dates record when the decisions were taken, which git cannot confirm and cannot refute. `ADR-06` and `ADR-07`, written on 2026-09-03, now say so.

## 5. Unverified register

Claims this pass relied on but could not show with a command. Each is either an `F0.VER` row already, or is listed here so nobody reads it as verified.

| Claim | Status |
|---|---|
| ~~`virtme-ng` reports whether KVM acceleration is in use~~ | **Moot, 2026-09-06**: the matrix does not use `virtme-ng` — distribution cloud images boot under plain `qemu`, and `vm probe` states KVM or TCG itself from whether `/dev/kvm` opens read-write (`F0.VM.01`) |
| ~~Nested virtualization is enabled on the owner's Windows host~~ | **Verified 2026-09-06**: seven guests booted with `-enable-kvm -cpu host` inside WSL2 (`F0.VM.02`), which cannot happen without it |
| ~~Landlock is *active*, not merely configured, on this WSL2 kernel~~ | **Verified 2026-09-05 by `F0.WSL.01`**: ABI 7, and a real `restrict_self` returned `EACCES` for a write outside the allowed path. The lesson is that the config flag was the weaker evidence — `CONFIG_SECURITY_LANDLOCK=y` says the code is compiled, not that the LSM is enforcing; only the syscall says that |
| glibc issues `openat` for `open()` on the matrix VM images (musl not checked) | Verified on this host's glibc by disassembly; holds for glibc ≥ 2.26 |
| ~~Debian 12's stock LSM list includes `landlock`~~ | **Verified 2026-09-06 by `F0.VM.02`**, and it includes more than that: the active list is `lockdown,capability,landlock,yama,apparmor,tomoyo,bpf` — Landlock ABI 2 **and** BPF-LSM active, so Debian 12 is tier L3 out of the box. The seal's "L2 or L2-" hedge for that row was too pessimistic by two tiers |
| `systemd-binfmt.service` in an imported WSL2 distribution flushes the kernel-wide `binfmt_misc` table, removing this distribution's `WSLInterop` entry | **Attributed, 2026-09-06** (`F0.WSL.02`): the entry vanished after `aisme-wsl2-ubuntu-24.04` first booted with systemd, and that unit flushes the table on start. `vm up wsl2-*` masks the unit in the guest; the next import after the owner re-registers interop measures whether the entry survives |
| A WSL2 distribution reaches cgroup v1 through a `.wslconfig` `kernelCommandLine` setting rather than through what its init mounts | Unmeasured (`F0.WSL.02`): this host's `/proc/cmdline` carries no cgroup parameter and mounts v2 only, so the v1 variant's mechanism is still to be found before it can be a row |
| `docs/02` §R1 numbers are stable | The register is append-only by the report's own rule; `F0.VER.nn` depends on it |
| ~~The exact exit code of `verify-budgets` on stubs~~ | **Verified 2026-09-05 by `F0.REPO.03`**: exit 0, with all 42 metrics reporting `skipped: no artefact`. The GATE F0 comment was right |

## 6. Verdict

The plan is integral: every reference resolves, every gate command has an owner in or before the phase that runs it, every phase has an Entry, an Exit and a gate block whose lines execute. It is realisable: the first session has a host-prerequisites task, a `doctor` command, and a stated order in `STATE.md`. It is testable: every number a gate reads has a `budgets.toml` key with a direction and a boundary rule, every detector has a task, every corpus a manifest.

What this seal does **not** guarantee is the outcome of the twenty measurements in §F0.4. Four of them decide plan rows by design. That is not a gap; it is the plan refusing to claim what it has not measured. The first week of F0 is where those answers arrive.
