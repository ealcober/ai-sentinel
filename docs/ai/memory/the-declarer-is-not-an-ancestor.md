---
name: the-declarer-is-not-an-ancestor
description: A pre-tool hook is a sibling of the process its tool spawns, so subtree attribution finds nothing — and guessing the most recent declaration would corrupt the ground truth it feeds
type: domain
---

`aisme-agentsim`'s attribution walks an action's ancestry for a declaration made by an **ancestor**. That is exact for a process that declares and then forks, which is what `agentsim` does. **A pre-tool hook does not do that.** The agent spawns the hook, and the agent spawns the tool's subprocess: they are **siblings**.

Measured on 2026-09-15 in the real topology — `aisme run` → agent → {hook, tool} — with both planes finally reaching one WAL: **55 of 55 actions unattributed**.

**The two match clauses are not equal, and the difference is the whole design:**

| the declaration was made by | is it exact? | why |
|---|---|---|
| an **ancestor** of the action | **yes**, whatever else is running | its subtree contains the action and no other declarer's subtree does |
| a **child of an ancestor** (a hook) | only with **one** call in flight | every hook of a session shares the agent as its parent, so they all match at once |

That is why an end marker is needed at all: without one, every past declaration stays a candidate for ever and the count can never fall.

**Why marking beats guessing, and it is not a matter of taste.** A most-recent heuristic in a **ground truth** is worse than the same heuristic in a detector, because the error **correlates with what is being measured**: the correlator will also guess "the most recent declaration", so scoring it against a ground truth built that way manufactures agreement. The bias is toward optimism. Provenance benchmarks exclude ambiguous nodes from scoring for this reason, and Linux audit emits `auid=unset` rather than inventing a plausible user.

**The frequency is measured**: `docs/12` M3 found **14.4 %** of 11,182 model turns issuing parallel tool calls — about one turn in seven, with every summary total still coming out right.

**How to apply:** decide ambiguity **before** choosing a candidate, and only for the sibling clause. Count ambiguous separately from unexplained: they carry the same `0` on the wire because the format has one way to say *no ground truth*, but many ambiguous means heavy parallelism and many unexplained means a hook that was not firing — different problems, same symptom.

**The trap that caught me:** the first version consulted the in-flight count for *every* match, which marked the ancestor case ambiguous too. The module's own central test — `actions_are_attributed_by_ancestry_and_not_by_arrival_order` — failed, and it was right to. A rule that needs that test changed has grown beyond what was designed.

**Source:** `F0.ASSET.02` and `F2.WS.03`, measured 2026-09-15; `docs/research/03`, section 3

Related: [[two-planes-never-measured-together]], [[a-path-is-a-spelling]]
