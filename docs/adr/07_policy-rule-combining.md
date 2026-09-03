# ADR-07 — Rule combining is strictest-verdict-wins, and exceptions narrow a rule rather than override one

**Status**: **Accepted** 2026-08-17 · **Raised by**: project owner as open question `Q-11` · **Formalizes**: Annex B §B.10–B.13

## Context

AISME-PL rules match on path prefixes, globs, exec classes, destination CIDRs and taint bitmasks. Several rules can match one event with overlapping — not identical — match sets, so the language needs a rule-combining algorithm. Two candidates were considered:

- **(A) strictest-verdict-wins** — evaluate every matching rule, take the maximum on `allow < warn < escalate < deny`. Order-independent.
- **(B) most-specific-wins** — longest matching prefix, routing-table style.

(A) was implemented as the safe default and the question was left open pending research. Three independent investigations were run against primary sources: OASIS XACML 3.0, the Cedar OOPSLA 2024 paper and its Lean proofs, kernel source and documentation for seccomp, LSM, cgroup BPF, Landlock, SELinux and AppArmor, AWS and Google Cloud IAM, Kubernetes NetworkPolicy and KEP-2091, Istio, nftables, OPA, Zanzibar and OpenFGA, plus the firewall-anomaly and policy-algebra literature.

## Decision

**Keep (A). Reject (B).** Exceptions are expressed by narrowing a rule's own match set (`except`, §B.11), never by precedence. Guardrails are compile-time assertions (§B.12), never runtime precedence. `tier` is reserved for authority and may never be derived from specificity (§B.13). The verdict order is normatively a **total order**, because §B.9's per-backend degradation proof depends on it. Every verdict carries `decided_by`.

## Why

**Every system that composes rules from independent authors chose deny-overrides.** XACML's overrides algorithms are order-independent by construction, and the spec says so: *"The children may be processed in any order."* Its `ordered-` variants exist only to make **obligation collection** deterministic, not the decision. AWS IAM: *"an explicit deny overrides any allows… the order in which the policies are evaluated is not important."* Google Cloud IAM checks deny policies first, regardless of roles. Kubernetes NetworkPolicy: *"policies do not conflict; they are additive… order of evaluation does not affect the policy result."* Cedar proves "forbid trumps permit" and "default deny" in Lean, and states that *"decisions are indifferent to the order that policies are considered."* Where precedence exists across units, it encodes **who wrote the rule** — Kubernetes' Admin/NetworkPolicy/Baseline tiers, AppArmor 4.1's author-declared `priority` — **never how specific it is.** No surveyed system arbitrates cross-authority conflict by computed specificity.

**The platform AISME builds on already does this, at every layer.** `seccomp(2)` orders its actions `ALLOW < LOG < TRACE < USER_NOTIF < ERRNO < KILL` — *allow < warn < escalate < deny*, the same lattice this language uses — and takes the highest-precedence action across all filters, with the join implemented as an integer comparison. `bpf_prog_run_array_cg` runs every program and never lets a recorded deny be overwritten. LSM chains short-circuit on denial and cannot turn a deny back into an allow. Landlock intersects across layers and *"only adding more restrictions is allowed."* AppArmor's DFA merges permissions with bitwise OR and then applies `allow &= ~deny`. **Three of AISME's five backends implement (A) in kernel C whether the language chooses it or not.**

**For this language, (B) is not riskier — it is undefined.** Specificity is well defined on one axis. AISME's match space is not one axis: a glob against a prefix has no principled ordering, and a taint-and-destination rule is incomparable to every path rule. In more than one dimension "more specific" is set inclusion, a partial order; overlapping-but-incomparable pairs are the normal case, and the only remaining tiebreaker is rule order — which is first-match-wins with its documented shadowing, redundancy and correlation anomalies, where deleting a rule changes verdicts nobody touched.

**Landlock makes it structural, not stylistic.** Under (A) the permitted set is antitone in the rule set: adding a rule can only shrink it, which is exactly Landlock's semantics. Under (B) a new, more specific, more permissive rule *enlarges* the permitted set, and Landlock cannot widen — ever. **Under (B) there would exist policies with no sound Landlock encoding**, and detecting them would require computing the effective verdict over the whole match space instead of checking one rule at a time.

**Order-independence buys three things the implementation uses.** Sound early exit (evaluation may stop at `deny`; a partial evaluation under (B) bounds nothing). Sound indexing — the LPM trie *is* a slice, and slicing is sound only because the operator is associative, commutative and idempotent; seccomp precomputes a per-syscall bitmap for the same reason, and Cedar measures 10–18× from slicing. And mergeability: the union of two policy files is the pointwise maximum, so a shipped baseline, an organisation's policy and a local policy compose with no conflict.

Analysis gets easier too. Ramli et al. give unreachability as a per-rule `∀Q` predicate for the overrides algorithms and as an index-quantified **pairwise** predicate for first-applicable, noting *"we need to add extra rules in the program transformations"*. Margrave reports that DNF *"does not scale beyond all but the simplest policies"* because *"the expression must encode the order of evaluation."*

## Consequences

**The cost is real and it is the exception case.** No rule can lower another's verdict, so "deny `/etc` except `/etc/hosts`" needs a mechanism. `except` is that mechanism, and it is what Cedar (`unless` on a `forbid`), AWS IAM (`NotAction`/`NotResource` on a `Deny`) and Google Cloud IAM (`exceptionPrincipals` as a field on the deny rule) all chose: **narrow the restrictive rule's own predicate, leave the combining algorithm alone.** Specificity then lives inside one rule, on one axis, written by one author, where it is well defined.

**The usability objection is real and mitigated.** A 54-participant study (Reeder et al., CMU-CyLab-09-006) measured accuracy gains up to 78 % for specificity-precedence over deny-precedence. Its preconditions do not hold here — a strict resource hierarchy and non-nesting groups, i.e. a single-axis match space — and it concedes that specificity *"cannot resolve the conflict"* for peer groups and for two-dimensional conflicts. Its winning method is a hybrid, not pure (B). The residual cost is attribution: a surprising verdict is hard to trace. **`decided_by` is the answer**, copied from seccomp's `*match`.

**Risks.** `except` could grow into an unbounded escape hatch; if it nests or references other rules, the language loses analyzability the way Rego does — OpenFGA's experience with `but not` is the cautionary case, where exclusion cost a CVE, a tenfold query increase and a removed reverse index. §B.11 forbids nesting and cross-rule reference for exactly this reason. Separately, strictest-wins makes over-blocking easier to introduce, which collides with `I-15`; `F1.PL.09`'s "which rules does this rule raise" diagnostic is the mitigation and it is only cheap because of (A).

**What would falsify this.** A real policy that cannot be written without cross-rule precedence, where restructuring into one rule with `except` is genuinely impossible rather than inconvenient. AppArmor took fifteen years to accumulate enough such cases to justify `priority`. Track the count; if it arrives, §B.13 already reserves the keyword and states the shape the answer must take.

## Follow-up actions

- [x] Annex B §B.10 (order and combining), §B.11 (`except`), §B.12 (compile-time guardrails), §B.13 (reserved tiers).
- [x] §B.9 declares a monotone verdict map per backend; `f(max S) = max f(S)` makes the expressiveness check per-rule.
- [x] `F1.PL.09` diagnostics and `F1.PL.10` `decided_by`.
- [ ] `F1.PL.02` implements the `except` well-formedness rules and the shadowed-`allow` unreachability check.
- [ ] Count real cases that would need cross-rule precedence. If they accumulate, revisit §B.13 in a new ADR.

## Note on a claim not made

Order-independence is often said to be what enables Cedar's SMT analysis. The paper attributes that to its **type system and type-directed translation into decidable theories**, not to order-independence. The compositional-reasoning claim that *is* supported is from Cedar's reference documentation: forbid policies *"can be understood independently of any permit policies created now or in the future"*. That is the property this decision buys, and it is the one claimed here.
