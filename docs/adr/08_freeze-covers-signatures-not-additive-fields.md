# ADR-08 — The F1 freeze binds trait signatures; `#[non_exhaustive]` data types grow additively

**Status**: **Accepted** 2026-09-07 · **Raised by**: `Q-13`'s consequence — point 13 of `docs/05_challenge_ampliacion_f2.md` must add `seccomp_addfd` to `CapabilitySet`, four days after GATE F1 froze the L1 surface · **Amends**: `ADR-03` §"Make the interface freeze a milestone"

## Context

`ADR-03` freezes the L1 traits at GATE F1 so five tracks can code against contracts that cannot move, and it names the failure it fears: *"The freeze could be treated as advisory. If traits drift silently after F1, parallel tracks desynchronize invisibly."*

The first change to arrive after the freeze is not a trait. `Sensor::capabilities(&self) -> CapabilitySet` keeps its signature exactly; what must change is `CapabilitySet`, which gains a field because point 13 measured that `seccomp_unotify` and `SECCOMP_IOCTL_NOTIF_ADDFD` are two capabilities and the L2- boundary needs the second one. Reading `ADR-03` literally — "the L1 *traits*" — permits it. Reading it in spirit — "contracts that cannot move" — it is exactly the drift the ADR fears. The freeze cannot decide its own scope, so this ADR decides it once instead of re-arguing it per field.

## Decision

The freeze binds **what a caller writes and what an implementor must implement**:

- **Frozen, ADR-gated.** A trait's method set; any method's parameter types, return type and receiver; the meaning of a returned value. Removing or renaming a field of a type in a frozen signature. Changing a field's type, its unit, or what it asserts. Making an optional thing required.
- **Permitted without an ADR, additively.** A **new field on a `#[non_exhaustive]` struct** or a new variant on a `#[non_exhaustive]` enum, provided the type has `Default` or a `NONE`-style constant, the new field's zero value means *"not measured / not present"*, and every existing field keeps its exact meaning.

An additive change lands with three things in the same commit: the field's own doc comment naming what measures it, the `NONE`/`Default` value, and a test pinning what the absence means. Where the type feeds a derived decision — a tier, a verdict, a budget — the commit also updates that derivation and its test, because a field nobody reads is not a capability, it is a comment.

## Why

**`#[non_exhaustive]` is already the project's chosen mechanism for exactly this.** `CapabilitySet` carries it, alongside `Default` and `CapabilitySet::NONE`; so do `SensorConfig`, `SensorHealth`, `Outcome`, `RiskBand` and the `enforce`/`adjudicate` types. The attribute exists to make a type growable without breaking downstream construction: outside the defining crate a struct literal is refused and callers must write `..CapabilitySet::NONE`, so a new field cannot silently take a value nobody chose. Declaring the type growable and then forbidding growth would leave the annotation meaning nothing.

**It matches the rule the wire already lives by.** §3.6 makes `RawEvent` append-only: fields are never reordered, resized or repurposed, and a new one consumes reserved space. `F1.EV.03` pins every offset at compile time so a violation fails the build rather than a review. This ADR is that rule applied one layer up, with `#[non_exhaustive]` in the role the pinned offsets play: the compiler, not a convention, is what refuses the illegal change.

**The alternative fails in the direction the project cares about.** If adding a measured capability needs an ADR, the cheap path when a probe finds something is to *not* add the field and let the existing one carry two meanings. That is what produced this ADR: `seccomp_unotify` was already carrying "can trap" and "can deliver a decision safely", and the conflated field reported **L2- on a 5.4 kernel that cannot deliver one** — a tier that overstates what the machine enforces, which is the optimistic direction and the urgent one. A freeze that makes honesty expensive buys desynchronization protection by paying in false capability claims.

**What the parallel tracks actually depend on is unharmed.** A track compiling against `Sensor` calls `capabilities()` and reads the fields it knows. A new field it has never heard of changes no call site, no match arm and no trait impl; `MockSensor` and `NullEnforcer` keep working unchanged. The desynchronization `ADR-03` fears comes from a moved method or a changed meaning, and both stay ADR-gated here.

## Consequences

- `CapabilitySet` gains `seccomp_addfd` in the same commit that closes point 13, with `tier_of` reading it, a `degradations` line naming what its absence costs, and a test pinning that a kernel with the notifier but without `ADDFD` is **L1**.
- `verify-layering` still cannot see this class of change: it checks direction, not shape. The guard is `#[non_exhaustive]` plus review, and this ADR is what review cites.
- A field added under this rule and later found to mean something different is **not** covered: changing a meaning is a frozen change and needs its own ADR.
- `ADR-03`'s freeze sentence is read with this ADR from now on; the two are not in conflict, this one states the scope `ADR-03` left implicit.
