// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
//! The event taxonomy: `EventKind`, its ranges, and the wire code it decodes from.
//!
//! Normative source: plan §F1.1.1. `EventKind` is `u16` and **append-only**:
//! ranges are reserved per category and never reordered, a new variant takes
//! the next free value inside its range, and a category that fills its range
//! gets a second range. The ranges are also the kernel's grouping primitive —
//! "is this an execution hazard?" is one comparison on the code, no map lookup.

/// A kind as it travels on the wire: the bare `u16`.
///
/// This is the field `RawEvent` carries, not [`EventKind`] itself. A Rust enum
/// read from memory the kernel wrote is undefined behaviour the moment the
/// value is one this binary does not know — exactly the version skew §3.6 wants
/// *detected*. So the wire holds a code, every bit pattern of which is valid,
/// and [`KindCode::decode`] is the honest "unknown kind — recorded, not
/// interpreted" path (`I-17`).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KindCode(pub u16);

impl KindCode {
    /// The category this code falls in, from its high nibble — known or not.
    ///
    /// A code inside a reserved range is classified even when its exact variant
    /// is unknown, which is what lets a consumer built against an older wire
    /// version file an unrecognised process event under `Process` rather than
    /// drop it.
    #[must_use]
    pub const fn range(self) -> Option<Range> {
        Range::of(self.0)
    }

    /// The variant this code names, or the code back when this binary does
    /// not know it.
    ///
    /// # Errors
    ///
    /// [`UnknownKind`] carries the code, so the caller can still record it.
    pub const fn decode(self) -> Result<EventKind, UnknownKind> {
        match EventKind::from_code(self.0) {
            Some(kind) => Ok(kind),
            None => Err(UnknownKind(self)),
        }
    }
}

impl From<EventKind> for KindCode {
    fn from(kind: EventKind) -> Self {
        Self(kind as u16)
    }
}

/// A wire code this binary has no variant for: a newer producer, or corruption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownKind(pub KindCode);

/// The reserved ranges, one per category, in wire order.
///
/// Each range owns one payload struct (plan §F1.1.1, second rule); the
/// mapping lives in [`crate::payload`] and `F1.EV.03` asserts it is total.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Range {
    /// `0x0000–0x0FFF` — lifecycle and self-observability.
    Meta,
    /// `0x1000–0x1FFF`.
    Process,
    /// `0x2000–0x2FFF`.
    File,
    /// `0x3000–0x3FFF`.
    Network,
    /// `0x4000–0x4FFF` — the never-promptable classes.
    Hazard,
    /// `0x5000–0x5FFF` — anti-analysis signals (`H-05`).
    Introspection,
    /// `0x6000–0x6FFF` — the intent plane (F4, F9).
    Semantic,
    /// `0x7000–0x7FFF` — enforcement and the permission model.
    Decision,
    /// `0x8000–0x8FFF` — Annex G.
    Detection,
    /// `0x9000–0x9FFF`.
    Forensic,
}

impl Range {
    /// Every range, in wire order. The table `F1.EV.03` iterates.
    pub const ALL: [Range; 10] = [
        Range::Meta,
        Range::Process,
        Range::File,
        Range::Network,
        Range::Hazard,
        Range::Introspection,
        Range::Semantic,
        Range::Decision,
        Range::Detection,
        Range::Forensic,
    ];

    /// The range a code belongs to, if its high nibble is a reserved one.
    #[must_use]
    pub const fn of(code: u16) -> Option<Range> {
        Some(match code >> 12 {
            0x0 => Range::Meta,
            0x1 => Range::Process,
            0x2 => Range::File,
            0x3 => Range::Network,
            0x4 => Range::Hazard,
            0x5 => Range::Introspection,
            0x6 => Range::Semantic,
            0x7 => Range::Decision,
            0x8 => Range::Detection,
            0x9 => Range::Forensic,
            _ => return None,
        })
    }

    /// The first code of the range. The range is `[first, first + 0x1000)`.
    #[must_use]
    pub const fn first(self) -> u16 {
        (self as u16) << 12
    }

    /// Whether a code lies inside this range — the one comparison the kernel
    /// makes, written out: `code >= first && code < first + 0x1000`.
    #[must_use]
    pub const fn contains(self, code: u16) -> bool {
        code >= self.first() && code < self.first() + 0x1000
    }
}

/// What happened, as a discriminated set this binary knows.
///
/// `#[non_exhaustive]`: a consumer built against an older wire version cannot
/// match exhaustively and silently miss a new kind — it carries a `_ =>` arm.
/// The values are normative (plan §F1.1.1) and never renumbered.
#[repr(u16)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventKind {
    // 0x0000–0x0FFF  META — lifecycle and self-observability
    /// A monitored session began.
    SessionStart = 0x0001,
    /// A monitored session ended.
    SessionEnd = 0x0002,
    /// The capability set changed (a sensor came or went).
    CapabilityChange = 0x0003,
    /// `I-17`: observation lapsed, recorded as a gap.
    CoverageGap = 0x0004,
    /// Ring overflow, carrying the count of what was lost.
    DropNotice = 0x0005,
    /// A new compiled policy generation became effective.
    PolicyGeneration = 0x0006,
    /// The engine entered the `DEGRADED` state.
    DegradedEnter = 0x0007,
    /// The engine left the `DEGRADED` state.
    DegradedLeave = 0x0008,

    // 0x1000–0x1FFF  PROCESS
    /// `fork`/`clone`.
    ProcFork = 0x1001,
    /// `execve`.
    ProcExec = 0x1002,
    /// Process exit.
    ProcExit = 0x1003,
    /// Credential change.
    ProcSetuid = 0x1004,
    /// The process moved between cgroups.
    ProcCgroupMove = 0x1005,

    // 0x2000–0x2FFF  FILE
    /// A file was opened.
    FileOpen = 0x2001,
    /// A file was written.
    FileWrite = 0x2002,
    /// A file was unlinked.
    FileUnlink = 0x2003,
    /// A file was renamed.
    FileRename = 0x2004,
    /// A file was truncated.
    FileTruncate = 0x2005,
    /// A file's mode changed.
    FileChmod = 0x2006,
    /// A hard link was made.
    FileLink = 0x2007,
    /// A filesystem was mounted.
    FileMount = 0x2008,

    // 0x3000–0x3FFF  NETWORK
    /// An outbound connection was attempted.
    SockConnect = 0x3001,
    /// An inbound connection was accepted.
    SockAccept = 0x3002,
    /// Data was sent.
    SockSend = 0x3003,
    /// A socket closed.
    SockClose = 0x3004,
    /// A DNS query was made.
    DnsQuery = 0x3005,
    /// A mobile tunnel flow opened (F10).
    FlowOpen = 0x3006,
    /// A mobile tunnel flow closed (F10).
    FlowClose = 0x3007,

    // 0x4000–0x4FFF  EXECUTION HAZARD — the never-promptable classes
    /// `memfd_create`: fileless execution staging.
    MemfdCreate = 0x4001,
    /// `execveat` on a descriptor.
    ExecveAt = 0x4002,
    /// A preload environment variable was set.
    PreloadEnv = 0x4003,

    // 0x5000–0x5FFF  INTROSPECTION — anti-analysis signals (H-05)
    /// `ptrace(PTRACE_ATTACH)`.
    PtraceAttach = 0x5001,
    /// `process_vm_readv`/`writev`.
    ProcessVmRw = 0x5002,
    /// `/proc/*/maps` read.
    MapsRead = 0x5003,
    /// The `bpf` syscall.
    BpfCall = 0x5004,
    /// `perf_event_open`.
    PerfEventOpen = 0x5005,
    /// A process observed AISME itself.
    SelfObservation = 0x5006,

    // 0x6000–0x6FFF  SEMANTIC — the intent plane (F4, F9)
    /// A prompt: the apex of causality.
    Prompt = 0x6001,
    /// The model's reasoning trace.
    ChainOfThought = 0x6002,
    /// A structured tool invocation.
    ToolCall = 0x6003,
    /// What a tool returned — the context plane.
    ToolResult = 0x6004,
    /// A tool manifest was loaded.
    ToolManifest = 0x6005,
    /// One inference turn.
    InferenceTurn = 0x6006,

    // 0x7000–0x7FFF  DECISION — enforcement and the permission model
    /// A verdict was issued.
    VerdictIssued = 0x7001,
    /// An escalation was raised.
    EscalationRaised = 0x7002,
    /// An escalation was resolved.
    EscalationResolved = 0x7003,
    /// A grant was created.
    GrantCreated = 0x7004,
    /// A grant expired.
    GrantExpired = 0x7005,
    /// A grant was revoked.
    GrantRevoked = 0x7006,
    /// A suppression rule matched (`I-26`: notification only).
    SuppressionHit = 0x7007,
    /// An attempt to widen a session's scope.
    ScopeWidenAttempt = 0x7008,

    // 0x8000–0x8FFF  DETECTION — Annex G
    /// A detector fired.
    FindingRaised = 0x8001,
    /// The session risk score changed.
    SessionRiskChanged = 0x8002,

    // 0x9000–0x9FFF  FORENSIC
    /// A Merkle block closed.
    MerkleBlockClosed = 0x9001,
    /// A root was anchored externally.
    RootAnchored = 0x9002,
}

impl EventKind {
    /// Every variant this binary knows, in wire order. The producer-coverage
    /// check of `F1.EV.03` iterates it; keep it in step with the enum.
    pub const ALL: [EventKind; 55] = [
        EventKind::SessionStart,
        EventKind::SessionEnd,
        EventKind::CapabilityChange,
        EventKind::CoverageGap,
        EventKind::DropNotice,
        EventKind::PolicyGeneration,
        EventKind::DegradedEnter,
        EventKind::DegradedLeave,
        EventKind::ProcFork,
        EventKind::ProcExec,
        EventKind::ProcExit,
        EventKind::ProcSetuid,
        EventKind::ProcCgroupMove,
        EventKind::FileOpen,
        EventKind::FileWrite,
        EventKind::FileUnlink,
        EventKind::FileRename,
        EventKind::FileTruncate,
        EventKind::FileChmod,
        EventKind::FileLink,
        EventKind::FileMount,
        EventKind::SockConnect,
        EventKind::SockAccept,
        EventKind::SockSend,
        EventKind::SockClose,
        EventKind::DnsQuery,
        EventKind::FlowOpen,
        EventKind::FlowClose,
        EventKind::MemfdCreate,
        EventKind::ExecveAt,
        EventKind::PreloadEnv,
        EventKind::PtraceAttach,
        EventKind::ProcessVmRw,
        EventKind::MapsRead,
        EventKind::BpfCall,
        EventKind::PerfEventOpen,
        EventKind::SelfObservation,
        EventKind::Prompt,
        EventKind::ChainOfThought,
        EventKind::ToolCall,
        EventKind::ToolResult,
        EventKind::ToolManifest,
        EventKind::InferenceTurn,
        EventKind::VerdictIssued,
        EventKind::EscalationRaised,
        EventKind::EscalationResolved,
        EventKind::GrantCreated,
        EventKind::GrantExpired,
        EventKind::GrantRevoked,
        EventKind::SuppressionHit,
        EventKind::ScopeWidenAttempt,
        EventKind::FindingRaised,
        EventKind::SessionRiskChanged,
        EventKind::MerkleBlockClosed,
        EventKind::RootAnchored,
    ];

    /// The wire code of this variant.
    #[must_use]
    pub const fn code(self) -> KindCode {
        KindCode(self as u16)
    }

    /// The range this variant lives in. Total by construction: every variant
    /// is declared inside a reserved range.
    #[must_use]
    pub const fn range(self) -> Range {
        match Range::of(self as u16) {
            Some(range) => range,
            // Unreachable while every variant sits in a reserved range; the
            // property test of `F1.EV.03` keeps that true as variants are added.
            None => Range::Meta,
        }
    }

    /// The variant for a code, if this binary knows it. A `match` rather than
    /// a transmute: the only sound way to turn kernel-written bytes into an
    /// enum is to enumerate the values that are valid.
    #[must_use]
    pub const fn from_code(code: u16) -> Option<EventKind> {
        Some(match code {
            0x0001 => EventKind::SessionStart,
            0x0002 => EventKind::SessionEnd,
            0x0003 => EventKind::CapabilityChange,
            0x0004 => EventKind::CoverageGap,
            0x0005 => EventKind::DropNotice,
            0x0006 => EventKind::PolicyGeneration,
            0x0007 => EventKind::DegradedEnter,
            0x0008 => EventKind::DegradedLeave,
            0x1001 => EventKind::ProcFork,
            0x1002 => EventKind::ProcExec,
            0x1003 => EventKind::ProcExit,
            0x1004 => EventKind::ProcSetuid,
            0x1005 => EventKind::ProcCgroupMove,
            0x2001 => EventKind::FileOpen,
            0x2002 => EventKind::FileWrite,
            0x2003 => EventKind::FileUnlink,
            0x2004 => EventKind::FileRename,
            0x2005 => EventKind::FileTruncate,
            0x2006 => EventKind::FileChmod,
            0x2007 => EventKind::FileLink,
            0x2008 => EventKind::FileMount,
            0x3001 => EventKind::SockConnect,
            0x3002 => EventKind::SockAccept,
            0x3003 => EventKind::SockSend,
            0x3004 => EventKind::SockClose,
            0x3005 => EventKind::DnsQuery,
            0x3006 => EventKind::FlowOpen,
            0x3007 => EventKind::FlowClose,
            0x4001 => EventKind::MemfdCreate,
            0x4002 => EventKind::ExecveAt,
            0x4003 => EventKind::PreloadEnv,
            0x5001 => EventKind::PtraceAttach,
            0x5002 => EventKind::ProcessVmRw,
            0x5003 => EventKind::MapsRead,
            0x5004 => EventKind::BpfCall,
            0x5005 => EventKind::PerfEventOpen,
            0x5006 => EventKind::SelfObservation,
            0x6001 => EventKind::Prompt,
            0x6002 => EventKind::ChainOfThought,
            0x6003 => EventKind::ToolCall,
            0x6004 => EventKind::ToolResult,
            0x6005 => EventKind::ToolManifest,
            0x6006 => EventKind::InferenceTurn,
            0x7001 => EventKind::VerdictIssued,
            0x7002 => EventKind::EscalationRaised,
            0x7003 => EventKind::EscalationResolved,
            0x7004 => EventKind::GrantCreated,
            0x7005 => EventKind::GrantExpired,
            0x7006 => EventKind::GrantRevoked,
            0x7007 => EventKind::SuppressionHit,
            0x7008 => EventKind::ScopeWidenAttempt,
            0x8001 => EventKind::FindingRaised,
            0x8002 => EventKind::SessionRiskChanged,
            0x9001 => EventKind::MerkleBlockClosed,
            0x9002 => EventKind::RootAnchored,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_round_trips_through_its_code() {
        for kind in EventKind::ALL {
            assert_eq!(kind.code().decode(), Ok(kind), "{kind:?}");
        }
    }

    #[test]
    fn every_variant_sits_in_the_range_its_value_names() {
        for kind in EventKind::ALL {
            let range = kind.range();
            assert!(range.contains(kind as u16), "{kind:?} outside {range:?}");
            assert_eq!(Range::of(kind as u16), Some(range));
        }
    }

    #[test]
    fn the_hazard_check_is_one_range_comparison() {
        // The kernel's form of the question, plan §F1.1.1, written as the
        // `contains` the range type offers so clippy and the kernel agree.
        let is_hazard = |code: u16| (0x4000..0x5000).contains(&code);
        for kind in EventKind::ALL {
            assert_eq!(is_hazard(kind as u16), kind.range() == Range::Hazard);
        }
    }

    #[test]
    fn an_unknown_code_is_reported_not_interpreted() {
        // Inside a reserved range: the category is still known.
        let newer = KindCode(0x1FFF);
        assert_eq!(newer.decode(), Err(UnknownKind(newer)));
        assert_eq!(newer.range(), Some(Range::Process));
        // Outside every reserved range: nothing is known about it.
        let garbage = KindCode(0xFFFF);
        assert_eq!(garbage.decode(), Err(UnknownKind(garbage)));
        assert_eq!(garbage.range(), None);
        // And zero, the value an unwritten event slot carries.
        assert_eq!(KindCode(0).decode(), Err(UnknownKind(KindCode(0))));
    }

    #[test]
    fn all_lists_every_variant_once() {
        let mut codes: [u16; 55] = EventKind::ALL.map(|k| k as u16);
        codes.sort_unstable();
        for pair in codes.windows(2) {
            assert!(pair[0] < pair[1], "duplicate code {:#06x}", pair[0]);
        }
    }

    #[test]
    fn ranges_are_contiguous_and_ordered() {
        for (i, range) in (0u16..).zip(Range::ALL) {
            assert_eq!(range as u16, i);
            assert_eq!(range.first(), i << 12);
        }
    }
}
