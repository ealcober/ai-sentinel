// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
//! One payload struct per [`Range`], and the union that carries them.
//!
//! Plan §F1.1.1, second rule: `EventPayload`'s variant is determined by the
//! kind's range, one struct per range, each ≤ 256 B. The plan names the
//! structs and leaves their fields to this task; they are derived from the
//! critical attributes of Annex A.1 with three rules of their own:
//!
//! - **Integers only.** No `bool`, no enum, no pointer. Every bit pattern of
//!   every field is a valid value, which is what makes reading the union by
//!   range sound (see [`EventPayload::view`]) and what lets kernel-written
//!   bytes be looked at without a validation pass on the hot path.
//! - **Exactly 256 B each**, with a `reserved` tail. §3.6 says fields are never
//!   reordered, resized or repurposed; a new field consumes the tail, so the
//!   union's size and every existing offset stay put.
//! - **Strings are inline, bounded, and carry their length.** The kernel side
//!   copies at most the array's size and sets the truncation flag on the
//!   event; user space interns them to `StrId` at ingest (`F1.EV.04`).

use crate::kind::Range;

/// The size of every payload struct, and of the union.
pub const PAYLOAD_SIZE: usize = 256;

/// Lifecycle and self-observability (`Range::Meta`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetaPayload {
    /// The capability level after the change (`L3`…`L1`, `DEGRADED`), as the
    /// degradation state machine numbers it (`F1.PA.05`).
    pub capability_level: u8,
    /// Why: a reason code owned by the producer.
    pub reason: u8,
    /// Layout padding; always zero.
    pub pad0: [u8; 6],
    /// `DropNotice`: how many events the ring lost.
    pub dropped: u64,
    /// `PolicyGeneration`: the generation that became effective.
    pub policy_generation: u64,
    /// `CoverageGap`: when observation lapsed, boot-monotonic.
    pub gap_start_ns: u64,
    /// `CoverageGap`: when it resumed, boot-monotonic.
    pub gap_end_ns: u64,
    /// Append-only tail; new fields consume it.
    pub reserved: [u8; 216],
}

/// Process lifecycle (`Range::Process`). Annex A.1 `Process`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcPayload {
    /// The cgroup the process runs in — the session's scope handle.
    pub cgroup_id: u64,
    /// Hash of the argument vector; the vector itself is not carried.
    pub argv_hash: u64,
    /// `ProcExit`: the exit status.
    pub exit_code: i32,
    /// `ProcSetuid`: the new uid.
    pub new_uid: u32,
    /// `ProcSetuid`: the new gid.
    pub new_gid: u32,
    /// `ProcFork`: the child's pid.
    pub child_pid: u32,
    /// Bytes of `exe` that are meaningful.
    pub exe_len: u16,
    /// The kernel's `comm`, as `task_struct` bounds it.
    pub comm: [u8; 16],
    /// The executable path, bounded and possibly truncated.
    pub exe: [u8; 128],
    /// Append-only tail; new fields consume it.
    pub reserved: [u8; 78],
}

/// File access (`Range::File`). Annex A.1 `File`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilePayload {
    /// Inode number.
    pub inode: u64,
    /// Device the inode lives on.
    pub dev: u64,
    /// Size at the time of the event.
    pub size: u64,
    /// Open flags, or the operation's flags.
    pub flags: u32,
    /// Mode bits.
    pub mode: u32,
    /// The path class the policy assigns (`PERSISTENCE_CONFIG`, …), numbered by
    /// the compiled policy; zero when unclassified.
    pub path_class: u8,
    /// Layout padding; always zero.
    pub pad0: u8,
    /// Bytes of `path` that are meaningful.
    pub path_len: u16,
    /// The path, bounded and possibly truncated.
    pub path: [u8; 200],
    /// Append-only tail; new fields consume it.
    pub reserved: [u8; 20],
}

/// Network activity (`Range::Network`). Annex A.1 `Socket`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetPayload {
    /// Bytes moved by this event.
    pub bytes: u64,
    /// Remote address; IPv4 sits in the first four bytes.
    pub remote_addr: [u8; 16],
    /// Local address; IPv4 sits in the first four bytes.
    pub local_addr: [u8; 16],
    /// Remote port, host order.
    pub remote_port: u16,
    /// Local port, host order.
    pub local_port: u16,
    /// Address family (`AF_INET`, `AF_INET6`).
    pub family: u8,
    /// Transport protocol number; QUIC is UDP here and named by `name`.
    pub proto: u8,
    /// Connection state as the producer numbers it.
    pub state: u8,
    /// Bytes of `name` that are meaningful.
    pub name_len: u8,
    /// `DnsQuery`: the name asked for; TLS: the SNI.
    pub name: [u8; 128],
    /// Append-only tail; new fields consume it.
    pub reserved: [u8; 80],
}

/// Execution hazards (`Range::Hazard`) — the never-promptable classes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HazardPayload {
    /// The syscall's flags (`MFD_*`, `AT_*`).
    pub flags: u32,
    /// `ExecveAt`: the descriptor executed.
    pub fd: i32,
    /// Bytes of `name` that are meaningful.
    pub name_len: u16,
    /// Bytes of `target` that are meaningful.
    pub target_len: u16,
    /// Layout padding; always zero.
    pub pad0: [u8; 4],
    /// `MemfdCreate`: the memfd's name; `PreloadEnv`: the variable.
    pub name: [u8; 64],
    /// `PreloadEnv`: the value; `ExecveAt`: the resolved path.
    pub target: [u8; 128],
    /// Append-only tail; new fields consume it.
    pub reserved: [u8; 48],
}

/// Anti-analysis signals (`Range::Introspection`, `H-05`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntrospectPayload {
    /// The process looked at.
    pub target_pid: u32,
    /// Its thread group.
    pub target_tgid: u32,
    /// `ptrace` request, `bpf` command or `perf_event_open` type.
    pub request: u32,
    /// Bytes of `path` that are meaningful.
    pub path_len: u16,
    /// Layout padding; always zero.
    pub pad0: [u8; 2],
    /// `MapsRead`: the `/proc` path read.
    pub path: [u8; 128],
    /// Append-only tail; new fields consume it.
    pub reserved: [u8; 112],
}

/// The intent plane (`Range::Semantic`). Annex A.1 `Prompt`, `ChainOfThought`,
/// `ToolCall`, `ToolResult`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemanticPayload {
    /// The tool call this belongs to.
    pub toolcall_id: u64,
    /// The inference turn this belongs to.
    pub inference_id: u64,
    /// Hash of the content (prompt text, reasoning, result body).
    pub content_hash: [u8; 32],
    /// Hash of the declared intent (`ChainOfThought`).
    pub intent_hash: [u8; 32],
    /// Token count where the producer knows it.
    pub token_count: u32,
    /// `ToolResult`: where it came from — `File`, `Web`, `Mcp`, `Sdk` — as the
    /// producer numbers it.
    pub origin: u8,
    /// `ToolResult`: nonzero when the content carries instructions.
    pub instruction_bearing: u8,
    /// Bytes of `tool_name` that are meaningful.
    pub name_len: u16,
    /// `ToolCall`: the tool's name.
    pub tool_name: [u8; 64],
    /// Append-only tail; new fields consume it.
    pub reserved: [u8; 104],
}

/// Enforcement and the permission model (`Range::Decision`). Annex A.1
/// `Grant`, `SuppressionRule`, and the verdict fields.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecisionPayload {
    /// The escalation this decision answers or raises.
    pub escalation_id: u64,
    /// The grant created, expired or revoked.
    pub grant_id: u64,
    /// Hash of the scope the grant or rule applies to.
    pub scope_hash: u64,
    /// §B.10 `decided_by`: the rule that supplied the maximum.
    pub decided_by: u32,
    /// `I-26`: the suppression rule that silenced notification, or zero.
    pub suppressed_by: u32,
    /// Time to live, seconds.
    pub ttl_s: u32,
    /// The verdict, as [`crate::verdict::Verdict`] numbers it.
    pub verdict: u8,
    /// The permission group.
    pub group: u8,
    /// The adjudication channel that answered.
    pub channel: u8,
    /// Layout padding; always zero.
    pub pad0: u8,
    /// Append-only tail; new fields consume it.
    pub reserved: [u8; 216],
}

/// Detector output (`Range::Detection`, Annex G). Annex A.1 `Finding`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetectionPayload {
    /// Sequence numbers of the events that are the evidence.
    pub evidence: [u64; 8],
    /// `SessionRiskChanged`: the new score, in thousandths.
    pub risk_milli: u32,
    /// The detector (`DT-01`…), by number.
    pub dt: u8,
    /// Severity as the detector numbers it.
    pub severity: u8,
    /// How many entries of `evidence` are meaningful.
    pub evidence_len: u8,
    /// Layout padding; always zero.
    pub pad0: u8,
    /// `I-26`: the suppression rule that silenced notification, or zero.
    pub suppressed_by: u32,
    /// Layout padding; always zero.
    pub pad1: [u8; 4],
    /// Append-only tail; new fields consume it.
    pub reserved: [u8; 176],
}

/// Merkle chaining and anchoring (`Range::Forensic`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForensicPayload {
    /// The block that closed or was anchored.
    pub block_id: u64,
    /// Leaves in the block.
    pub leaf_count: u32,
    /// §2.18 `key_hw`: which signing backend, as the producer numbers it.
    pub key_hw: u8,
    /// Bytes of `anchor` that are meaningful.
    pub anchor_len: u8,
    /// Layout padding; always zero.
    pub pad0: [u8; 2],
    /// The block's Merkle root.
    pub root: [u8; 32],
    /// `RootAnchored`: the external anchor reference.
    pub anchor: [u8; 64],
    /// Append-only tail; new fields consume it.
    pub reserved: [u8; 144],
}

/// The payload slot of a `RawEvent`: one of the ten structs, chosen by the
/// kind's range, or the raw bytes.
///
/// A union whose discriminant lives in another field is the shape that
/// misreads under skew; the range→struct map being total (`F1.EV.03`) and the
/// structs being all-integer are what close it.
#[repr(C)]
#[derive(Clone, Copy)]
pub union EventPayload {
    /// `Range::Meta`.
    pub meta: MetaPayload,
    /// `Range::Process`.
    pub process: ProcPayload,
    /// `Range::File`.
    pub file: FilePayload,
    /// `Range::Network`.
    pub net: NetPayload,
    /// `Range::Hazard`.
    pub hazard: HazardPayload,
    /// `Range::Introspection`.
    pub introspect: IntrospectPayload,
    /// `Range::Semantic`.
    pub semantic: SemanticPayload,
    /// `Range::Decision`.
    pub decision: DecisionPayload,
    /// `Range::Detection`.
    pub detection: DetectionPayload,
    /// `Range::Forensic`.
    pub forensic: ForensicPayload,
    /// The bytes as they are.
    pub bytes: [u8; PAYLOAD_SIZE],
}

/// A payload seen through its range: the safe way to read the union.
#[derive(Clone, Copy, Debug)]
pub enum Payload<'a> {
    /// `Range::Meta`.
    Meta(&'a MetaPayload),
    /// `Range::Process`.
    Process(&'a ProcPayload),
    /// `Range::File`.
    File(&'a FilePayload),
    /// `Range::Network`.
    Network(&'a NetPayload),
    /// `Range::Hazard`.
    Hazard(&'a HazardPayload),
    /// `Range::Introspection`.
    Introspection(&'a IntrospectPayload),
    /// `Range::Semantic`.
    Semantic(&'a SemanticPayload),
    /// `Range::Decision`.
    Decision(&'a DecisionPayload),
    /// `Range::Detection`.
    Detection(&'a DetectionPayload),
    /// `Range::Forensic`.
    Forensic(&'a ForensicPayload),
}

impl EventPayload {
    /// All zeroes — a valid value of every member.
    pub const ZERO: EventPayload = EventPayload {
        bytes: [0; PAYLOAD_SIZE],
    };

    /// The payload as the struct its range owns.
    ///
    /// Total over [`Range`]: every range has a struct, so a kind in a reserved
    /// range is viewable even when its exact variant is unknown to this binary.
    #[must_use]
    pub fn view(&self, range: Range) -> Payload<'_> {
        // SAFETY: every member of the union is a `repr(C)` struct of exactly
        // `PAYLOAD_SIZE` bytes made only of integer fields and arrays of them,
        // so every bit pattern of the union is a valid value of every member;
        // reading any member from any state of the union is therefore defined.
        unsafe {
            match range {
                Range::Meta => Payload::Meta(&self.meta),
                Range::Process => Payload::Process(&self.process),
                Range::File => Payload::File(&self.file),
                Range::Network => Payload::Network(&self.net),
                Range::Hazard => Payload::Hazard(&self.hazard),
                Range::Introspection => Payload::Introspection(&self.introspect),
                Range::Semantic => Payload::Semantic(&self.semantic),
                Range::Decision => Payload::Decision(&self.decision),
                Range::Detection => Payload::Detection(&self.detection),
                Range::Forensic => Payload::Forensic(&self.forensic),
            }
        }
    }

    /// The bytes as they are.
    #[must_use]
    pub fn bytes(&self) -> &[u8; PAYLOAD_SIZE] {
        // SAFETY: `bytes` is an integer array covering the whole union; every
        // bit pattern is a valid value of it.
        unsafe { &self.bytes }
    }
}

impl core::fmt::Debug for EventPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EventPayload")
            .field("bytes", self.bytes())
            .finish()
    }
}

/// Every payload struct is exactly `PAYLOAD_SIZE` bytes, 8-aligned. Checked
/// when the crate compiles, for both the kernel and the user-space target.
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<MetaPayload>() == PAYLOAD_SIZE);
    assert!(size_of::<ProcPayload>() == PAYLOAD_SIZE);
    assert!(size_of::<FilePayload>() == PAYLOAD_SIZE);
    assert!(size_of::<NetPayload>() == PAYLOAD_SIZE);
    assert!(size_of::<HazardPayload>() == PAYLOAD_SIZE);
    assert!(size_of::<IntrospectPayload>() == PAYLOAD_SIZE);
    assert!(size_of::<SemanticPayload>() == PAYLOAD_SIZE);
    assert!(size_of::<DecisionPayload>() == PAYLOAD_SIZE);
    assert!(size_of::<DetectionPayload>() == PAYLOAD_SIZE);
    assert!(size_of::<ForensicPayload>() == PAYLOAD_SIZE);
    assert!(size_of::<EventPayload>() == PAYLOAD_SIZE);
    assert!(align_of::<EventPayload>() == 8);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_range_views_as_its_own_struct() {
        let payload = EventPayload::ZERO;
        for range in Range::ALL {
            let seen = match payload.view(range) {
                Payload::Meta(_) => Range::Meta,
                Payload::Process(_) => Range::Process,
                Payload::File(_) => Range::File,
                Payload::Network(_) => Range::Network,
                Payload::Hazard(_) => Range::Hazard,
                Payload::Introspection(_) => Range::Introspection,
                Payload::Semantic(_) => Range::Semantic,
                Payload::Decision(_) => Range::Decision,
                Payload::Detection(_) => Range::Detection,
                Payload::Forensic(_) => Range::Forensic,
            };
            assert_eq!(seen, range);
        }
    }

    #[test]
    fn any_bit_pattern_is_a_valid_view() {
        // Kernel-written bytes are never validated on the hot path, so every
        // pattern must be readable as every struct. All-ones is the pattern a
        // `bool` or an enum field would have made undefined.
        let payload = EventPayload {
            bytes: [0xFF; PAYLOAD_SIZE],
        };
        for range in Range::ALL {
            let _ = payload.view(range);
        }
        if let Payload::File(file) = payload.view(Range::File) {
            assert_eq!(file.path_len, u16::MAX);
            assert_eq!(file.inode, u64::MAX);
        }
    }

    #[test]
    fn a_file_path_written_through_the_union_reads_back_by_range() {
        let mut payload = EventPayload::ZERO;
        let mut file = FilePayload {
            inode: 42,
            dev: 7,
            size: 0,
            flags: 0,
            mode: 0o644,
            path_class: 0,
            pad0: 0,
            path_len: 8,
            path: [0; 200],
            reserved: [0; 20],
        };
        file.path[..8].copy_from_slice(b"/etc/foo");
        payload.file = file;
        match payload.view(Range::File) {
            Payload::File(seen) => {
                assert_eq!(*seen, file);
                assert_eq!(&seen.path[..usize::from(seen.path_len)], b"/etc/foo");
            }
            other => panic!("wrong view: {other:?}"),
        }
        assert_eq!(payload.bytes()[0], 42);
    }
}
