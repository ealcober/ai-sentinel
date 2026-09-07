// SPDX-License-Identifier: Apache-2.0
//! The causal graph ontology (plan Annex A, normative; `F1.ON.01`).
//!
//! Node and edge *types* only. The graph that holds them and enforces A.3's
//! invariants is `F1.ON.02`; the clocks are `F1.ON.03`; the taint algebra is
//! `F1.ON.04`. Every node is `Copy` and heap-free — a bounded array where the
//! plan writes `[]` — because nodes are made inside the hot loop's correlate
//! step, which allocates nothing in steady state (`F1.RT.03`). Variable text
//! is a [`StrId`] from the interner (`F1.EV.04`).

use core::net::IpAddr;

use crate::intern::StrId;
use crate::taint::Taint;

/// A boot-monotonic timestamp in nanoseconds: the only clock used for order
/// (A.3). Wall-clock is metadata, carried elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct BootNs(pub u64);

/// A monitored session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u64);

/// A node's identity inside one graph, issued by the graph (`F1.ON.02`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub u64);

/// A 256-bit content digest. Which function is the WAL's business
/// (`F1.RT.05`); the ontology only compares them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl core::fmt::Debug for Digest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Digest(")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…)")
    }
}

/// The permission groups, exactly the grammar's `GROUP` (Annex B §B.0).
/// Append-only; the discriminant is what the WAL and the wire's
/// `DecisionPayload::group` carry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PermissionGroup {
    /// Read/write outside the declared roots.
    FilesOutsideWorkspace = 1,
    /// `/etc`, `System32`, boot config, systemd units, Run keys, shell profiles.
    SystemConfig = 2,
    /// SSH keys, `.env`, keychain, credential manager, cloud config.
    Credentials = 3,
    /// Connections outside the allowlist.
    NetworkEgress = 4,
    /// Running binaries outside the allowlist.
    Execute = 5,
    /// `memfd_create` + `execveat`, reflective loading.
    FilelessExecute = 6,
    /// cron, systemd timers, Scheduled Tasks, autostart.
    Persistence = 7,
    /// Config-as-code persistence: `.git/hooks`, `package.json` scripts, …
    PersistenceConfig = 8,
    /// System-wide package managers.
    PackageInstall = 9,
    /// Anything targeting AISME itself.
    SelfProtection = 10,
    /// Camera, microphone, location, clipboard.
    Device = 11,
}

impl PermissionGroup {
    /// Every group, in grammar order.
    pub const ALL: [PermissionGroup; 11] = [
        PermissionGroup::FilesOutsideWorkspace,
        PermissionGroup::SystemConfig,
        PermissionGroup::Credentials,
        PermissionGroup::NetworkEgress,
        PermissionGroup::Execute,
        PermissionGroup::FilelessExecute,
        PermissionGroup::Persistence,
        PermissionGroup::PersistenceConfig,
        PermissionGroup::PackageInstall,
        PermissionGroup::SelfProtection,
        PermissionGroup::Device,
    ];

    /// `I-05`: the three groups that are never promptable, never grantable
    /// through an in-flow prompt, and never suppressible (`I-26`). The policy
    /// compiler refuses a policy that says otherwise (`F1.PL.04`, `F1.PL.07`).
    pub const NEVER_PROMPTABLE: [PermissionGroup; 3] = [
        PermissionGroup::SystemConfig,
        PermissionGroup::FilelessExecute,
        PermissionGroup::SelfProtection,
    ];

    /// Whether `I-05` applies.
    #[must_use]
    pub fn never_promptable(self) -> bool {
        PermissionGroup::NEVER_PROMPTABLE.contains(&self)
    }

    /// The grammar's spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            PermissionGroup::FilesOutsideWorkspace => "FILES_OUTSIDE_WORKSPACE",
            PermissionGroup::SystemConfig => "SYSTEM_CONFIG",
            PermissionGroup::Credentials => "CREDENTIALS",
            PermissionGroup::NetworkEgress => "NETWORK_EGRESS",
            PermissionGroup::Execute => "EXECUTE",
            PermissionGroup::FilelessExecute => "FILELESS_EXECUTE",
            PermissionGroup::Persistence => "PERSISTENCE",
            PermissionGroup::PersistenceConfig => "PERSISTENCE_CONFIG",
            PermissionGroup::PackageInstall => "PACKAGE_INSTALL",
            PermissionGroup::SelfProtection => "SELF_PROTECTION",
            PermissionGroup::Device => "DEVICE",
        }
    }

    /// From the grammar's spelling.
    #[must_use]
    pub fn parse(name: &str) -> Option<PermissionGroup> {
        PermissionGroup::ALL
            .into_iter()
            .find(|g| g.as_str() == name)
    }

    /// From the wire byte (`DecisionPayload::group`).
    #[must_use]
    pub fn from_code(code: u8) -> Option<PermissionGroup> {
        PermissionGroup::ALL.into_iter().find(|g| *g as u8 == code)
    }
}

/// What a path *is* to the policy, assigned at ingest. The file-touching
/// permission groups each name a class; `PersistenceConfig` is the class
/// `F1.PL.06` adds to the grammar and `DT-06` classifies by diff.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum PathClass {
    /// Not classified — inside the workspace, or unknown.
    #[default]
    Unclassified = 0,
    /// Outside every declared root.
    OutsideWorkspace = 1,
    /// System configuration.
    SystemConfig = 2,
    /// Credential material.
    Credentials = 3,
    /// A persistence mechanism.
    Persistence = 4,
    /// Config-as-code persistence.
    PersistenceConfig = 5,
    /// AISME's own files (`.aisme/**`).
    SelfProtection = 6,
}

impl PathClass {
    /// The group a class answers to, if any.
    #[must_use]
    pub const fn group(self) -> Option<PermissionGroup> {
        Some(match self {
            PathClass::Unclassified => return None,
            PathClass::OutsideWorkspace => PermissionGroup::FilesOutsideWorkspace,
            PathClass::SystemConfig => PermissionGroup::SystemConfig,
            PathClass::Credentials => PermissionGroup::Credentials,
            PathClass::Persistence => PermissionGroup::Persistence,
            PathClass::PersistenceConfig => PermissionGroup::PersistenceConfig,
            PathClass::SelfProtection => PermissionGroup::SelfProtection,
        })
    }
}

/// Transport of a `Socket`. QUIC is its own value: it rides UDP, Landlock
/// cannot see it (`F0.VER.20`), and its SNI comes from the Initial packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP other than QUIC.
    Udp,
    /// QUIC / HTTP-3.
    Quic,
    /// A UNIX-domain socket.
    Unix,
    /// Anything else, by IP protocol number.
    Other(u8),
}

/// Where a `Socket` is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SocketState {
    /// `connect()` issued.
    Connecting,
    /// Established.
    Established,
    /// Closed.
    Closed,
    /// Refused by enforcement (`EPERM`).
    Denied,
}

/// Who answered a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GrantedBy {
    /// A human principal, by peer-credential uid (`F7.PS.08`).
    Human {
        /// The uid.
        uid: u32,
    },
    /// The policy itself, without a prompt.
    Policy,
    /// A remote adjudicator — capped by `I-06`, never `CRITICAL`.
    Remote,
}

/// The targets a `ToolCall` declares, bounded so the node stays heap-free.
/// More than `MAX` are counted, not kept: `overflow` says how many.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct DeclaredTargets {
    ids: [StrId; DeclaredTargets::MAX],
    len: u8,
    /// Targets beyond `MAX` that were declared and not kept.
    pub overflow: u16,
}

impl DeclaredTargets {
    /// How many targets a node keeps.
    pub const MAX: usize = 8;

    /// The kept targets.
    #[must_use]
    pub fn as_slice(&self) -> &[StrId] {
        &self.ids[..usize::from(self.len)]
    }
}

impl FromIterator<StrId> for DeclaredTargets {
    /// Keeps the first `MAX`, counts the rest.
    fn from_iter<I: IntoIterator<Item = StrId>>(targets: I) -> DeclaredTargets {
        let mut out = DeclaredTargets::default();
        for id in targets {
            if usize::from(out.len) < DeclaredTargets::MAX {
                out.ids[usize::from(out.len)] = id;
                out.len += 1;
            } else {
                out.overflow = out.overflow.saturating_add(1);
            }
        }
        out
    }
}

/// A node of the causal graph: Annex A.1, one variant per row.
///
/// `Copy` and heap-free by construction. `ToolResult`, `SuppressionRule` and
/// `Finding` are `F1.ON.06`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node {
    /// Human or CI stimulus; the apex of causality.
    Prompt {
        /// The session.
        session_id: SessionId,
        /// When.
        ts: BootNs,
        /// Digest of the text; the text itself never leaves the machine (`I-08`).
        raw_text_hash: Digest,
        /// Tokens, where known.
        token_count: u32,
    },
    /// The model's internal reasoning trace.
    ChainOfThought {
        /// The inference turn.
        inference_id: u64,
        /// The model's name.
        model: StrId,
        /// Digest of the reasoning.
        reasoning_hash: Digest,
        /// What it said it would do — what `diverges_from` compares against.
        declared_intent: StrId,
    },
    /// A structured invocation emitted by the agent.
    ToolCall {
        /// The tool's name.
        tool_name: StrId,
        /// Digest of the parameters.
        params_hash: Digest,
        /// The call's own id.
        toolcall_id: u64,
        /// What it declared it would touch.
        declared_targets: DeclaredTargets,
    },
    /// The OS instantiation of a `ToolCall`.
    Process {
        /// Thread id.
        pid: u32,
        /// Thread group.
        tgid: u32,
        /// Parent thread group.
        ppid: u32,
        /// The executable.
        exe_path: StrId,
        /// Digest of the argument vector, as the wire carries it.
        argv_hash: u64,
        /// The cgroup — the session's scope handle.
        cgroup: u64,
        /// Taint acquired so far.
        taint: Taint,
    },
    /// A persistent artifact touched.
    File {
        /// Inode.
        inode: u64,
        /// Device.
        dev: u64,
        /// The canonical path.
        canonical_path: StrId,
        /// What the path is to the policy.
        path_class: PathClass,
        /// Digest of the content, when it was read.
        content_hash: Option<Digest>,
        /// Shannon entropy of the content in thousandths of a bit per byte,
        /// when measured; integer so equal inputs give equal nodes everywhere.
        entropy_milli: Option<u16>,
        /// Size in bytes.
        size: u64,
        /// The label writers leave and readers acquire (`H-13`).
        taint: Taint,
    },
    /// A network conduit.
    Socket {
        /// Transport.
        proto: Proto,
        /// Remote address; `None` for a UNIX socket.
        remote_addr: Option<IpAddr>,
        /// Remote port.
        remote_port: u16,
        /// Server name, from TLS or the QUIC Initial, when seen.
        sni: Option<StrId>,
        /// JA4 fingerprint, when computed.
        ja4: Option<StrId>,
        /// JA4H fingerprint, when computed.
        ja4h: Option<StrId>,
        /// Bytes out so far.
        bytes_out: u64,
        /// Where it is in its life.
        state: SocketState,
    },
    /// A permission decision — changes **enforcement**.
    Grant {
        /// The group granted.
        group: PermissionGroup,
        /// The scope, as the grammar spells it.
        scope: StrId,
        /// Time to live, seconds.
        ttl_s: u32,
        /// Who answered.
        granted_by: GrantedBy,
        /// The rule the grant compiled into.
        rule_id: StrId,
    },
    /// A compiled policy rule a decision cites — the target of `denied_by`
    /// and `declassified_by`, which A.2 names and A.1 needed a row for.
    Rule {
        /// The rule's `id` from the policy source.
        rule_id: StrId,
        /// The policy generation it belongs to.
        generation: u64,
    },
}

/// The kind of a node, for edge endpoint rules and the WAL.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NodeKind {
    /// `Node::Prompt`.
    Prompt = 1,
    /// `Node::ChainOfThought`.
    ChainOfThought = 2,
    /// `Node::ToolCall`.
    ToolCall = 3,
    /// `Node::Process`.
    Process = 4,
    /// `Node::File`.
    File = 5,
    /// `Node::Socket`.
    Socket = 6,
    /// `Node::Grant`.
    Grant = 7,
    /// `Node::Rule`.
    Rule = 8,
}

impl Node {
    /// Which kind this is.
    #[must_use]
    pub const fn kind(&self) -> NodeKind {
        match self {
            Node::Prompt { .. } => NodeKind::Prompt,
            Node::ChainOfThought { .. } => NodeKind::ChainOfThought,
            Node::ToolCall { .. } => NodeKind::ToolCall,
            Node::Process { .. } => NodeKind::Process,
            Node::File { .. } => NodeKind::File,
            Node::Socket { .. } => NodeKind::Socket,
            Node::Grant { .. } => NodeKind::Grant,
            Node::Rule { .. } => NodeKind::Rule,
        }
    }

    /// The taint a node carries, for the kinds that carry one.
    #[must_use]
    pub const fn taint(&self) -> Option<Taint> {
        match self {
            Node::Process { taint, .. } | Node::File { taint, .. } => Some(*taint),
            _ => None,
        }
    }
}

/// An edge of the causal graph: Annex A.2, one variant per row.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EdgeKind {
    /// `ToolCall → Prompt | ChainOfThought`: why the tool was invoked.
    GeneratedBy = 1,
    /// `ToolCall → Process`: logical intent → physical process.
    ExecutedAs = 2,
    /// `Process → Process`: lineage; carries taint.
    Spawned = 3,
    /// `Process → File`: access.
    Read = 4,
    /// `Process → File`: access with mutation.
    Mutated = 5,
    /// `Process → Socket`: egress.
    ConnectedTo = 6,
    /// `Process → Socket`: egress when the taint conditions hold.
    ExfiltratedTo = 7,
    /// `Process → File | Socket`: taint acquisition.
    TaintedBy = 8,
    /// `Process → Grant | Rule`: taint release with justification (`H-13`).
    DeclassifiedBy = 9,
    /// `any → Rule`: enforcement, retained as evidence.
    DeniedBy = 10,
    /// `Process → ChainOfThought`: **causal disparity** — declared intent ≠
    /// physical action. The edge that makes this a security graph.
    DivergesFrom = 11,
    /// `ToolResult → ToolCall`: where an untrusted input entered (`F1.ON.06`).
    ReturnedBy = 12,
    /// `any → Finding`: which detector fired (`F1.ON.06`).
    DetectedBy = 13,
    /// `event → SuppressionRule`: notification suppressed; still recorded,
    /// still enforced (`I-26`; `F1.ON.06`).
    SuppressedBy = 14,
    /// `Process → earlier denied_by target`: the `DT-05` join.
    RetriedAfterDeny = 15,
}

impl EdgeKind {
    /// Every edge kind, in A.2 order.
    pub const ALL: [EdgeKind; 15] = [
        EdgeKind::GeneratedBy,
        EdgeKind::ExecutedAs,
        EdgeKind::Spawned,
        EdgeKind::Read,
        EdgeKind::Mutated,
        EdgeKind::ConnectedTo,
        EdgeKind::ExfiltratedTo,
        EdgeKind::TaintedBy,
        EdgeKind::DeclassifiedBy,
        EdgeKind::DeniedBy,
        EdgeKind::DivergesFrom,
        EdgeKind::ReturnedBy,
        EdgeKind::DetectedBy,
        EdgeKind::SuppressedBy,
        EdgeKind::RetriedAfterDeny,
    ];

    /// A.2's `From → To` column as data: which node kinds may sit at each
    /// end. An empty slice means *any*. `F1.ON.02` validates edges against
    /// this; the kinds `F1.ON.06` adds extend the `To` sides then.
    #[must_use]
    pub const fn endpoints(self) -> (&'static [NodeKind], &'static [NodeKind]) {
        use NodeKind as K;
        match self {
            EdgeKind::GeneratedBy => (&[K::ToolCall], &[K::Prompt, K::ChainOfThought]),
            EdgeKind::ExecutedAs => (&[K::ToolCall], &[K::Process]),
            EdgeKind::Spawned => (&[K::Process], &[K::Process]),
            EdgeKind::Read | EdgeKind::Mutated => (&[K::Process], &[K::File]),
            EdgeKind::ConnectedTo | EdgeKind::ExfiltratedTo => (&[K::Process], &[K::Socket]),
            EdgeKind::TaintedBy => (&[K::Process], &[K::File, K::Socket]),
            EdgeKind::DeclassifiedBy => (&[K::Process], &[K::Grant, K::Rule]),
            EdgeKind::DeniedBy => (&[], &[K::Rule]),
            EdgeKind::DivergesFrom => (&[K::Process], &[K::ChainOfThought]),
            // Their `ToolResult`, `Finding` and `SuppressionRule` ends arrive
            // with `F1.ON.06`; until then the constraint is the side A.1 has.
            EdgeKind::ReturnedBy => (&[], &[K::ToolCall]),
            EdgeKind::DetectedBy | EdgeKind::SuppressedBy => (&[], &[]),
            EdgeKind::RetriedAfterDeny => (&[K::Process], &[K::Rule]),
        }
    }

    /// Whether an edge of this kind may run from `from` to `to`.
    #[must_use]
    pub fn permits(self, from: NodeKind, to: NodeKind) -> bool {
        let (froms, tos) = self.endpoints();
        (froms.is_empty() || froms.contains(&from)) && (tos.is_empty() || tos.contains(&to))
    }
}

/// An edge: two node ids and a kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Edge {
    /// Source.
    pub from: NodeId,
    /// Target.
    pub to: NodeId,
    /// Meaning.
    pub kind: EdgeKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nodes_are_copy_and_heap_free() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<Node>();
        assert_copy::<Edge>();
        // A bound, not a pin: the graph holds many of these.
        assert!(
            core::mem::size_of::<Node>() <= 128,
            "{}",
            core::mem::size_of::<Node>()
        );
    }

    #[test]
    fn the_never_promptable_groups_are_i05s_three() {
        let never: Vec<&str> = PermissionGroup::ALL
            .into_iter()
            .filter(|g| g.never_promptable())
            .map(PermissionGroup::as_str)
            .collect();
        assert_eq!(
            never,
            ["SYSTEM_CONFIG", "FILELESS_EXECUTE", "SELF_PROTECTION"]
        );
    }

    #[test]
    fn groups_round_trip_through_the_grammar_and_the_wire() {
        for group in PermissionGroup::ALL {
            assert_eq!(PermissionGroup::parse(group.as_str()), Some(group));
            assert_eq!(PermissionGroup::from_code(group as u8), Some(group));
        }
        assert_eq!(PermissionGroup::parse("NETWORK"), None);
        assert_eq!(PermissionGroup::from_code(0), None);
        assert_eq!(PermissionGroup::from_code(12), None);
    }

    #[test]
    fn every_path_class_but_unclassified_answers_to_a_group() {
        assert_eq!(PathClass::Unclassified.group(), None);
        assert_eq!(
            PathClass::SelfProtection.group(),
            Some(PermissionGroup::SelfProtection)
        );
        assert_eq!(
            PathClass::PersistenceConfig.group(),
            Some(PermissionGroup::PersistenceConfig)
        );
    }

    #[test]
    fn edge_endpoints_follow_a2() {
        use NodeKind as K;
        assert!(EdgeKind::GeneratedBy.permits(K::ToolCall, K::Prompt));
        assert!(EdgeKind::GeneratedBy.permits(K::ToolCall, K::ChainOfThought));
        assert!(!EdgeKind::GeneratedBy.permits(K::Process, K::Prompt));
        assert!(EdgeKind::ExecutedAs.permits(K::ToolCall, K::Process));
        assert!(!EdgeKind::ExecutedAs.permits(K::Process, K::Process));
        assert!(EdgeKind::Spawned.permits(K::Process, K::Process));
        assert!(EdgeKind::Mutated.permits(K::Process, K::File));
        assert!(!EdgeKind::Mutated.permits(K::Process, K::Socket));
        assert!(EdgeKind::TaintedBy.permits(K::Process, K::Socket));
        assert!(EdgeKind::DeclassifiedBy.permits(K::Process, K::Grant));
        assert!(EdgeKind::DeniedBy.permits(K::Socket, K::Rule), "any → rule");
        assert!(!EdgeKind::DeniedBy.permits(K::Socket, K::Grant));
        assert!(EdgeKind::DivergesFrom.permits(K::Process, K::ChainOfThought));
        assert!(!EdgeKind::DivergesFrom.permits(K::ToolCall, K::ChainOfThought));
        assert!(EdgeKind::RetriedAfterDeny.permits(K::Process, K::Rule));
        assert_eq!(EdgeKind::ALL.len(), 15);
    }

    #[test]
    fn declared_targets_are_bounded_and_count_the_overflow() {
        let targets: DeclaredTargets = (1..=12u32).map(StrId::from_raw).collect();
        assert_eq!(targets.as_slice().len(), DeclaredTargets::MAX);
        assert_eq!(targets.overflow, 4);
        assert_eq!(targets.as_slice()[0], StrId::from_raw(1));
        let none: DeclaredTargets = core::iter::empty().collect();
        assert_eq!(none.as_slice(), &[]);
    }

    #[test]
    fn node_kind_and_taint_are_read_from_the_variant() {
        let file = Node::File {
            inode: 1,
            dev: 1,
            canonical_path: StrId::from_raw(1),
            path_class: PathClass::Credentials,
            content_hash: None,
            entropy_milli: Some(7_900),
            size: 0,
            taint: Taint::SECRET_MATERIAL,
        };
        assert_eq!(file.kind(), NodeKind::File);
        assert_eq!(file.taint(), Some(Taint::SECRET_MATERIAL));
        let rule = Node::Rule {
            rule_id: StrId::from_raw(2),
            generation: 3,
        };
        assert_eq!(rule.kind(), NodeKind::Rule);
        assert_eq!(rule.taint(), None);
        assert_eq!(format!("{:?}", Digest([0xAB; 32])), "Digest(abababab…)");
    }
}
