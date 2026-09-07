// SPDX-License-Identifier: Apache-2.0
//! What the platform gives us (plan §2.23; Annex D).
//!
//! The system never fails to start because a capability is missing: it
//! detects, degrades, and declares it loudly. These are the probe results,
//! as §2.23 lists them, with one rule: **the default is nothing present.**
//! A capability is `true` only because a probe measured it, never because
//! nobody wrote `false` (general rule 9). The probe abstraction and the tier
//! derived from the set are `F1.PA.04`.

/// Which signing backend holds the forensic key (§2.18).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum KeyHw {
    /// No hardware key; software Ed25519, and external anchoring by default.
    #[default]
    None,
    /// TPM 2.0, P-256.
    Tpm2P256,
    /// Apple Secure Enclave, P-256.
    SecureEnclaveP256,
    /// Android `StrongBox`, P-256.
    StrongBoxP256,
    /// Software Ed25519, stated as such.
    SoftwareEd25519,
}

/// The workstation probe (§2.23 `Capabilities`).
///
/// A wide struct of flags on purpose: it mirrors §2.23 field for field, and
/// packing the probes into bitflags would make the mirror unreadable and the
/// diff against the plan hard to check.
#[allow(clippy::struct_excessive_bools)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct CapabilitySet {
    /// `/sys/kernel/btf/vmlinux`.
    pub btf: bool,
    /// `bpf` in the active LSM list.
    pub bpf_lsm: bool,
    /// `BPF_MAP_TYPE_RINGBUF`, kernel ≥ 5.8.
    pub ringbuf: bool,
    /// Sleepable LSM programs, kernel ≥ 5.10.
    pub sleepable_lsm: bool,
    /// The seccomp user notifier exists — a syscall can be *trapped*.
    /// `SECCOMP_GET_NOTIF_SIZES`, kernel ≥ 5.0; `CONTINUE` ≥ 5.5.
    pub seccomp_unotify: bool,
    /// `SECCOMP_IOCTL_NOTIF_ADDFD` exists — a decision can be *delivered*
    /// without the target re-resolving the path (`I-28`). Kernel ≥ 5.9;
    /// `ADDFD_FLAG_SEND` ≥ 5.14. Separate from `seccomp_unotify` because
    /// trapping and answering are different capabilities: 5.4 has the first
    /// and not the second, measured on the matrix (`F0.VM.02`).
    pub seccomp_addfd: bool,
    /// cgroup v2 freezer, kernel ≥ 5.2 with cgroup2 mounted.
    pub cgroup_v2_freeze: bool,
    /// uprobes.
    pub uprobe: bool,
    /// Landlock ABI: 0 absent; ≥ 3 truncate; ≥ 4 TCP ports.
    pub landlock_abi: u8,
    /// `BPF_CGROUP_INET4/6_CONNECT` attachable.
    pub cgroup_sock_addr: bool,
    /// Running under WSL2: changes tier guidance, `/mnt` semantics, no TPM.
    pub wsl2: bool,
    /// A TPM device exists.
    pub tpm: bool,
    /// The signing backend.
    pub key_hw: KeyHw,
    /// Windows minifilter loaded — `[POST]`.
    pub minifilter_loaded: bool,
    /// ETW-TI available — requires PPL, `[POST]`.
    pub etw_ti: bool,
    /// Running as PPL — `[POST]`.
    pub ppl: bool,
    /// A local UI is attached; drives the T2 freeze budget (§2.20.5).
    pub local_ui_attached: bool,
    /// Paired mobile devices currently reachable.
    pub remote_devices: u8,
    /// APNs/FCM reachable.
    pub push_available: bool,
}

impl CapabilitySet {
    /// Nothing present, nothing assumed.
    pub const NONE: CapabilitySet = CapabilitySet {
        btf: false,
        bpf_lsm: false,
        ringbuf: false,
        sleepable_lsm: false,
        seccomp_unotify: false,
        seccomp_addfd: false,
        cgroup_v2_freeze: false,
        uprobe: false,
        landlock_abi: 0,
        cgroup_sock_addr: false,
        wsl2: false,
        tpm: false,
        key_hw: KeyHw::None,
        minifilter_loaded: false,
        etw_ti: false,
        ppl: false,
        local_ui_attached: false,
        remote_devices: 0,
        push_available: false,
    };
}

/// The mobile probe (§2.23 `SentinelCapabilities`).
#[allow(clippy::struct_excessive_bools)]
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct SentinelCapabilities {
    /// `VpnService` / `NEPacketTunnelProvider` running.
    pub tunnel_active: bool,
    /// Android `getConnectionOwnerUid`; iOS MDM only.
    pub flow_uid_attribution: bool,
    /// Android `PACKAGE_USAGE_STATS` granted.
    pub usage_stats: bool,
    /// Package inventory readable.
    pub package_inventory: bool,
    /// Apps reporting through the Sentinel SDK.
    pub sdk_peers: u16,
    /// Device Owner / Supervised.
    pub managed: bool,
    /// Rooted: enables S5 `[POST]`, and a risk signal.
    pub rooted: bool,
    /// Play Integrity / App Attest.
    pub integrity_verdict: IntegrityVerdict,
}

/// Play Integrity / App Attest, as the platform reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum IntegrityVerdict {
    /// Not asked, or the platform did not answer.
    #[default]
    Unknown,
    /// Meets the platform's integrity bar.
    Meets,
    /// Does not.
    Fails,
}
