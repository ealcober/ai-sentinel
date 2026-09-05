# 01 — F0 verification backlog: outcomes

> Plan §F0.4 defines twenty-one rows. `F0.VER.15` is `DEPRECATED` (its claim `R1-15` was withdrawn under `I-27`), leaving **twenty live rows**. `cargo xtask verify-backlog` reads this file and fails while any live row has an empty `Outcome`. That is the correct state until GATE F0.
>
> `Outcome` is one of **`HOLDS`**, **`FAILS`**, **`WITHDRAWN`**, or empty when unmeasured. A row measured on one host and not the matrix says so in `Observed`.

## Measurement host

| | |
|---|---|
| Kernel | `6.18.33.1-microsoft-standard-WSL2` (`#1 SMP PREEMPT_DYNAMIC Fri Jun 5 01:12:21 UTC 2026`) |
| Distribution | Ubuntu under WSL2, `systemd=true` in `/etc/wsl.conf`, PID 1 is `systemd` |
| Probe | `F0.WSL.01`, run 2026-09-05. Read-only apart from a Landlock enforcement test writing under `/tmp`, in a forked child |

## Rows

| ID | Claim | Command run | Observed | Outcome |
|---|---|---|---|---|
| `F0.VER.01` | Rust 1.82 is recent enough for the Aya version F3 pins | — | | |
| `F0.VER.02` | `strip = "symbols"` preserves the `cargo-auditable` `.dep-v0` section | — | | |
| `F0.VER.03` | `extracted/*.txt` carries all technical content of the `.docx` originals | — | | |
| `F0.VER.04` **`[BLOCKING]`** | Landlock is active on the matrix kernels and in stock WSL2 | `landlock_create_ruleset(NULL,0,LANDLOCK_CREATE_RULESET_VERSION)`; then a real `restrict_self` in a forked child | **ABI 7.** `CONFIG_SECURITY_LANDLOCK=y`; `landlock` is first in `CONFIG_LSM`. Enforcement proven, not merely advertised: with `WRITE_FILE\|MAKE_REG` handled and one `PATH_BENEATH` rule, a write inside the allowed directory succeeded and a write outside returned **`EACCES`**. **Stock WSL2 only; the matrix kernels are `F0.VM.02`** | **`HOLDS`** (WSL2) |
| `F0.VER.05` | `seccomp_unotify`: a blocked syscall fails with `ENOSYS` when the listener fd closes | — | | |
| `F0.VER.06` | BPF kfuncs carry no stability contract | — | | |
| `F0.VER.07` | Embedded DuckDB baseline RSS is ~30–50 MB before ingest | — | | |
| `F0.VER.08` | `bpf_probe_write_user` sets a kernel taint flag | — | | |
| `F0.VER.09` | Which runtimes honour `SSLKEYLOGFILE` versus `--tls-keylog` | — | | |
| `F0.VER.10` | OTel `gen_ai.*` semantic conventions exist with the attribute names H-09 uses | — | | |
| `F0.VER.11` | arXiv `2510.08907` is the SAC paper and injects KV, not tokens | — | | |
| `F0.VER.12` **`[BLOCKING]`** | Commodity TPM, Secure Enclave and StrongBox offer non-exportable P-256, not Ed25519 | `ls /dev/tpm*`; `zcat /proc/config.gz \| grep CONFIG_TPM` | **Not measurable on this host**: `CONFIG_TPM` is not set and no `/dev/tpm*` exists, which is `F0.VER.18`, not a TPM capability answer. Apple and Android hardware not at hand. Per §F0.4 the row stays open with the missing hardware named; `key_hw` records `unverified` for those platforms | |
| `F0.VER.13` | BLAKE3 is 5–10× faster than SHA-256 on 320-byte leaves | — | | |
| `F0.VER.14` | Landlock audit records arrived in kernel 6.15 | — | | |
| `F0.VER.15` | ~~GitHub-hosted runners cannot run WSL2~~ | — | Withdrawn: moot under `I-27`, no hosted CI | **`DEPRECATED`** |
| `F0.VER.16` **`[BLOCKING]`** | `BPF_CGROUP_INET4/6_CONNECT` attaches with `bpf` absent from the LSM list and denies only session flows | Prerequisites read from `/proc/config.gz` and `/proc/mounts`; the attach test needs a loader | **Prerequisites all present**: `CONFIG_BPF_SYSCALL=y`, `CONFIG_CGROUP_BPF=y`, cgroup v2 mounted and unified (no v1 controllers), root controllers `cpuset cpu io memory hugetlb pids rdma`, BTF at `/sys/kernel/btf/vmlinux`. **The attach itself is not measured**: it needs a loaded BPF program, and `clang`, `bpf-linker` and `bpftool` are absent (`F0.REPO.06`). Measuring it is blocked on the toolchain, not on the kernel | |
| `F0.VER.17` | iOS App Groups are scoped to one developer team | — | | |
| `F0.VER.18` **`[BLOCKING]`** | WSL2 exposes no TPM | `ls /dev/tpm* /dev/tpmrm*`; `CONFIG_TPM` in `/proc/config.gz` | **No TPM.** `CONFIG_TPM` is **not set** in the stock kernel, so there is no driver, and `/dev/` contains no `tpm*` node. The absence is structural, not a missing device | **`HOLDS`** |
| `F0.VER.19` | A BPF program range-checking `EventKind` in one comparison is verifier-accepted | — | Blocked on the same toolchain as `F0.VER.16` | |
| `F0.VER.20` | Landlock ABI 4 port rules | Same syscall as `F0.VER.04` | **ABI 7 ≥ 4**, so network rules exist on this kernel. What ABI 4 port rules can *express* (TCP `bind`/`connect` only, no UDP) still needs a functional test | |
| `F0.VER.21` | KVM is usable inside the owner's WSL2 host | `stat /dev/kvm`; group membership; `/proc/cpuinfo` flags | `/dev/kvm` present, owned by group **`kvm`**; **the user is not in that group**, so it is not readable or writable today. CPU reports `vmx`, so nested virtualization is on at the Windows host | **`FAILS`** — remedy is `usermod -aG kvm`, owned by `F0.REPO.06` |

## What these outcomes decide

1. **Tier L2 is real on WSL2, and proven rather than assumed.** `F0.VER.04` was `[BLOCKING]` because the L2 tier row, `F3.3`, `F2.WS.11` and risk `R-15` all rest on Landlock actually denying. It does: a write outside the allowed path returned `EACCES` under a real ruleset. `R-15` does not apply to WSL2.
2. **WSL2 can reach L3 with a configuration change, not a kernel rebuild.** Plan §2.16.1 left this conditional open and asked F0 to settle it. `CONFIG_BPF_LSM=y` **is** compiled into the stock kernel, and `CONFIG_LSM` is `landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo` — `bpf` is **not** in the active list. So WSL2 is **L2 by default**, exactly as the plan says, and reaching L3 needs only `kernelCommandLine=` in `.wslconfig` plus `wsl --shutdown`. The custom-bzImage fallback the plan held in reserve is not needed on this kernel.
3. **Forensics on WSL2 are software-signed, by construction.** `F0.VER.18` holds with no TPM driver at all, so `R-18` stands and external anchoring is the default there (`I-18`).
4. **The toolchain, not the kernel, is what blocks the remaining blocking row.** `F0.VER.16` has every kernel prerequisite and no loader. It unblocks with `F0.REPO.06`.
5. **`cat /sys/kernel/security/lsm` is the wrong probe on this platform.** securityfs is not mounted on stock WSL2, so the file does not exist and a literal reading returns "no LSM list" — an absence read as a value, which general rule 9 forbids. `/proc/config.gz` and the Landlock syscall are the reliable probes, and §F0.4's command column says so.
