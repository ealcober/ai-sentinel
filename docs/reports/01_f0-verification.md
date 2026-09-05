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
| `F0.VER.01` | Rust 1.82 is recent enough for the Aya version F3 pins | `cargo info aya`, `cargo info aya-ebpf`; the `edition` field of `bpf-linker 0.11.0` | **`aya 0.14.0` and `aya-ebpf 0.2.1` both declare `rust-version: 1.87.0`**, and `bpf-linker 0.11.0` is `edition = "2024"`, which Cargo rejects below 1.85. The pin was 1.82.0, so `cargo install bpf-linker` failed inside the repository with *feature `edition2024` is required* | **`FAILS`** — root pin moved to `1.97.1`, `rust-version` to `1.87` |
| `F0.VER.02` | `strip = "symbols"` preserves the `cargo-auditable` `.dep-v0` section | — | | |
| `F0.VER.03` | `extracted/*.txt` carries all technical content of the `.docx` originals | — | | |
| `F0.VER.04` **`[BLOCKING]`** | Landlock is active on the matrix kernels and in stock WSL2 | `landlock_create_ruleset(NULL,0,LANDLOCK_CREATE_RULESET_VERSION)`; then a real `restrict_self` in a forked child | **ABI 7.** `CONFIG_SECURITY_LANDLOCK=y`; `landlock` is first in `CONFIG_LSM`. Enforcement proven, not merely advertised: with `WRITE_FILE\|MAKE_REG` handled and one `PATH_BENEATH` rule, a write inside the allowed directory succeeded and a write outside returned **`EACCES`**. **Stock WSL2 only; the matrix kernels are `F0.VM.02`** | **`HOLDS`** (WSL2) |
| `F0.VER.05` | `seccomp_unotify`: a blocked syscall fails with `ENOSYS` when the listener fd closes | A real `SECCOMP_RET_USER_NOTIF` filter on `getpid`, listener closed without answering, in a forked child | **`getpid` returned `-1`, errno 38 `ENOSYS`.** The listener dying is a defined outcome, not a hang | **`HOLDS`** |
| `F0.VER.06` | BPF kfuncs carry no stability contract | — | | |
| `F0.VER.07` | Embedded DuckDB baseline RSS is ~30–50 MB before ingest | — | | |
| `F0.VER.08` | `bpf_probe_write_user` sets a kernel taint flag | — | | |
| `F0.VER.09` | Which runtimes honour `SSLKEYLOGFILE` versus `--tls-keylog` | — | | |
| `F0.VER.10` | OTel `gen_ai.*` semantic conventions exist with the attribute names H-09 uses | — | | |
| `F0.VER.11` | arXiv `2510.08907` is the SAC paper and injects KV, not tokens | — | | |
| `F0.VER.12` **`[BLOCKING]`** | Commodity TPM, Secure Enclave and StrongBox offer non-exportable P-256, not Ed25519 | `ls /dev/tpm*`; `zcat /proc/config.gz \| grep CONFIG_TPM` | **Not measurable on this host**: `CONFIG_TPM` is not set and no `/dev/tpm*` exists, which is `F0.VER.18`, not a TPM capability answer. Apple and Android hardware not at hand. Per §F0.4 the row stays open with the missing hardware named; `key_hw` records `unverified` for those platforms | |
| `F0.VER.13` | BLAKE3 is 5–10× faster than SHA-256 on 320-byte leaves | 2 M iterations of each over a 320-byte leaf, warmed, `--release` | **6.41×** on a stock build; **4.40×** with `-C target-cpu=native`. The test CPU has **no SHA-NI** (`sha_ni` absent from `/proc/cpuinfo`), which is what the ratio is really measuring | **`HOLDS`** on this hardware, with the caveat recorded in §2.18 |
| `F0.VER.14` | Landlock audit records arrived in kernel 6.15 | `landlock_restrict_self` with each `LOG_*` flag, in a forked child | All three accepted on `6.18.33.1`: `LOG_SAME_EXEC_OFF`, `LOG_NEW_EXEC_ON`, `LOG_SUBDOMAINS_OFF`. **Presence is confirmed; the 6.15 boundary is not** — that needs an older kernel, so it belongs to `F0.VM.02` | **`HOLDS`** for presence; the version boundary stays open |
| `F0.VER.15` | ~~GitHub-hosted runners cannot run WSL2~~ | — | Withdrawn: moot under `I-27`, no hosted CI | **`DEPRECATED`** |
| `F0.VER.16` **`[BLOCKING]`** | `BPF_CGROUP_INET4/6_CONNECT` attaches with `bpf` absent from the LSM list and denies only session flows | Prerequisites read from `/proc/config.gz` and `/proc/mounts`; the attach test needs a loader | **Prerequisites all present**: `CONFIG_BPF_SYSCALL=y`, `CONFIG_CGROUP_BPF=y`, cgroup v2 mounted and unified (no v1 controllers), root controllers `cpuset cpu io memory hugetlb pids rdma`, BTF at `/sys/kernel/btf/vmlinux`. **The attach itself is not measured**: it needs a loaded BPF program, and `clang`, `bpf-linker` and `bpftool` are absent (`F0.REPO.06`). Measuring it is blocked on the toolchain, not on the kernel | |
| `F0.VER.17` | iOS App Groups are scoped to one developer team | — | | |
| `F0.VER.18` **`[BLOCKING]`** | WSL2 exposes no TPM | `ls /dev/tpm* /dev/tpmrm*`; `CONFIG_TPM` in `/proc/config.gz` | **No TPM.** `CONFIG_TPM` is **not set** in the stock kernel, so there is no driver, and `/dev/` contains no `tpm*` node. The absence is structural, not a missing device | **`HOLDS`** |
| `F0.VER.19` | A BPF program range-checking `EventKind` in one comparison is verifier-accepted | — | Blocked on the same toolchain as `F0.VER.16` | |
| `F0.VER.20` | Landlock ABI 4 port rules | A real net ruleset: add a TCP port rule, restrict self, then connect to an allowed port, a denied port and a UDP port | **Confirmed, and enforcing.** A `LANDLOCK_RULE_NET_PORT` rule was accepted; a connect to the denied port returned **`EACCES`** while the allowed port reached `ECONNREFUSED`, which is past Landlock. `handled_access_net` bit 2 was **refused with `EINVAL`** — there is no UDP access bit — and a UDP connect to the denied port succeeded unrestricted | **`HOLDS`** |
| `F0.VER.21` | KVM is usable inside the owner's WSL2 host | `stat /dev/kvm`; group membership; `/proc/cpuinfo` flags | `/dev/kvm` present, owned by group **`kvm`**; **the user is not in that group**, so it is not readable or writable today. CPU reports `vmx`, so nested virtualization is on at the Windows host | **`FAILS`** — remedy is `usermod -aG kvm`, owned by `F0.REPO.06` |

## What these outcomes decide

0. **A prediction of mine fell, and the reason is worth more than the number.** Before measuring `F0.VER.13` I predicted 1–3× rather than the plan's 5–10×, reasoning that BLAKE3's advantage comes from SIMD parallelism over long inputs and that 320 bytes is too small to collect it. The measurement is 6.41×, inside the plan's range. The input size was not the variable that mattered: **SHA-NI was.** This CPU has none, so `sha2` runs a software SHA-256 at 160 MB/s; on a CPU with the extension it would be several times faster and the ratio would largely close. The lesson is that a hash benchmark without naming the target's crypto extensions is not a measurement of the algorithms, and the plan now says so where it chooses BLAKE3.

1. **Landlock cannot see UDP, so it cannot see QUIC.** `F0.VER.20` measured that `handled_access_net` has only TCP bind and connect bits and refuses anything else with `EINVAL`, and a UDP connect under a restricting ruleset went through untouched. This is not a gap in the design — the L2 network deny was always the cgroup `connect` hook — but it does mean Landlock is a **file** primitive with a narrow TCP addendum, and Annex B §B.9 now says so rather than implying address matching it does not have.

2. **`F0.VER.01` is why this register exists.** The claim was written when Aya was not yet pinned, and it is wrong by five minor versions. The failure surfaced the moment a real dependency was fetched, not through review. The root toolchain is now `1.97.1` and the MSRV `1.87`, the floor Aya sets; the workspace compiles and passes `clippy -D warnings` unchanged under it. **The lesson worth keeping: checking that a pinned toolchain is installed is not checking that it is adequate.** The previous commit verified the first and reported the file's claim as true; only fetching Aya's manifest tested the second.

3. **Tier L2 is real on WSL2, and proven rather than assumed.** `F0.VER.04` was `[BLOCKING]` because the L2 tier row, `F3.3`, `F2.WS.11` and risk `R-15` all rest on Landlock actually denying. It does: a write outside the allowed path returned `EACCES` under a real ruleset. `R-15` does not apply to WSL2.
4. **WSL2 can reach L3 with a configuration change, not a kernel rebuild.** Plan §2.16.1 left this conditional open and asked F0 to settle it. `CONFIG_BPF_LSM=y` **is** compiled into the stock kernel, and `CONFIG_LSM` is `landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo` — `bpf` is **not** in the active list. So WSL2 is **L2 by default**, exactly as the plan says, and reaching L3 needs only `kernelCommandLine=` in `.wslconfig` plus `wsl --shutdown`. The custom-bzImage fallback the plan held in reserve is not needed on this kernel.
5. **Forensics on WSL2 are software-signed, by construction.** `F0.VER.18` holds with no TPM driver at all, so `R-18` stands and external anchoring is the default there (`I-18`).
6. **The toolchain, not the kernel, is what blocks the remaining blocking row.** `F0.VER.16` has every kernel prerequisite and no loader. It unblocks with `F0.REPO.06`.
7. **`cat /sys/kernel/security/lsm` is the wrong probe on this platform.** securityfs is not mounted on stock WSL2, so the file does not exist and a literal reading returns "no LSM list" — an absence read as a value, which general rule 9 forbids. `/proc/config.gz` and the Landlock syscall are the reliable probes, and §F0.4's command column says so.
