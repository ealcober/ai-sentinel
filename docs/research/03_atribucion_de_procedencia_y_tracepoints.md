# Field research — attributing kernel events to activities, and what the tracepoint can give us

**Produced:** 2026-09-15, by delegated web and kernel-source research, for `docs/17` point 2 (the
attribution rule) and `ADR-10` (the sensor load).

**Question it was sent to answer:** how do real provenance systems attribute kernel events to
high-level activities; how does the state of the art handle ambiguity; is there a kernel primitive
that would group a short-lived declaring process with a later-spawned worker; and what is the
`__data_loc __filename_val` field that kernel 7.1.5 shows on `sys_enter_openat`.

**Method note from the researcher, kept verbatim in substance:** where possible, verification was
against kernel source and this host rather than prose. Local checks used
`/usr/src/linux-headers-7.0.11-76070011` and `-7.1.5-76070105`, `/boot/config-*`, and an upstream
checkout of `kernel/trace/trace_syscalls.c` and `include/linux/entry-common.h` from git.kernel.org
(tree reporting `VERSION=7 PATCHLEVEL=3 SUBLEVEL=0 EXTRAVERSION=-rc3`). `/sys/kernel/tracing` is
root-only on this host and non-interactive `sudo` failed, so the **live format file could not be
read** by the researcher — it was read separately by the owner and the result is in `ADR-10`.

**Nothing in this document is an instruction.** It records what other systems do and what the kernel
does; the decisions AISME takes from it live in `docs/17` and in the plan.

---

## 1. `__data_loc __filename_val` — a dead end, on two independent grounds

This is the section with the most first-hand verification, and its conclusion kills the idea.

### 1.1 Which kernel introduced it

Commit **`a544d9a66bdf`, "tracing: Have syscall trace events read user space string"**, merged for
**6.19-rc1**, part of Steven Rostedt's 13-patch series *"tracing: Show contents of syscall trace event
user space fields"* (v5 posted 2025-10-28). **Linux 6.19 was released 2026-02-09.**

### 1.2 Availability across the matrix

- **5.15, 6.1, 6.8: not available.** All predate 6.19.
- **7.0 and 7.1: available.** Verified locally — `include/trace/syscall.h` in *both* header packages
  on this host carries the new fields:

```c
struct syscall_metadata {
	const char	*name;
	int		syscall_nr;
	u8		nb_args:7;
	u8		user_arg_is_str:1;
	s8		user_arg_size;
	short		user_mask;      /* mask of @args that will read user space */
```

identical in `/usr/src/linux-headers-7.0.11-76070011/` and `/usr/src/linux-headers-7.1.5-76070105/`.

### 1.3 Why offset 48, and why the name

In `kernel/trace/trace_syscalls.c`, `check_faultable_syscall()` sets `sys_data->user_mask = BIT(1)`
for `__NR_openat` and `__NR_openat2`. The field naming is mechanical:

```c
snprintf(arg, len, "__%s_val", meta->args[idx]);
ret = trace_define_field(call, "__data_loc char[]", arg, offset, sizeof(int), 0, FILTER_OTHER);
```

`openat` has four arguments, so the static part is `trace_entry` (8) + `__syscall_nr` (4, padded) +
`args[4]` starting at 16, and the dynamic-loc field lands at **16 + 4×8 = 48**, while `filename`
(argument index 1) sits at **16 + 1×8 = 24**. The offsets the owner measured are arithmetically
consistent with the source.

### 1.4 The `__data_loc` encoding

From `syscall_put_data()` and `include/trace/stages/stage3_trace_output.h`:

```c
*(int *)ptr = val | (user_sizes[i] << 16);   /* val = offset from start of record */
```
```c
#define __get_dynamic_array(field)     ((void *)__entry + (__entry->__data_loc_##field & 0xffff))
#define __get_dynamic_array_len(field) ((__entry->__data_loc_##field >> 16) & 0xffff)
```

Low 16 bits: byte offset from the start of the record. High 16 bits: length.

### 1.5 **eBPF cannot read it.** This is the finding.

Verified by reading the current upstream `perf_call_bpf_enter()`:

```c
static int perf_call_bpf_enter(struct trace_event_call *call,
			       struct syscall_metadata *sys_data,
			       int syscall_nr, unsigned long *args)
{
	struct syscall_tp_t {
		struct trace_entry ent;
		int syscall_nr;
		unsigned long args[SYSCALL_DEFINE_MAXARGS];
	} __aligned(8) param;
	...
	for (i = 0; i < sys_data->nb_args; i++)
		param.args[i] = args[i];
	return trace_call_bpf_faultable(call, &param);
}
```

`perf_syscall_enter()` *does* call `syscall_put_data()` to append the user string to the perf record —
but BPF is handed a freshly built `param` containing only `{ent, syscall_nr, args[6]}`. **The dynamic
area is never in the BPF context.** A `BPF_PROG_TYPE_TRACEPOINT` program on
`syscalls/sys_enter_openat` cannot reach `__filename_val` even though the format file advertises it.
The field is for ftrace ring-buffer readers and `perf record`/`perf script` consumers.

### 1.6 And it would not close the TOCTOU window anyway

From `include/linux/entry-common.h`:

```c
	/* Do seccomp after ptrace, to catch any tracer changes. */
	if (work & SYSCALL_WORK_SECCOMP) { ... }

	if (unlikely(work & SYSCALL_WORK_SYSCALL_TRACEPOINT))
		trace_syscall_enter(regs);

	if (IS_ENABLED(CONFIG_AUDITSYSCALL) && unlikely(audit_context()))
		syscall_enter_audit(regs);
```

`trace_syscall_enter()` fires **before** the syscall body runs. The kernel's copy of the filename
therefore happens at exactly the same instant our own `bpf_probe_read_user_str_bytes` would. Another
thread sharing the address space can still rewrite the buffer between that copy and the real
`getname()` inside `do_sys_openat2`. **The window is identical; only the identity of the copier
changes.**

What it would buy:

1. **Fault reliability.** The kernel copy runs in faultable context
   (`tracepoint_is_faultable()`, `trace_user_fault_read()`), so a paged-out path is faulted in rather
   than returning `-EFAULT`.
2. One copy shared by all consumers rather than one per program.

What it costs, and this is disqualifying on its own:

```
/boot/config-7.1.5-76070105-generic:  CONFIG_TRACE_SYSCALL_BUF_SIZE_DEFAULT=63
kernel/trace/trace.h:                 #define SYSCALL_FAULT_USER_MAX 165
kernel/trace/trace_syscalls.c:        #define SYSCALL_FAULT_MAX_CNT 3
```

The Kconfig help, read from the headers package on this host: *"Some system call trace events will
record the data from a user space address that one of the parameters point to. The amount of data per
event is limited… For a tracing instance, this size may be changed by writing into its
`syscall_user_buf_size` file."* Range 0–165, **default 63**, at most three user arguments per syscall.
**Default truncation at 63 bytes makes it useless for real paths.**

### 1.7 What actually closes the TOCTOU window

- **BPF LSM** (`security_file_open` and friends): the arguments have already been copied into kernel
  space. An August 2026 study states it directly — *"security checks occur after arguments have been
  copied into kernel space"* — and that **"69 % of system calls take at least one [user-space
  pointer]"** vulnerable to TOCTOU.
- **Falco 0.42.0** (2025) removed syscall *enter* events from its pipeline entirely, keeping *"a few
  selected enter events… internally for TOCTOU mitigation"*.
- Background on the attack shape, blog and not peer-reviewed: Doyensec, *"Bypassing eBPF security
  monitoring"*, 2022-10-11.

### 1.8 One genuinely useful thing from the same era

**Sleepable BPF on tracepoints was merged into `bpf-next` on 2026-04-22** (a six-patch series, v13).
It adds `trace_call_bpf_faultable()` — visible in the upstream source above — and lets a
`tracepoint/syscalls/*` program call **`bpf_copy_from_user()`**, a user read that can page-fault.
**That is the reliable read**, without `__filename_val`, without the 63-byte cap, and without the
format-file field being unreachable.

---

## 2. How production and research systems attribute kernel events to activities

Four mechanisms are in use, ranked by what the literature actually trusts.

### 2.1 Explicit correlation identifiers — the only thing anyone trusts under concurrency

- **CamFlow** keeps per-task provenance state and gives applications a **pseudofile interface to
  disclose their own provenance**, attached to the disclosing task. Explicit injection, not inference.
  (SoCC 2017.)
- **Distributed tracing** settled this argument twenty years ago: W3C `traceparent` metadata
  propagation, not timing inference. **Magpie** (OSDI'04) did **not** use time windows — it used an
  **event schema plus a temporal join** to extract requests.
- **Execution-unit partitioning** is the provenance world's answer to "one process, many concurrent
  activities": BEEP (NDSS'13), MPI (USENIX Sec'17), ProTracer, UIScope, OmegaLog, MCI. **Every one of
  them requires an explicit boundary marker** — binary-reverse-engineered event loops, source
  annotations, or application log events. **None infers boundaries from time.** OmegaLog uses PID/TID
  as a disambiguator *and* grafts application-log events onto the graph.

### 2.2 Cgroups — the production grouping primitive

systemd's whole model is one cgroup (a scope or service unit) per activity, and the August 2026
telemetry study finds cgroup-attached LSM programs give the **lowest** overhead ("pre filtering").
Visible from eBPF through `bpf_get_current_cgroup_id()` and
`bpf_get_current_ancestor_cgroup_id()`.

### 2.3 Process ancestry — what the eBPF security products do, and the weakest

Tetragon attaches a full ancestor chain to every event (`GetAncestorProcessesInternal` walks to PID 1
or 2); Falco keeps a thread table. Neither has any notion of *which activity* — they answer *which
process tree*, which is a different question. **The sibling case AISME hit is the canonical failure
mode of ancestry-based attribution, not an edge case.**

### 2.4 Session and login ids — too coarse

`/proc/PID/sessionid` is **read-only**, assigned serially at login and inherited; `loginuid` needs
`CAP_AUDIT_CONTROL` to rewrite once set. One id per *login*, so every concurrent activity in one agent
session shares it.

### 2.5 On concurrency, specifically

The honest summary of the literature: **nobody** solves "two activities in flight under the same
parent" by inference. They solve it by making the boundary explicit — partitioning, schemas,
propagated ids — or they accept the imprecision and say so. The request-tracing survey literature
classifies Project5 and WAP5, the timing-inference systems, as those that *"accept the imprecision of
probabilistic correlation methods"* (arXiv:1003.0955 §6.1 and arXiv:1007.4057, both verified by
extracting the PDFs).

Recent eBPF provenance systems worth knowing: **eAudit** (IEEE S&P 2024, 81 syscall tracepoints,
per-CPU ring buffers); **ProvBPF**; and the August 2026 comparison of capture mechanisms with measured
numbers — eBPF tracepoint overhead **1.43 % network, 8.63 % file, 1.22 % process**, with CamFlow and
SPADE suffering *"90 to 100 % log loss in most workloads"* while eAudit *"loses no logs in any
workload"* but skips graph construction.

---

## 3. Ambiguous attribution — marking versus guessing

**Marking ambiguity is standard practice, and it is the norm specifically for ground-truth
construction.** Guessing is what deployed tools do, and nobody has published its error rate.

Evidence that marking is standard:

- **Provenance benchmark practice.** *"How Benchmarks and Evaluation Protocols Shape Conclusions in
  Provenance-Based Intrusion Detection"* (arXiv:2608.01454, Sep 2026): processes reached only by a
  forward trace are labelled **"contaminated" and ignored during scoring**, because *"Excluding them
  prevents the evaluation from rewarding or penalizing detections on nodes whose role is ambiguous and
  cannot be confidently tied to the documented attack chain."* The same paper reports how much of a
  real trace never even links into the graph: **Cadets 11.8 %, FiveDirections 34.4 %, Theia 58.1 %,
  Trace 59.0 %** of raw events unlinkable.
- **Linux audit ships an explicit unattributed marker.** `auid=unset` / `4294967295` (`(uid_t)-1`) is
  emitted for any process not descended from a login — the kernel does **not** guess a plausible user.
- **W3C Trace Context / OpenTelemetry:** a missing or invalid `traceparent` starts a **new root
  trace**. The specification deliberately does not infer a parent from timing or process identity.
- **BEEP's framing of the default**, quoted: *"a causality analysis may **conservatively** indicate
  numerous causal chains"* and *"a subject (i.e., process) is causally related to all the objects it
  has accessed so far"*. The conventional audit default under ambiguity is **over-attribution —
  attribute to all** — never "pick the most recent". Systems that reduce it do so with explicit unit
  boundaries.

**A published error rate for "attribute to the most recent activity" does not exist.** The researcher
looked through the provenance-partitioning, black-box-tracing and AI-agent-monitoring literature. The
closest is the qualitative classification of timing correlation as probabilistic and imprecise.

**Direction of bias, and why it matters here.** Quoted from the researcher:

> A most-recent heuristic in a **ground-truth** set is worse than the same heuristic in a detector,
> because the error correlates with the thing you are measuring. Your correlation engine's most likely
> guess is also "the most recent declaration"; scoring it against a ground truth built the same way
> manufactures agreement. The bias is toward **optimism**, which by your own Rule 4 makes it urgent.
> Marking ambiguous and excluding those events from scoring is both the published norm and the
> conservative direction.

---

## 4. Kernel primitives for grouping a short-lived declarer with a later-spawned worker

Strictly, nothing works with *zero* cooperation: attribution information has to enter the kernel from
somewhere. Ranked by cooperation cost.

### 4.1 A cgroup v2 sub-cgroup per activity — the answer, unprivileged, one `mkdir`

- A kernel-visible id readable from any BPF program: `bpf_get_current_cgroup_id()`, plus
  `bpf_get_current_ancestor_cgroup_id()` to roll up to the agent.
- **Inherited automatically**: *"On creation, all processes are put in the cgroup that the parent
  process belongs to at the time"* (cgroup-v2 admin guide) — so a declaring process and any worker
  spawned into the activity cgroup share it with no further calls.
- **Privilege: none, given delegation.** systemd's `Delegate=` chowns the cgroup directory to the
  unit's UID so an unprivileged process can create child cgroups and write `cgroup.subtree_control`.
  That is exactly how `systemd --user` works.
- Migration rule, if moving rather than spawning: write access to `cgroup.procs` of the source, the
  destination, **and their common ancestor**.
- **`clone3(CLONE_INTO_CGROUP)`** (Linux **5.7**) spawns straight into the target cgroup, closing the
  create-then-migrate race. `EACCES` if the cgroup restrictions are not met, `EBUSY` if a domain
  controller is enabled there, `EOPNOTSUPP` for domain-invalid.
- Cooperation required from whoever spawns the work: `mkdirat` plus one extra `clone3` flag.

### 4.2 Audit container ID — would have been perfect; it does not exist

`/proc/PID/audit_containerid`: `u64`, inherited on fork and clone, write-once per nesting,
`CAP_AUDIT_CONTROL`. Proposed by Richard Guy Briggs, **eight or more revisions, LWN coverage in 2017
and 2018, last posted 2019, never merged.** Do not design around it.

### 4.3 Audit session id — unusable

Read-only, one per login, inherited. It cannot separate two concurrent activities in one session.

### 4.4 `PR_SET_NAME` — reject

`comm` is 16 bytes **including** the NUL (15 usable characters), per thread, and **reset by `execve()`
to the new binary's name**. A tag written before spawning a worker does not survive the worker's exec,
which is exactly the transition it would need to survive. It also destroys the process name forensics
wants.

### 4.5 Namespaces as tags

A per-activity mount or UTS namespace, with the namespace inode number readable from BPF via
`task->nsproxy->…->ns.inum`. Needs `CAP_SYS_ADMIN` or an unprivileged user namespace, often disabled
on hardened hosts, with heavy side effects. Only worth it where the design is already sandboxing per
activity.

### 4.6 `io_uring` "task groups" — no such thing, and it makes this worse

Requests travel through shared-memory rings, so syscall-level tracing sees ring setup and not the
requests; work punted to `io-wq` runs in kernel worker threads named `iou-wrk-<tid>` **outside the
normal syscall path**, so syscall-number-keyed audit rules may not fire at all. A blind spot to
document, not a primitive to exploit.

### 4.7 BPF-side tagging

`task_local_storage` plus `sched_process_fork` propagation needs no kernel primitive and is the
cheapest *implementation* of whatever tag is chosen. On its own it inherits the same sibling problem:
tagging the agent at declaration time and propagating to later children is "latest declaration wins"
with extra steps.

---

## 5. eBPF monitoring of AI agents, 2025–2026

**AgentSight** — arXiv:2508.02736 (Aug 2025), published at the 4th Workshop on Practical Adoption
Challenges of ML for Systems, ACM DOI `10.1145/3766882.3767169`. The closest published prior art, and
the most useful finding here, because **it uses exactly the heuristic under question and never
measures it**:

> correlation signals: (i) *"tracks fork and execve events to link actions in child processes back to
> the parent agent"*; (ii) temporal proximity — *"using a 100-500 ms window for temporal
> correlation"*; (iii) argument matching of filenames, URLs and commands from LLM responses against
> syscall arguments.

- Overhead: **2.9 % average** — 3.4 % repository understanding, 4.9 % code writing, 0.4 % compilation;
  *"Each experiment was run 3 times with and without AgentSight."*
- **No attribution accuracy and no error rate are reported.** The evaluation is case studies.
- **Concurrency — several in-flight requests under one agent — is not addressed.**

**"Right to History: A Sovereignty Kernel for Verifiable AI Agent Execution"** — arXiv:2602.20214
(Feb 2026). States the gap explicitly: *"These tools operate at the syscall granularity—they observe
open(), execve(), and cgroup counters, but cannot attribute syscall sequences to agent-level semantic
actions."* Its answer sidesteps the kernel entirely: agents submit structured semantic actions to a
userspace "kernel". Measured: 0.7–1.3 ms median action latency, about 400 actions/s.

**Vendor, flagged as marketing rather than evaluation:** ARMO, *"eBPF for AI Agent Enforcement"*,
2026-03-31. Concedes the same gap — eBPF sees *"that a connection was made, that a file was opened,
that a process spawned. It cannot see why."* Claims 1–2.5 % CPU and about 1 % memory per node,
"comparable" to Tetragon and Falco at 1–3 % CPU. **No detection rates, no false-positive rates, no
attribution accuracy.**

**Surveys, application-layer only, no kernel measurements:** *From Agent Traces to Trust*
(arXiv:2606.04990, Jun 2026); *Trustworthy Agentic AI* (arXiv:2609.13731, Sep 2026); *Responsible
Agentic AI Requires Explicit Provenance* (arXiv:2605.17169, May 2026); *Lingering Authority*
(arXiv:2606.22504, Jun 2026).

**The existing conclusion holds: no third-party evaluation of any commercial kernel-level agent
guardrail was found.** The only peer-reviewed measured overhead for an eBPF AI-agent monitor is
AgentSight's 2.9 %. There are no published detection rates from anyone.

---

## 6. Register of unverified and refuted claims

1. **REFUTED mid-research.** A search summary reported *"WAP5 has a false rate around 90 % when
   messages of different task trees interleave."* The researcher downloaded arXiv:1007.4057 and
   extracted the text: the only 90 % in the paper is **PreciseTracer's own path accuracy under 10 %
   log deletion** (Fig. 9), not WAP5's error. **Do not cite that number.** What is citable is the
   qualitative classification of Project5 and WAP5 as accepting *"the imprecision of probabilistic
   correlation methods"*.
2. **Not verified first-hand by the researcher:** the live format file on this host — `/sys/kernel/tracing`
   is mode-restricted and non-interactive `sudo` failed. The offsets are *arithmetically consistent*
   with the source. (The owner read the file separately on 2026-09-15 and the offsets hold; see
   `ADR-10`.)
3. **Not verified on 7.1.5 specifically:** the `perf_call_bpf_enter()` body read is upstream
   7.3.0-rc3, and the headers package ships no `.c` files. The feature's *presence* on 7.0.11 and
   7.1.5 is verified via `struct syscall_metadata`; the **BPF-invisibility** conclusion is from
   upstream source plus the original perf patch, both showing the same `syscall_tp_t` copy.
   Falsifiable in ten minutes: load a `tracepoint/syscalls/sys_enter_openat` program that reads `ctx`
   at offset 48 and see whether the verifier accepts it and whether the value is non-zero.
4. **Not verified:** whether `syscall_user_buf_size` is runtime-writable per tracing instance on
   7.1.5 — that is from the Kconfig help text only.
5. **Not researched:** `SCHED_CORE` cookies (`prctl(PR_SCHED_CORE)`, `task->core_cookie`) as a shared
   inheritable tag. Mentioned for completeness; the permission model was not checked and
   `CONFIG_SCHED_CORE` was not verified here. It changes scheduling behaviour, so the researcher would
   not pursue it.
6. **Blog and mailing-list sources, flagged as such:** the Doyensec eBPF-bypass post, the Cloudflare
   `io_uring` worker-pool post, the ARMO vendor post, and the `ratatoskr.run` and `lkml.iu.edu` list
   archives — the patches they carry are primary, the surrounding commentary is not.

---

## 7. The researcher's own closing opinion, kept as such

> The `__filename_val` route is a dead end on two independent grounds: BPF cannot see the field, and
> it would not close the TOCTOU window if it could. If you want a reliable filename from a syscall
> tracepoint, the merged sleepable-tracepoint work (`bpf_copy_from_user()`) is the mechanism; if you
> want a TOCTOU-free one, it is BPF LSM. For attribution, a per-activity cgroup plus
> `clone3(CLONE_INTO_CGROUP)` costs the spawner one `mkdirat` and one flag, is unprivileged under
> systemd delegation, and is inherited by the kernel for free — and every event that still cannot be
> tied to an activity gets marked ambiguous and excluded from scoring, which is what the benchmark
> literature already does.

---

## Sources

**Kernel.** Commit `a544d9a66bdf` and the *"tracing: Show contents of syscall trace event user space
fields"* series — [v5 cover letter](http://www.mail-archive.com/linux-trace-kernel@vger.kernel.org/msg14254.html) ·
[patch 02/13, ftrace side](http://www.mail-archive.com/linux-trace-kernel@vger.kernel.org/msg14256.html) ·
[patch 04/13, perf side](https://lkml.iu.edu/2510.3/08250.html) ·
[6.19-rc1 attribution, Feb 2026](https://ratatoskr.run/dtrace/2026/02/12510608/t) ·
[Linux 6.19 release](https://www.helpnetsecurity.com/2026/02/09/linux-kernel-6-19-released/) ·
[sleepable tracepoints merged 2026-04-22](https://ratatoskr.run/bpf/2026/04/7947455/t) ·
[cgroup v2 admin guide](https://docs.kernel.org/admin-guide/cgroup-v2.html) ·
[`clone(2)`](https://man7.org/linux/man-pages/man2/clone.2.html) ·
[`bpf_get_current_ancestor_cgroup_id`](https://docs.ebpf.io/linux/helper-function/bpf_get_current_ancestor_cgroup_id/) ·
[audit loginuid ABI](https://www.kernel.org/doc/Documentation/ABI/stable/procfs-audit_loginuid) ·
[`audit.rules(7)`](https://www.man7.org/linux/man-pages/man7/audit.rules.7.html) ·
[systemd cgroup delegation](https://systemd.io/CGROUP_DELEGATION/) ·
[audit container ID RFE](https://github.com/linux-audit/audit-kernel/wiki/RFE-Audit-Container-ID) ·
[LWN on audit container ids](https://lwn.net/Articles/750313/)

**Papers.**
[CamFlow, SoCC 2017](https://tfjmp.org/publications/2017-socc.pdf) ·
[Magpie, OSDI'04](https://www.usenix.org/legacy/event/osdi04/tech/full_papers/barham/barham.pdf) ·
[BEEP, NDSS'13](https://www.cs.purdue.edu/homes/dxu/pubs/NDSS13.pdf) ·
[MPI, USENIX Sec'17](https://www.cs.purdue.edu/homes/dxu/pubs/Security17.pdf) ·
[OmegaLog, NDSS'20](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24270.pdf) ·
[eAudit, IEEE S&P 2024](https://www.seclab.cs.sunysb.edu/seclab/pubs/eaudit.pdf) ·
[Capture-mechanism comparison, Aug 2026](https://arxiv.org/html/2608.11418v1) ·
[Benchmarks and evaluation protocols in provenance IDS, Sep 2026](https://arxiv.org/html/2608.01454) ·
[AgentSight](https://arxiv.org/html/2508.02736v2) ·
[Right to History, arXiv:2602.20214](https://arxiv.org/abs/2602.20214) ·
request-tracing surveys arXiv:1003.0955 and arXiv:1007.4057

**Blog and vendor, secondary.**
[Falco 0.42.0](https://falco.org/blog/falco-0-42-0/) ·
[Doyensec — bypassing eBPF security monitoring](https://blog.doyensec.com/2022/10/11/ebpf-bypass-security-monitoring.html) ·
[Tetragon events](https://tetragon.io/docs/concepts/events/) ·
[Cloudflare — io_uring worker pool](https://blog.cloudflare.com/missing-manuals-io_uring-worker-pool/) ·
[uringscope](https://github.com/rch0wdhury/uringscope) ·
[ARMO](https://www.armosec.io/blog/ebpf-based-ai-agent-enforcement/)
