// SPDX-License-Identifier: GPL-2.0-only
//! The BPF programs.
//!
//! Built for `bpfel-unknown-none` by `cargo xtask build-ebpf`, never by
//! `cargo check --workspace`. The object it produces is embedded into
//! `aisme-agentd` with `include_bytes!`.
//!
//! GPL-2.0-only is not a preference: the verifier inspects which helpers a
//! program calls, and a `gpl_only` helper requires the program to declare a
//! GPL-compatible licence at load time. `LICENSE` below is that declaration, and
//! it is read by the kernel, not by a human.

#![no_std]
#![no_main]

// F0 pinned the toolchain and proved it builds against Aya. `F2.WS.01` adds
// the first real program: one tracepoint. The full probe set is F3.

use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_boot_ns,
    bpf_probe_read_user_str_bytes,
};
use aya_ebpf::macros::{map, tracepoint};
use aya_ebpf::maps::{HashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::TracePointContext;
use aisme_ebpf_common::{EventKind, Outcome, RawEvent, FLAG_PATH_UNRESOLVED, FLAG_TRUNCATED};

/// Sessions to observe: `tgid` → `session_id`, written by `aisme run` when it
/// opens a session (§3.3 step 1).
///
/// Filtering here rather than in user space is the whole point: the non-session
/// overhead of §2.22 is one hash lookup per `openat`, against a firehose that
/// would otherwise cross the ring boundary to be discarded.
#[map]
static AISME_SESSIONS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

/// The event ring. 256 KiB holds 819 events of [`RAW_EVENT_SIZE`]; the loader
/// may coerce the size, and the kernel requires a power-of-two multiple of the
/// page size.
#[map]
static AISME_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Per-CPU monotonic sequence. Per-CPU is what makes it monotonic without an
/// atomic: one producer per CPU, so `seq` totally orders that producer's events
/// and nothing more is claimed (`RawEvent::seq`).
#[map]
static AISME_SEQ: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU count of events the ring had no room for. `F2.WS.02` turns the
/// delta into a `DropNotice`: a drop that is not counted is an absence read as
/// a value.
#[map]
static AISME_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Byte offset of `filename` in the `sys_enter_openat` trace-event record.
///
/// The record is `common_*` (8 bytes) + `__syscall_nr` (4, padded to 8), then
/// one 8-byte slot per syscall argument: `dfd` at 16, `filename` at 24,
/// `flags` at 32, `mode` at 40. This is an ABI detail of a *format file*, not
/// of the kernel headers, so it is **verified in the guest** against
/// `/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format` by
/// `cargo xtask vm probe` rather than trusted here.
const OPENAT_FILENAME_OFFSET: usize = 24;
/// `flags`, by the same layout.
const OPENAT_FLAGS_OFFSET: usize = 32;
/// `mode`, by the same layout.
const OPENAT_MODE_OFFSET: usize = 40;

/// `sys_enter_openat` — the one probe `F0.VER.03` justified: glibc issues
/// `openat` for `open()` and never `openat2`, so this is what sees `cat` and
/// `sh`.
///
/// Always returns 0. A tracepoint's return value cannot deny anything, and
/// this program observes; enforcement is seccomp and Landlock (`F2.WS.05`).
#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    let _ = observe_openat(&ctx);
    0
}

fn observe_openat(ctx: &TracePointContext) -> Result<(), i32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;

    // Not a session: the cheapest possible exit, before any reserve.
    // SAFETY: `get` on a BPF hash map is unsafe only because the returned
    // reference borrows map memory that another CPU may update; it is read
    // here and copied out immediately.
    let Some(session_id) = (unsafe { AISME_SESSIONS.get(&tgid) }).copied() else {
        return Ok(());
    };

    // SAFETY: reading a fixed offset inside the trace-event record the kernel
    // handed this program. The offset is a compile-time constant inside the
    // record's size, and the guest probe checks it against the format file.
    let filename: *const u8 = unsafe { ctx.read_at(OPENAT_FILENAME_OFFSET) }?;
    // SAFETY: as above.
    let flags: u64 = unsafe { ctx.read_at(OPENAT_FLAGS_OFFSET) }?;
    // SAFETY: as above.
    let mode: u64 = unsafe { ctx.read_at(OPENAT_MODE_OFFSET) }?;

    let Some(mut slot) = AISME_EVENTS.reserve::<RawEvent>(0) else {
        bump_drops();
        return Ok(());
    };

    // The reserved bytes are whatever the ring last held, so the event is
    // written whole from ZERO before any field is set: a slot must never carry
    // a stale byte into user space.
    let event: &mut RawEvent = slot.write(RawEvent::ZERO);
    // SAFETY: a helper with no arguments and no pointers; unsafe only because
    // every `bpf_*` helper is. Boot-monotonic is the only clock §3.3 orders by.
    event.ts_ns = unsafe { bpf_ktime_get_boot_ns() };
    event.seq = next_seq();
    event.session_id = session_id;
    event.pid = pid;
    event.tgid = tgid;
    // `ppid` stays 0. A parent's tgid lives in `task_struct->real_parent`,
    // which needs `bpf_get_current_task` plus CO-RE against a vmlinux BTF —
    // neither of which F2 loads. Ingest fills it from `/proc/<tgid>/status`
    // (`F2.WS.02`), and 0 means "the producer did not have it": tgid 0 is
    // `swapper` and can never be a real parent, so the sentinel is unambiguous.
    event.uid = bpf_get_current_uid_gid() as u32;
    event.kind = EventKind::FileOpen.into();
    event.outcome = Outcome::Observed.into();

    // SAFETY: the payload union's members are all-integer `repr(C)` structs of
    // the same size, so writing through one member is defined; `kind` above
    // says this event's range is File, which is what makes `.file` the right
    // member to write.
    let file = unsafe { &mut event.payload.file };
    file.flags = flags as u32;
    file.mode = mode as u32;
    let read = {
        let dest = &mut file.path;
        // SAFETY: `filename` is the syscall's own argument pointer, read into
        // a bounded buffer by a helper that faults safely on a bad address —
        // which is why a failure here is a value, not a crash.
        unsafe { bpf_probe_read_user_str_bytes(filename, dest) }.map(<[u8]>::len)
    };

    // Provenance, always: this is the caller's string, not the kernel's
    // resolution, and nothing may decide from it (`I-28`).
    event.flags = FLAG_PATH_UNRESOLVED;
    match read {
        Ok(len) => {
            file.path_len = len as u16;
            // The helper truncates and reports the length including its NUL,
            // capped at the buffer, so a full buffer is the only truncation
            // signal available. A path of exactly PATH_MAX_INLINE - 1 bytes is
            // therefore reported as truncated when it was exact: the error is
            // toward claiming *less* is known, which is the safe direction for
            // a provenance flag.
            if len + 1 >= file.path.len() {
                event.flags |= FLAG_TRUNCATED;
            }
        }
        Err(_) => {
            // The pointer did not resolve. The event is still real — a session
            // called `openat` — so it is submitted with an empty path rather
            // than dropped, and `path_len == 0` with FLAG_PATH_UNRESOLVED set
            // says exactly that much and no more.
            file.path_len = 0;
        }
    }

    slot.submit(0);
    Ok(())
}

/// The next per-CPU sequence number, starting at 1: `seq == 0` is a slot
/// nobody wrote, like `kind == 0`.
fn next_seq() -> u64 {
    let Some(cell) = AISME_SEQ.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: a per-CPU array element is owned by this CPU for the duration of
    // this program, which the kernel does not preempt, so this is not shared.
    unsafe {
        *cell = (*cell).wrapping_add(1);
        *cell
    }
}

/// Count one event the ring had no room for.
fn bump_drops() {
    if let Some(cell) = AISME_DROPS.get_ptr_mut(0) {
        // SAFETY: as `next_seq`.
        unsafe { *cell = (*cell).wrapping_add(1) };
    }
}


/// Compile-time proof that the wire types build for `bpfel-unknown-none` with
/// the layout user space expects (`F1.EV.01`): the BPF side of `H-04`.
const _: () = assert!(core::mem::size_of::<aisme_ebpf_common::RawEvent>() == aisme_ebpf_common::RAW_EVENT_SIZE);

/// The licence string the verifier reads when the object is loaded.
#[unsafe(link_section = "license")]
#[used]
pub static LICENSE: [u8; 4] = *b"GPL\0";

/// `no_std` with `no_main` has no runtime to unwind into. A BPF program cannot
/// panic in the Rust sense anyway — the verifier rejects unbounded loops, so this
/// is unreachable by construction and exists to satisfy the target.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
