// SPDX-License-Identifier: Apache-2.0
//! `BpfSensor` — one tracepoint, one real ring buffer (`F2.WS.01`).
//!
//! The Linux end of [`Sensor`]. It loads the object `cargo xtask build-ebpf`
//! produces, attaches `syscalls/sys_enter_openat`, and drains
//! `BPF_MAP_TYPE_RINGBUF` into the caller's batch without allocating.
//!
//! **It does not fall back to a perf buffer.** Annex D.1 records the fallback
//! for kernels below 5.8, and `F3.PT.*` owns it: a second transport with its
//! own ordering and copy semantics, shipped untested inside a risk-removal
//! phase, would add the risk the phase exists to remove. Here the absence is
//! reported as [`ErrorKind::Unsupported`] naming the kernel and the map type.

use std::time::{Duration, Instant};

use aisme_core::capability::CapabilitySet;
use aisme_core::error::{Error, ErrorKind, Result};
use aisme_core::sensor::{EventBatch, Sensor, SensorConfig, SensorHealth};
use aisme_ebpf_common::{RawEvent, RAW_EVENT_SIZE};
use aya::maps::{HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::{Ebpf, EbpfLoader};

/// The trace-event category and name the program attaches to. `F0.VER.03`
/// settled the choice by disassembly: glibc issues `openat` for `open()` and
/// never `openat2`, so this is the one probe that sees `cat` and `sh`.
const TRACEPOINT: (&str, &str) = ("syscalls", "sys_enter_openat");
/// The program's symbol in the object, which is also its name to `aya`.
const PROGRAM: &str = "sys_enter_openat";
/// Map names, as the BPF object exports them.
const EVENTS_MAP: &str = "AISME_EVENTS";
/// Sessions to observe: `tgid` → `session_id`.
const SESSIONS_MAP: &str = "AISME_SESSIONS";

/// The object, embedded when `cargo xtask build-ebpf` has produced one.
///
/// Empty otherwise, which `start` reports rather than failing the build: the
/// object is produced by a different toolchain for a different target, so
/// requiring it at compile time would make `cargo check --workspace` depend on
/// a nightly cross-build. See `build.rs`.
#[cfg(bpf_object_present)]
const OBJECT: &[u8] = include_bytes!(env!("AISME_BPF_OBJECT"));
/// No object was built; `start` says so and names the command.
#[cfg(not(bpf_object_present))]
const OBJECT: &[u8] = &[];

/// One tracepoint, one ring buffer, no allocation on the drain path.
pub struct BpfSensor {
    loaded: Option<Loaded>,
    /// Set when the attachment is known to be gone. The watchdog that would
    /// re-attach is `F3.LD.03`; this only reports.
    detached: Option<String>,
}

/// What exists once `start` succeeds. `Ebpf` owns the programs and their
/// links; dropping it detaches, which is what `stop` relies on.
struct Loaded {
    /// Kept alive: dropping it closes the links and unloads the programs.
    ebpf: Ebpf,
    ring: RingBuf<MapData>,
}

impl BpfSensor {
    /// A sensor that has not attached yet.
    #[must_use]
    pub fn new() -> BpfSensor {
        BpfSensor {
            loaded: None,
            detached: None,
        }
    }

    /// The kernel release, for a message a reader can act on. Read from
    /// `/proc`, not from `uname(2)`, to keep this crate free of a libc call
    /// for one string; an unreadable file yields `"unknown"` rather than a
    /// guess, because a version invented here would be worse than absent.
    fn kernel_release() -> String {
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_or_else(|_| "unknown".to_owned(), |s| s.trim().to_owned())
    }

    /// Observe `tgid` as part of `session_id` (§3.3 step 1).
    ///
    /// The filter lives in the kernel because filtering in user space would
    /// move the whole `openat` firehose across the ring boundary to be
    /// discarded. `F2.WS.08` calls this when `aisme run` opens a session.
    ///
    /// # Errors
    ///
    /// `Invalid` when the sensor has not started, or the map rejects the write.
    pub fn watch(&mut self, tgid: u32, session_id: u64) -> Result<()> {
        let loaded = self
            .loaded
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::Invalid, "watch before start"))?;
        let mut sessions: BpfHashMap<&mut MapData, u32, u64> = loaded
            .ebpf
            .map_mut(SESSIONS_MAP)
            .ok_or_else(|| Error::new(ErrorKind::Invalid, "no AISME_SESSIONS map in the object"))
            .and_then(|m| {
                BpfHashMap::try_from(m)
                    .map_err(|e| Error::new(ErrorKind::Invalid, format!("AISME_SESSIONS: {e}")))
            })?;
        sessions
            .insert(tgid, session_id, 0)
            .map_err(|e| Error::new(ErrorKind::Failed, format!("AISME_SESSIONS insert: {e}")))
    }

    /// Stop observing `tgid`.
    ///
    /// # Errors
    ///
    /// As [`BpfSensor::watch`]. A tgid that was not watched is not an error:
    /// closing a session twice must be safe.
    pub fn unwatch(&mut self, tgid: u32) -> Result<()> {
        let loaded = self
            .loaded
            .as_mut()
            .ok_or_else(|| Error::new(ErrorKind::Invalid, "unwatch before start"))?;
        let mut sessions: BpfHashMap<&mut MapData, u32, u64> = loaded
            .ebpf
            .map_mut(SESSIONS_MAP)
            .ok_or_else(|| Error::new(ErrorKind::Invalid, "no AISME_SESSIONS map in the object"))
            .and_then(|m| {
                BpfHashMap::try_from(m)
                    .map_err(|e| Error::new(ErrorKind::Invalid, format!("AISME_SESSIONS: {e}")))
            })?;
        let _ = sessions.remove(&tgid);
        Ok(())
    }
}

impl Default for BpfSensor {
    fn default() -> BpfSensor {
        BpfSensor::new()
    }
}

impl Sensor for BpfSensor {
    fn start(&mut self, _cfg: &SensorConfig) -> Result<()> {
        if OBJECT.is_empty() {
            return Err(Error::unsupported(
                "no BPF object is embedded; run `cargo xtask build-ebpf` and rebuild",
            ));
        }

        // Loading *is* the ring-buffer feature test. A kernel without
        // BPF_MAP_TYPE_RINGBUF (below 5.8) refuses to create the map, and the
        // load fails there. Asking the kernel beats reading its version
        // string: a backport makes the version wrong in one direction and a
        // vendor kernel in the other, which is the lesson F0.VM.02 paid for.
        let mut ebpf = EbpfLoader::new().load(OBJECT).map_err(|e| {
            // The loader's own words first, then the kernel, and a cause only
            // where one was actually established. An earlier version of this
            // message blamed BPF_MAP_TYPE_RINGBUF for every failure; a run on
            // 6.8 then reported a missing-BTF parse error dressed as a
            // ring-buffer problem, which is a cause asserted rather than
            // measured — the thing this project treats as a defect everywhere
            // else.
            let text = e.to_string();
            let likely = if text.contains("map") && text.contains("create") {
                " — a kernel below 5.8 has no BPF_MAP_TYPE_RINGBUF, and F2 requires it; the \
                 perf-buffer fallback is F3.PT.*, not this phase"
            } else {
                ""
            };
            Error::unsupported(format!(
                "kernel {} refused the object: {text}{likely}",
                Self::kernel_release()
            ))
        })?;

        let program: &mut TracePoint = ebpf
            .program_mut(PROGRAM)
            .ok_or_else(|| Error::new(ErrorKind::Invalid, format!("no program {PROGRAM}")))?
            .try_into()
            .map_err(|e| {
                Error::new(
                    ErrorKind::Invalid,
                    format!("{PROGRAM} is not a tracepoint: {e}"),
                )
            })?;
        program
            .load()
            .map_err(|e| Error::failed(format!("verifier rejected {PROGRAM}: {e}")))?;
        program
            .attach(TRACEPOINT.0, TRACEPOINT.1)
            .map_err(|e| Error::failed(format!("attach {}/{}: {e}", TRACEPOINT.0, TRACEPOINT.1)))?;

        let ring = ebpf
            .take_map(EVENTS_MAP)
            .ok_or_else(|| Error::new(ErrorKind::Invalid, format!("no map {EVENTS_MAP}")))
            .and_then(|m| {
                RingBuf::try_from(m)
                    .map_err(|e| Error::new(ErrorKind::Invalid, format!("{EVENTS_MAP}: {e}")))
            })?;

        self.detached = None;
        self.loaded = Some(Loaded { ebpf, ring });
        Ok(())
    }

    fn poll(&mut self, out: &mut EventBatch, budget: Duration) -> Result<usize> {
        let Some(loaded) = self.loaded.as_mut() else {
            return Err(Error::new(ErrorKind::Detached, "poll before start"));
        };
        let deadline = Instant::now() + budget;
        let mut added = 0usize;
        // Non-blocking: `next` returns None when the ring is empty, so this
        // loop ends on an empty ring, a full batch or the budget — never on a
        // syscall that could block past it.
        while out.remaining() > 0 {
            let Some(item) = loaded.ring.next() else {
                break;
            };
            let bytes: &[u8] = &item;
            // A record of the wrong size is a producer this binary cannot
            // read. It is skipped rather than parsed, and the skip shows as a
            // gap in `seq` rather than as a silently misread event (§3.6).
            if let Ok(exact) = <[u8; RAW_EVENT_SIZE]>::try_from(bytes) {
                // `push` cannot fail: `remaining() > 0` was just checked, and
                // this is the only writer.
                if out.push(RawEvent::from_bytes(exact)).is_ok() {
                    added += 1;
                }
            }
            drop(item);
            if Instant::now() >= deadline {
                break;
            }
        }
        Ok(added)
    }

    fn capabilities(&self) -> CapabilitySet {
        // Only what this sensor actually established. The full probe — BTF,
        // Landlock, the LSM list, seccomp — is `F3.LD.01`; reporting anything
        // here that was not measured would be an absence read as a value.
        // Built from NONE by assignment rather than by a struct expression:
        // `CapabilitySet` is `#[non_exhaustive]`, so a literal is refused
        // outside its own crate. That refusal is the point — it is what lets
        // the type grow a field without this call site silently defaulting it
        // (`ADR-08`).
        let mut caps = CapabilitySet::NONE;
        caps.ringbuf = self.loaded.is_some();
        caps
    }

    fn health(&self) -> SensorHealth {
        match (&self.detached, &self.loaded) {
            (Some(reason), _) => SensorHealth::Detached {
                reason: reason.clone(),
            },
            (None, Some(_)) => SensorHealth::Healthy,
            (None, None) => SensorHealth::Detached {
                reason: "not started".to_owned(),
            },
        }
    }

    fn stop(&mut self) -> Result<()> {
        // Dropping `Ebpf` closes every link and unloads the programs, so
        // detaching is exactly this. Nothing is pinned, so nothing survives.
        self.loaded = None;
        self.detached = Some("stopped".to_owned());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything here runs on the host, so it exercises only what needs no
    /// kernel: `I-12` forbids a kernel-touching test outside a VM, and the
    /// load, attach and drain are covered by `cargo xtask vm run`.
    #[test]
    fn a_sensor_that_never_started_is_detached_and_claims_nothing() {
        let sensor = BpfSensor::new();
        assert_eq!(
            sensor.health(),
            SensorHealth::Detached {
                reason: "not started".to_owned()
            }
        );
        // The capability is derived from what was established, not asserted.
        assert!(!sensor.capabilities().ringbuf);
        assert_eq!(sensor.capabilities(), CapabilitySet::NONE);
    }

    #[test]
    fn polling_before_start_is_detached_rather_than_empty() {
        // An empty result would be indistinguishable from "no events", which
        // is an absence read as a value: the hot loop would see a healthy,
        // quiet sensor where there is no sensor at all.
        let mut sensor = BpfSensor::new();
        let mut batch = EventBatch::with_capacity(4);
        let err = sensor
            .poll(&mut batch, Duration::from_millis(1))
            .expect_err("must not report zero events");
        assert_eq!(err.kind, ErrorKind::Detached);
        assert!(batch.is_empty());
    }

    #[test]
    fn watching_before_start_is_refused_rather_than_queued() {
        let mut sensor = BpfSensor::new();
        let err = sensor.watch(1234, 99).expect_err("no map exists yet");
        assert_eq!(err.kind, ErrorKind::Invalid);
    }

    #[test]
    fn stop_is_idempotent_and_leaves_the_sensor_readable() {
        let mut sensor = BpfSensor::new();
        sensor.stop().expect("stopping a stopped sensor is fine");
        sensor.stop().expect("twice, too");
        assert!(matches!(sensor.health(), SensorHealth::Detached { .. }));
    }
}
