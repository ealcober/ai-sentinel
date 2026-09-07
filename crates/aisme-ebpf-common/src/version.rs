// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
//! Wire-version negotiation (plan §3.6, `F1.EV.02`).
//!
//! Five artefacts talk to each other and every pairing needs a compatibility
//! rule or a field upgrade corrupts data. Two of them meet here: the BPF
//! program ↔ `agentd` pairing refuses to attach on a mismatch, and the
//! `agentd` ↔ `forensicd` pairing stamps every WAL segment header. Both sides
//! compile this crate, so both sides carry [`Handshake::LOCAL`]; the check is
//! pure and `no_std` so the loader (F3), the hot loop (`F1.RT.03`) and the
//! WAL reader (`F1.RT.05`) call the same function and print the same words.

use core::fmt;
use core::mem::offset_of;

use crate::event::{RawEvent, RAW_EVENT_SIZE, WIRE_VERSION};
use crate::kind::EventKind;
use crate::payload::PAYLOAD_SIZE;

/// A fingerprint of the layout this binary was compiled with: the sizes, the
/// offset of every `RawEvent` field, and every kind code. Two binaries that
/// agree on [`WIRE_VERSION`] but not on this were built from different
/// definitions — the mistake a version byte alone does not catch, because
/// nobody bumps the byte for the change they did not notice they made.
pub const SCHEMA_HASH: u64 = fnv1a_64(&LAYOUT);

/// The layout descriptor `SCHEMA_HASH` digests. Every entry is a number the
/// compiler fixes: change a field's position or a kind's value and the hash
/// moves; rename a field and it does not, which is right — names are not on
/// the wire.
const LAYOUT: [u64; 18 + EventKind::ALL.len()] = {
    let mut layout = [0u64; 18 + EventKind::ALL.len()];
    layout[0] = WIRE_VERSION as u64;
    layout[1] = RAW_EVENT_SIZE as u64;
    layout[2] = PAYLOAD_SIZE as u64;
    layout[3] = offset_of!(RawEvent, ts_ns) as u64;
    layout[4] = offset_of!(RawEvent, seq) as u64;
    layout[5] = offset_of!(RawEvent, session_id) as u64;
    layout[6] = offset_of!(RawEvent, pid) as u64;
    layout[7] = offset_of!(RawEvent, tgid) as u64;
    layout[8] = offset_of!(RawEvent, ppid) as u64;
    layout[9] = offset_of!(RawEvent, uid) as u64;
    layout[10] = offset_of!(RawEvent, taint) as u64;
    layout[11] = offset_of!(RawEvent, kind) as u64;
    layout[12] = offset_of!(RawEvent, outcome) as u64;
    layout[13] = offset_of!(RawEvent, flags) as u64;
    layout[14] = offset_of!(RawEvent, wire_version) as u64;
    layout[15] = offset_of!(RawEvent, reserved) as u64;
    layout[16] = offset_of!(RawEvent, payload) as u64;
    layout[17] = EventKind::ALL.len() as u64;
    let mut i = 0;
    while i < EventKind::ALL.len() {
        layout[18 + i] = EventKind::ALL[i] as u64;
        i += 1;
    }
    layout
};

/// FNV-1a over the little-endian bytes of the words: `const`, dependency-free,
/// and only ever compared for equality.
const fn fnv1a_64(words: &[u64]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < words.len() {
        let bytes = words[i].to_le_bytes();
        let mut j = 0;
        while j < 8 {
            hash ^= bytes[j] as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            j += 1;
        }
        i += 1;
    }
    hash
}

/// What one side of a pairing declares before any event crosses it.
///
/// The BPF object carries its producer's handshake in a read-only map the
/// loader reads before attaching (F3); a WAL segment header carries the
/// writer's (`F1.RT.05`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Handshake {
    /// The producer's [`WIRE_VERSION`].
    pub wire_version: u8,
    /// Layout padding; always zero.
    pub pad0: [u8; 7],
    /// The producer's [`SCHEMA_HASH`].
    pub schema_hash: u64,
}

impl Handshake {
    /// This binary's own declaration.
    pub const LOCAL: Handshake = Handshake {
        wire_version: WIRE_VERSION,
        pad0: [0; 7],
        schema_hash: SCHEMA_HASH,
    };

    /// Whether a producer that declared `self` may talk to this binary.
    ///
    /// # Errors
    ///
    /// [`WireVersionMismatch`] names both sides. Refusing is the whole
    /// mechanism: a mismatch is never bridged, never coerced, never skipped
    /// silently — the caller refuses to attach, or skips the segment and warns.
    pub const fn negotiate(self) -> Result<(), WireVersionMismatch> {
        if self.wire_version != WIRE_VERSION {
            return Err(WireVersionMismatch::Version {
                expected: WIRE_VERSION,
                found: self.wire_version,
            });
        }
        if self.schema_hash != SCHEMA_HASH {
            return Err(WireVersionMismatch::Schema {
                expected: SCHEMA_HASH,
                found: self.schema_hash,
            });
        }
        Ok(())
    }
}

/// Whether one event was written by a producer this binary can read — the
/// per-event form of the check, one byte compare on the hot loop.
///
/// # Errors
///
/// [`WireVersionMismatch::Version`] with both bytes.
pub const fn check_event(event: &RawEvent) -> Result<(), WireVersionMismatch> {
    if event.wire_version == WIRE_VERSION {
        Ok(())
    } else {
        Err(WireVersionMismatch::Version {
            expected: WIRE_VERSION,
            found: event.wire_version,
        })
    }
}

/// The two sides do not agree on the wire. Carries both values so the
/// diagnostic says which side is old, not merely that they differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WireVersionMismatch {
    /// The version bytes differ.
    Version {
        /// This binary's.
        expected: u8,
        /// The producer's.
        found: u8,
    },
    /// The version bytes agree and the layouts do not: a definition changed
    /// without its version bump.
    Schema {
        /// This binary's.
        expected: u64,
        /// The producer's.
        found: u64,
    },
}

impl fmt::Display for WireVersionMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            WireVersionMismatch::Version { expected, found } => {
                let side = if found < expected {
                    "the producer is older"
                } else {
                    "the producer is newer"
                };
                write!(
                    f,
                    "wire version mismatch: this binary speaks {expected}, the producer speaks {found} ({side}); refusing — rebuild both from the same aisme-ebpf-common"
                )
            }
            WireVersionMismatch::Schema { expected, found } => write!(
                f,
                "wire schema mismatch at version {WIRE_VERSION}: this binary's layout is {expected:#018x}, the producer's is {found:#018x}; a wire type changed without a WIRE_VERSION bump — refusing"
            ),
        }
    }
}

impl core::error::Error for WireVersionMismatch {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_producer_built_from_this_crate_is_accepted() {
        assert_eq!(Handshake::LOCAL.negotiate(), Ok(()));
        assert_eq!(check_event(&RawEvent::ZERO), Ok(()));
    }

    #[test]
    fn an_old_driver_is_refused_by_a_new_daemon_and_says_which_is_old() {
        // The plan's test: the daemon is this binary; the driver declares the
        // version before this one.
        let old_driver = Handshake {
            wire_version: WIRE_VERSION.wrapping_sub(1),
            ..Handshake::LOCAL
        };
        let refusal = old_driver.negotiate().unwrap_err();
        assert_eq!(
            refusal,
            WireVersionMismatch::Version {
                expected: WIRE_VERSION,
                found: WIRE_VERSION.wrapping_sub(1)
            }
        );
        let mut text = heapless_string();
        core::fmt::write(&mut text, format_args!("{refusal}")).unwrap();
        assert!(
            text.as_str().contains("the producer is older"),
            "{}",
            text.as_str()
        );
        assert!(text.as_str().contains("refusing"));
    }

    #[test]
    fn a_new_driver_is_refused_by_an_old_daemon() {
        let mut event = RawEvent::ZERO;
        event.wire_version = WIRE_VERSION + 1;
        assert_eq!(
            check_event(&event),
            Err(WireVersionMismatch::Version {
                expected: WIRE_VERSION,
                found: WIRE_VERSION + 1
            })
        );
        let mut text = heapless_string();
        core::fmt::write(
            &mut text,
            format_args!("{}", check_event(&event).unwrap_err()),
        )
        .unwrap();
        assert!(text.as_str().contains("the producer is newer"));
    }

    #[test]
    fn the_same_version_with_a_different_layout_is_refused() {
        // The change nobody bumped the byte for.
        let drifted = Handshake {
            schema_hash: SCHEMA_HASH ^ 1,
            ..Handshake::LOCAL
        };
        assert!(matches!(
            drifted.negotiate(),
            Err(WireVersionMismatch::Schema { expected, found })
                if expected == SCHEMA_HASH && found == SCHEMA_HASH ^ 1
        ));
    }

    #[test]
    fn the_schema_hash_digests_positions_and_codes_not_names() {
        // Moving a field or renumbering a kind must move the hash; the
        // descriptor is what makes that true, so check what it holds.
        assert_eq!(LAYOUT[1], 320);
        assert_eq!(LAYOUT[11], 44, "kind sits at byte 44");
        assert_eq!(LAYOUT[16], 64, "payload sits at byte 64");
        assert_eq!(LAYOUT[17], 55);
        assert_eq!(LAYOUT[18], 0x0001);
        assert_eq!(LAYOUT[LAYOUT.len() - 1], 0x9002);
        // And the digest is sensitive to any one word.
        let mut moved = LAYOUT;
        moved[16] = 72;
        assert_ne!(fnv1a_64(&moved), SCHEMA_HASH);
        let mut renumbered = LAYOUT;
        renumbered[18] = 0x0009;
        assert_ne!(fnv1a_64(&renumbered), SCHEMA_HASH);
    }

    #[test]
    fn handshake_is_a_fixed_sixteen_bytes() {
        assert_eq!(core::mem::size_of::<Handshake>(), 16);
        assert_eq!(core::mem::align_of::<Handshake>(), 8);
    }

    /// A bounded `fmt::Write` sink, since the crate has no `alloc`.
    struct Sink {
        buf: [u8; 256],
        len: usize,
    }

    impl Sink {
        fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }

    impl fmt::Write for Sink {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let end = self.len + s.len();
            if end > self.buf.len() {
                return Err(fmt::Error);
            }
            self.buf[self.len..end].copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }

    fn heapless_string() -> Sink {
        Sink {
            buf: [0; 256],
            len: 0,
        }
    }
}
