// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
//! `F1.EV.03`: the wire's properties, checked over the whole code space.
//!
//! The compile-time half — size, every offset, endianness — lives beside the
//! types in `event.rs` and `payload.rs`, where it fails the build on either
//! target. This file holds what needs to run: the code space is `u16`, so the
//! properties are checked exhaustively rather than sampled.

use aisme_ebpf_common::{
    EventKind, EventPayload, KindCode, Payload, Range, RawEvent, RAW_EVENT_SIZE,
};

/// Every code either decodes to a variant that sits in the range the code
/// names, or decodes to nothing — never to a variant of another range.
#[test]
fn decoding_never_crosses_a_range() {
    for code in 0..=u16::MAX {
        match KindCode(code).decode() {
            Ok(kind) => {
                assert_eq!(Some(kind.range()), Range::of(code), "{code:#06x}");
                assert!(kind.range().contains(code));
                assert_eq!(kind.code(), KindCode(code));
            }
            Err(unknown) => assert_eq!(unknown.0, KindCode(code)),
        }
    }
}

/// `EventKind::ALL` and `from_code` describe the same set: nothing decodes
/// that `ALL` omits, and nothing in `ALL` fails to decode.
#[test]
fn all_is_exactly_the_decodable_set() {
    let decodable = (0..=u16::MAX)
        .filter(|&code| KindCode(code).decode().is_ok())
        .count();
    assert_eq!(decodable, EventKind::ALL.len());
    for kind in EventKind::ALL {
        assert_eq!(kind.code().decode(), Ok(kind));
    }
}

/// The range → payload map is total: every reserved range views as a payload,
/// and every code in a reserved range views — known variant or not.
#[test]
fn every_reserved_code_views_as_its_range_payload() {
    let payload = EventPayload::ZERO;
    for code in 0..=u16::MAX {
        let Some(range) = Range::of(code) else {
            assert!(
                code >= 0xA000,
                "{code:#06x} unclassified below the last range"
            );
            continue;
        };
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
        assert_eq!(seen, range, "{code:#06x}");
    }
}

/// The wire is little-endian, and the two-byte kind at offset 44 is read the
/// way `bpfel` writes it: low byte first.
#[test]
fn the_kind_is_little_endian_on_the_wire() {
    let mut bytes = [0u8; RAW_EVENT_SIZE];
    bytes[44] = 0x01;
    bytes[45] = 0x20; // FileOpen = 0x2001
                      // SAFETY: every field of `RawEvent` is an integer, an integer newtype or
                      // the all-integer payload union, so every bit pattern is a valid value.
    let event: RawEvent = unsafe { core::mem::transmute(bytes) };
    assert_eq!(event.kind.decode(), Ok(EventKind::FileOpen));
    assert_eq!(u16::from_le_bytes([bytes[44], bytes[45]]), 0x2001);
}

/// A `RawEvent` written as bytes and read back is the same event: the type
/// carries no padding whose contents could differ, so the whole 320 bytes are
/// the wire.
#[test]
fn a_round_trip_through_bytes_is_the_identity() {
    let mut event = RawEvent::ZERO;
    event.ts_ns = 0x0102_0304_0506_0708;
    event.seq = 7;
    event.session_id = u64::MAX;
    event.pid = 1;
    event.tgid = 2;
    event.ppid = 3;
    event.uid = 1000;
    event.taint = 0b1010;
    event.kind = EventKind::SockConnect.into();
    event.flags = 1;
    event.payload.net.remote_port = 443;
    // SAFETY: `RawEvent` is `repr(C)` with no padding (every offset is pinned
    // at compile time and the fields tile the 320 bytes), so its bytes are
    // fully initialised and the transmute in each direction is a copy.
    let bytes: [u8; RAW_EVENT_SIZE] = unsafe { core::mem::transmute(event) };
    // SAFETY: as above — every bit pattern is a valid `RawEvent`.
    let back: RawEvent = unsafe { core::mem::transmute(bytes) };
    assert_eq!(back.ts_ns, event.ts_ns);
    assert_eq!(back.kind, event.kind);
    assert_eq!(back.taint, 0b1010);
    assert_eq!(back.payload.bytes(), event.payload.bytes());
    assert_eq!(&bytes[0..8], &0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(&bytes[44..46], &0x3001u16.to_le_bytes());
}
