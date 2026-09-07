// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
//! Wire types shared between the BPF programs and user space.
//!
//! `no_std`, zero dependencies, layout-stable: this crate is compiled into
//! kernel-verified code, so every type here is `repr(C)` and its layout is part
//! of the ABI. Changing one is a wire-format change (plan §F1.1.1).
#![no_std]

pub mod event;
pub mod kind;
pub mod payload;
pub mod verdict;
pub mod version;

pub use event::{Outcome, OutcomeCode, RawEvent, FLAG_TRUNCATED, RAW_EVENT_SIZE, WIRE_VERSION};
pub use kind::{EventKind, KindCode, Range};
pub use payload::{EventPayload, Payload, PAYLOAD_SIZE};
pub use verdict::Verdict;
pub use version::{check_event, Handshake, WireVersionMismatch, SCHEMA_HASH};
