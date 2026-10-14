// SPDX-License-Identifier: Apache-2.0
//! Shared desktop and mobile client core, exposed to the shells through uniffi.
//!
//! Keeps one client implementation behind two native surfaces (`ADR-04`).
//!
//! **A stub until phases `F8b` and `F11`** — the desktop shell and the mobile
//! one. One crate, two phases, which is the point of `ADR-04`.
