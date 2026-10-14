// SPDX-License-Identifier: Apache-2.0
//! `OpenTelemetry` export and semantic conventions.
//!
//! Prompts and chain-of-thought are excluded from export by default; hashes and
//! classifications only (`I-08`).
//!
//! **A stub, and no task table names it yet.** Every other stub in this
//! workspace can point at the phase that implements it; this one cannot, and
//! saying so is better than inventing a phase. Recorded as an open point in
//! `docs/ai/STATE.md` — the export surface is specified in plan §4.4 and
//! `I-08`, and which phase builds it is not.
