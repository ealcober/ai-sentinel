// SPDX-License-Identifier: Apache-2.0
//! Observer schema and scoring.
//!
//! Schema and scoring only; the HTTP client lives in `aisme-forensicd`. The
//! Observer can raise severity or ask for confirmation and can never authorize
//! (`I-04`).
//!
//! **A stub until phase `F6`**, which owns the Observer client and the
//! inter-rater reliability harness.
