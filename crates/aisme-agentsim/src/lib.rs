// SPDX-License-Identifier: Apache-2.0
//! `aisme-agentsim` — the agent simulator (`F1.SIM.01`, `F1.SIM.02`).
//!
//! One artefact serves two gates: the CPU gate replays it as component (c)
//! of §2.22's reference workload, and the correlation gate scores against
//! the hidden tokens it carries (§4.6). The library half is what the scorer
//! (`F5.CO.*`) and `verify-budgets` link against; the binary is what the
//! workload runs.

pub mod openbench;
pub mod record;
pub mod replay;
pub mod trace;
