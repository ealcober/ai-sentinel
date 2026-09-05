// SPDX-License-Identifier: Apache-2.0
//! Semantic capture ladder: TLS key-log tiers, offset resolution, SSE reassembly.
//!
//! Strictly read-only with respect to the observed process: it never patches,
//! hooks or defeats certificate pinning (`I-01`, `I-02`).
