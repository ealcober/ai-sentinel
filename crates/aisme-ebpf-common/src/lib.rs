// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
//! Wire types shared between the BPF programs and user space.
//!
//! `no_std`, zero dependencies, layout-stable: this crate is compiled into
//! kernel-verified code, so every type here is `repr(C)` and its layout is part
//! of the ABI. Changing one is a wire-format change (plan §F1.1.1).
#![no_std]
