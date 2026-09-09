// SPDX-License-Identifier: Apache-2.0
//! `aisme-loaderd --sample` — the torn-read run (`docs/06` points 4 and 6).
//!
//! The reader and the publisher are two invocations of **this** binary, so what
//! is measured is the shipped code and not a test-only reimplementation of it.

use crate::platform;

/// Sample the published policy `count` times while something else republishes.
///
/// The property: every sample must be *internally consistent* — the verdict it
/// reads must be one the publisher actually wrote, never absent and never a
/// third value. A half-filled trie would show up as an absent key or a verdict
/// from neither policy.
///
/// **This is weaker than sampling from a BPF program and says so.** It measures
/// the publisher's ordering, not the reader path F3 will have; the kernel-side
/// version is owed by `F3.PT.02`.
///
/// Returns the exit code.
pub fn run(count: u64, path: &str, expected: &[u8]) -> u8 {
    let reader = match platform::reader() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot open the published policy: {}", e.detail);
            return 1;
        }
    };
    let key = platform::lookup_key(path);
    let started = std::time::Instant::now();
    let mut swaps = 0u64;
    let mut absent = 0u64;
    let mut foreign = 0u64;
    let mut last_index: Option<u64> = None;
    let mut last_generation = 0u64;

    for _ in 0..count {
        let Ok(sample) = platform::sample(&reader, &key) else {
            eprintln!("a read failed mid-run");
            return 1;
        };
        if last_index.is_some_and(|i| i != sample.index) {
            swaps += 1;
        }
        last_index = Some(sample.index);
        last_generation = sample.generation;
        match sample.verdict {
            None => absent += 1,
            Some(v) if !expected.contains(&v) => foreign += 1,
            Some(_) => {}
        }
    }

    let elapsed = started.elapsed();
    println!("samples={count} swaps={swaps} absent={absent} foreign={foreign} generation={last_generation} elapsed_ms={}", elapsed.as_millis());

    if absent > 0 || foreign > 0 {
        eprintln!("TORN: a reader saw a policy the publisher never had in force");
        return 1;
    }
    if swaps == 0 {
        // The harness checking itself. A clean million with no swap means the
        // publisher stopped, and a run that never raced proves nothing.
        eprintln!("NO SWAP OBSERVED: the publisher was not running, so this run tested nothing");
        return 1;
    }
    println!("PASS sample: {count} reads, {swaps} swaps, none torn");
    0
}
