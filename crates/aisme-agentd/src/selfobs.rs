// SPDX-License-Identifier: Apache-2.0
//! Reading the daemon's own resource use (`F1.RT.06`, the L3 half).
//!
//! `aisme-core::metrics` holds the names and the snapshot; measuring RSS and
//! CPU is I/O, so it lives here. On Linux both come from `/proc/self`; on
//! anything else the values stay **absent**, which is what `Metrics` means by
//! `None` — a daemon that cannot measure itself says so instead of reporting
//! zero (`I-16`, and general rule 9).

use std::time::Instant;

/// What one process is using, as `/proc` reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessUsage {
    /// Resident set size — `aisme.daemon.rss_bytes`.
    pub rss_bytes: u64,
    /// CPU as thousandths of one core since the last sample —
    /// `aisme.daemon.cpu_ratio`.
    pub cpu_milli: u32,
}

/// Samples this process's usage, keeping enough state to turn the kernel's
/// cumulative counters into a rate.
#[derive(Debug)]
pub struct SelfObserver {
    last: Option<(Instant, u64)>,
    ticks_per_second: u64,
    page_size: u64,
}

impl SelfObserver {
    /// A sampler for this process.
    #[must_use]
    pub fn new() -> SelfObserver {
        SelfObserver {
            last: None,
            // `sysconf(_SC_CLK_TCK)` is 100 on every Linux AISME targets;
            // reading it needs libc, and being wrong here scales the CPU
            // ratio rather than breaking it. F5.OB.* replaces the constant
            // when it takes the OTLP exporter.
            ticks_per_second: 100,
            page_size: 4096,
        }
    }

    /// Sample. The first call establishes the baseline and reports a CPU
    /// ratio of zero *for the interval it did not observe* — not because it
    /// measured zero: `rss_bytes` is real from the first call.
    ///
    /// Returns `None` where the platform does not expose `/proc/self`, which
    /// keeps the metric absent rather than zero.
    pub fn sample(&mut self) -> Option<ProcessUsage> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        // Fields 14 and 15 (utime, stime), 1-based, after the comm field —
        // which can contain spaces and parentheses, so the split starts
        // after the last ')'.
        let after_comm = &stat[stat.rfind(')')? + 1..];
        let mut fields = after_comm.split_whitespace();
        let utime: u64 = fields.nth(11)?.parse().ok()?;
        let stime: u64 = fields.next()?.parse().ok()?;
        let ticks = utime + stime;
        let now = Instant::now();
        // Integer arithmetic, like DT-09's score: a ratio computed in
        // floating point differs between targets in its last digits, and
        // this number ends up in a budget report that is compared across
        // machines. thousandths = ticks * (1000 / tps) ms of CPU, over the
        // elapsed ms, times 1000.
        let cpu_milli = match self.last {
            Some((then, prior_ticks)) => {
                let elapsed_ms =
                    u64::try_from(now.duration_since(then).as_millis()).unwrap_or(u64::MAX);
                let used_ticks = ticks.saturating_sub(prior_ticks);
                if elapsed_ms == 0 || self.ticks_per_second == 0 {
                    0
                } else {
                    let milli = used_ticks
                        .saturating_mul(1_000_000)
                        .saturating_div(self.ticks_per_second.saturating_mul(elapsed_ms));
                    u32::try_from(milli).unwrap_or(u32::MAX)
                }
            }
            None => 0,
        };
        self.last = Some((now, ticks));
        Some(ProcessUsage {
            rss_bytes: rss_pages * self.page_size,
            cpu_milli,
        })
    }
}

impl Default for SelfObserver {
    fn default() -> SelfObserver {
        SelfObserver::new()
    }
}

#[cfg(test)]
// A panic *is* the failure report in a test, so the two lints the daemon
// denies are allowed here — and only here, which is the point: the denial
// covers the code that runs in production (§3.5, F1.RT.08).
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_daemon_can_measure_its_own_resident_size() {
        let mut observer = SelfObserver::new();
        let Some(first) = observer.sample() else {
            // Not Linux: the metric stays absent, which is the point.
            return;
        };
        assert!(
            first.rss_bytes > 1024 * 1024,
            "rss {} looks wrong",
            first.rss_bytes
        );
        assert!(
            first.rss_bytes < 512 * 1024 * 1024,
            "rss {} looks wrong",
            first.rss_bytes
        );
        assert_eq!(
            first.cpu_milli, 0,
            "the first sample has no interval to rate"
        );

        // Burn a little CPU so the second sample has something to report.
        let mut sink = 0u64;
        let start = Instant::now();
        while start.elapsed().as_millis() < 30 {
            sink = sink.wrapping_add(u64::try_from(start.elapsed().as_nanos()).unwrap_or(0));
        }
        assert!(sink > 0);
        let second = observer.sample().expect("second sample");
        assert!(
            second.cpu_milli <= 1_000 * 64,
            "cpu {} exceeds any sane host",
            second.cpu_milli
        );
    }

    #[test]
    fn a_sample_feeds_the_core_snapshot() {
        let mut metrics = aisme_core::metrics::Metrics::default();
        let mut observer = SelfObserver::new();
        if let Some(usage) = observer.sample() {
            metrics.observe_process(usage.rss_bytes, usage.cpu_milli);
            assert_eq!(metrics.rss_bytes, Some(usage.rss_bytes));
        } else {
            assert_eq!(metrics.rss_bytes, None, "unmeasured stays absent");
        }
    }
}
