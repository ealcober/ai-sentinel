// SPDX-License-Identifier: Apache-2.0
//! `--open-bench`: what one `openat` costs the agent, measured from inside the
//! session (`F2.WS.09`).
//!
//! **It lives in the simulator because it is the simulated agent's own
//! experience.** T1 is not a number the supervisor can report about itself: the
//! figure that matters is how long the syscall was *held* from the caller's
//! side, and only the caller can time that. The simulator is the process
//! `aisme run` `exec`s, so it is the one that can.
//!
//! **It must be the `exec`ed process and not a child of one.** A grandchild's
//! path arguments cannot be read by a sibling supervisor under Yama's default
//! `ptrace_scope`, so every open in it is denied and the figure would measure a
//! refusal instead of a decision. That is the open decision recorded in
//! `docs/10`; until it is taken, a bench that ran through `sh -c` would report
//! a fast, meaningless number.

use std::time::Instant;

/// One bench run's request.
pub struct Request {
    /// The path to open, over and over.
    pub path: String,
    /// How many times.
    pub count: u32,
    /// Ask for creation and writing rather than reading — the shape a Landlock
    /// write scope has an opinion about.
    pub create: bool,
}

impl Request {
    /// Parse `--open-bench <path> [--count N] [--create]`.
    ///
    /// # Errors
    ///
    /// The first argument that does not belong, named.
    pub fn parse(args: &[String]) -> Result<Option<Request>, String> {
        let Some(at) = args.iter().position(|a| a == "--open-bench") else {
            return Ok(None);
        };
        let path = args
            .get(at + 1)
            .filter(|a| !a.starts_with("--"))
            .cloned()
            .ok_or_else(|| "--open-bench needs a path".to_owned())?;
        let mut count = 1_000_u32;
        let mut create = false;
        let mut it = args[at + 2..].iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--count" => {
                    let raw = it
                        .next()
                        .ok_or_else(|| "--count needs a value".to_owned())?;
                    count = raw
                        .parse()
                        .map_err(|_| format!("--count {raw} is not a number"))?;
                }
                "--create" => create = true,
                other => return Err(format!("unknown argument `{other}`")),
            }
        }
        if count == 0 {
            return Err("--count 0 measures nothing".to_owned());
        }
        Ok(Some(Request {
            path,
            count,
            create,
        }))
    }
}

/// What the run cost, in microseconds.
pub struct Report {
    /// Opens that returned a descriptor.
    pub ok: u32,
    /// Opens the kernel refused — a measurement, not a failure: a denial is
    /// exactly what the Landlock leg is timing.
    pub denied: u32,
    /// Every sample, sorted, so any percentile can be taken from one run.
    samples_us: Vec<f64>,
}

impl Report {
    /// The value below which `q` of the samples fall, by nearest rank.
    ///
    /// **Nearest rank, not interpolation.** Every sample is a syscall that
    /// really took that long, and a p99 that is the average of two neighbours
    /// is a duration nothing experienced. With a rank the figure can always be
    /// pointed at.
    #[must_use]
    pub fn percentile(&self, q: f64) -> f64 {
        if self.samples_us.is_empty() {
            return 0.0;
        }
        let last = self.samples_us.len() - 1;
        #[expect(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a rank into a sample vector; the count is far below f64's exact range"
        )]
        let rank = ((q * self.samples_us.len() as f64).ceil() as usize).saturating_sub(1);
        self.samples_us[rank.min(last)]
    }

    /// How many samples the percentiles were taken over.
    ///
    /// Printed with every figure, because **a p999 over 100 samples is not a
    /// p999** — it is the maximum wearing a percentile's name.
    #[must_use]
    pub fn samples(&self) -> usize {
        self.samples_us.len()
    }
}

/// Open `path` `count` times, timing each one.
///
/// Each open is closed immediately: the descriptor is not the measurement, and
/// a run of a hundred thousand that kept them would hit the descriptor limit
/// and start measuring `EMFILE`.
#[must_use]
pub fn run(request: &Request) -> Report {
    let mut samples_us = Vec::with_capacity(request.count as usize);
    let (mut ok, mut denied) = (0, 0);
    for _ in 0..request.count {
        let started = Instant::now();
        let opened = if request.create {
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&request.path)
        } else {
            std::fs::File::open(&request.path)
        };
        // Taken before the descriptor is dropped: `close` is not part of the
        // syscall being measured.
        let elapsed = started.elapsed();
        match opened {
            Ok(file) => {
                ok += 1;
                drop(file);
            }
            Err(_) => denied += 1,
        }
        samples_us.push(elapsed.as_secs_f64() * 1_000_000.0);
    }
    samples_us.sort_by(f64::total_cmp);
    Report {
        ok,
        denied,
        samples_us,
    }
}

/// One line, parseable and readable, with every figure carrying its count.
#[must_use]
pub fn render(request: &Request, report: &Report) -> String {
    format!(
        "open-bench path={} count={} ok={} denied={} samples={} \
         p50_us={:.3} p95_us={:.3} p99_us={:.3} p999_us={:.3}",
        request.path,
        request.count,
        report.ok,
        report.denied,
        report.samples(),
        report.percentile(0.50),
        report.percentile(0.95),
        report.percentile(0.99),
        report.percentile(0.999),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{run, Report, Request};

    fn report_of(samples: &[f64]) -> Report {
        let mut sorted = samples.to_vec();
        sorted.sort_by(f64::total_cmp);
        Report {
            ok: u32::try_from(sorted.len()).unwrap_or(0),
            denied: 0,
            samples_us: sorted,
        }
    }

    /// A distribution whose percentiles are known by construction: ninety-nine
    /// samples of 1 µs and one of 1000 µs.
    ///
    /// The p99 is the assertion that matters. A **mean** over this set is about
    /// 11 µs — which is why §2.22 states percentiles: the mean hides exactly
    /// the tail these budgets exist to bound.
    #[test]
    fn a_known_distribution_yields_its_known_percentiles() {
        let mut samples = vec![1.0; 99];
        samples.push(1000.0);
        let report = report_of(&samples);

        assert_eq!(report.samples(), 100);
        assert!((report.percentile(0.50) - 1.0).abs() < f64::EPSILON, "p50");
        assert!((report.percentile(0.95) - 1.0).abs() < f64::EPSILON, "p95");
        assert!(
            (report.percentile(0.99) - 1.0).abs() < f64::EPSILON,
            "p99 over 100 samples is the 99th, which is still 1 µs"
        );
        assert!(
            (report.percentile(0.999) - 1000.0).abs() < f64::EPSILON,
            "the outlier is the p999, and a mean would have hidden it"
        );
    }

    /// Every sample the percentile returns is a sample that was taken.
    ///
    /// Nearest rank rather than interpolation: a figure between two neighbours
    /// is a duration nothing experienced and nobody can point at.
    #[test]
    fn a_percentile_is_always_one_of_the_samples() {
        let report = report_of(&[3.0, 1.0, 4.0, 1.5, 9.0, 2.6]);
        for q in [0.0, 0.25, 0.5, 0.95, 0.99, 1.0] {
            let value = report.percentile(q);
            assert!(
                [3.0, 1.0, 4.0, 1.5, 9.0, 2.6]
                    .iter()
                    .any(|s| (s - value).abs() < f64::EPSILON),
                "p{q} returned {value}, which is not a sample"
            );
        }
    }

    /// An empty run answers zero rather than panicking on an empty vector —
    /// and `--count 0` is refused before it can produce one.
    #[test]
    fn no_samples_is_zero_and_not_a_panic() {
        assert!((report_of(&[]).percentile(0.99) - 0.0).abs() < f64::EPSILON);
        let args = [
            "--open-bench".to_owned(),
            "/etc/hostname".to_owned(),
            "--count".to_owned(),
            "0".to_owned(),
        ];
        assert!(Request::parse(&args).is_err());
    }

    /// The harness measures a real syscall, and a refusal is counted as one.
    ///
    /// Calibration before anything is believed: a path that exists is opened
    /// `count` times and every open succeeds; a path that does not is refused
    /// every time and still yields `count` samples, because the time a denial
    /// takes is exactly what the Landlock leg reports.
    #[test]
    fn the_harness_counts_what_happened_and_times_denials_too() {
        let opened = run(&Request {
            path: "/etc/hostname".to_owned(),
            count: 32,
            create: false,
        });
        assert_eq!(opened.ok, 32);
        assert_eq!(opened.denied, 0);
        assert_eq!(opened.samples(), 32);

        let refused = run(&Request {
            path: "/proc/nonexistent-aisme-probe".to_owned(),
            count: 32,
            create: false,
        });
        assert_eq!(refused.ok, 0);
        assert_eq!(refused.denied, 32);
        assert_eq!(
            refused.samples(),
            32,
            "a denial is a measurement; dropping its sample would bias the figure fast"
        );
    }
}
