// SPDX-License-Identifier: Apache-2.0
//! `DT-09` — session risk accumulation (`F1.DT.02`).
//!
//! A decaying score in thousandths: taint acquisitions, class shifts,
//! instruction-bearing inputs, denies and detector hits each contribute.
//! It drives the prompt's policy-severity line and `aisme.session.risk`
//! (`F5.DT.06`), and at `Critical` the session's posture tightens.
//!
//! Three properties the plan asks for, and how each is made true:
//!
//! - **Deterministic.** Integer arithmetic only — thousandths, never
//!   floating point, so identical input gives an identical score on every
//!   target (`T4.13.01`). Decay is exponential by halving over a
//!   half-life, computed from elapsed nanoseconds passed in, never from a
//!   clock this module reads.
//! - **Decaying.** Risk is a statement about *now*; a session that did one
//!   worrying thing an hour ago and nothing since is not the session that
//!   did it a second ago.
//! - **Weights as data.** [`Weights`] is a plain struct that `F1.DT.03`
//!   loads as signed bytes. Nothing here is learned, and nothing here
//!   decides a verdict — the score sets the *posture* and what the prompt
//!   shows (`H-12`: severity may rise, never authorize).

use crate::ontology::Severity;

/// What each kind of event contributes, in thousandths of a risk point.
/// Shipped as signed data (`F1.DT.03`); these are the defaults the product
/// ships with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Weights {
    /// A taint category acquired.
    pub taint_acquired: u32,
    /// The session did something in a class it had not done before.
    pub class_shift: u32,
    /// An instruction-bearing input entered the context plane.
    pub instruction_bearing_input: u32,
    /// A deny was enforced.
    pub deny: u32,
    /// A detector fired, scaled by its severity.
    pub detector_hit: [u32; 4],
    /// Half-life of the score, in seconds.
    pub half_life_s: u32,
    /// Thresholds: the score at which the posture reaches Medium, High and
    /// Critical. Below the first, the posture is Low.
    pub thresholds: [u32; 3],
}

impl Weights {
    /// The shipped defaults.
    pub const DEFAULT: Weights = Weights {
        taint_acquired: 1_000,
        class_shift: 1_500,
        instruction_bearing_input: 2_500,
        deny: 3_000,
        // Low, Medium, High, Critical.
        detector_hit: [500, 2_000, 5_000, 10_000],
        half_life_s: 900,
        thresholds: [5_000, 12_000, 25_000],
    };

    /// Whether the weights are usable: a zero half-life would never decay
    /// and thresholds out of order would make the posture non-monotone.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.half_life_s > 0
            && self.thresholds.windows(2).all(|w| w[0] < w[1])
            && self.detector_hit.windows(2).all(|w| w[0] <= w[1])
    }
}

impl Default for Weights {
    fn default() -> Weights {
        Weights::DEFAULT
    }
}

/// Something that moved the score.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskEvent {
    /// A taint category was acquired.
    TaintAcquired,
    /// An action class new to this session.
    ClassShift,
    /// An instruction-bearing input entered.
    InstructionBearingInput,
    /// A deny was enforced.
    Deny,
    /// A detector fired.
    DetectorHit(Severity),
}

/// The accumulator. Deterministic, decaying, and it never decides anything:
/// it reports a score and a posture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionRisk {
    weights: Weights,
    score_milli: u32,
    last_ns: u64,
}

impl SessionRisk {
    /// A session starting at zero at `now_ns`.
    #[must_use]
    pub const fn new(weights: Weights, now_ns: u64) -> SessionRisk {
        SessionRisk {
            weights,
            score_milli: 0,
            last_ns: now_ns,
        }
    }

    /// The score at the last observation, in thousandths.
    #[must_use]
    pub const fn score_milli(&self) -> u32 {
        self.score_milli
    }

    /// The score as it stands at `now_ns`, decayed but not recorded.
    #[must_use]
    pub const fn score_at(&self, now_ns: u64) -> u32 {
        decay(
            self.score_milli,
            now_ns.saturating_sub(self.last_ns),
            self.weights.half_life_s,
        )
    }

    /// The posture at `now_ns`: what the prompt's severity line shows.
    #[must_use]
    pub fn posture_at(&self, now_ns: u64) -> Severity {
        let score = self.score_at(now_ns);
        let [medium, high, critical] = self.weights.thresholds;
        if score >= critical {
            Severity::Critical
        } else if score >= high {
            Severity::High
        } else if score >= medium {
            Severity::Medium
        } else {
            Severity::Low
        }
    }

    /// Record an event at `now_ns`: decay to now, then add its weight.
    /// Returns the new score.
    pub fn observe(&mut self, event: RiskEvent, now_ns: u64) -> u32 {
        self.score_milli = self.score_at(now_ns);
        self.last_ns = now_ns.max(self.last_ns);
        let w = &self.weights;
        let add = match event {
            RiskEvent::TaintAcquired => w.taint_acquired,
            RiskEvent::ClassShift => w.class_shift,
            RiskEvent::InstructionBearingInput => w.instruction_bearing_input,
            RiskEvent::Deny => w.deny,
            RiskEvent::DetectorHit(severity) => w.detector_hit[severity as usize - 1],
        };
        self.score_milli = self.score_milli.saturating_add(add);
        self.score_milli
    }
}

/// Halve `score` once per half-life, by integer arithmetic: the same answer
/// on every target, and no floating point on a path the WAL records.
///
/// Whole half-lives shift; the remainder interpolates linearly between the
/// two ends of the last one, which is monotone and needs no `powf`.
const fn decay(score: u32, elapsed_ns: u64, half_life_seconds: u32) -> u32 {
    if score == 0 || elapsed_ns == 0 || half_life_seconds == 0 {
        return score;
    }
    let half_life_ns = (half_life_seconds as u64) * 1_000_000_000;
    let whole = elapsed_ns / half_life_ns;
    if whole >= 32 {
        return 0;
    }
    #[allow(clippy::cast_possible_truncation)] // whole < 32
    let halved = score >> (whole as u32);
    let remainder = elapsed_ns % half_life_ns;
    // Between `halved` and `halved / 2`, linearly in the remainder.
    let span = (halved - halved / 2) as u64;
    // The quotient is at most `span`, which came from a u32, so the
    // narrowing cannot lose anything.
    #[allow(clippy::cast_possible_truncation)]
    let taken = (span * remainder / half_life_ns) as u32;
    halved - taken
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn the_shipped_weights_are_well_formed_and_the_broken_ones_are_not() {
        assert!(Weights::DEFAULT.is_well_formed());
        assert!(!Weights {
            half_life_s: 0,
            ..Weights::DEFAULT
        }
        .is_well_formed());
        assert!(!Weights {
            thresholds: [10, 5, 20],
            ..Weights::DEFAULT
        }
        .is_well_formed());
        assert!(!Weights {
            detector_hit: [10, 5, 20, 30],
            ..Weights::DEFAULT
        }
        .is_well_formed());
    }

    #[test]
    fn events_accumulate_and_the_posture_follows_the_thresholds() {
        let mut risk = SessionRisk::new(Weights::DEFAULT, 0);
        assert_eq!(risk.posture_at(0), Severity::Low);
        assert_eq!(risk.observe(RiskEvent::InstructionBearingInput, 0), 2_500);
        assert_eq!(risk.observe(RiskEvent::ClassShift, 0), 4_000);
        assert_eq!(
            risk.posture_at(0),
            Severity::Low,
            "below the first threshold"
        );
        assert_eq!(risk.observe(RiskEvent::Deny, 0), 7_000);
        assert_eq!(risk.posture_at(0), Severity::Medium);
        assert_eq!(
            risk.observe(RiskEvent::DetectorHit(Severity::High), 0),
            12_000
        );
        assert_eq!(risk.posture_at(0), Severity::High);
        assert_eq!(
            risk.observe(RiskEvent::DetectorHit(Severity::Critical), 0),
            22_000
        );
        assert_eq!(risk.observe(RiskEvent::TaintAcquired, 0), 23_000);
        assert_eq!(
            risk.observe(RiskEvent::DetectorHit(Severity::Low), 0),
            23_500
        );
        assert!(risk.score_milli() < 25_000);
        assert_eq!(risk.posture_at(0), Severity::High);
        assert_eq!(risk.observe(RiskEvent::Deny, 0), 26_500);
        assert_eq!(risk.posture_at(0), Severity::Critical);
    }

    #[test]
    fn the_score_halves_every_half_life_and_reaches_zero() {
        let weights = Weights {
            half_life_s: 100,
            ..Weights::DEFAULT
        };
        let mut risk = SessionRisk::new(weights, 0);
        risk.observe(RiskEvent::DetectorHit(Severity::Critical), 0);
        assert_eq!(risk.score_milli(), 10_000);
        assert_eq!(risk.score_at(100 * SECOND), 5_000);
        assert_eq!(risk.score_at(200 * SECOND), 2_500);
        assert_eq!(risk.score_at(300 * SECOND), 1_250);
        assert_eq!(risk.score_at(50 * SECOND), 7_500, "half way, half the step");
        assert_eq!(
            risk.score_at(10_000 * SECOND),
            0,
            "an old session is not a risky one"
        );
        // Monotone: never rises with time, never dips below the next whole
        // half-life's value.
        let mut previous = u32::MAX;
        for t in (0..400).step_by(7) {
            let now = risk.score_at(t * SECOND);
            assert!(now <= previous, "rose at {t}s: {now} > {previous}");
            previous = now;
        }
    }

    #[test]
    fn the_same_sequence_gives_the_same_score_every_time_and_time_moves_forward_only() {
        let run = || {
            let mut risk = SessionRisk::new(Weights::DEFAULT, 0);
            for (event, t) in [
                (RiskEvent::TaintAcquired, 0),
                (RiskEvent::InstructionBearingInput, 30),
                (RiskEvent::ClassShift, 300),
                (RiskEvent::DetectorHit(Severity::Medium), 900),
                (RiskEvent::Deny, 1_800),
            ] {
                risk.observe(event, t * SECOND);
            }
            (risk.score_milli(), risk.posture_at(1_800 * SECOND))
        };
        assert_eq!(run(), run());
        assert_eq!(
            run().0,
            5_487,
            "the value, measured then pinned: a silent change of arithmetic is a changed product"
        );
        // An event stamped before the last one does not rewind the clock.
        let mut risk = SessionRisk::new(Weights::DEFAULT, 100 * SECOND);
        risk.observe(RiskEvent::Deny, 100 * SECOND);
        let after = risk.score_milli();
        risk.observe(RiskEvent::TaintAcquired, 0);
        assert_eq!(risk.score_milli(), after + Weights::DEFAULT.taint_acquired);
    }
}
