// SPDX-License-Identifier: Apache-2.0
//! The error the L1 traits return.
//!
//! Small on purpose: an adapter's own failure detail travels in `detail`,
//! and the engine reacts to `kind`. `#[non_exhaustive]` on the kind, so a
//! kind added later does not change the trait signatures the freeze
//! protects (§3.7).

/// The engine's `Result`.
pub type Result<T> = core::result::Result<T, Error>;

/// Why a trait call failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// What class of failure.
    pub kind: ErrorKind,
    /// The adapter's words, for the log and the UI.
    pub detail: String,
}

/// The classes the engine distinguishes.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The platform cannot do this at all; the degradation state machine
    /// records which function it lost (`I-19`).
    Unsupported,
    /// A sensor or enforcer lost its attachment: `DEGRADED`, loudly.
    Detached,
    /// The budget passed before the answer came.
    Timeout,
    /// The caller asked for something the current state does not admit
    /// (a token already resumed, a generation already published).
    Invalid,
    /// It failed; `detail` says how.
    Failed,
}

impl Error {
    /// An error of `kind` with `detail`.
    #[must_use]
    pub fn new(kind: ErrorKind, detail: impl Into<String>) -> Error {
        Error {
            kind,
            detail: detail.into(),
        }
    }

    /// [`ErrorKind::Unsupported`].
    #[must_use]
    pub fn unsupported(detail: impl Into<String>) -> Error {
        Error::new(ErrorKind::Unsupported, detail)
    }

    /// [`ErrorKind::Failed`].
    #[must_use]
    pub fn failed(detail: impl Into<String>) -> Error {
        Error::new(ErrorKind::Failed, detail)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.detail)
    }
}

impl core::error::Error for Error {}
