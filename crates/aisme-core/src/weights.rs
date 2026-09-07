// SPDX-License-Identifier: Apache-2.0
//! The signed-weights format and its pure verifier (`F1.DT.03`).
//!
//! Detector weights, thresholds and the risk model ship as **signed data**,
//! like the offset manifest (`F4.DB.01`) and the endpoint catalogue: shipping
//! them as data is what lets them be updated without a release, and signing
//! them is what stops that from becoming an update channel into a security
//! decision.
//!
//! Two rules make this safe, and both are structural here:
//!
//! - **The loader is L3, the verifier is L1.** `aisme-core` has no crypto and
//!   no I/O: it parses the bytes, computes the digest, and asks a
//!   [`SignatureVerifier`] the loader supplies. So the parsing — the part an
//!   attacker's bytes reach first — is testable on every target, and the key
//!   handling lives where the platform's key store is.
//! - **No learned weights in a verdict path.** A weights file changes what
//!   the *risk score* and the prompt's severity line say (`DT-09`,
//!   `H-12`'s monotonicity). It cannot change a verdict, because
//!   [`CompiledPolicy`](crate::policy::CompiledPolicy) is compiled from
//!   policy text and never reads this file. [`Weights::is_well_formed`] is
//!   checked before the bytes are accepted, so a signed-but-nonsensical file
//!   is refused too.

use crate::risk::Weights;

/// The magic the file starts with: `AISMEW` and a format version.
pub const MAGIC: [u8; 8] = *b"AISMEW\x01\x00";

/// The format's version, the last byte of [`MAGIC`].
pub const FORMAT_VERSION: u8 = 1;

/// What the loader must be able to do, and all it must be able to do: say
/// whether `signature` is a valid signature of `message` under a key it
/// trusts. The implementation is L3 (`F5.FO.02`'s P-256 on the workstation,
/// the platform key store on mobile); `aisme-core` never sees a key.
pub trait SignatureVerifier {
    /// Whether the signature holds.
    fn verify(&self, message: &[u8], signature: &[u8], key_id: &[u8; 8]) -> bool;
}

/// Why a weights file was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WeightsError {
    /// Not this format, or not this version of it.
    BadMagic,
    /// The file ends inside a field.
    Truncated {
        /// Bytes the header says the file needs.
        needed: usize,
        /// Bytes there are.
        got: usize,
    },
    /// The digest over the body does not match the one in the header: the
    /// file is corrupt, whatever the signature says.
    DigestMismatch,
    /// The signature does not hold under the named key.
    SignatureInvalid,
    /// The values are signed and nonsensical — a zero half-life, thresholds
    /// out of order.
    NotWellFormed,
    /// The generation is not newer than the one already loaded: a signed
    /// *old* file is a rollback, and a rollback is an attack.
    Rollback {
        /// What the file says.
        offered: u32,
        /// What is already in force.
        current: u32,
    },
}

impl core::fmt::Display for WeightsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WeightsError::BadMagic => write!(
                f,
                "not an AISME weights file, or not format version {FORMAT_VERSION}"
            ),
            WeightsError::Truncated { needed, got } => {
                write!(f, "truncated: needs {needed} bytes, has {got}")
            }
            WeightsError::DigestMismatch => {
                write!(f, "digest mismatch: the body does not match its header")
            }
            WeightsError::SignatureInvalid => {
                write!(f, "signature does not hold under the named key")
            }
            WeightsError::NotWellFormed => write!(
                f,
                "values are not well formed (zero half-life, or thresholds out of order)"
            ),
            WeightsError::Rollback { offered, current } => {
                write!(f, "generation {offered} is not newer than {current}: a signed old file is a rollback")
            }
        }
    }
}

impl core::error::Error for WeightsError {}

/// A verified weights file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedWeights {
    /// Monotonic; a file that is not newer is refused.
    pub generation: u32,
    /// Which key signed it, for the loader's diagnostics.
    pub key_id: [u8; 8],
    /// The values.
    pub weights: Weights,
}

/// Header: magic (8) · generation (4) · key id (8) · signature length (2) ·
/// body length (2) · digest (32) = 56 bytes, then the body, then the
/// signature.
const HEADER: usize = 8 + 4 + 8 + 2 + 2 + 32;
/// Body: eleven `u32` — the weights, in declaration order.
const BODY: usize = 11 * 4;

/// Verify a weights file and return what it holds.
///
/// `current_generation` is what is already in force; pass 0 when nothing is.
///
/// # Errors
///
/// [`WeightsError`], in the order the checks are cheap: shape, digest,
/// signature, then meaning. A file that fails any of them changes nothing.
pub fn verify(
    bytes: &[u8],
    verifier: &dyn SignatureVerifier,
    current_generation: u32,
) -> Result<SignedWeights, WeightsError> {
    if bytes.len() < HEADER {
        return Err(WeightsError::Truncated {
            needed: HEADER,
            got: bytes.len(),
        });
    }
    if bytes[..8] != MAGIC {
        return Err(WeightsError::BadMagic);
    }
    let generation = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let mut key_id = [0u8; 8];
    key_id.copy_from_slice(&bytes[12..20]);
    let sig_len = usize::from(u16::from_le_bytes([bytes[20], bytes[21]]));
    let body_len = usize::from(u16::from_le_bytes([bytes[22], bytes[23]]));
    let digest = &bytes[24..56];
    let needed = HEADER + body_len + sig_len;
    if bytes.len() < needed || body_len != BODY {
        return Err(WeightsError::Truncated {
            needed: HEADER + BODY + sig_len,
            got: bytes.len(),
        });
    }
    let body = &bytes[HEADER..HEADER + body_len];
    let signature = &bytes[HEADER + body_len..needed];
    // The digest is checked before the signature so a corrupt file is named
    // corrupt rather than "unsigned", which sends the reader after the wrong
    // problem.
    if blake3::hash(body).as_bytes()[..] != *digest {
        return Err(WeightsError::DigestMismatch);
    }
    // The signature covers the header up to and including the digest, so the
    // generation and the key id are signed too — otherwise a rollback could
    // be made by editing the header of a valid file.
    if !verifier.verify(&bytes[..56], signature, &key_id) {
        return Err(WeightsError::SignatureInvalid);
    }
    if generation <= current_generation {
        return Err(WeightsError::Rollback {
            offered: generation,
            current: current_generation,
        });
    }
    let weights = decode_body(body);
    if !weights.is_well_formed() {
        return Err(WeightsError::NotWellFormed);
    }
    Ok(SignedWeights {
        generation,
        key_id,
        weights,
    })
}

/// The bytes of a weights file, without its signature: what a signer signs
/// and what [`verify`] checks. Same shape, so the two cannot drift.
#[must_use]
pub fn encode(generation: u32, key_id: [u8; 8], weights: &Weights, signature: &[u8]) -> Vec<u8> {
    let body = encode_body(weights);
    let mut out = Vec::with_capacity(HEADER + body.len() + signature.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(&key_id);
    let sig_len = u16::try_from(signature.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&sig_len.to_le_bytes());
    out.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_le_bytes());
    out.extend_from_slice(blake3::hash(&body).as_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(signature);
    out
}

fn encode_body(w: &Weights) -> Vec<u8> {
    let fields = [
        w.taint_acquired,
        w.class_shift,
        w.instruction_bearing_input,
        w.deny,
        w.detector_hit[0],
        w.detector_hit[1],
        w.detector_hit[2],
        w.detector_hit[3],
        w.half_life_s,
        w.thresholds[0],
        w.thresholds[1],
    ];
    fields.iter().flat_map(|n| n.to_le_bytes()).collect()
}

fn decode_body(body: &[u8]) -> Weights {
    let at = |i: usize| {
        u32::from_le_bytes([
            body[i * 4],
            body[i * 4 + 1],
            body[i * 4 + 2],
            body[i * 4 + 3],
        ])
    };
    Weights {
        taint_acquired: at(0),
        class_shift: at(1),
        instruction_bearing_input: at(2),
        deny: at(3),
        detector_hit: [at(4), at(5), at(6), at(7)],
        half_life_s: at(8),
        // The third threshold is not in the body: `thresholds[2]` is the
        // CRITICAL bar, and a file may not lower it — the shipped value
        // stands, whatever the file says.
        thresholds: [at(9), at(10), Weights::DEFAULT.thresholds[2]],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Accepts one signature and no other: the loader's job, mocked.
    struct OnlyThis(&'static [u8]);

    impl SignatureVerifier for OnlyThis {
        fn verify(&self, _message: &[u8], signature: &[u8], _key_id: &[u8; 8]) -> bool {
            signature == self.0
        }
    }

    /// Stands in for a real signature over the header: it holds only for the
    /// generation the file was signed with.
    struct OverMessage;

    impl SignatureVerifier for OverMessage {
        fn verify(&self, message: &[u8], _signature: &[u8], _key_id: &[u8; 8]) -> bool {
            message[8..12] == 9u32.to_le_bytes()
        }
    }

    const SIG: &[u8] = b"a-valid-signature";
    const KEY: [u8; 8] = *b"key-0001";

    fn file(generation: u32, weights: &Weights) -> Vec<u8> {
        encode(generation, KEY, weights, SIG)
    }

    #[test]
    fn a_well_formed_signed_file_round_trips() {
        let bytes = file(7, &Weights::DEFAULT);
        let out = verify(&bytes, &OnlyThis(SIG), 6).unwrap();
        assert_eq!(out.generation, 7);
        assert_eq!(out.key_id, KEY);
        assert_eq!(out.weights, Weights::DEFAULT);
    }

    #[test]
    fn every_way_a_file_can_be_wrong_is_named() {
        let good = file(7, &Weights::DEFAULT);
        assert_eq!(
            verify(&[], &OnlyThis(SIG), 0),
            Err(WeightsError::Truncated { needed: 56, got: 0 })
        );
        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            verify(&bad_magic, &OnlyThis(SIG), 0),
            Err(WeightsError::BadMagic)
        );
        let mut corrupt = good.clone();
        corrupt[56] ^= 0xFF;
        assert_eq!(
            verify(&corrupt, &OnlyThis(SIG), 0),
            Err(WeightsError::DigestMismatch)
        );
        assert_eq!(
            verify(&good, &OnlyThis(b"another"), 0),
            Err(WeightsError::SignatureInvalid)
        );
        assert_eq!(
            verify(&good, &OnlyThis(SIG), 7),
            Err(WeightsError::Rollback {
                offered: 7,
                current: 7
            }),
            "the same generation is a rollback too"
        );
        let broken = file(
            8,
            &Weights {
                half_life_s: 0,
                ..Weights::DEFAULT
            },
        );
        assert_eq!(
            verify(&broken, &OnlyThis(SIG), 0),
            Err(WeightsError::NotWellFormed)
        );
        let truncated = &good[..good.len() - 3];
        assert!(matches!(
            verify(truncated, &OnlyThis(SIG), 0),
            Err(WeightsError::Truncated { .. })
        ));
    }

    #[test]
    fn the_header_is_signed_so_a_rollback_cannot_be_edited_into_a_valid_file() {
        // Editing the generation of a signed file leaves the signature over
        // the *old* header; a verifier that checks the message would refuse.
        let good = file(9, &Weights::DEFAULT);
        let mut edited = good.clone();
        edited[8] = 1;
        assert!(verify(&good, &OverMessage, 0).is_ok());
        assert_eq!(
            verify(&edited, &OverMessage, 0),
            Err(WeightsError::SignatureInvalid)
        );
    }

    #[test]
    fn a_file_cannot_lower_the_critical_bar() {
        // The CRITICAL threshold is not in the body: a signed file that
        // wanted to make every session critical cannot, because the shipped
        // value is what is used.
        let mut greedy = Weights::DEFAULT;
        greedy.thresholds = [1, 2, 3];
        let out = verify(&file(8, &greedy), &OnlyThis(SIG), 0).unwrap();
        assert_eq!(out.weights.thresholds[0], 1);
        assert_eq!(out.weights.thresholds[1], 2);
        assert_eq!(
            out.weights.thresholds[2],
            Weights::DEFAULT.thresholds[2],
            "the CRITICAL bar is the shipped one"
        );
    }
}
