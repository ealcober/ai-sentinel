// SPDX-License-Identifier: Apache-2.0
//! AISME-PL: the policy language (plan Annex B).
//!
//! `ast` is what a policy *says*, one type per production of §B.0; `parse`
//! turns TOML text into it and refuses what the grammar does not admit. The
//! compiler — static validation, the IR, the backends — is `F1.PL.02`
//! onwards. The language is deliberately not Turing-complete: no negation,
//! no nesting, no arithmetic (§B.0), because it compiles into a BPF program
//! with a verifier loop budget, and because a policy you cannot analyse is a
//! policy you cannot trust.

pub mod ast;
pub mod backend;
pub mod compile;
pub mod encode;
pub mod parse;

pub use ast::{Assert, Match, MatchKey, Policy, Rule, SessionDefaults, Suppression, Text};
pub use backend::{
    BackendCapabilities, BackendKind, Degradation, LowerError, PolicyBackend, PolicyGeneration,
    VerdictMap,
};
pub use compile::{
    compile, Bindings, CompileError, CompileErrorKind, CompiledPolicy, CompiledRule, Predicate,
    Settings, Term,
};
pub use encode::{digest, encode, PolicyDigest, POLICY_ENCODING_VERSION};
pub use parse::{parse, ParseError};
