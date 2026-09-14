// SPDX-License-Identifier: Apache-2.0
//! JSON-RPC 2.0 for the control plane (Annex I; `F1.IPC.01`).
//!
//! The envelope, the twelve methods with their authorization classes, and
//! Annex I.2's rule that separates the two kinds of "no":
//!
//! > Protocol failures are JSON-RPC errors; **domain outcomes are results**.
//!
//! `expired`, `superseded` and `conflict` are successful calls with a
//! negative answer, so a client can never confuse "the network failed" with
//! "the answer is no" — which is the difference between retrying and not.

use crate::json::{self, Value};

/// The protocol version this crate speaks (§I.4, semver in `aisme-proto`).
pub const PROTOCOL_VERSION: &str = "1.0.0";

/// The most declarations one session may make in a minute (`F2.WS.03`).
///
/// Derived, not guessed: the reference workload is **200 tool calls/hour**
/// (plan §2.19), which is 3.33 a minute. 64 leaves about nineteen times that in
/// headroom, so a legitimate burst — an agent firing a batch of calls — never
/// trips it, while a declaration storm is cut at 64 instead of being unbounded.
/// A storm is cheap to send and expensive to correlate, which is what makes the
/// bound a denial-of-service defence rather than tidiness.
///
/// Exceeding it is a **result**, not an error (Annex I.2): the caller is told
/// `rate_limited` and the declarations already accepted are unaffected.
pub const DECLARATIONS_PER_MINUTE: u32 = 64;

/// Who may call a method (Annex I, four classes). The **server** checks
/// this on every call; a client never does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AuthClass {
    /// Read-only methods.
    AnyAuthenticated,
    /// `SO_PEERCRED`, uid matching the installing user.
    LocalPeer,
    /// A paired device over a valid Noise session; `allow` additionally
    /// carries a hardware signature, `deny` does not (`I-06`).
    RemotePeer,
    /// A local peer whose process is **not inside any session cgroup** —
    /// the mechanical distinction between the user and the agent
    /// (`F7.PS.08`).
    HumanPrincipal,
}

/// The methods of Annex I.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    /// Tier, `key_hw`, coverage boundary, versions.
    GetCapabilities,
    /// Session summaries.
    ListSessions,
    /// One session's detail.
    GetSession,
    /// A graph delta.
    GetGraph,
    /// The event stream.
    Subscribe,
    /// Answer an escalation.
    RespondEscalation,
    /// Compare-and-swap the policy.
    SetPolicy,
    /// Create or revoke a grant.
    ManageGrant,
    /// Create or revoke a suppression rule.
    ManageSuppression,
    /// Pair a device.
    PairDevice,
    /// Revoke a device.
    RevokeDevice,
    /// Inclusion proofs and anchor status.
    VerifySession,
    /// An agent volunteers that a tool call is starting (`F2.WS.03`).
    ///
    /// **It authorizes nothing.** It creates no grant, changes no verdict and
    /// carries no scope; `DT-04` exists precisely because a declaration may be
    /// a lie. It is an observation, recorded beside the actions it claims to
    /// explain so that correlation has something to match against while the
    /// actions happen.
    ///
    /// The correlation token never travels on this method. If it did, the
    /// engine could join on it and §4.6's precision and recall would measure
    /// the join instead of the correlator.
    DeclareToolCall,
    /// The privileged loader tells the daemon which policy generation it just
    /// published (`F2.WS.04`).
    ///
    /// **It carries a number, never a map.** `aisme-agentd` holds no policy-map
    /// descriptor, readable or writable: handing it one over `SCM_RIGHTS` would
    /// leave its empty `CapabilityBoundingSet=` decorative, the capability gone
    /// and the authority kept (`F1.RT.07`). What it needs to stamp on a WAL
    /// segment is a `u64`, and a `u64` travels over the socket it already
    /// speaks.
    SetPolicyGeneration,
    /// `aisme run` tells the daemon a session has started, and hands it the
    /// seccomp listener for it (`F2.WS.05`, `F2.WS.08`).
    ///
    /// **It carries a descriptor, and which one matters.** The notify fd lets
    /// the daemon answer one held syscall for this session and nothing else; it
    /// cannot change what the kernel enforces. That is the opposite of the
    /// *writable policy map* `docs/06` point 3 refused, which would have handed
    /// the daemon authority the privilege split exists to remove.
    ///
    /// The F2 slice of `docs/design/02_aisme-run.md` step 3; `F8.CLI.01` widens
    /// it to the rest of what a session registration carries.
    RegisterSession,
}

impl Method {
    /// Every method, in Annex I.1's order.
    pub const ALL: [Method; 15] = [
        Method::GetCapabilities,
        Method::ListSessions,
        Method::GetSession,
        Method::GetGraph,
        Method::Subscribe,
        Method::RespondEscalation,
        Method::SetPolicy,
        Method::ManageGrant,
        Method::ManageSuppression,
        Method::PairDevice,
        Method::RevokeDevice,
        Method::VerifySession,
        Method::DeclareToolCall,
        Method::SetPolicyGeneration,
        Method::RegisterSession,
    ];

    /// The name on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::DeclareToolCall => "declareToolCall",
            Method::SetPolicyGeneration => "setPolicyGeneration",
            Method::RegisterSession => "registerSession",
            Method::GetCapabilities => "getCapabilities",
            Method::ListSessions => "listSessions",
            Method::GetSession => "getSession",
            Method::GetGraph => "getGraph",
            Method::Subscribe => "subscribe",
            Method::RespondEscalation => "respondEscalation",
            Method::SetPolicy => "setPolicy",
            Method::ManageGrant => "manageGrant",
            Method::ManageSuppression => "manageSuppression",
            Method::PairDevice => "pairDevice",
            Method::RevokeDevice => "revokeDevice",
            Method::VerifySession => "verifySession",
        }
    }

    /// From the name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.as_str() == name)
    }

    /// The **least** privileged class that may call it. `respondEscalation`
    /// is `RemotePeer` because a paired device may deny; whether its
    /// *allow* is honoured is `I-06`'s question, answered with the
    /// signature and the severity, not with the method's class.
    #[must_use]
    pub const fn auth(self) -> AuthClass {
        match self {
            Method::GetCapabilities
            | Method::ListSessions
            | Method::GetSession
            | Method::GetGraph
            | Method::Subscribe
            | Method::VerifySession
            // An agent declares its own work, so the class is the weakest one:
            // requiring more would mean the agent could not speak about itself,
            // and the declaration grants nothing that would need protecting.
            | Method::DeclareToolCall => AuthClass::AnyAuthenticated,
            Method::RespondEscalation | Method::RevokeDevice => AuthClass::RemotePeer,
            // The loader runs as root on this machine; the class that means
            // "a process on this host, not a paired device" is the right one,
            // and it is the same class `pairDevice` uses.
            Method::PairDevice | Method::SetPolicyGeneration | Method::RegisterSession => {
                AuthClass::LocalPeer
            }
            Method::SetPolicy | Method::ManageGrant | Method::ManageSuppression => {
                AuthClass::HumanPrincipal
            }
        }
    }

    /// Whether calling it twice is the same as calling it once (Annex I.1).
    #[must_use]
    pub const fn idempotent(self) -> bool {
        !matches!(
            self,
            // Two identical declarations are two tool calls, not one
            // retried: replaying them would invent work that never happened.
            // Registering the same session twice is two sessions, not one
            // retried: each has its own listener, and replaying one would
            // orphan a filter with nobody answering it.
            Method::SetPolicy
                | Method::PairDevice
                | Method::Subscribe
                | Method::DeclareToolCall
                | Method::RegisterSession
        )
    }
}

/// Annex I.2's error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// Malformed request.
    InvalidRequest,
    /// Unknown method.
    MethodNotFound,
    /// Unknown `session_id` / `escalation_id` / `device_id`.
    InvalidParams,
    /// Unauthorized — names the class required, never why the caller failed.
    Unauthorized,
    /// Version incompatible; carries both versions (§3.6).
    VersionIncompatible,
}

impl ErrorCode {
    /// The number on the wire.
    #[must_use]
    pub const fn code(self) -> i64 {
        match self {
            ErrorCode::InvalidRequest => -32600,
            ErrorCode::MethodNotFound => -32601,
            ErrorCode::InvalidParams => -32602,
            ErrorCode::Unauthorized => -32001,
            ErrorCode::VersionIncompatible => -32002,
        }
    }
}

/// A request, as parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The id, echoed in the response. `None` is a notification.
    pub id: Option<i64>,
    /// The method.
    pub method: Method,
    /// The params, as sent.
    pub params: Value,
}

/// Why a request was refused before it reached a handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestError {
    /// The id, when the request had one that could be read.
    pub id: Option<i64>,
    /// Which error.
    pub code: ErrorCode,
    /// What to say. Never says *why* authorization failed (Annex I.2).
    pub message: String,
}

/// Parse a request.
///
/// # Errors
///
/// [`RequestError`] with the id when one could be read, so the client can
/// match the failure to its call.
pub fn parse_request(text: &str) -> Result<Request, RequestError> {
    let value = json::parse(text).map_err(|e| RequestError {
        id: None,
        code: ErrorCode::InvalidRequest,
        message: format!("malformed JSON: {e}"),
    })?;
    let id = value.get("id").and_then(Value::as_int);
    let bad = |code, message: &str| RequestError {
        id,
        code,
        message: message.to_owned(),
    };
    if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(bad(ErrorCode::InvalidRequest, "jsonrpc must be \"2.0\""));
    }
    let name = value
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| bad(ErrorCode::InvalidRequest, "method must be a string"))?;
    let method = Method::parse(name).ok_or_else(|| {
        bad(
            ErrorCode::MethodNotFound,
            &format!("unknown method `{name}`"),
        )
    })?;
    Ok(Request {
        id,
        method,
        params: value.get("params").cloned().unwrap_or(Value::Null),
    })
}

/// A successful response — including the domain outcomes that are *not*
/// errors (Annex I.2).
#[must_use]
pub fn response(id: Option<i64>, result: Value) -> String {
    json::write(&Value::object([
        ("jsonrpc", Value::string("2.0")),
        ("id", id.map_or(Value::Null, Value::Int)),
        ("result", result),
    ]))
}

/// An error response.
#[must_use]
pub fn error(id: Option<i64>, code: ErrorCode, message: &str) -> String {
    json::write(&Value::object([
        ("jsonrpc", Value::string("2.0")),
        ("id", id.map_or(Value::Null, Value::Int)),
        (
            "error",
            Value::object([
                ("code", Value::Int(code.code())),
                ("message", Value::string(message)),
            ]),
        ),
    ]))
}

/// The refusal a remote `allow` gets when `I-06` does not permit it. A
/// **result**, not an error: the call succeeded and the answer is no.
#[must_use]
pub fn rejected(reason_class: &str) -> Value {
    Value::object([
        ("outcome", Value::string("rejected")),
        ("reason_class", Value::string(reason_class)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_annex_i_method_is_here_with_its_class() {
        let plan = include_str!("../../../docs/01_phase5_implementation_plan.md");
        for method in Method::ALL {
            assert!(
                plan.contains(&format!("`{}`", method.as_str())),
                "{} is not in Annex I.1",
                method.as_str()
            );
            assert_eq!(Method::parse(method.as_str()), Some(method));
        }
        assert_eq!(Method::parse("deleteEverything"), None);
        assert_eq!(Method::GetSession.auth(), AuthClass::AnyAuthenticated);
        assert_eq!(Method::SetPolicy.auth(), AuthClass::HumanPrincipal);
        assert_eq!(Method::ManageGrant.auth(), AuthClass::HumanPrincipal);
        assert_eq!(Method::PairDevice.auth(), AuthClass::LocalPeer);
        assert_eq!(Method::RespondEscalation.auth(), AuthClass::RemotePeer);
        assert!(!Method::SetPolicy.idempotent(), "compare-and-swap");
        assert!(Method::ManageGrant.idempotent());
    }

    #[test]
    fn a_request_parses_and_a_malformed_one_is_named() {
        let request = parse_request(
            r#"{"jsonrpc":"2.0","id":1,"method":"getSession","params":{"session_id":7}}"#,
        )
        .unwrap();
        assert_eq!(request.id, Some(1));
        assert_eq!(request.method, Method::GetSession);
        assert_eq!(
            request.params.get("session_id").and_then(Value::as_int),
            Some(7)
        );

        let cases = [
            (r#"{"id":1}"#, ErrorCode::InvalidRequest),
            (
                r#"{"jsonrpc":"1.0","id":1,"method":"getSession"}"#,
                ErrorCode::InvalidRequest,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"nope"}"#,
                ErrorCode::MethodNotFound,
            ),
            ("not json", ErrorCode::InvalidRequest),
        ];
        for (text, code) in cases {
            assert_eq!(parse_request(text).unwrap_err().code, code, "{text}");
        }
        // The id survives the failure, so a client can match it to its call.
        assert_eq!(
            parse_request(r#"{"jsonrpc":"2.0","id":9,"method":"nope"}"#)
                .unwrap_err()
                .id,
            Some(9)
        );
    }

    #[test]
    fn a_domain_outcome_is_a_result_and_a_protocol_failure_is_an_error() {
        // Annex I.2's rule, which is what stops a client conflating "the
        // network failed" with "the answer is no".
        let expired = response(
            Some(3),
            Value::object([("outcome", Value::string("expired"))]),
        );
        let parsed = json::parse(&expired).unwrap();
        assert!(parsed.get("result").is_some());
        assert!(parsed.get("error").is_none());

        let unauthorized = error(Some(3), ErrorCode::Unauthorized, "human principal required");
        let parsed = json::parse(&unauthorized).unwrap();
        assert_eq!(
            parsed
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(Value::as_int),
            Some(-32001)
        );
        let message = parsed
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            message.contains("human principal"),
            "names the class required"
        );
        assert!(!message.contains("uid"), "never says why the caller failed");

        let rejection = rejected("critical_class");
        assert_eq!(
            rejection.get("outcome").and_then(Value::as_str),
            Some("rejected")
        );
    }

    #[test]
    fn the_error_codes_are_annex_i_2s() {
        assert_eq!(ErrorCode::InvalidRequest.code(), -32600);
        assert_eq!(ErrorCode::MethodNotFound.code(), -32601);
        assert_eq!(ErrorCode::InvalidParams.code(), -32602);
        assert_eq!(ErrorCode::Unauthorized.code(), -32001);
        assert_eq!(ErrorCode::VersionIncompatible.code(), -32002);
    }
}
