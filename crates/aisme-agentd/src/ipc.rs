// SPDX-License-Identifier: Apache-2.0
//! The local IPC server (`F1.IPC.01`): a Unix socket, peer identity from the
//! kernel, and the four authorization classes of Annex I.
//!
//! Two properties are the reason this exists in F1 rather than F8a:
//!
//! - **Authorization is by peer identity, not by anything the caller says.**
//!   `SO_PEERCRED` is answered by the kernel, so a client cannot claim a uid
//!   or a pid. `std::os::unix::net::UnixStream::peer_cred` is that call.
//! - **The human principal is a local peer whose process is not inside any
//!   session cgroup** (Annex I, `F7.PS.08`). That is the mechanical
//!   distinction between the user and the agent, and it is read from
//!   `/proc/<pid>/cgroup` — the agent cannot leave its own cgroup without
//!   the freeze and enforcement noticing.
//!
//! The transport is here (L3, I/O); the protocol is `aisme-proto` (L4).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use aisme_proto::json::Value;
use aisme_proto::rpc::{self, AuthClass, ErrorCode, Method};

/// Who is calling, as the kernel says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Peer {
    /// The caller's uid, from `SO_PEERCRED`.
    pub uid: u32,
    /// The caller's pid, from `SO_PEERCRED`, when the platform gives one.
    pub pid: Option<i32>,
    /// Whether that pid sits inside a session cgroup.
    pub in_session_cgroup: bool,
}

impl Peer {
    /// This process's own uid, for a server that has not been told the
    /// installing user's.
    #[must_use]
    pub fn from_current_uid() -> Peer {
        // `/proc/self/status`'s Uid line: the real uid is the first field.
        // SAFETY: `getuid` takes no arguments, cannot fail and touches no
        // memory of ours.
        let uid = unsafe { libc::getuid() };
        Peer {
            uid,
            pid: None,
            in_session_cgroup: false,
        }
    }

    /// The classes this peer satisfies.
    ///
    /// A remote peer is not a local one and never appears here: this server
    /// speaks to local sockets only, and the paired-device path is F11's.
    #[must_use]
    pub fn satisfies(&self, class: AuthClass, owner_uid: u32) -> bool {
        let local = self.uid == owner_uid;
        match class {
            AuthClass::AnyAuthenticated => true,
            AuthClass::LocalPeer | AuthClass::RemotePeer => local,
            // The distinction F7.PS.08 needs: the user, not the agent.
            AuthClass::HumanPrincipal => local && !self.in_session_cgroup,
        }
    }
}

/// Read the peer's identity from a connected socket.
///
/// # Errors
///
/// Whatever the kernel says when `SO_PEERCRED` fails.
pub fn peer_of(stream: &UnixStream) -> std::io::Result<Peer> {
    use std::os::fd::AsRawFd;

    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = u32::try_from(std::mem::size_of::<libc::ucred>()).unwrap_or(0);
    // SAFETY: `cred` is a live, correctly sized `ucred` and `len` is its
    // size; the fd is owned by `stream` for the duration of the call. This is
    // the kernel answering who the peer is — the one fact a client cannot
    // forge, which is why the whole authorization model rests on it.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(Peer {
        uid: cred.uid,
        pid: Some(cred.pid),
        in_session_cgroup: in_session_cgroup(cred.pid),
    })
}

/// Whether a pid sits in one of AISME's session cgroups.
///
/// Absent evidence is **not** "the user": a pid whose cgroup cannot be read
/// is treated as possibly-agent, because reading an absence as a privilege
/// is how `F7.PS.08` would be defeated.
#[must_use]
pub fn in_session_cgroup(pid: i32) -> bool {
    let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
        return true;
    };
    text.lines().any(|line| {
        line.rsplit(':')
            .next()
            .is_some_and(|path| path.contains("/aisme.slice") || path.contains("/aisme-session-"))
    })
}

/// How many declarations a peer has made, and when the window started.
///
/// Keyed by the peer for now, not by the session: sessions are established by
/// `F2.WS.08`, and a limiter that pretended to key by one before it exists
/// would be counting something it cannot name.
pub struct Declarations {
    /// Start of the current minute, as a monotonic instant.
    window: std::time::Instant,
    /// Accepted in this window.
    count: u32,
    /// Where an accepted declaration goes: the hot loop, through the same
    /// `Sensor` interface the kernel's events arrive on. `None` when no loop
    /// is running — the answer is still `accepted`, because the bound and the
    /// validation are what the caller asked about, and a daemon serving the
    /// control plane without a loop is a real state (`--serve-ipc` alone).
    out: Option<crate::declare::Declared>,
}

impl Declarations {
    /// A fresh counter.
    #[must_use]
    pub fn new() -> Declarations {
        Declarations {
            window: std::time::Instant::now(),
            count: 0,
            out: None,
        }
    }

    /// A counter that delivers accepted declarations into the hot loop.
    #[must_use]
    pub fn feeding(out: crate::declare::Declared) -> Declarations {
        Declarations {
            out: Some(out),
            ..Declarations::new()
        }
    }

    /// Whether one more declaration fits, counting it if it does.
    ///
    /// The window is a plain reset rather than a sliding one: at this bound the
    /// difference is a burst of at most `2 × DECLARATIONS_PER_MINUTE` across a
    /// boundary, which is still bounded, and a sliding window costs a ring of
    /// timestamps in a daemon with a 50 MB budget.
    fn admit(&mut self) -> bool {
        if self.window.elapsed() >= std::time::Duration::from_secs(60) {
            self.window = std::time::Instant::now();
            self.count = 0;
        }
        if self.count >= rpc::DECLARATIONS_PER_MINUTE {
            return false;
        }
        self.count += 1;
        true
    }
}

impl Default for Declarations {
    fn default() -> Declarations {
        Declarations::new()
    }
}

/// Serve one line-framed request from `line`, as `peer`.
///
/// Framing is one JSON object per line: it is greppable in a capture, it
/// needs no length prefix to resynchronise after a bad frame, and the
/// protocol's messages are small (Annex I). Returns the response line.
#[must_use]
pub fn serve_line(
    line: &str,
    peer: &Peer,
    owner_uid: u32,
    declarations: &mut Declarations,
) -> String {
    let request = match rpc::parse_request(line) {
        Ok(request) => request,
        Err(e) => return rpc::error(e.id, e.code, &e.message),
    };
    let class = request.method.auth();
    if !peer.satisfies(class, owner_uid) {
        // Names the class required, never why this caller failed (Annex I.2).
        return rpc::error(
            request.id,
            ErrorCode::Unauthorized,
            &format!("{class:?} required"),
        );
    }
    match request.method {
        Method::GetCapabilities => rpc::response(
            request.id,
            Value::object([
                ("protocol_version", Value::string(rpc::PROTOCOL_VERSION)),
                ("engine_version", Value::string(env!("CARGO_PKG_VERSION"))),
                // The tier and key_hw come from the composition; F8a fills
                // the rest of Annex I's result in.
                (
                    "tier",
                    Value::string(aisme_core::tier::tier_of(&crate::platform::probe()).as_str()),
                ),
            ]),
        ),
        // `F2.WS.03`. A declaration is an observation, never an authorization:
        // it creates no grant, changes no verdict and carries no scope, and
        // `DT-04` exists because a declaration may be a lie. The engine records
        // it beside the actions it claims to explain and checks it later.
        Method::DeclareToolCall => {
            if !declarations.admit() {
                // A *result*, not an error (Annex I.2): the caller learns the
                // bound applied and the declarations already accepted stand.
                return rpc::response(
                    request.id,
                    Value::object([
                        ("outcome", Value::string("rate_limited")),
                        (
                            "per_minute",
                            Value::Int(i64::from(rpc::DECLARATIONS_PER_MINUTE)),
                        ),
                    ]),
                );
            }
            let toolcall_id = request.params.get("toolcall_id").and_then(|v| match v {
                Value::Int(n) => Some(*n),
                _ => None,
            });
            match toolcall_id {
                Some(id) => {
                    // Delivered as an event on the same stream as everything
                    // else, so correlation can check the claim against the
                    // actions instead of believing it (`DT-04`).
                    if let Some(out) = &declarations.out {
                        let name = request
                            .params
                            .get("tool_name")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let ts_ns = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
                        let event = crate::declare::declaration_event(
                            u64::try_from(id).unwrap_or(0),
                            name,
                            ts_ns,
                        );
                        // A closed receiver means the loop stopped. The caller
                        // is not told the declaration was recorded when it was
                        // not, so the answer becomes the honest one.
                        if out.send(event).is_err() {
                            return rpc::response(
                                request.id,
                                Value::object([
                                    ("outcome", Value::string("not_recorded")),
                                    ("reason", Value::string("the engine is not running")),
                                ]),
                            );
                        }
                    }
                    rpc::response(
                        request.id,
                        Value::object([
                            ("outcome", Value::string("accepted")),
                            ("toolcall_id", Value::Int(id)),
                        ]),
                    )
                }
                // A declaration with no id cannot be joined to anything, so
                // accepting it would record a fact nobody can use.
                None => rpc::error(
                    request.id,
                    ErrorCode::InvalidParams,
                    "toolcall_id is required and must be an integer",
                ),
            }
        }
        // Every other method is F8a's; saying so is better than a stub that
        // answers something plausible.
        other => rpc::response(
            request.id,
            Value::object([
                ("outcome", Value::string("unimplemented")),
                ("method", Value::string(other.as_str())),
                ("arrives_in", Value::string("F8a")),
            ]),
        ),
    }
}

/// Listen on `path`, serving one connection at a time.
///
/// # Errors
///
/// Binding or accepting.
pub fn serve(path: &Path, owner_uid: u32, until: impl FnMut() -> bool) -> std::io::Result<()> {
    serve_with(path, owner_uid, Declarations::new, until)
}

/// `serve`, delivering accepted declarations into a running hot loop.
///
/// # Errors
///
/// Binding or accepting.
pub fn serve_feeding(
    path: &Path,
    owner_uid: u32,
    declared: crate::declare::Declared,
    until: impl FnMut() -> bool,
) -> std::io::Result<()> {
    serve_with(
        path,
        owner_uid,
        move || Declarations::feeding(declared.clone()),
        until,
    )
}

fn serve_with(
    path: &Path,
    owner_uid: u32,
    mut counter: impl FnMut() -> Declarations,
    mut until: impl FnMut() -> bool,
) -> std::io::Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    for stream in listener.incoming() {
        let stream = stream?;
        let peer = peer_of(&stream)?;
        let reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        // One counter per connection: a peer that reconnects to reset it has
        // done the expensive part of the attack — a new connection, a new
        // SO_PEERCRED check — for a new window, which is a far worse trade than
        // sending declarations down one socket. F2.WS.08 keys it by session.
        let mut declarations = counter();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            writeln!(
                writer,
                "{}",
                serve_line(&line, &peer, owner_uid, &mut declarations)
            )?;
        }
        if until() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
// A panic is the failure report in a test; the daemon's code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aisme_proto::json;

    const OWNER: u32 = 1000;

    /// An agent may declare its own work, and the declaration grants nothing:
    /// the answer carries an outcome and the id, and no scope, verdict or
    /// grant. `DT-04` exists because a declaration may be a lie, so anything
    /// resembling permission in this response would be a defect.
    #[test]
    fn an_agent_may_declare_its_own_tool_call_and_it_authorizes_nothing() {
        let mut d = Declarations::new();
        let response = call_with(
            "declareToolCall",
            r#"{"toolcall_id":7,"tool_name":"Bash","params_hash":"ab","declared_targets":["/tmp/x"]}"#,
            &agent(),
            &mut d,
        );
        let result = response.get("result").expect("a result, not an error");
        assert_eq!(
            result.get("outcome").and_then(json::Value::as_str),
            Some("accepted")
        );
        assert_eq!(
            result.get("toolcall_id").and_then(json::Value::as_int),
            Some(7)
        );
        for forbidden in ["grant", "grant_id", "scope", "verdict", "allow", "token"] {
            assert!(
                result.get(forbidden).is_none(),
                "a declaration must not answer with `{forbidden}`"
            );
        }
    }

    /// Beyond the bound the answer is a *result*, not an error (Annex I.2), and
    /// everything accepted before it stands.
    #[test]
    fn declarations_beyond_the_bound_are_rate_limited_and_the_accepted_ones_stand() {
        let mut d = Declarations::new();
        let params = r#"{"toolcall_id":1}"#;
        for i in 0..rpc::DECLARATIONS_PER_MINUTE {
            let response = call_with("declareToolCall", params, &agent(), &mut d);
            assert_eq!(
                response
                    .get("result")
                    .and_then(|r| r.get("outcome"))
                    .and_then(json::Value::as_str),
                Some("accepted"),
                "declaration {i} of the allowance"
            );
        }
        let over = call_with("declareToolCall", params, &agent(), &mut d);
        let result = over.get("result").expect("a result, never an error");
        assert_eq!(
            result.get("outcome").and_then(json::Value::as_str),
            Some("rate_limited")
        );
        assert_eq!(
            result.get("per_minute").and_then(json::Value::as_int),
            Some(i64::from(rpc::DECLARATIONS_PER_MINUTE)),
            "the caller is told the bound that applied"
        );
        assert!(
            over.get("error").is_none(),
            "a bound is not a protocol error"
        );
    }

    /// The connection, end to end: a declaration on the socket becomes an
    /// event on the hot loop's stream. Without this the method would be a
    /// validated answer that recorded nothing, which is the kind of seam that
    /// looks finished and is not.
    #[test]
    fn an_accepted_declaration_reaches_the_engine_as_a_toolcall_event() {
        use aisme_core::sensor::{EventBatch, Sensor as _};
        use aisme_ebpf_common::{EventKind, Payload};

        let (mut sensor, tx) = crate::declare::DeclarationSensor::new();
        let mut d = Declarations::feeding(tx);
        let response = call_with(
            "declareToolCall",
            r#"{"toolcall_id":5,"tool_name":"Bash"}"#,
            &agent(),
            &mut d,
        );
        assert_eq!(
            response
                .get("result")
                .and_then(|r| r.get("outcome"))
                .and_then(json::Value::as_str),
            Some("accepted")
        );

        let mut batch = EventBatch::with_capacity(4);
        assert_eq!(
            sensor
                .poll(&mut batch, std::time::Duration::ZERO)
                .expect("poll"),
            1,
            "the declaration arrived on the sensor stream"
        );
        let event = batch.as_slice()[0];
        assert_eq!(event.kind.decode(), Ok(EventKind::ToolCall));
        match event.payload() {
            Some(Payload::Semantic(s)) => {
                assert_eq!(s.toolcall_id, 5);
                assert_eq!(&s.tool_name[..s.name_len as usize], b"Bash");
            }
            other => panic!("wrong view: {other:?}"),
        }
    }

    /// When the loop is gone the caller is told so, rather than being told the
    /// declaration was recorded when nothing recorded it.
    #[test]
    fn a_declaration_with_no_engine_behind_it_says_not_recorded() {
        let (sensor, tx) = crate::declare::DeclarationSensor::new();
        let mut d = Declarations::feeding(tx);
        drop(sensor);
        let response = call_with(
            "declareToolCall",
            r#"{"toolcall_id":1,"tool_name":"Bash"}"#,
            &agent(),
            &mut d,
        );
        assert_eq!(
            response
                .get("result")
                .and_then(|r| r.get("outcome"))
                .and_then(json::Value::as_str),
            Some("not_recorded")
        );
    }

    /// A declaration nobody can join to anything is refused rather than
    /// recorded: accepting it would store a fact with no use.
    #[test]
    fn a_declaration_without_an_id_is_refused() {
        let mut d = Declarations::new();
        let response = call_with(
            "declareToolCall",
            r#"{"tool_name":"Bash"}"#,
            &agent(),
            &mut d,
        );
        assert!(response.get("result").is_none());
        assert!(response.get("error").is_some());
    }

    fn user() -> Peer {
        Peer {
            uid: OWNER,
            pid: Some(10),
            in_session_cgroup: false,
        }
    }

    fn agent() -> Peer {
        Peer {
            uid: OWNER,
            pid: Some(11),
            in_session_cgroup: true,
        }
    }

    fn stranger() -> Peer {
        Peer {
            uid: OWNER + 1,
            pid: Some(12),
            in_session_cgroup: false,
        }
    }

    fn call(method: &str, peer: &Peer) -> json::Value {
        call_with(method, "{}", peer, &mut Declarations::new())
    }

    /// One call with its own params and its own counter, so a test can send
    /// several and watch the bound apply.
    fn call_with(method: &str, params: &str, peer: &Peer, d: &mut Declarations) -> json::Value {
        let line = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
        json::parse(&serve_line(&line, peer, OWNER, d)).unwrap()
    }

    #[test]
    fn the_agent_may_read_but_may_not_change_policy_grants_or_suppression() {
        // F7.PS.08's whole point: an agent-originated mutation is refused,
        // and it is refused by *where the caller is*, not by anything it says.
        for method in ["setPolicy", "manageGrant", "manageSuppression"] {
            let refused = call(method, &agent());
            assert_eq!(
                refused
                    .get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(json::Value::as_int),
                Some(-32001),
                "{method} from inside a session cgroup must be refused"
            );
            let allowed = call(method, &user());
            assert!(
                allowed.get("result").is_some(),
                "{method} from the user must be allowed"
            );
        }
        // Reading is open to any authenticated peer, agent included.
        assert!(call("getSession", &agent()).get("result").is_some());
        assert!(call("getCapabilities", &agent()).get("result").is_some());
    }

    #[test]
    fn another_uid_is_not_a_local_peer() {
        assert!(call("pairDevice", &stranger()).get("error").is_some());
        assert!(call("pairDevice", &user()).get("result").is_some());
        // But read-only methods are open to any authenticated peer.
        assert!(call("listSessions", &stranger()).get("result").is_some());
    }

    #[test]
    fn getcapabilities_answers_with_the_versions_and_the_tier() {
        let result = call("getCapabilities", &user());
        let result = result.get("result").unwrap();
        assert_eq!(
            result.get("protocol_version").and_then(json::Value::as_str),
            Some(rpc::PROTOCOL_VERSION)
        );
        assert!(result.get("tier").and_then(json::Value::as_str).is_some());
        // Everything else says it is not implemented rather than answering
        // something plausible.
        let later = call("getGraph", &user());
        assert_eq!(
            later
                .get("result")
                .and_then(|r| r.get("arrives_in"))
                .and_then(json::Value::as_str),
            Some("F8a")
        );
    }

    #[test]
    fn a_malformed_line_is_a_protocol_error_with_the_id_when_there_is_one() {
        let response =
            json::parse(&serve_line("{", &user(), OWNER, &mut Declarations::new())).unwrap();
        assert_eq!(
            response
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(json::Value::as_int),
            Some(-32600)
        );
        let response = json::parse(&serve_line(
            r#"{"jsonrpc":"2.0","id":42,"method":"nope"}"#,
            &user(),
            OWNER,
            &mut Declarations::new(),
        ))
        .unwrap();
        assert_eq!(response.get("id").and_then(json::Value::as_int), Some(42));
        assert_eq!(
            response
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(json::Value::as_int),
            Some(-32601)
        );
    }

    #[test]
    fn an_unreadable_cgroup_is_treated_as_possibly_agent() {
        // Absence read as "the user" would defeat F7.PS.08; a pid that
        // cannot be inspected is assumed to be inside a session.
        assert!(in_session_cgroup(i32::MAX), "a pid that does not exist");
        // This test's own process is not in an AISME session cgroup.
        let me = std::process::id();
        assert!(!in_session_cgroup(i32::try_from(me).unwrap()));
    }

    #[test]
    fn the_socket_round_trips_a_real_call() {
        let dir = std::env::temp_dir().join(format!("aisme-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.sock");
        let owner = Peer::from_current_uid();
        let server_path = path.clone();
        let server = std::thread::spawn(move || {
            serve(&server_path, owner.uid, || true).unwrap();
        });
        // Wait for the socket to appear rather than sleep a guess.
        for _ in 0..1_000 {
            if path.exists() {
                break;
            }
            std::thread::yield_now();
        }
        let mut client = UnixStream::connect(&path).unwrap();
        writeln!(
            client,
            r#"{{"jsonrpc":"2.0","id":5,"method":"getCapabilities"}}"#
        )
        .unwrap();
        let mut reply = String::new();
        BufReader::new(client.try_clone().unwrap())
            .read_line(&mut reply)
            .unwrap();
        drop(client);
        server.join().unwrap();
        let parsed = json::parse(reply.trim()).unwrap();
        assert_eq!(parsed.get("id").and_then(json::Value::as_int), Some(5));
        assert!(parsed.get("result").is_some(), "{reply}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
