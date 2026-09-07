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

/// Serve one line-framed request from `line`, as `peer`.
///
/// Framing is one JSON object per line: it is greppable in a capture, it
/// needs no length prefix to resynchronise after a bad frame, and the
/// protocol's messages are small (Annex I). Returns the response line.
#[must_use]
pub fn serve_line(line: &str, peer: &Peer, owner_uid: u32) -> String {
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
pub fn serve(path: &Path, owner_uid: u32, mut until: impl FnMut() -> bool) -> std::io::Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    for stream in listener.incoming() {
        let stream = stream?;
        let peer = peer_of(&stream)?;
        let reader = BufReader::new(stream.try_clone()?);
        let mut writer = stream;
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            writeln!(writer, "{}", serve_line(&line, &peer, owner_uid))?;
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
        let line = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{}}}}"#);
        json::parse(&serve_line(&line, peer, OWNER)).unwrap()
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
        let response = json::parse(&serve_line("{", &user(), OWNER)).unwrap();
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
