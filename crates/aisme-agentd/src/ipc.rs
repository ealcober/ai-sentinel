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

use std::io::Write;
#[cfg(test)]
use std::io::{BufRead as _, BufReader};
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
        line.rsplit(':').next().is_some_and(|path| {
            // The names sessions are actually given. `aisme run` creates
            // `aisme-<16 hex>` under its own cgroup (`F2.WS.08`) and the
            // deployed unit delegates a `sessions` subgroup, so a pattern that
            // matched neither classified every agent as the user — the one
            // direction this must never fail in.
            path.contains("/aisme-") || path.contains("/aisme.slice") || path.contains("/sessions/")
        })
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

/// What `getCapabilities` answers.
///
/// `policy_generation` is present **only when known**: a daemon that answered 0
/// before the first publication would be indistinguishable from one told
/// generation 0, which is the absence-read-as-value this field exists to avoid.
fn capabilities(generation: Option<aisme_core::policy::PolicyGeneration>) -> Value {
    let mut fields = std::collections::BTreeMap::from([
        (
            "protocol_version".to_owned(),
            Value::string(rpc::PROTOCOL_VERSION),
        ),
        (
            "engine_version".to_owned(),
            Value::string(env!("CARGO_PKG_VERSION")),
        ),
        // The tier and key_hw come from the composition; F8a fills the rest of
        // Annex I's result in.
        (
            "tier".to_owned(),
            Value::string(aisme_core::tier::tier_of(&crate::platform::probe()).as_str()),
        ),
    ]);
    if let Some(g) = generation {
        fields.insert(
            "policy_generation".to_owned(),
            Value::Int(i64::try_from(g.0).unwrap_or(i64::MAX)),
        );
    }
    Value::Object(fields)
}

/// Take a session's registration, and the listener it carries.
///
/// The descriptor **is** the message: a registration without one would leave a
/// filtered process with nobody to answer its syscalls, and every `openat` in
/// that session would fail with `ENOSYS` while the daemon reported success.
/// Constrain a session cgroup path a client named, before the daemon will ever
/// `rmdir` it.
///
/// **What this protects against is not the peer.** The socket is uid-matched,
/// so a caller that reaches here can already remove its own cgroups with its
/// own hands; no check here takes an ability away from it. What the check does
/// is bound what *the daemon* can be asked to delete, so that a malformed or
/// mistaken registration cannot turn the daemon into the tool that removes
/// something nobody asked about.
///
/// The last component must be a session name, which is what makes the rule
/// worth having: `rmdir` is then reachable only for an `aisme-<16 hex>`
/// directory, never for a slice, a scope, or the delegated root itself.
///
/// # Errors
///
/// The first rule the path breaks, in the words the caller needs.
fn checked_session_cgroup(path: &str) -> Result<String, &'static str> {
    // The unified hierarchy's mount point. A cgroup path outside it is not a
    // cgroup, whatever it is named.
    const ROOT: &str = "/sys/fs/cgroup/";

    if !path.starts_with(ROOT) {
        return Err("cgroup must be under /sys/fs/cgroup");
    }
    if path.contains('\0') {
        return Err("cgroup must not contain a NUL");
    }
    let rest = &path[ROOT.len()..];
    if rest
        .split('/')
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err("cgroup must be a normalised path with no empty or dot components");
    }
    // `aisme-` and exactly sixteen lowercase hexadecimal digits: the format
    // `aisme run` prints and the only shape this daemon will remove.
    let Some(last) = rest.rsplit('/').next() else {
        return Err("cgroup must name a session directory");
    };
    let Some(id) = last.strip_prefix("aisme-") else {
        return Err("the last component of cgroup must be aisme-<16 hex>");
    };
    if id.len() != 16 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("the last component of cgroup must be aisme-<16 hex>");
    }
    Ok(path.to_owned())
}

fn register_session(request: &rpc::Request, ancillary: &mut Ancillary) -> String {
    let listener = ancillary.received.take();
    let trapping = matches!(request.params.get("trapping"), Some(Value::Bool(true)));
    // A filtered session with nobody to answer it is the one registration that
    // must be refused: every `openat` in it would fail with `ENOSYS`. An
    // unfiltered one carries no listener by construction and is accepted —
    // the daemon watches it rather than supervising it.
    if trapping && listener.is_none() {
        return rpc::error(
            request.id,
            ErrorCode::InvalidParams,
            "a session that installs a seccomp filter must carry its listener as SCM_RIGHTS",
        );
    }
    let Some(Value::Int(session_id)) = request.params.get("session_id") else {
        return rpc::error(
            request.id,
            ErrorCode::InvalidParams,
            "session_id must be an integer",
        );
    };
    // The one place in this protocol where a client's string becomes a
    // filesystem operation, so it is constrained before it is stored rather
    // than before it is used: a value that reaches the struct has already been
    // checked, and no later caller has to remember to.
    let cgroup = match request.params.get("cgroup") {
        None => None,
        Some(Value::Str(path)) => match checked_session_cgroup(path) {
            Ok(path) => Some(path),
            Err(why) => return rpc::error(request.id, ErrorCode::InvalidParams, why),
        },
        Some(_) => {
            return rpc::error(
                request.id,
                ErrorCode::InvalidParams,
                "cgroup must be a string",
            )
        }
    };
    ancillary.registered = Some(Registered {
        // The codec has no unsigned integer and a session id is an opaque
        // token: the same bits go back out.
        session_id: u64::from_ne_bytes(session_id.to_ne_bytes()),
        // Absent is a session with no terminal, which is a real state: the
        // adjudicator answers with its timeout default rather than prompting
        // into nothing (`F2.WS.06`).
        tty: request
            .params
            .get("tty")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        // An empty list is a session that escalates nothing, which is a real
        // state and the default: every open it makes is answered with a
        // validated descriptor and nobody is asked.
        escalate: match request.params.get("escalate") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect(),
            _ => Vec::new(),
        },
        unattended: request
            .params
            .get("unattended")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        listener,
        cgroup,
    });
    rpc::response(
        request.id,
        Value::object([("outcome", Value::string("accepted"))]),
    )
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
    generation: &mut Option<aisme_core::policy::PolicyGeneration>,
    ancillary: &mut Ancillary,
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
        Method::GetCapabilities => rpc::response(request.id, capabilities(*generation)),
        // `F2.WS.05`/`F2.WS.08`. A session starts and hands over the listener
        // for it. The descriptor is the message: a registration without one
        // would leave a filtered process with nobody to answer its syscalls,
        // and every `openat` in it would fail with ENOSYS.
        Method::RegisterSession => register_session(&request, ancillary),
        // `F2.WS.04`. The loader publishes, then tells the daemon the number.        // It carries no descriptor: `agentd` holds no policy-map fd of any
        // kind, because `SCM_RIGHTS` would leave its empty
        // `CapabilityBoundingSet=` decorative (`F1.RT.07`).
        Method::SetPolicyGeneration => {
            match request.params.get("generation") {
                Some(Value::Int(n)) if *n >= 0 => {
                    *generation = Some(aisme_core::policy::PolicyGeneration(
                        u64::try_from(*n).unwrap_or(0),
                    ));
                    rpc::response(
                        request.id,
                        Value::object([("outcome", Value::string("accepted"))]),
                    )
                }
                // A generation that is absent, negative or not an integer is
                // refused rather than defaulted: a default here would stamp a
                // wrong number on every segment the daemon opens next.
                _ => rpc::error(
                    request.id,
                    ErrorCode::InvalidParams,
                    "generation must be a non-negative integer",
                ),
            }
        }
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

/// A session that registered, with the listener it handed over.
#[derive(Debug)]
pub struct Registered {
    /// The session's own id, as `aisme run` prints it.
    pub session_id: u64,
    /// The controlling terminal of the session, for `F2.WS.06`'s prompt.
    ///
    /// `agentd` has none of its own, so the session names one for it. Absent is
    /// a real state and not a default: a session with no terminal gets the
    /// adjudicator's timeout verdict rather than a prompt written into nothing.
    pub tty: Option<String>,
    /// Path prefixes whose opens are escalated to a human instead of being
    /// permitted silently.
    ///
    /// F2's one hardcoded rule, carried by the session rather than compiled in
    /// the daemon: the loader owns the policy and the daemon holds no map
    /// (`docs/06` point 3), so what the session escalates is what the session
    /// declares. `F3.PT.02`'s kernel-side trie replaces this with the compiled
    /// policy the kernel itself reads.
    pub escalate: Vec<String>,
    /// An answer to use instead of asking, for gates and unattended runs.
    ///
    /// **Read once by `aisme run`, before `exec`, and carried here.** The
    /// adjudicator must never read it from the daemon's own environment: a
    /// daemon-side read could be steered by anything able to set a variable in
    /// the daemon, which includes the agent being adjudicated.
    pub unattended: Option<String>,
    /// The seccomp listener for that session, when there is one.
    ///
    /// **Optional, because not every session is filtered.** A session without
    /// `--trap-openat` installs no filter and has no listener to hand over, and
    /// it is still a session the daemon must know about: it has a cgroup, and
    /// somebody has to release it (`docs/10` point 2). Making the descriptor
    /// the message is what made unfiltered sessions invisible.
    pub listener: Option<std::os::fd::OwnedFd>,
    /// The session's own cgroup, for the daemon to release when it empties.
    ///
    /// `exec` has no after, so the process that created the directory is the
    /// supervised command by the time it could clean up. The daemon waits on
    /// `cgroup.events` instead and removes it when the kernel says it is empty.
    pub cgroup: Option<String>,
}

/// The descriptor that arrived with a request, and the session it registered.
///
/// One value rather than two parameters, so `serve_line` keeps a signature a
/// reader can hold in their head.
#[derive(Debug, Default)]
pub struct Ancillary {
    /// Set by the reader when a request carried a descriptor.
    pub received: Option<std::os::fd::OwnedFd>,
    /// Set by the handler when that descriptor registered a session. The caller
    /// takes it and starts answering notifications for it.
    pub registered: Option<Registered>,
}

/// Read line-framed requests, keeping any descriptor sent alongside one.
///
/// **`BufReader::lines()` cannot be used here.** It reads with `read(2)`, which
/// delivers the bytes and **silently discards** the `SCM_RIGHTS` control
/// message: the registration would be accepted and the listener it exists to
/// carry would be gone, with nothing reporting a problem. `recvmsg` is the only
/// reader that sees both.
struct Requests {
    fd: std::os::fd::RawFd,
    buf: Vec<u8>,
    /// A descriptor delivered by the last `recvmsg`, waiting for the line it
    /// came with. The client sends the request and its descriptor in one
    /// `sendmsg`, so it belongs to the next line completed.
    pending: Option<std::os::fd::OwnedFd>,
    eof: bool,
}

impl Requests {
    const fn new(fd: std::os::fd::RawFd) -> Requests {
        Requests {
            fd,
            buf: Vec::new(),
            pending: None,
            eof: false,
        }
    }

    /// The next request, and the descriptor that came with it.
    fn next(&mut self) -> std::io::Result<Option<(String, Option<std::os::fd::OwnedFd>)>> {
        loop {
            if let Some(at) = self.buf.iter().position(|b| *b == b'\n') {
                let line = self.buf.drain(..=at).collect::<Vec<u8>>();
                let line = String::from_utf8_lossy(&line[..line.len() - 1]).into_owned();
                return Ok(Some((line, self.pending.take())));
            }
            if self.eof {
                // A trailing line with no newline is still a request.
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let line = String::from_utf8_lossy(&std::mem::take(&mut self.buf)).into_owned();
                return Ok(Some((line, self.pending.take())));
            }
            self.fill()?;
        }
    }

    /// One `recvmsg`, appending bytes and keeping any descriptor.
    fn fill(&mut self) -> std::io::Result<()> {
        use std::os::fd::{FromRawFd, OwnedFd, RawFd};

        let mut chunk = [0u8; 4096];
        let mut iov = libc::iovec {
            iov_base: chunk.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: chunk.len(),
        };
        // SAFETY: a pure size computation.
        let space = unsafe { libc::CMSG_SPACE(u32::try_from(size_of::<RawFd>()).unwrap_or(4)) };
        let mut control = vec![0u8; space as usize];
        // SAFETY: a zeroed `msghdr`; every field used below is set first.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = std::ptr::addr_of_mut!(iov);
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
        msg.msg_controllen = control.len() as _;

        // SAFETY: `msg` is initialised and the kernel writes only into the
        // buffers it points at, both of which outlive the call.
        let got = unsafe { libc::recvmsg(self.fd, std::ptr::addr_of_mut!(msg), 0) };
        if got < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if got == 0 {
            self.eof = true;
            return Ok(());
        }
        // SAFETY: reading back the control message the kernel just wrote into
        // the buffer we supplied.
        let fd = unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(std::ptr::addr_of!(msg));
            if cmsg.is_null()
                || (*cmsg).cmsg_level != libc::SOL_SOCKET
                || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            {
                None
            } else {
                Some(std::ptr::read_unaligned(
                    libc::CMSG_DATA(cmsg).cast::<RawFd>(),
                ))
            }
        };
        if let Some(fd) = fd.filter(|fd| *fd >= 0) {
            // SAFETY: the kernel installed this descriptor in our table and
            // nothing else owns it.
            self.pending = Some(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        self.buf
            .extend_from_slice(&chunk[..usize::try_from(got).unwrap_or(0)]);
        Ok(())
    }
}

/// The policy generation the daemon has been told, shared with whoever stamps
/// it on a WAL segment.
///
/// One cell rather than a channel: the last number wins and there is no history
/// to preserve, so a queue would add ordering nobody reads.
pub type GenerationCell =
    std::sync::Arc<std::sync::Mutex<Option<aisme_core::policy::PolicyGeneration>>>;

/// A cell that has been told nothing.
#[must_use]
pub fn generation_cell() -> GenerationCell {
    std::sync::Arc::new(std::sync::Mutex::new(None))
}

/// Listen on `path`, serving one connection at a time.
///
/// # Errors
///
/// Binding or accepting.
pub fn serve(path: &Path, owner_uid: u32, until: impl FnMut() -> bool) -> std::io::Result<()> {
    // Nothing answers notifications on this path: `serve` is the read-only
    // surface, and a session registered here would hand over a listener with no
    // loop behind it. `serve_feeding_sharing` is the one `aisme run` uses.
    serve_with(
        path,
        owner_uid,
        &generation_cell(),
        Declarations::new,
        drop,
        until,
    )
}

/// `serve_feeding`, sharing the cell the WAL sink reads at each segment roll.
///
/// # Errors
///
/// Binding or accepting.
pub fn serve_feeding_sharing(
    path: &Path,
    owner_uid: u32,
    declared: crate::declare::Declared,
    generation: &GenerationCell,
    on_session: impl FnMut(Registered),
    until: impl FnMut() -> bool,
) -> std::io::Result<()> {
    serve_with(
        path,
        owner_uid,
        generation,
        move || Declarations::feeding(declared.clone()),
        on_session,
        until,
    )
}

fn serve_with(
    path: &Path,
    owner_uid: u32,
    generation: &GenerationCell,
    mut counter: impl FnMut() -> Declarations,
    mut on_session: impl FnMut(Registered),
    mut until: impl FnMut() -> bool,
) -> std::io::Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    for stream in listener.incoming() {
        let stream = stream?;
        let peer = peer_of(&stream)?;
        let mut requests = Requests::new(std::os::fd::AsRawFd::as_raw_fd(&stream));
        let mut writer = stream.try_clone()?;
        // Held so the descriptor `requests` reads from stays open.
        let _stream = stream;
        // One counter per connection: a peer that reconnects to reset it has
        // done the expensive part of the attack — a new connection, a new
        // SO_PEERCRED check — for a new window, which is a far worse trade than
        // sending declarations down one socket. F2.WS.08 keys it by session.
        let mut declarations = counter();
        while let Some((line, received)) = requests.next()? {
            if line.trim().is_empty() {
                continue;
            }
            let mut ancillary = Ancillary {
                received,
                registered: None,
            };
            writeln!(writer, "{}", {
                // Held only across one request. A poisoned lock means a
                // previous request panicked mid-write, and continuing with
                // whatever was there would stamp an unknown number on a
                // segment — so the value is taken either way and the caller
                // sees the same answer.
                let mut told = match generation.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                serve_line(
                    &line,
                    &peer,
                    owner_uid,
                    &mut declarations,
                    &mut told,
                    &mut ancillary,
                )
            })?;
            if let Some(session) = ancillary.registered.take() {
                on_session(session);
            }
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
        json::parse(&serve_line(
            &line,
            peer,
            OWNER,
            d,
            &mut None,
            &mut Ancillary::default(),
        ))
        .unwrap()
    }

    /// A **filtered** session without its listener is refused; an unfiltered
    /// one is not.
    ///
    /// The refusal exists because accepting a filtered registration with no
    /// descriptor would leave a process with nobody to answer its syscalls:
    /// every `openat` in it would fail with `ENOSYS` and the daemon would have
    /// reported success. It must not extend to a session that installed no
    /// filter — that session has no listener to carry, and refusing it is what
    /// made unfiltered sessions invisible to the daemon and left their cgroups
    /// behind for ever.
    #[test]
    fn a_trapping_session_without_its_listener_is_refused() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"registerSession","params":{"session_id":7,"trapping":true}}"#;

        let mut empty = Ancillary::default();
        let refused = json::parse(&serve_line(
            line,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut empty,
        ))
        .unwrap();
        assert!(
            refused.get("error").is_some(),
            "a registration with no descriptor was accepted: {refused:?}"
        );
        assert!(empty.registered.is_none());

        // With one, it is accepted and the caller is handed the session.
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(b);
        let mut carried = Ancillary {
            received: Some(std::os::fd::OwnedFd::from(a)),
            registered: None,
        };
        let accepted = json::parse(&serve_line(
            line,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut carried,
        ))
        .unwrap();
        assert_eq!(
            accepted
                .get("result")
                .and_then(|r| r.get("outcome"))
                .and_then(json::Value::as_str),
            Some("accepted")
        );
        let session = carried.registered.expect("the session reached the caller");
        assert_eq!(session.session_id, 7);
        assert_eq!(session.tty, None, "no tty is a real state, not a default");
        assert!(
            carried.received.is_none(),
            "the descriptor was left behind as well as taken"
        );

        // And a session that installed no filter is accepted with no
        // descriptor at all: it is watched, not supervised.
        let watched =
            r#"{"jsonrpc":"2.0","id":1,"method":"registerSession","params":{"session_id":8}}"#;
        let mut bare = Ancillary::default();
        let accepted = json::parse(&serve_line(
            watched,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut bare,
        ))
        .unwrap();
        assert!(
            accepted.get("error").is_none(),
            "an unfiltered session was refused for having no listener: {accepted:?}"
        );
        let session = bare
            .registered
            .expect("the watched session reached the caller");
        assert!(
            session.listener.is_none(),
            "a watched session carries no listener, and that is the state itself"
        );
    }

    /// The one place a client's string becomes a filesystem operation, and the
    /// only shape the daemon will ever `rmdir`.
    ///
    /// Driven through `serve_line`, so what runs is the validator the daemon
    /// runs and not a copy of its rules. Each rejected case is a different way
    /// of naming something that is not a session cgroup, and the accepted one
    /// is the shape `aisme run` actually prints.
    #[test]
    fn a_cgroup_that_is_not_a_session_directory_is_refused_and_named() {
        let root = "/sys/fs/cgroup/user.slice/aisme-0123456789abcdef";
        for (cgroup, why) in [
            ("/etc", "outside the hierarchy"),
            ("/sys/fs/cgroup", "the hierarchy root itself"),
            ("/sys/fs/cgroup/user.slice", "a slice, not a session"),
            (
                "/sys/fs/cgroup/user.slice/../../../etc",
                "dot-dot traversal",
            ),
            (
                "/sys/fs/cgroup/user.slice/aisme-nothex0123456",
                "sixteen characters that are not hexadecimal",
            ),
            (
                "/sys/fs/cgroup/user.slice/aisme-0123456789abcde",
                "fifteen digits, one short",
            ),
            (
                "/sys/fs/cgroup/user.slice//aisme-0123456789abcdef",
                "an empty component",
            ),
        ] {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"registerSession","params":{{"session_id":7,"cgroup":"{cgroup}"}}}}"#
            );
            let mut carried = Ancillary::default();
            let answer = json::parse(&serve_line(
                &line,
                &user(),
                OWNER,
                &mut Declarations::new(),
                &mut None,
                &mut carried,
            ))
            .unwrap();
            assert!(
                answer.get("error").is_some(),
                "accepted {cgroup} ({why}): {answer:?}"
            );
            assert!(
                carried.registered.is_none(),
                "{cgroup} ({why}) reached the caller anyway"
            );
        }

        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"registerSession","params":{{"session_id":7,"cgroup":"{root}"}}}}"#
        );
        let mut carried = Ancillary::default();
        let accepted = json::parse(&serve_line(
            &line,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut carried,
        ))
        .unwrap();
        assert!(
            accepted.get("error").is_none(),
            "a real session cgroup was refused: {accepted:?}"
        );
        assert_eq!(
            carried
                .registered
                .expect("the session reached the caller")
                .cgroup
                .as_deref(),
            Some(root)
        );
    }

    /// A session registration from a peer that is not local is refused by
    /// **where the caller is**, before its descriptor is looked at.
    #[test]
    fn a_session_registration_from_a_stranger_is_refused() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(b);
        let mut carried = Ancillary {
            received: Some(std::os::fd::OwnedFd::from(a)),
            registered: None,
        };
        let refused = json::parse(&serve_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"registerSession","params":{"session_id":7}}"#,
            &stranger(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut carried,
        ))
        .unwrap();
        assert_eq!(
            refused
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(json::Value::as_int),
            Some(-32001)
        );
        assert!(carried.registered.is_none());
    }

    /// `setPolicyGeneration` is accepted from a local peer, refused from one
    /// that is not, and the number reaches the next `getCapabilities`.
    #[test]
    fn the_generation_is_told_once_and_answered_thereafter() {
        let mut told = None;
        let send =
            |peer: &Peer, params: &str, told: &mut Option<aisme_core::policy::PolicyGeneration>| {
                let line = format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"setPolicyGeneration","params":{params}}}"#
                );
                json::parse(&serve_line(
                    &line,
                    peer,
                    OWNER,
                    &mut Declarations::new(),
                    told,
                    &mut Ancillary::default(),
                ))
                .unwrap()
            };

        // Before anyone says anything, the field is ABSENT — not zero. A
        // daemon answering 0 would be indistinguishable from one told 0.
        let caps = json::parse(&serve_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"getCapabilities","params":{}}"#,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut told,
            &mut Ancillary::default(),
        ))
        .unwrap();
        assert!(
            caps.get("result")
                .and_then(|r| r.get("policy_generation"))
                .is_none(),
            "an untold daemon must not claim a generation"
        );

        // A peer whose uid is not the owner's is refused by where it is.
        let refused = send(&stranger(), r#"{"generation":7}"#, &mut told);
        assert_eq!(
            refused
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(json::Value::as_int),
            Some(-32001)
        );
        assert_eq!(told, None, "a refused call must not have written the cell");

        let accepted = send(&user(), r#"{"generation":7}"#, &mut told);
        assert_eq!(
            accepted
                .get("result")
                .and_then(|r| r.get("outcome"))
                .and_then(json::Value::as_str),
            Some("accepted")
        );
        assert_eq!(told, Some(aisme_core::policy::PolicyGeneration(7)));

        // A generation that is absent or negative is refused, never defaulted:
        // a default would stamp a wrong number on every following segment.
        for bad in ["{}", r#"{"generation":-1}"#, r#"{"generation":"7"}"#] {
            let response = send(&user(), bad, &mut told);
            assert!(response.get("error").is_some(), "{bad} must be refused");
            assert_eq!(told, Some(aisme_core::policy::PolicyGeneration(7)), "{bad}");
        }

        let caps = json::parse(&serve_line(
            r#"{"jsonrpc":"2.0","id":1,"method":"getCapabilities","params":{}}"#,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut told,
            &mut Ancillary::default(),
        ))
        .unwrap();
        assert_eq!(
            caps.get("result")
                .and_then(|r| r.get("policy_generation"))
                .and_then(json::Value::as_int),
            Some(7)
        );
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
        let response = json::parse(&serve_line(
            "{",
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut Ancillary::default(),
        ))
        .unwrap();
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
            &mut None,
            &mut Ancillary::default(),
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
        // Retry the **connect**, against a wall-clock deadline.
        //
        // Two corrections to what stood here, and the test failed under a
        // parallel run to earn both. It waited for the *path to exist*, which
        // the listener creates before it accepts — so a socket that is there is
        // not a socket that answers. And it bounded the wait in
        // `yield_now()` calls, which is a guess measured in scheduler turns
        // rather than in time: a thousand of them pass in microseconds on an
        // idle machine and can elapse before the server thread is scheduled at
        // all when the rest of the suite is running. A flaky test is a gate
        // people learn to re-run.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut client = loop {
            match UnixStream::connect(&path) {
                Ok(client) => break client,
                Err(e) => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the server never accepted a connection on {}: {e}",
                        path.display()
                    );
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
        };
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
