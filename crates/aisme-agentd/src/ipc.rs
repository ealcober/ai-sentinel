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
/// What a session declared about itself, kept for as long as it runs.
///
/// The daemon holds these because the **supervisor is no longer the daemon**:
/// `aisme run` is the session's own parent, which is the only process Yama will
/// let read a descendant's memory without a capability. The daemon still holds
/// the policy, the adjudicator and the WAL, so it still decides — it is asked,
/// once per held open, over `decideOpen`.
pub struct SessionFacts {
    /// The controlling terminal the session named, for `F2.WS.06`'s prompt.
    pub tty: Option<String>,
    /// Path prefixes this session escalates when no daemon policy is in force.
    pub escalate: Vec<String>,
    /// An answer to use instead of asking, read once by `aisme run`.
    pub unattended: Option<String>,
    /// The operator's policy compiled **for this session**, when one is in
    /// force. `${…}` variables resolve to facts about *this* session, so the
    /// compilation cannot happen once at startup before any session exists —
    /// which is what `Bindings`' own documentation says and what the daemon
    /// used to do anyway, leaving `${workspace}` matching a directory no
    /// machine has.
    pub policy: Option<std::sync::Arc<aisme_core::policy::CompiledPolicy>>,
}

/// A parsed policy and the file it was read from.
///
/// The daemon parses at startup, so a policy that is not a policy still refuses
/// the daemon rather than the first session; the *binding* is what waits, and
/// it waits because there is nothing to bind to until a session exists.
pub struct PolicySource {
    /// The policy as written.
    pub policy: aisme_core::policy::Policy,
    /// Where it was read from, for diagnostics.
    pub path: String,
}

/// Everything the daemon needs to answer a supervisor.
///
/// One value rather than four parameters: a signature that grew to carry the
/// policy, the sessions and their counters would be a signature nobody reads
/// before adding the fifth thing to it.
pub struct Supervision {
    /// The operator's **parsed** policy, when one was given, with the file it
    /// came from so a diagnostic can name it. It is compiled once per session
    /// registration and never here: see [`SessionFacts::policy`].
    pub policy: Option<std::sync::Arc<PolicySource>>,
    /// The sessions that have registered, by id.
    pub sessions: std::sync::Mutex<std::collections::BTreeMap<u64, SessionFacts>>,
    /// Where an observed open goes, so the daemon still sees the actions after
    /// the notification loop moved into the session.
    pub observed: std::sync::Mutex<Option<crate::declare::Declared>>,
}

impl Supervision {
    /// A daemon with no policy and no sessions yet.
    #[must_use]
    pub fn new(policy: Option<std::sync::Arc<PolicySource>>) -> Supervision {
        Supervision {
            policy,
            sessions: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            observed: std::sync::Mutex::new(None),
        }
    }

    /// Send observed opens to the engine, so they reach the WAL.
    pub fn observing(&self, into: crate::declare::Declared) {
        if let Ok(mut slot) = self.observed.lock() {
            *slot = Some(into);
        }
    }
}

/// `decideOpen` — the supervisor asks, the daemon answers.
///
/// **The daemon decides and the session enforces**, which is the split the
/// kernel forces: only an ancestor may read a held open's path without a
/// capability, and only the daemon holds the compiled policy. A session that
/// decided what governs it would be deciding whether to be enforced.
///
/// The open is recorded on the way through. With the notification loop in the
/// session, this call is the **only** thing that tells the daemon an action
/// happened, so dropping the record here would make the WAL silent about
/// everything a supervised session did.
fn decide_open(request: &rpc::Request, supervision: &Supervision) -> String {
    use aisme_ebpf_common::Verdict;

    let Some(Value::Int(raw)) = request.params.get("session_id") else {
        return rpc::error(
            request.id,
            ErrorCode::InvalidParams,
            "session_id must be an integer",
        );
    };
    let session_id = u64::from_ne_bytes(raw.to_ne_bytes());
    let Some(path) = request.params.get("path").and_then(Value::as_str) else {
        return rpc::error(
            request.id,
            ErrorCode::InvalidParams,
            "path must be a string",
        );
    };

    // **Who made the call**, from `seccomp_notif.pid`, which the kernel writes
    // when it suspends the syscall. Absent is recorded as absent rather than as
    // zero: an action with no actor cannot be attributed to any declaration,
    // and a `0` that means *we were not told* is indistinguishable from a `0`
    // that means *the kernel*.
    let actor = match request.params.get("pid") {
        Some(Value::Int(pid)) => u32::try_from(*pid).ok(),
        _ => None,
    };
    // And its parent, so the recording carries an **ancestry** and not just a
    // set of pids: correlation walks from an action up to the process that
    // declared the intent, and a chain with no links is a chain that cannot be
    // walked. The supervisor reads it while the syscall is suspended, which is
    // the only moment the process is certainly still alive.
    let actor_parent = match request.params.get("ppid") {
        Some(Value::Int(ppid)) => u32::try_from(*ppid).ok(),
        _ => None,
    };

    // Recorded before it is judged: an open the daemon refused to answer is
    // still an open that happened.
    record_open(supervision, session_id, actor, actor_parent, path);

    let facts = supervision.sessions.lock().ok().and_then(|sessions| {
        sessions.get(&session_id).map(|facts| {
            (
                facts.tty.clone(),
                facts.escalate.clone(),
                facts.unattended.clone(),
                facts.policy.clone(),
            )
        })
    });
    let Some((tty, escalate, unattended, policy)) = facts else {
        // An unregistered session is not a session this daemon is supervising,
        // and answering it would be answering for a policy nobody bound to it.
        return rpc::error(
            request.id,
            ErrorCode::InvalidParams,
            "no such session; register it before asking",
        );
    };

    // **This session's** policy, not the daemon's: `${workspace}` and
    // `${home}` mean different directories for two sessions running under the
    // same daemon, so a verdict taken from a policy compiled before either of
    // them existed would be a verdict about nobody.
    let verdict = match &policy {
        Some(policy) => {
            let facts = aisme_core::policy::EventFacts {
                path: Some(path),
                ..aisme_core::policy::EventFacts::default()
            };
            aisme_core::policy::evaluate(policy, &facts).verdict
        }
        // No daemon policy: the session's declared escalate class is the
        // shorthand, exactly as it was when the loop lived here.
        None if escalate.iter().any(|p| path.starts_with(p.as_str())) => Verdict::Escalate,
        None => Verdict::Allow,
    };

    let asked = verdict == Verdict::Escalate;
    let verdict = if asked {
        ask_a_human(session_id, path, tty.as_deref(), unattended.as_deref())
    } else {
        verdict
    };
    rpc::response(
        request.id,
        Value::object([
            // The wire numbers, which `aisme-ebpf-common` fixes: Allow 0, Warn
            // 1, Escalate 2, Deny 3. The supervisor reads them back with the
            // same enum, so the two cannot disagree about which is which.
            ("verdict", Value::Int(verdict as i64)),
            // **Whether anybody was asked**, which the verdict alone cannot
            // say: an escalation answered *deny* and a compiled deny both come
            // back as `Deny`, and the difference between them is the whole
            // security argument. A compiled deny asks nobody, so no answer
            // exists to get wrong and no timeout has to expire for it to hold.
            ("asked", Value::Bool(asked)),
        ]),
    )
}

/// Put one observed open on the same stream every other event travels.
fn record_open(
    supervision: &Supervision,
    session_id: u64,
    actor: Option<u32>,
    actor_parent: Option<u32>,
    path: &str,
) {
    let Ok(slot) = supervision.observed.lock() else {
        return;
    };
    let Some(out) = slot.as_ref() else {
        return;
    };
    let mut event = aisme_ebpf_common::RawEvent::ZERO;
    event.kind = aisme_ebpf_common::EventKind::FileOpen.into();
    event.outcome = aisme_ebpf_common::Outcome::Observed.into();
    event.session_id = session_id;
    // The process the action belongs to. Correlation walks an ancestry from
    // here to find the declaration whose subtree contains it, so an event that
    // leaves this zero is an action nothing can ever be matched to
    // (`F2.WS.03`, and measured again here on 2026-09-15).
    event.tgid = actor.unwrap_or(0);
    event.ppid = actor_parent.unwrap_or(0);
    event.ts_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            u64::try_from(d.as_nanos() & u128::from(u64::MAX)).unwrap_or(0)
        });
    // Written through L0's accessor, so the one place that knows the layout is
    // the one place that writes it. The path is what the caller asked the
    // kernel for, resolved by the supervisor before it asked, so
    // `FLAG_PATH_UNRESOLVED` would be a lie here and is not set.
    let mut truncated = false;
    if let Some((buffer, len)) = event.file_path_mut() {
        let bytes = path.as_bytes();
        let n = bytes.len().min(buffer.len());
        buffer[..n].copy_from_slice(&bytes[..n]);
        *len = u16::try_from(n).unwrap_or(0);
        truncated = n < bytes.len();
    }
    if truncated {
        event.flags |= aisme_ebpf_common::FLAG_TRUNCATED;
    }
    let _ = out.send(event);
}

/// Ask whoever this session said could answer.
fn ask_a_human(
    session_id: u64,
    path: &str,
    tty: Option<&str>,
    unattended: Option<&str>,
) -> aisme_ebpf_common::Verdict {
    use aisme_core::adjudicate::{Adjudicator as _, Escalation};
    use aisme_core::enforce::EscalationId;
    use aisme_core::ontology::{PermissionGroup, SessionId, Severity};

    // The answer comes from the session's registration, never from this
    // process's environment: a daemon-side read could be steered by anything
    // able to set a variable in the daemon, which includes the agent being
    // adjudicated.
    let unattended = unattended.and_then(|v| match v {
        "d" => Some(crate::terminal::Unattended(
            aisme_ebpf_common::Verdict::Deny,
        )),
        "1" | "s" | "a" => Some(crate::terminal::Unattended(
            aisme_ebpf_common::Verdict::Allow,
        )),
        _ => None,
    });
    let mut adjudicator =
        crate::terminal::TerminalAdjudicator::new(tty.map(ToOwned::to_owned), unattended);
    // An unattended session waits for nobody: the answer is already known, and
    // a budget it will never spend would only slow a gate down.
    if unattended.is_some() {
        adjudicator = adjudicator.with_budget(std::time::Duration::ZERO);
    }
    let question = Escalation::new(
        EscalationId(session_id),
        SessionId(session_id),
        PermissionGroup::Credentials,
        "escalate",
        Severity::High,
        format!("read {path}"),
    );
    crate::runtime::block_on(adjudicator.ask(&question))
}

/// `declareToolCall` (`F2.WS.03`) — an agent volunteers what it is about to do.
///
/// It authorizes nothing: no grant, no verdict, no scope. The declaration is
/// recorded **beside** the actions it claims to explain so correlation can
/// check the claim rather than believe it (`DT-04`), and the process that made
/// it comes from `SO_PEERCRED` rather than from the message — a caller that
/// could name its own pid could attribute its actions to somebody else.
fn declare_tool_call(
    request: &rpc::Request,
    peer: &Peer,
    declarations: &mut Declarations,
) -> String {
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
                    peer.pid.and_then(|p| u32::try_from(p).ok()),
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

/// The home directory of `uid`, as the system says it is.
///
/// **From the uid, never from a variable.** The uid comes from `SO_PEERCRED`
/// and the kernel writes it, so it cannot be claimed; `HOME` in anyone's
/// environment can. A session that named its own `${home}` would aim a
/// credential rule at an empty directory and be allowed everywhere the rule was
/// supposed to hold.
fn home_of(uid: u32) -> Option<String> {
    let mut buf = [0 as libc::c_char; 4096];
    // SAFETY: an all-zero `passwd` is the documented starting point; it is
    // filled by the call below or left unused.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `pwd`, `buf` and `found` are ours and outlive the call, and the
    // length passed is `buf`'s own. `getpwuid_r` is the reentrant form; the
    // plain one returns a shared static this daemon's two workers could race.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            std::ptr::addr_of_mut!(pwd),
            buf.as_mut_ptr(),
            buf.len(),
            std::ptr::addr_of_mut!(found),
        )
    };
    if rc != 0 || found.is_null() {
        // No such user, or a name service that could not answer. Absent is
        // reported as absent: binding `${home}` to something invented would
        // silently move every rule that uses it.
        return None;
    }
    // SAFETY: on success `pw_dir` points into `buf`, which is still alive.
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    dir.to_str().ok().map(ToOwned::to_owned)
}

/// Compile the operator's policy for one session, with that session's own
/// bindings.
///
/// Both bindings come from facts the **system** supplies: `${home}` from the
/// peer's uid, and `${workspace}` from the scope the person who typed
/// `aisme run --scope` chose — the same trust position `--scope` already has,
/// where widening it is the operator's act and never the agent's.
///
/// A failure refuses **this session**, not the daemon: the other sessions
/// running under it are governed by a policy that compiled, and taking them
/// down with a new registration would make one bad launch an outage.
fn compile_for_session(
    source: &PolicySource,
    scope: Option<&str>,
    uid: u32,
) -> Result<aisme_core::policy::CompiledPolicy, String> {
    use aisme_core::policy::{compile, Bindings};

    let mut bindings = Bindings::new();
    if let Some(scope) = scope {
        bindings = bindings.with("workspace", scope);
    }
    if let Some(home) = home_of(uid) {
        bindings = bindings.with("home", &home);
    }
    compile(&source.policy, &bindings).map_err(|errors| {
        errors
            .iter()
            .map(|e| format!("{}: {e}", source.path))
            .collect::<Vec<String>>()
            .join("; ")
    })
}

fn register_session(
    request: &rpc::Request,
    peer: &Peer,
    ancillary: &mut Ancillary,
    supervision: &Supervision,
) -> String {
    // **No descriptor travels on this message.** The seccomp listener stays in
    // the session, because the process that answers a held open must be able to
    // read its path argument — and Yama grants that to an **ancestor**, which
    // is `aisme run` and never this daemon (`docs/11` point 1, `docs/12`). What
    // the daemon needs is what the session declares about itself, and a
    // `decideOpen` call when a held open needs a verdict.
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
    // The session's declared scope, which is what `${workspace}` resolves to.
    // With a policy in force it is **required**: a policy using `${workspace}`
    // would not compile without it, and one that does not use it would silently
    // become a different policy if the value were invented here.
    let scope = request.params.get("scope").and_then(Value::as_str);
    let compiled = match supervision.policy.as_ref() {
        None => None,
        Some(source) => {
            if scope.is_none() {
                return rpc::error(
                    request.id,
                    ErrorCode::InvalidParams,
                    "scope is required while a policy is in force: it is what ${workspace} means",
                );
            }
            match compile_for_session(source, scope, peer.uid) {
                Ok(compiled) => Some(std::sync::Arc::new(compiled)),
                // Named, and only this session is refused. The variable and the
                // rule are in the compiler's own diagnostic.
                Err(why) => return rpc::error(request.id, ErrorCode::InvalidParams, &why),
            }
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
        cgroup,
    });
    // Kept for as long as the session runs, because `decideOpen` needs them and
    // the supervisor that will call it is a different process from this one.
    if let (Ok(mut sessions), Some(registered)) =
        (supervision.sessions.lock(), ancillary.registered.as_ref())
    {
        sessions.insert(
            registered.session_id,
            SessionFacts {
                tty: registered.tty.clone(),
                escalate: registered.escalate.clone(),
                unattended: registered.unattended.clone(),
                policy: compiled,
            },
        );
    }
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
    supervision: &Supervision,
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
        Method::RegisterSession => register_session(&request, peer, ancillary, supervision),
        // The session's own supervisor asking what the policy says about one
        // held open (`docs/11` point 1). The daemon decides; the session
        // enforces, because only an ancestor may read a held open's path
        // without a capability.
        Method::DecideOpen => decide_open(&request, supervision),
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
        Method::DeclareToolCall => declare_tool_call(&request, peer, declarations),
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

/// Listen on `path`, serving every connection concurrently.
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
        // No policy and no sessions: this surface answers `decideOpen` with
        // "no such session", which is the honest answer from a server that is
        // supervising nothing.
        &std::sync::Arc::new(Supervision::new(None)),
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
    supervision: &std::sync::Arc<Supervision>,
    on_session: impl Fn(Registered) + Send + Sync + 'static,
    until: impl FnMut() -> bool,
) -> std::io::Result<()> {
    serve_with(
        path,
        owner_uid,
        generation,
        supervision,
        move || Declarations::feeding(declared.clone()),
        on_session,
        until,
    )
}

/// How many connections this daemon serves at once.
///
/// A bound rather than none, because the socket is uid-matched and an
/// unbounded accept loop would let anything that can reach it spawn threads
/// until the 50 MB budget breaks — a silent degradation where `I-19` wants a
/// named refusal. Nothing in F2 comes near it: a session holds one connection
/// and a hook holds one at a time.
const MAX_CONNECTIONS: usize = 64;

/// Decrements the live-connection count however the thread ends, panic
/// included. A counter that only falls on the happy path is a leak with extra
/// steps.
struct Live(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::Release);
    }
}

/// Serve one accepted connection until the peer closes it.
///
/// Everything here is per connection, which is what lets the connections run
/// concurrently without sharing anything but the mutexes they already shared.
fn serve_connection(
    stream: std::os::unix::net::UnixStream,
    peer: &Peer,
    owner_uid: u32,
    generation: &GenerationCell,
    supervision: &Supervision,
    declarations: &mut Declarations,
    on_session: &(dyn Fn(Registered) + Send + Sync),
) -> std::io::Result<()> {
    let mut requests = Requests::new(std::os::fd::AsRawFd::as_raw_fd(&stream));
    let mut writer = stream.try_clone()?;
    // Held so the descriptor `requests` reads from stays open.
    let _stream = stream;
    {
        while let Some((line, received)) = requests.next()? {
            if line.trim().is_empty() {
                continue;
            }
            let mut ancillary = Ancillary {
                received,
                registered: None,
            };
            // **The generation is copied in and written back, never held
            // across the request.** `serve_line` can block for the length of an
            // adjudication — `decide_open` calls `ask_a_human` on this thread
            // and the terminal budget is ten seconds — so a lock spanning it
            // would make one prompt freeze every other connection, which is the
            // deadlock this server was just fixed for, moved one level down. It
            // was measured doing exactly that: the second caller waited the
            // full ten seconds.
            //
            // A poisoned lock means a previous request panicked mid-write, and
            // continuing with whatever was there would stamp an unknown number
            // on a segment — so the value is taken either way and the caller
            // sees the same answer.
            let taken = |cell: &GenerationCell| match cell.lock() {
                Ok(g) => *g,
                Err(poisoned) => *poisoned.into_inner(),
            };
            let before = taken(generation);
            let mut told = before;
            let answer = serve_line(
                &line,
                peer,
                owner_uid,
                declarations,
                &mut told,
                &mut ancillary,
                supervision,
            );
            if told != before {
                // Only `setPolicyGeneration` reaches here, and only the daemon's
                // own loader calls it. Last writer wins, which is what a single
                // cell meant before too.
                match generation.lock() {
                    Ok(mut g) => *g = told,
                    Err(poisoned) => *poisoned.into_inner() = told,
                }
            }
            writeln!(writer, "{answer}")?;
            // No method carries a descriptor any more — the seccomp listener
            // stays in the session, whose own parent answers it. One that
            // arrives is **closed**, not leaked and not ignored: the reader
            // uses `recvmsg` precisely so a control message cannot be lost, and
            // the point of that is undone if what it catches is then dropped on
            // the floor of the process.
            if let Some(stray) = ancillary.received.take() {
                drop(stray);
                eprintln!("ipc: a request carried a descriptor no method takes; it was closed");
            }
            if let Some(session) = ancillary.registered.take() {
                on_session(session);
            }
        }
    }
    Ok(())
}

/// Listen on `path`, serving every connection **concurrently**, one thread
/// each.
///
/// **Serially was a deadlock, and it was measured.** `aisme run` holds one
/// connection open for the whole session — for `decideOpen` when it traps, for
/// the registration when it does not — so a hook connecting from inside that
/// session queued behind it and was never reached: the session hung for ever,
/// with `aisme run` in `recv_wait_event`, the shell in `do_wait` and
/// `aisme declare` in `unix_stream_data_wait`. The intent plane and the
/// enforcement plane could not both exist in one session.
///
/// **A thread each, and not one thread polling many**, because this daemon's
/// own handler blocks by the second: `decide_open` calls `ask_a_human` on the
/// serving thread and the terminal budget is ten seconds. A multiplexer would
/// have frozen every session and every hook for the length of one prompt.
///
/// Nothing new is shared. `Declarations` was already per connection, the
/// generation cell was already an `Arc<Mutex<…>>`, and `Supervision` was
/// already built out of mutexes. What changed is who runs the loop.
fn serve_with(
    path: &Path,
    owner_uid: u32,
    generation: &GenerationCell,
    supervision: &std::sync::Arc<Supervision>,
    counter: impl Fn() -> Declarations + Send + Sync + 'static,
    on_session: impl Fn(Registered) + Send + Sync + 'static,
    mut until: impl FnMut() -> bool,
) -> std::io::Result<()> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    if path.exists() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    let counter = Arc::new(counter);
    let on_session = Arc::new(on_session);
    let live = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let stream = stream?;
        let peer = peer_of(&stream)?;

        if live.load(Ordering::Acquire) >= MAX_CONNECTIONS {
            // Named and closed, never queued: a caller left waiting on a socket
            // that will not be read cannot tell that from a slow answer, and a
            // hook that cannot tell them apart spends its whole budget finding
            // out (`I-19`).
            let mut writer = stream;
            let _ = writeln!(
                writer,
                "{}",
                rpc::error(
                    None,
                    ErrorCode::InvalidRequest,
                    &format!("the daemon is serving {MAX_CONNECTIONS} connections; try again"),
                )
            );
            eprintln!("ipc: refused a connection at the {MAX_CONNECTIONS}-connection bound");
            continue;
        }

        live.fetch_add(1, Ordering::Release);
        let (generation, supervision) = (generation.clone(), Arc::clone(supervision));
        let (counter, on_session) = (Arc::clone(&counter), Arc::clone(&on_session));
        let live = Arc::clone(&live);
        std::thread::spawn(move || {
            // Dropped however this thread ends, so a panic below costs one
            // connection's slot and not the bound.
            let _slot = Live(live);
            // One counter per connection: a peer that reconnects to reset it
            // has done the expensive part of the attack — a new connection, a
            // new `SO_PEERCRED` check — for a new window, which is a far worse
            // trade than sending declarations down one socket. `F2.WS.08` keys
            // it by session.
            let mut declarations = counter();
            // A panic must cost the connection that caused it and not the
            // daemon. Serially it took the whole accept loop down with it;
            // concurrently it would take every other session's supervisor too,
            // which is a much worse trade for the same defect.
            let served = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                serve_connection(
                    stream,
                    &peer,
                    owner_uid,
                    &generation,
                    &supervision,
                    &mut declarations,
                    on_session.as_ref(),
                )
            }));
            match served {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("ipc: connection ended: {e}"),
                Err(_) => {
                    eprintln!("ipc: a connection panicked; it was closed and the daemon runs");
                }
            }
        });

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

    /// A policy parsed from source, for a test that needs one in force.
    fn parsed(source: &str) -> PolicySource {
        PolicySource {
            policy: aisme_core::policy::parse(source).expect("the test policy parses"),
            path: "<test>".to_owned(),
        }
    }

    /// Register one session through the production path, with `extra` spliced
    /// into its params, and return the daemon's answer.
    fn register_with(supervision: &Supervision, id: i64, extra: &str) -> json::Value {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"registerSession","params":{{"session_id":{id},"trapping":true{extra}}}}}"#
        );
        json::parse(&serve_line(
            &line,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut Ancillary::default(),
            supervision,
        ))
        .unwrap()
    }

    /// Ask `decideOpen` about one path, and return the wire verdict.
    fn verdict_for(supervision: &Supervision, id: i64, path: &str) -> Option<i64> {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"decideOpen","params":{{"session_id":{id},"path":"{path}"}}}}"#
        );
        json::parse(&serve_line(
            &line,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut Ancillary::default(),
            supervision,
        ))
        .unwrap()
        .get("result")?
        .get("verdict")?
        .as_int()
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
            &Supervision::new(None),
        ))
        .unwrap()
    }

    /// **No descriptor travels on `registerSession`**, and a session that
    /// installs a filter is accepted without one.
    ///
    /// The seccomp listener stays in the session, because the process that
    /// answers a held open must be able to read its path argument and Yama
    /// grants that to an **ancestor** — which is `aisme run` and never this
    /// daemon. What the daemon needs is what the session declares about itself,
    /// and a `decideOpen` call when a held open needs a verdict.
    #[test]
    fn a_registration_carries_no_descriptor_and_is_accepted_without_one() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"registerSession","params":{"session_id":7,"trapping":true}}"#;
        let mut bare = Ancillary::default();
        let accepted = json::parse(&serve_line(
            line,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut bare,
            &Supervision::new(None),
        ))
        .unwrap();
        assert_eq!(
            accepted
                .get("result")
                .and_then(|r| r.get("outcome"))
                .and_then(json::Value::as_str),
            Some("accepted"),
            "a filtered session was refused for carrying no listener: {accepted:?}"
        );
        let session = bare.registered.expect("the session reached the caller");
        assert_eq!(session.session_id, 7);
        assert_eq!(session.tty, None, "no tty is a real state, not a default");

        // A descriptor sent anyway is **not** consumed by the registration. The
        // server closes it rather than leaking it, and a registration that
        // quietly took one would be a second way to supervise — which is a
        // second thing to keep true.
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(b);
        let mut carried = Ancillary {
            received: Some(std::os::fd::OwnedFd::from(a)),
            registered: None,
        };
        let answer = json::parse(&serve_line(
            line,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut carried,
            &Supervision::new(None),
        ))
        .unwrap();
        assert!(answer.get("error").is_none());
        assert!(
            carried.received.is_some(),
            "the registration consumed a descriptor it has no use for"
        );
    }

    /// A `decideOpen` for a session nobody registered is **refused**.
    ///
    /// Answering it would be answering for a policy nothing bound to that
    /// session — and a supervisor that got an answer for a session the daemon
    /// is not supervising would believe it was supervised.
    #[test]
    fn deciding_for_an_unregistered_session_is_refused() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"decideOpen","params":{"session_id":99,"path":"/etc/hostname"}}"#;
        let answer = json::parse(&serve_line(
            line,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut Ancillary::default(),
            &Supervision::new(None),
        ))
        .unwrap();
        assert!(
            answer.get("error").is_some(),
            "a session the daemon never saw was decided for: {answer:?}"
        );
    }

    /// **An observed open carries the process that made it, and that process's
    /// parent.**
    ///
    /// Since `ADR-09` the notification loop lives in the session, so `decideOpen`
    /// is the daemon's **only** sight of an action — and correlation attributes
    /// an action to the declaration whose process *subtree* contains it. An
    /// ancestry is walked from a pid, so an action with no pid can never be
    /// matched to any declaration.
    ///
    /// Measured on 2026-09-15 before this held: every `FileOpen` in the WAL of a
    /// real supervised session read `tgid=0`, and
    /// `aisme-agentsim --to-trace` reported **every** action unattributed. It is
    /// the same defect `F2.WS.03` closed for declarations, which were measured
    /// arriving as `tgid=0 pid=0 kind=ToolCall` before the declaring process was
    /// put on the wire.
    ///
    /// The pid is the kernel's — `seccomp_notif.pid`, written when the call was
    /// suspended — and the parent is read by the supervisor while it is still
    /// suspended, which is the only moment a short-lived process is certainly
    /// still there to be asked.
    #[test]
    fn an_observed_open_carries_the_process_that_made_it_and_its_parent() {
        use aisme_core::sensor::{EventBatch, Sensor as _};
        use aisme_ebpf_common::EventKind;

        let (mut sensor, tx) = crate::declare::DeclarationSensor::new();
        let supervision = Supervision::new(None);
        supervision.observing(tx);
        register_with(&supervision, 7, "");

        let line = r#"{"jsonrpc":"2.0","id":1,"method":"decideOpen","params":{"session_id":7,"pid":4242,"ppid":424,"path":"/etc/hostname"}}"#;
        let _ = serve_line(
            line,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut Ancillary::default(),
            &supervision,
        );

        let mut batch = EventBatch::with_capacity(4);
        assert_eq!(
            sensor
                .poll(&mut batch, std::time::Duration::ZERO)
                .expect("poll"),
            1,
            "the open did not reach the engine at all"
        );
        let event = batch.as_slice()[0];
        assert_eq!(event.kind.decode(), Ok(EventKind::FileOpen));
        assert_eq!(
            (event.tgid, event.ppid),
            (4242, 424),
            "the action arrived with no actor or no ancestry, so nothing can attribute it"
        );
    }

    /// An open whose caller was not named is recorded with **no** actor, and not
    /// with a plausible one.
    ///
    /// Zero here means *we were not told*, which is what the recorder reads as
    /// unexplained. Substituting the session's own pid, or the daemon's, would
    /// attribute the action to a process that did not make it — a worse answer
    /// than none, because it is indistinguishable from a correct one.
    #[test]
    fn an_open_with_no_caller_named_is_recorded_without_one() {
        use aisme_core::sensor::{EventBatch, Sensor as _};

        let (mut sensor, tx) = crate::declare::DeclarationSensor::new();
        let supervision = Supervision::new(None);
        supervision.observing(tx);
        register_with(&supervision, 7, "");

        let line = r#"{"jsonrpc":"2.0","id":1,"method":"decideOpen","params":{"session_id":7,"path":"/etc/hostname"}}"#;
        let _ = serve_line(
            line,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut Ancillary::default(),
            &supervision,
        );

        let mut batch = EventBatch::with_capacity(4);
        assert_eq!(
            sensor
                .poll(&mut batch, std::time::Duration::ZERO)
                .expect("poll"),
            1
        );
        assert_eq!((batch.as_slice()[0].tgid, batch.as_slice()[0].ppid), (0, 0));
    }

    /// A policy in force is compiled **per session**, and two sessions with
    /// different scopes get different verdicts from the same file.
    ///
    /// This is the test the old daemon could not pass and would not have
    /// failed: it compiled once at startup with no bindings at all, so
    /// `${workspace}` matched a directory no machine has while every line it
    /// printed said three rules were in force. A rule that cannot fire is
    /// worse than no rule, because the gate that tests it still passes.
    ///
    /// `${home}` is not varied here and cannot be: it is derived from the
    /// peer's uid, and one test process has one uid. That is the property, not
    /// a gap in the test — a session that could choose its own `${home}` would
    /// aim a credential rule at an empty directory.
    #[test]
    fn two_sessions_with_different_scopes_are_judged_by_different_policies() {
        let source = parsed(
            "[[rule]]\nid = \"scope\"\ngroup = \"FILES_OUTSIDE_WORKSPACE\"\nmatch = { path_under = \"${workspace}\" }\nverdict = \"escalate\"\n",
        );
        let supervision = Supervision::new(Some(std::sync::Arc::new(source)));
        register_with(&supervision, 1, r#","scope":"/tmp/alpha","unattended":"d""#);
        register_with(&supervision, 2, r#","scope":"/tmp/beta","unattended":"d""#);

        assert_eq!(
            verdict_for(&supervision, 1, "/tmp/alpha/file"),
            Some(3),
            "the first session's own workspace did not reach its rule"
        );
        assert_eq!(
            verdict_for(&supervision, 2, "/tmp/alpha/file"),
            Some(0),
            "the second session was judged by the first session's workspace: \
             the policy was compiled once and shared"
        );
    }

    /// A session whose policy cannot be bound is refused, **and the daemon is
    /// not**: another session registering afterwards still succeeds.
    ///
    /// The refusal names the variable and the rule, because the operator who
    /// has to fix it is reading this line and nothing else.
    #[test]
    fn a_session_whose_policy_will_not_compile_is_refused_and_the_daemon_is_not() {
        let source = parsed(
            "[[rule]]\nid = \"nowhere\"\ngroup = \"FILES_OUTSIDE_WORKSPACE\"\nmatch = { path_under = \"${nowhere}\" }\nverdict = \"allow\"\n",
        );
        let supervision = Supervision::new(Some(std::sync::Arc::new(source)));
        let refused = register_with(&supervision, 1, r#","scope":"/tmp/alpha""#);
        let message = refused
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        assert!(
            message.contains("nowhere"),
            "the refusal names neither the variable nor the rule: {refused:?}"
        );

        // The daemon is still serving, and a session it *can* bind still runs.
        let source = parsed(
            "[[rule]]\nid = \"scope\"\ngroup = \"FILES_OUTSIDE_WORKSPACE\"\nmatch = { path_under = \"${workspace}\" }\nverdict = \"allow\"\n",
        );
        let supervision = Supervision::new(Some(std::sync::Arc::new(source)));
        let accepted = register_with(&supervision, 2, r#","scope":"/tmp/beta""#);
        assert!(
            accepted.get("result").is_some(),
            "a later registration was refused too: {accepted:?}"
        );
    }

    /// A session cannot choose what `${home}` means, and a registration that
    /// tries is not obeyed.
    ///
    /// The binding comes from the peer's uid, which the kernel writes into
    /// `SO_PEERCRED`. A session that could name its own home would point every
    /// credential rule at a directory it had just created and be allowed
    /// everywhere the rule was meant to hold.
    #[test]
    fn a_session_cannot_name_its_own_home() {
        let source = parsed(
            "[[rule]]\nid = \"creds\"\ngroup = \"CREDENTIALS\"\nmatch = { path_glob = \"${home}/.aws/**\" }\nverdict = \"deny\"\n",
        );
        let supervision = Supervision::new(Some(std::sync::Arc::new(source)));
        register_with(
            &supervision,
            1,
            r#","scope":"/tmp/alpha","home":"/tmp/not-my-home""#,
        );

        let real = home_of(user().uid).expect("this test's own user has a home");
        assert_eq!(
            verdict_for(&supervision, 1, &format!("{real}/.aws/credentials")),
            Some(3),
            "the rule stopped covering the peer's real home"
        );
        assert_eq!(
            verdict_for(&supervision, 1, "/tmp/not-my-home/.aws/credentials"),
            Some(0),
            "the session's claimed home was bound: it chose what governed it"
        );
    }

    /// With no daemon policy, the session's declared escalate class decides —
    /// and the answer says **whether anybody was asked**.
    ///
    /// That flag is the whole security argument in one field: an escalation
    /// answered *deny* and a compiled deny both come back as `Deny`, and only a
    /// compiled deny asks nobody. A supervisor that could not tell them apart
    /// could not report the difference either.
    #[test]
    fn the_answer_says_whether_anybody_was_asked() {
        let supervision = Supervision::new(None);
        let register = r#"{"jsonrpc":"2.0","id":1,"method":"registerSession","params":{"session_id":7,"trapping":true,"unattended":"d","escalate":["/etc/shadow"]}}"#;
        let _ = serve_line(
            register,
            &user(),
            OWNER,
            &mut Declarations::new(),
            &mut None,
            &mut Ancillary::default(),
            &supervision,
        );

        let decide = |path: &str| {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"decideOpen","params":{{"session_id":7,"path":"{path}"}}}}"#
            );
            json::parse(&serve_line(
                &line,
                &user(),
                OWNER,
                &mut Declarations::new(),
                &mut None,
                &mut Ancillary::default(),
                &supervision,
            ))
            .unwrap()
        };

        let plain = decide("/etc/hostname");
        let result = plain.get("result").expect("a verdict");
        assert_eq!(
            result.get("verdict").and_then(json::Value::as_int),
            Some(0),
            "a path no rule names is allowed (§B.10's default)"
        );
        assert_eq!(
            result.get("asked"),
            Some(&json::Value::Bool(false)),
            "nobody should have been asked about a path nothing escalates"
        );

        let escalated = decide("/etc/shadow");
        let result = escalated.get("result").expect("a verdict");
        assert_eq!(
            result.get("asked"),
            Some(&json::Value::Bool(true)),
            "the escalate class must reach the adjudicator"
        );
        assert_eq!(
            result.get("verdict").and_then(json::Value::as_int),
            Some(3),
            "the session's unattended answer was `d`, and the answer decides"
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
                &Supervision::new(None),
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
            &Supervision::new(None),
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
            &Supervision::new(None),
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
                    &Supervision::new(None),
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
            &Supervision::new(None),
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
            &Supervision::new(None),
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
            &Supervision::new(None),
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
            &Supervision::new(None),
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

    /// A scratch server on its own thread, and a connected client.
    ///
    /// `until` is `|| false`, so the accept loop keeps accepting: a test about
    /// concurrency cannot use a server that stops after one connection.
    fn server(tag: &str) -> (std::path::PathBuf, std::sync::Arc<Supervision>) {
        let dir = std::env::temp_dir().join(format!("aisme-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("control.sock");
        let supervision = std::sync::Arc::new(Supervision::new(None));
        let owner = Peer::from_current_uid();
        let (server_path, shared) = (path.clone(), std::sync::Arc::clone(&supervision));
        std::thread::spawn(move || {
            let _ = serve_with(
                &server_path,
                owner.uid,
                &generation_cell(),
                &shared,
                Declarations::new,
                drop,
                || false,
            );
        });
        (path, supervision)
    }

    /// Connect, against a wall-clock deadline rather than a guess.
    fn connect(path: &std::path::Path) -> UnixStream {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Ok(client) = UnixStream::connect(path) {
                return client;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the server never accepted a connection on {}",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// One request, one reply.
    fn ask(client: &UnixStream, line: &str) -> json::Value {
        writeln!(&mut client.try_clone().unwrap(), "{line}").unwrap();
        let mut reply = String::new();
        BufReader::new(client.try_clone().unwrap())
            .read_line(&mut reply)
            .unwrap();
        json::parse(reply.trim()).unwrap()
    }

    /// **A connection held open does not stop the daemon serving another.**
    ///
    /// This is the measured deadlock, made deterministic. `aisme run` holds one
    /// connection open for the whole session — for `decideOpen` when it traps,
    /// for the registration when it does not — and served serially that meant a
    /// hook connecting from inside the session queued behind it and was never
    /// reached. Measured in the real topology: the session hung for ever, and
    /// with a budget on the hook's socket five declarations took 103 ms each
    /// and one of five landed.
    ///
    /// The first client here sends **nothing at all**, which is what a session
    /// between two opens looks like from the server's side.
    #[test]
    fn a_connection_held_open_does_not_stop_another_being_served() {
        let (path, _supervision) = server("ipc-concurrent");
        let idle = connect(&path);
        // Make the server commit to this connection: one request, answered, and
        // then silence. Serially, the loop is now inside this connection's read.
        let first = ask(
            &idle,
            r#"{"jsonrpc":"2.0","id":1,"method":"getCapabilities"}"#,
        );
        assert!(first.get("result").is_some(), "{first:?}");

        let hook = connect(&path);
        let answer = ask(
            &hook,
            r#"{"jsonrpc":"2.0","id":2,"method":"getCapabilities"}"#,
        );
        assert_eq!(
            answer.get("id").and_then(json::Value::as_int),
            Some(2),
            "a second connection was not served while the first was held open, \
             which is the deadlock the intent plane died of"
        );
        drop(idle);
        drop(hook);
    }

    /// **And a handler that blocks does not freeze the daemon either.**
    ///
    /// This is the assertion that chooses a thread per connection over one
    /// thread polling many. `decide_open` calls `ask_a_human` **on the serving
    /// thread**, and the terminal budget is ten seconds: under a multiplexer,
    /// one escalation prompt would freeze every other session and every hook
    /// for the length of it. A design that assumes handlers are quick is wrong
    /// in this daemon, and this test is what says so.
    ///
    /// The prompt is a real one, on a real pty, and it is answered at the end —
    /// so the test costs milliseconds rather than the ten seconds it is about.
    #[test]
    fn a_blocked_adjudication_does_not_freeze_the_daemon() {
        let (path, supervision) = server("ipc-prompt");

        // A terminal nobody is typing into, yet.
        let (mut master, tty) = scratch_pty();

        let escalating = parsed(
            "[[rule]]\nid = \"e\"\ngroup = \"CREDENTIALS\"\nmatch = { path_under = \"/etc/shadow\" }\nverdict = \"escalate\"\n",
        );
        let compiled = compile_for_session(&escalating, Some("/tmp"), Peer::from_current_uid().uid)
            .expect("the test policy binds");
        supervision.sessions.lock().unwrap().insert(
            9,
            SessionFacts {
                tty: Some(tty),
                escalate: Vec::new(),
                unattended: None,
                policy: Some(std::sync::Arc::new(compiled)),
            },
        );

        // This connection will sit inside `ask_a_human` until a key is typed.
        let prompting = connect(&path);
        let waiting = std::thread::spawn(move || {
            ask(
                &prompting,
                r#"{"jsonrpc":"2.0","id":1,"method":"decideOpen","params":{"session_id":9,"path":"/etc/shadow"}}"#,
            )
        });

        // Meanwhile, somebody else is answered — and quickly.
        let other = connect(&path);
        let started = std::time::Instant::now();
        let answer = ask(
            &other,
            r#"{"jsonrpc":"2.0","id":2,"method":"getCapabilities"}"#,
        );
        let took = started.elapsed();
        assert_eq!(answer.get("id").and_then(json::Value::as_int), Some(2));
        assert!(
            took < std::time::Duration::from_secs(5),
            "a second caller waited {took:?} behind an adjudication prompt; the prompt's \
             own budget is ten seconds, so this is the whole of it"
        );

        // Now answer the prompt, so the test does not spend the budget.
        master.write_all(b"d").unwrap();
        master.flush().unwrap();
        let verdict = waiting.join().unwrap();
        assert_eq!(
            verdict
                .get("result")
                .and_then(|r| r.get("verdict"))
                .and_then(json::Value::as_int),
            Some(3),
            "the answer typed at the terminal was not the verdict: {verdict:?}"
        );
        drop(other);
    }

    /// The bound is a **named refusal**, not a silent queue.
    ///
    /// The socket is uid-matched, so the party that could exhaust it is the
    /// owner rather than the agent — but an unbounded accept loop would let
    /// anything reaching the socket spawn threads until the 50 MB budget broke,
    /// which is a silent degradation where `I-19` wants a refusal that says so.
    #[test]
    fn the_connection_bound_refuses_by_name_and_the_daemon_keeps_serving() {
        let (path, _supervision) = server("ipc-bound");

        // Fill it. Each connection is made to commit the server to a thread by
        // exchanging one request.
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let client = connect(&path);
            let _ = ask(
                &client,
                r#"{"jsonrpc":"2.0","id":1,"method":"getCapabilities"}"#,
            );
            held.push(client);
        }

        let refused = connect(&path);
        let mut reply = String::new();
        BufReader::new(refused.try_clone().unwrap())
            .read_line(&mut reply)
            .unwrap();
        let parsed = json::parse(reply.trim()).unwrap();
        let message = parsed
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        assert!(
            message.contains(&MAX_CONNECTIONS.to_string()),
            "the refusal does not say what the bound is: {parsed:?}"
        );

        // And the daemon is still a daemon: free one slot, and the next caller
        // is served.
        held.pop();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let client = connect(&path);
            let answer = ask(
                &client,
                r#"{"jsonrpc":"2.0","id":7,"method":"getCapabilities"}"#,
            );
            if answer.get("result").is_some() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the bound never released after a connection closed: {answer:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// A pty, for a test that needs a terminal nobody is typing into.
    ///
    /// `ptsname_r`, never `ptsname`: the plain form returns a pointer into
    /// libc's own **static** storage and every test in this binary shares one
    /// process, so two tests opening a pty at once would race on that buffer
    /// and one would adjudicate against the other's terminal.
    fn scratch_pty() -> (std::fs::File, String) {
        use std::os::fd::FromRawFd as _;

        // SAFETY: `posix_openpt` returns a descriptor we then own.
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        assert!(master >= 0, "posix_openpt");
        // SAFETY: the descriptor just returned.
        assert_eq!(unsafe { libc::grantpt(master) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::unlockpt(master) }, 0);
        let mut buffer = [0 as libc::c_char; 256];
        // SAFETY: `buffer` is ours, outlives the call, and its length is passed.
        let rc = unsafe { libc::ptsname_r(master, buffer.as_mut_ptr(), buffer.len()) };
        assert_eq!(rc, 0, "ptsname_r");
        // SAFETY: on success the buffer holds a NUL-terminated name.
        let name = unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: we own `master` and nothing else does.
        (unsafe { std::fs::File::from_raw_fd(master) }, name)
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
