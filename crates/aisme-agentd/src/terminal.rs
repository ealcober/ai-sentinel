// SPDX-License-Identifier: Apache-2.0
//! `TerminalAdjudicator` — the human, in the terminal the session already owns
//! (`F2.WS.06`).
//!
//! `docs/design/01_permission-model.md` §7.3 makes the argument and it is why
//! `aisme run` is the default onboarding path: when a session is started as
//! `aisme run -- <cmd>` **we own the terminal**, so the prompt goes where the
//! developer is already looking — over SSH, in a container, in tmux, and in
//! WSL2 where the daemon is in Linux and the desktop is in Windows. It sidesteps
//! the entire GNOME/KDE/Wayland/X11 problem for the commonest developer case.
//!
//! **`agentd` has no controlling terminal; the session does.** `aisme run` sends
//! the path of its own in `registerSession`, and this opens it when it must ask.

use std::time::Duration;

use aisme_core::adjudicate::{
    AdjudicationChannel, Adjudicator, BoxFuture, Escalation, GrantCeiling, TimeoutDefault, Warning,
};
use aisme_ebpf_common::Verdict;

/// What a keystroke means. §7.3's four answers, and nothing else is one.
///
/// A key that is not here is **not** a default: it is re-read, because a
/// mistyped character that silently meant `deny` would teach an operator that
/// their answer does not matter.
const fn verdict_of(key: u8) -> Option<Verdict> {
    match key {
        b'd' | b'D' => Some(Verdict::Deny),
        // Allow once, this session, and always differ in the *grant* they
        // create, which is `F7`'s; at F2 all three permit this syscall and the
        // grant is recorded as not yet implemented rather than faked.
        b'1' | b's' | b'S' | b'a' | b'A' => Some(Verdict::Allow),
        _ => None,
    }
}

/// An answer given without a human, for gates and unattended runs.
///
/// **Read once, in `aisme run`, before `exec`** — never here, and never from
/// the daemon's own environment. An adjudicator that read its environment could
/// be steered by anything able to set a variable in the daemon, which includes
/// the agent it is adjudicating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unattended(pub Verdict);

/// Ask a human in the session's terminal.
pub struct TerminalAdjudicator {
    /// The session's controlling terminal. `None` is a real state: a session
    /// with no terminal is answered with the timeout verdict at once, rather
    /// than waiting a budget it cannot spend on a prompt nobody will see.
    tty: Option<String>,
    /// When set, every question is answered with this and recorded as
    /// unattended, so a gate's run is never mistaken for a human's decision.
    unattended: Option<Unattended>,
    /// How many were answered without a human, for the summary.
    pub answered_unattended: u64,
    /// How long a human has. Defaults to §2.20.5's value for this channel; a
    /// caller may shorten it, and a gate does.
    budget: Duration,
}

impl TerminalAdjudicator {
    /// One for a session.
    #[must_use]
    pub const fn new(tty: Option<String>, unattended: Option<Unattended>) -> TerminalAdjudicator {
        TerminalAdjudicator {
            tty,
            unattended,
            answered_unattended: 0,
            // A terminal the developer is looking at is the focused case;
            // §2.20.5 gives it 10 s.
            budget: AdjudicationChannel::Terminal.budget(true),
        }
    }

    /// The same adjudicator with a shorter budget.
    ///
    /// The default is §2.20.5's and stays the default; this exists because a
    /// test that proves the timeout works must not take ten seconds to do it,
    /// and because a deployment with a different T2 ceiling will need it.
    #[must_use]
    pub const fn with_budget(mut self, budget: Duration) -> TerminalAdjudicator {
        self.budget = budget;
        self
    }

    /// §7.3's prompt, as the design note draws it.
    ///
    /// Composed here rather than in the design note's words being re-invented:
    /// the note is the source, and this renders it.
    #[must_use]
    pub fn prompt(request: &Escalation) -> String {
        use std::fmt::Write as _;

        let mut out = format!("\n⚠ AISME  {}\n", request.summary);
        if let Some(intent) = &request.declared_intent {
            // An agent's declared intent is shown as a **claim**, never as a
            // fact: `DT-04` exists because a declaration may be a lie.
            let _ = writeln!(out, "         Stated intent: {intent:?}");
        }
        let _ = writeln!(
            out,
            "         {} · rule {}",
            request.group.as_str(),
            request.rule_id
        );
        out.push_str("         [d] deny  [1] allow once  [s] allow this session  [a] always > ");
        out
    }

    /// Write the prompt and wait for one keystroke, within `budget`.
    ///
    /// Returns `None` when the budget ran out or the terminal could not be
    /// used — the caller then applies the channel's timeout default, which for
    /// the escalate class is `deny`.
    fn ask_the_terminal(&self, request: &Escalation, budget: Duration) -> Option<Verdict> {
        use std::io::{Read as _, Write as _};

        let tty = self.tty.as_ref()?;
        // Opened read-write: the prompt goes to the terminal itself, never to
        // stdout, which a pipe the agent controls could capture — and an agent
        // that can read the prompt can answer it.
        let mut handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(tty)
            .ok()?;
        handle.write_all(Self::prompt(request).as_bytes()).ok()?;
        handle.flush().ok()?;

        // One keystroke means one keystroke. A terminal is in canonical mode by
        // default and hands a reader nothing until a newline, so `[d] deny …`
        // would sit there having answered nothing until the budget ran out —
        // measured: the prompt returned the timeout verdict while the answer
        // was already typed. Raw mode is restored before returning, whatever
        // happens, so the session's terminal is left as it was found.
        let _raw = RawMode::enter(&handle);

        let deadline = std::time::Instant::now() + budget;
        let mut key = [0u8; 1];
        loop {
            let left = deadline.checked_duration_since(std::time::Instant::now())?;
            if !wait_readable(&handle, left) {
                // The budget is enforced here and not by the caller, so a
                // caller that forgot to time out still fails closed.
                let _ = handle.write_all(b"\n(no answer within the budget)\n");
                return None;
            }
            match handle.read(&mut key) {
                Ok(1) => {
                    if let Some(verdict) = verdict_of(key[0]) {
                        let _ = handle.write_all(b"\n");
                        return Some(verdict);
                    }
                    // Not one of the four: ask again rather than choose.
                }
                // Interrupted for the same reason `wait_readable` can be, and
                // with the same answer: resume, the deadline still bounds it.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                _ => return None,
            }
        }
    }
}

/// A terminal put into raw mode for the life of the value, and restored when
/// it is dropped.
///
/// Dropped on every path, including a `?` that leaves early: a prompt that
/// returned without restoring would hand the developer back a terminal with no
/// echo and no line editing, which is the sort of damage a guard must not do.
struct RawMode {
    fd: std::os::fd::RawFd,
    saved: Option<libc::termios>,
}

impl RawMode {
    /// Holds the descriptor rather than a borrow of the `File`: the caller
    /// still needs it mutably to write the prompt and read the answer.
    fn enter(handle: &std::fs::File) -> RawMode {
        use std::os::fd::AsRawFd as _;

        let fd = handle.as_raw_fd();
        // SAFETY: a zeroed `termios` is the documented input; `tcgetattr`
        // fills it or fails, and the result is checked.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: the descriptor is valid for the call and `saved` is ours.
        if unsafe { libc::tcgetattr(fd, std::ptr::addr_of_mut!(saved)) } != 0 {
            // Not a terminal — a pipe or a file. Nothing to set and nothing to
            // restore, and the read below still works.
            return RawMode { fd, saved: None };
        }
        let mut raw = saved;
        // Characters as they are typed, not lines, and not echoed: the answer
        // is one key and the prompt already shows the choices.
        raw.c_lflag &= !(libc::ICANON | libc::ECHO);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        // SAFETY: `raw` is a complete `termios` derived from the one the
        // kernel just gave us.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, std::ptr::addr_of!(raw)) };
        RawMode {
            fd,
            saved: Some(saved),
        }
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(saved) = self.saved {
            // SAFETY: restoring the exact settings read in `enter`, on the
            // descriptor they were read from.
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, std::ptr::addr_of!(saved)) };
        }
    }
}

/// Whether the descriptor has something to read before `timeout`.
///
/// **A signal is not an answer, and it is not a timeout either.** `poll` returns
/// `EINTR` whenever a caught signal arrives, and Linux never restarts it — not
/// even under `SA_RESTART`. Treating that as *the budget ran out* reads an
/// absence as a value: measured, a 300 ms budget was given up on in **4.4 ms**
/// because another thread reaped a child. The daemon reaps children, so this
/// would deny a developer who was about to type. The wait is therefore against
/// a deadline, and an interruption resumes it with the time that is left.
fn wait_readable(handle: &std::fs::File, timeout: Duration) -> bool {
    use std::os::fd::AsRawFd as _;

    let deadline = std::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let mut fds = libc::pollfd {
            fd: handle.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = i32::try_from(left.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: one `pollfd` we own, and a count that matches it.
        let rc = unsafe { libc::poll(std::ptr::addr_of_mut!(fds), 1, ms) };
        if rc < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            && !left.is_zero()
        {
            continue;
        }
        return rc > 0 && fds.revents & libc::POLLIN != 0;
    }
}

impl Adjudicator for TerminalAdjudicator {
    fn channel(&self) -> AdjudicationChannel {
        AdjudicationChannel::Terminal
    }

    fn budget(&self) -> Duration {
        self.budget
    }

    fn notify(&mut self, warning: &Warning) {
        // `Verdict::Warn` is a notice and never a question: it must not block,
        // and it must not be answerable.
        if let Some(tty) = &self.tty {
            use std::io::Write as _;
            if let Ok(mut handle) = std::fs::OpenOptions::new().write(true).open(tty) {
                let _ = writeln!(
                    handle,
                    "⚠ AISME  {} · rule {}",
                    warning.summary, warning.rule_id
                );
            }
        }
    }

    fn ask(&mut self, request: &Escalation) -> BoxFuture<'_, Verdict> {
        // `I-05`'s three groups are refused **before** the prompt is composed,
        // not after the human answers: asking about something that cannot be
        // permitted teaches an operator that their answer does not matter.
        if request.group.never_promptable() {
            return Box::pin(async { Verdict::Deny });
        }
        if let Some(Unattended(verdict)) = self.unattended {
            self.answered_unattended += 1;
            return Box::pin(async move { verdict });
        }
        let budget = self.budget();
        let answer = self.ask_the_terminal(request, budget);
        let fallback = match AdjudicationChannel::Terminal.on_timeout() {
            TimeoutDefault::Deny | TimeoutDefault::SessionDefault => Verdict::Deny,
        };
        Box::pin(async move { answer.unwrap_or(fallback) })
    }

    fn max_grant(&self) -> GrantCeiling {
        // A human at the machine's own terminal is the local ceiling.
        GrantCeiling::LOCAL
    }
}

#[cfg(test)]
// A panic is the failure report in a test; the daemon's code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{TerminalAdjudicator, Unattended};
    use aisme_core::adjudicate::{Adjudicator as _, Escalation};
    use aisme_core::enforce::EscalationId;
    use aisme_core::ontology::{PermissionGroup, SessionId, Severity};
    use aisme_ebpf_common::Verdict;
    use std::io::Write as _;

    /// A real pseudo-terminal: the master is ours to type into, the slave is
    /// what the adjudicator opens by path. Nothing here stands in for a
    /// terminal — this **is** one.
    fn pty() -> (std::fs::File, String) {
        use std::os::fd::FromRawFd as _;

        // SAFETY: `posix_openpt` returns a descriptor we then own.
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        assert!(
            master >= 0,
            "posix_openpt: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: the descriptor just returned.
        assert_eq!(unsafe { libc::grantpt(master) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { libc::unlockpt(master) }, 0);
        // SAFETY: `ptsname` returns a pointer into libc's own storage, read
        // immediately and copied.
        let name = unsafe {
            let p = libc::ptsname(master);
            assert!(!p.is_null());
            std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
        };
        // SAFETY: we own `master` and nothing else does.
        (unsafe { std::fs::File::from_raw_fd(master) }, name)
    }

    fn question(group: PermissionGroup) -> Escalation {
        Escalation::new(
            EscalationId(1),
            SessionId(1),
            group,
            "escalate-aws",
            Severity::High,
            "read ~/.aws/credentials",
        )
        .with_declared_intent("checking the deploy configuration")
    }

    /// Drive a future to completion on this thread.
    ///
    /// Every future this adjudicator returns is ready when it is polled — the
    /// blocking read happens before the `async` block is built — so a
    /// poll-once executor is the whole of what is needed, and pulling in a
    /// runtime to prove that would be the wrong trade.
    fn block_on<T>(future: aisme_core::adjudicate::BoxFuture<'_, T>) -> T {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        const VTABLE: RawWakerVTable = RawWakerVTable::new(
            |_| RawWaker::new(std::ptr::null(), &VTABLE),
            |_| {},
            |_| {},
            |_| {},
        );
        // SAFETY: the vtable's four functions are all no-ops over a null
        // pointer they never dereference, which is sound for a waker nothing
        // ever wakes.
        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut future = future;
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("this adjudicator's futures are ready when polled"),
        }
    }

    /// Each of §7.3's four answers, typed into a real terminal.
    #[test]
    fn a_human_answers_in_the_terminal_and_the_verdict_follows() {
        for (key, expected) in [
            (b'd', Verdict::Deny),
            (b'1', Verdict::Allow),
            (b's', Verdict::Allow),
            (b'a', Verdict::Allow),
        ] {
            let (mut master, slave) = pty();
            master.write_all(&[key]).unwrap();
            master.flush().unwrap();
            let mut adjudicator = TerminalAdjudicator::new(Some(slave), None);
            let verdict = block_on(adjudicator.ask(&question(PermissionGroup::Credentials)));
            assert_eq!(verdict, expected, "key {}", key as char);
        }
    }

    /// A key that is not one of the four is re-read, not taken as a default.
    #[test]
    fn a_key_that_is_not_an_answer_is_not_one() {
        let (mut master, slave) = pty();
        // Noise, then the real answer — and deliberately **no newline**. These
        // bytes are written before the adjudicator opens the slave, so the line
        // discipline is still canonical when they arrive; a newline here would
        // be processed as a line terminator and the rest would not be
        // delivered. In production the developer types after the prompt, with
        // raw mode already on.
        master.write_all(b"xq1").unwrap();
        master.flush().unwrap();
        let mut adjudicator = TerminalAdjudicator::new(Some(slave), None);
        let verdict = block_on(adjudicator.ask(&question(PermissionGroup::Credentials)));
        assert_eq!(
            verdict,
            Verdict::Allow,
            "a mistyped key was taken as an answer"
        );
    }

    /// No answer within the budget is `deny`, and the wait is **bounded**.
    ///
    /// The budget is enforced by the adjudicator and not by the caller, so a
    /// caller that forgot to time out still fails closed.
    #[test]
    fn silence_within_the_budget_is_a_deny_and_the_wait_is_bounded() {
        let (_master, slave) = pty();
        // Nothing is typed.
        let mut adjudicator = TerminalAdjudicator::new(Some(slave), None)
            .with_budget(std::time::Duration::from_millis(300));
        let started = std::time::Instant::now();
        let verdict = block_on(adjudicator.ask(&question(PermissionGroup::Credentials)));
        let waited = started.elapsed();
        assert_eq!(verdict, Verdict::Deny);
        assert!(
            waited >= std::time::Duration::from_millis(250),
            "it gave up in {waited:?}, before the budget it promised"
        );
        assert!(
            waited < std::time::Duration::from_secs(3),
            "it waited {waited:?}, which is not a budget"
        );
    }

    /// A signal that arrives mid-prompt does not end the wait.
    ///
    /// The flaky version of this is the test above under parallel load, which
    /// is how the defect was found; this one is deterministic. `SIGCONT` is
    /// chosen because its default action harms nothing — what makes it
    /// interrupt `poll` is that a handler is installed, and Linux returns
    /// `EINTR` from `poll` even under `SA_RESTART`. It is delivered to **this**
    /// thread with `pthread_kill`, so it cannot land on another test's thread.
    #[test]
    fn a_signal_does_not_end_the_wait_early() {
        extern "C" fn noop(_: libc::c_int) {}
        // SAFETY: installing a handler for a signal whose default action is to
        // continue an already-running process; the handler does nothing.
        unsafe { libc::signal(libc::SIGCONT, noop as *const () as libc::sighandler_t) };

        // SAFETY: `pthread_self` takes nothing and cannot fail.
        let me = unsafe { libc::pthread_self() };
        let ticker = std::thread::spawn(move || {
            for _ in 0..5 {
                std::thread::sleep(std::time::Duration::from_millis(40));
                // SAFETY: a thread id taken from the thread now waiting, which
                // is joined below and therefore still alive.
                unsafe { libc::pthread_kill(me, libc::SIGCONT) };
            }
        });

        let (_master, slave) = pty();
        let mut adjudicator = TerminalAdjudicator::new(Some(slave), None)
            .with_budget(std::time::Duration::from_millis(300));
        let started = std::time::Instant::now();
        let verdict = block_on(adjudicator.ask(&question(PermissionGroup::Credentials)));
        let waited = started.elapsed();
        ticker.join().unwrap();

        assert_eq!(verdict, Verdict::Deny);
        assert!(
            waited >= std::time::Duration::from_millis(250),
            "a signal ended the wait after {waited:?}: an interruption was read as a timeout"
        );
    }

    /// A session with no terminal is answered at once, not after a budget it
    /// cannot spend on a prompt nobody will see.
    #[test]
    fn no_terminal_yields_the_timeout_verdict_immediately() {
        let mut adjudicator = TerminalAdjudicator::new(None, None);
        let started = std::time::Instant::now();
        let verdict = block_on(adjudicator.ask(&question(PermissionGroup::Credentials)));
        assert_eq!(verdict, Verdict::Deny);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "it waited {:?} for a terminal it does not have",
            started.elapsed()
        );
    }

    /// `I-05`'s groups are refused **before** a prompt is composed: asking about
    /// something that cannot be permitted teaches an operator that their answer
    /// does not matter.
    #[test]
    fn a_never_promptable_group_is_refused_without_asking() {
        let never = PermissionGroup::ALL
            .iter()
            .copied()
            .find(|g| g.never_promptable())
            .expect("I-05 names three");
        let (mut master, slave) = pty();
        // An answer is waiting. If it were read, this would return Allow.
        master.write_all(b"a").unwrap();
        master.flush().unwrap();
        let mut adjudicator = TerminalAdjudicator::new(Some(slave), None);
        let verdict = block_on(adjudicator.ask(&question(never)));
        assert_eq!(verdict, Verdict::Deny);
    }

    /// The unattended answer is the one passed in, and the **ambient
    /// environment is ignored**.
    ///
    /// This is the test that fixes the ordering rule: `AISME_TERMINAL_ANSWER` is
    /// read once, in `aisme run`, before `exec`. An adjudicator that read its
    /// own environment could be steered by anything able to set a variable in
    /// the daemon — which includes the agent it adjudicates.
    #[test]
    fn the_unattended_answer_is_the_one_passed_in_and_never_the_environment() {
        // SAFETY: single-threaded within this test, and the point is that the
        // value below is NOT read.
        unsafe { std::env::set_var("AISME_TERMINAL_ANSWER", "a") };

        let mut adjudicator = TerminalAdjudicator::new(None, Some(Unattended(Verdict::Deny)));
        let verdict = block_on(adjudicator.ask(&question(PermissionGroup::Credentials)));
        assert_eq!(
            verdict,
            Verdict::Deny,
            "the adjudicator read its own environment"
        );
        assert_eq!(
            adjudicator.answered_unattended, 1,
            "not recorded as unattended"
        );

        // SAFETY: as above.
        unsafe { std::env::remove_var("AISME_TERMINAL_ANSWER") };
    }

    /// The prompt is §7.3's, and it shows a declared intent as a claim.
    #[test]
    fn the_prompt_carries_the_four_answers_and_marks_intent_as_claimed() {
        let text = TerminalAdjudicator::prompt(&question(PermissionGroup::Credentials));
        for answer in [
            "[d] deny",
            "[1] allow once",
            "[s] allow this session",
            "[a] always",
        ] {
            assert!(text.contains(answer), "missing {answer}: {text}");
        }
        assert!(text.contains("read ~/.aws/credentials"), "{text}");
        assert!(
            text.contains("\"checking the deploy configuration\""),
            "a declared intent must be shown quoted, as a claim: {text}"
        );
    }
}
