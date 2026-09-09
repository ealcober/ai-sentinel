// SPDX-License-Identifier: Apache-2.0
//! `aisme-loaderd --publish <policy-file>` (`F2.WS.04`; `docs/06` points 3–4).
//!
//! Compile, lower, pin, publish, print the generation, exit. The process does
//! not stay resident: what it created outlives it through its `bpffs` pin,
//! which is why the unit is `Type=oneshot` with `RemainAfterExit=yes`.

use aisme_core::policy::{compile, parse, Bindings, PolicyGeneration};
use aisme_proto::rpc::Method;

use crate::platform;

/// Run a publication and return the exit code.
///
/// Compilation failure prints every error with its position and returns
/// non-zero **before any map is touched** — the order is checked by a test that
/// runs without `CAP_BPF` and requires the compile error rather than a
/// permission error.
pub fn publish(path: &str, bindings: &Bindings) -> u8 {
    let image = match prepare(path, bindings) {
        Ok(image) => image,
        Err(refusal) => {
            for line in refusal.lines(path) {
                eprintln!("{line}");
            }
            return 1;
        }
    };
    match platform::publish(&image) {
        Ok(generation) => {
            if let Err(problem) = tell_agentd(AGENTD_SOCKET, generation) {
                // A warning, and the exit code stays 0: the kernel already
                // holds the policy, and a non-zero exit would say otherwise.
                eprintln!("published, but the daemon was not told: {problem}");
            }
            // Last line, and the only thing on stdout: `vm run` captures it and
            // a script reads it.
            println!("{}", generation.0);
            0
        }
        Err(e) => {
            eprintln!("publication refused: {}", e.detail);
            1
        }
    }
}

/// Where `aisme-agentd` serves its control plane, per its unit.
pub const AGENTD_SOCKET: &str = "/run/aisme/agentd.sock";

/// Tell the daemon which generation is now in force.
///
/// **A courtesy, not part of the publication.** The privileged act already
/// happened in the kernel; this only lets the daemon stamp the number on the
/// segments it opens next and answer `getCapabilities`. A daemon that is not
/// running is a warning and an exit code of 0 — failing here would report a
/// publication as failed while the kernel already holds it, which is the more
/// dangerous of the two wrong answers.
///
/// # Errors
///
/// Whatever stopped the message reaching the daemon.
pub fn tell_agentd(socket: &str, generation: PolicyGeneration) -> Result<String, String> {
    use std::io::{BufRead as _, BufReader, Write as _};

    let mut stream =
        std::os::unix::net::UnixStream::connect(socket).map_err(|e| format!("{socket}: {e}"))?;
    // The method name comes from `aisme-proto` rather than a literal, so this
    // cannot drift from the method the daemon serves.
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"{}","params":{{"generation":{}}}}}"#,
        Method::SetPolicyGeneration.as_str(),
        generation.0
    );
    stream
        .write_all(line.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|e| format!("{socket}: {e}"))?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|e| format!("{socket}: {e}"))?;
    Ok(reply.trim().to_owned())
}

/// Why a publication never reached a map.
///
/// The stage is part of the value, not only the message: the test that proves
/// nothing is touched before the policy compiles asserts on **which** stage
/// refused. A permission error where a parse error belongs would mean the
/// order is wrong.
#[derive(Debug)]
pub enum Refusal {
    /// The file could not be read.
    Read(String),
    /// It is not a policy.
    Parse(Vec<String>),
    /// It is a policy this compiler refuses.
    Compile(Vec<String>),
    /// It compiles but this platform cannot express it.
    Lower(String),
}

impl Refusal {
    /// The operator's lines, each already naming the file.
    #[must_use]
    pub fn lines(&self, path: &str) -> Vec<String> {
        match self {
            Refusal::Read(e) => vec![format!("cannot read {path}: {e}")],
            Refusal::Parse(errors) | Refusal::Compile(errors) => {
                errors.iter().map(|e| format!("{path}: {e}")).collect()
            }
            Refusal::Lower(e) => vec![format!("{path}: {e}")],
        }
    }
}

/// Everything that happens **before** a map is opened: read, parse, compile,
/// lower.
///
/// # Errors
///
/// The stage that refused, with its messages.
pub fn prepare(path: &str, bindings: &Bindings) -> Result<platform::Image, Refusal> {
    let source = std::fs::read_to_string(path).map_err(|e| Refusal::Read(e.to_string()))?;
    let policy = parse(&source)
        .map_err(|errors| Refusal::Parse(errors.iter().map(ToString::to_string).collect()))?;
    let compiled = compile(&policy, bindings)
        .map_err(|errors| Refusal::Compile(errors.iter().map(ToString::to_string).collect()))?;
    platform::lower(&compiled).map_err(|e| Refusal::Lower(e.detail.clone()))
}

/// Parse `k=v` pairs into bindings, refusing anything that is not one.
///
/// # Errors
///
/// The offending argument, so an operator sees which one.
pub fn bindings_from(args: &[String]) -> Result<Bindings, String> {
    let mut bindings = Bindings::new();
    for arg in args {
        let (k, v) = arg
            .split_once('=')
            .ok_or_else(|| format!("--bindings takes k=v, got {arg}"))?;
        bindings = bindings.with(k, v);
    }
    Ok(bindings)
}

#[cfg(test)]
mod tests {
    use super::{bindings_from, prepare, Refusal};
    use aisme_core::policy::Bindings;

    /// A file that is not a policy is refused at the parse stage, and the test
    /// runs **unprivileged**: if compilation happened after the maps were
    /// opened, this would fail with a permission error from `bpffs` instead,
    /// which is the distinction the assertion makes.
    #[test]
    fn a_file_that_is_not_a_policy_is_refused_before_any_map_is_opened() {
        let path = std::env::temp_dir().join("aisme-loaderd-not-a-policy.aisme");
        std::fs::write(&path, "this is not a policy {{{\n").unwrap();
        match prepare(path.to_str().unwrap(), &Bindings::new()) {
            Err(Refusal::Parse(errors)) => assert!(!errors.is_empty()),
            other => panic!("expected a parse refusal, got {other:?}"),
        }
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_missing_file_is_named_rather_than_treated_as_an_empty_policy() {
        // An unreadable input read as "no rules" would publish a policy that
        // allows everything, which is an absence read as a value.
        match prepare("/nonexistent/aisme/policy.aisme", &Bindings::new()) {
            Err(Refusal::Read(e)) => assert!(!e.is_empty()),
            other => panic!("expected a read refusal, got {other:?}"),
        }
    }

    /// A daemon that is not there is a named warning, never a failed
    /// publication: the kernel already holds the policy by the time this runs.
    #[test]
    fn a_missing_daemon_is_reported_and_not_fatal() {
        let problem = super::tell_agentd(
            "/nonexistent/aisme/agentd.sock",
            aisme_core::policy::PolicyGeneration(3),
        )
        .unwrap_err();
        assert!(problem.contains("agentd.sock"), "{problem}");
    }

    /// The wire name comes from `aisme-proto`, so the loader and the daemon
    /// cannot drift apart on it.
    #[test]
    fn the_method_told_is_the_method_served() {
        assert_eq!(
            aisme_proto::rpc::Method::SetPolicyGeneration.as_str(),
            "setPolicyGeneration"
        );
    }

    #[test]
    fn bindings_must_be_key_equals_value() {
        assert!(bindings_from(&["ws=/tmp".to_owned()]).is_ok());
        let bad = bindings_from(&["ws".to_owned()]).unwrap_err();
        assert!(bad.contains("k=v"), "{bad}");
    }
}
