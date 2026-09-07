// SPDX-License-Identifier: Apache-2.0
//! `DeclarationSensor`: what an agent says about itself, on the same stream as
//! what it does (`F2.WS.03`).
//!
//! A declaration arrives over the control socket, on a different thread from
//! the hot loop. It could have had its own path into the engine; it does not,
//! because §3.2's whole point is that there are three interfaces and not
//! fifteen subsystems. A declaration is an **observation**, so it arrives as a
//! `Sensor` — the engine sees one stream, correlation matches within it, and
//! the WAL records the declaration beside the actions it claims to explain.
//!
//! It is still not an authorization. `DT-04` exists because a declaration may
//! be a lie, and putting it on the same stream is what makes the lie
//! *checkable* against the actions rather than believed.

use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::Duration;

use aisme_core::capability::CapabilitySet;
use aisme_core::error::Result;
use aisme_core::sensor::{EventBatch, Sensor, SensorConfig, SensorHealth};
use aisme_ebpf_common::{EventKind, Outcome, RawEvent};

/// Build the event a declaration becomes.
///
/// The tool name is bounded by the wire (`SemanticPayload::tool_name` is 64
/// bytes) and truncation is marked, so a long name is visibly cut rather than
/// silently renamed.
#[must_use]
pub fn declaration_event(toolcall_id: u64, tool_name: &str, ts_ns: u64) -> RawEvent {
    let mut event = RawEvent::ZERO;
    event.kind = EventKind::ToolCall.into();
    event.outcome = Outcome::Observed.into();
    event.ts_ns = ts_ns;
    // Written through L0's accessor, so the one place that knows the layout is
    // the one place that writes it. It returns `None` for any kind outside the
    // Semantic range, and `kind` was set to `ToolCall` two lines up.
    let Some(semantic) = event.semantic_mut() else {
        return event;
    };
    semantic.toolcall_id = toolcall_id;
    let bytes = tool_name.as_bytes();
    let n = bytes.len().min(semantic.tool_name.len());
    semantic.tool_name[..n].copy_from_slice(&bytes[..n]);
    semantic.name_len = u16::try_from(n).unwrap_or(u16::MAX);
    if n < bytes.len() {
        event.flags |= aisme_ebpf_common::FLAG_TRUNCATED;
    }
    event
}

/// The sending half, handed to the control-plane server.
pub type Declared = Sender<RawEvent>;

/// Drains declarations into the hot loop.
pub struct DeclarationSensor {
    rx: Receiver<RawEvent>,
    /// Declarations the batch had no room for. Counted, because a dropped
    /// declaration is ground truth that never arrived, and a silent zero here
    /// would make a correlation gap look like an agent that said nothing.
    refused: u64,
}

impl DeclarationSensor {
    /// A sensor and the sender that feeds it.
    #[must_use]
    pub fn new() -> (DeclarationSensor, Declared) {
        let (tx, rx) = std::sync::mpsc::channel();
        (DeclarationSensor { rx, refused: 0 }, tx)
    }

    /// Declarations refused for want of room in a batch.
    #[must_use]
    pub const fn refused(&self) -> u64 {
        self.refused
    }
}

impl Sensor for DeclarationSensor {
    fn start(&mut self, _cfg: &SensorConfig) -> Result<()> {
        Ok(())
    }

    fn poll(&mut self, out: &mut EventBatch, _budget: Duration) -> Result<usize> {
        let mut added = 0;
        // `try_recv` never blocks and never allocates: the allocation for a
        // queued message happened on the sender's thread, which is the control
        // socket's, not the hot loop's (`I-22` is about this loop).
        while out.remaining() > 0 {
            match self.rx.try_recv() {
                Ok(event) => {
                    if out.push(event).is_ok() {
                        added += 1;
                    }
                }
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        // A full batch with more waiting is a refusal, not an absence.
        if out.remaining() == 0 && self.rx.try_recv().is_ok() {
            self.refused += 1;
        }
        Ok(added)
    }

    fn capabilities(&self) -> CapabilitySet {
        // It measures no platform capability; claiming one would be an
        // absence read as a value.
        CapabilitySet::NONE
    }

    fn health(&self) -> SensorHealth {
        // A sensor that is dropping declarations is degraded, and says which
        // function that costs (`I-19`). Reporting it through `health` rather
        // than a getter is what makes it *read*: the engine already polls
        // health, and a counter nobody reads is a counter that may as well not
        // exist.
        let refused = self.refused();
        if refused == 0 {
            return SensorHealth::Healthy;
        }
        SensorHealth::Degraded {
            lost: format!(
                "{refused} declaration(s) refused for want of batch room: correlation has no \
                 ground truth for those tool calls, so their actions look unexplained"
            ),
        }
    }

    fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
// A panic is the failure report in a test; the daemon's code stays denied.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aisme_ebpf_common::Payload;

    /// A declaration becomes an event the engine can read, on the same stream
    /// as everything else — kind `ToolCall`, outcome `Observed`, never a
    /// verdict of any kind.
    #[test]
    fn a_declaration_arrives_as_an_observed_toolcall_event() {
        let (mut sensor, tx) = DeclarationSensor::new();
        tx.send(declaration_event(42, "Bash", 1_000)).unwrap();
        let mut batch = EventBatch::with_capacity(4);
        assert_eq!(sensor.poll(&mut batch, Duration::ZERO).unwrap(), 1);

        let event = batch.as_slice()[0];
        assert_eq!(event.kind.decode(), Ok(EventKind::ToolCall));
        assert_eq!(
            event.outcome.decode(),
            Ok(Outcome::Observed),
            "a declaration is observed, never allowed or denied"
        );
        match event.payload() {
            Some(Payload::Semantic(s)) => {
                assert_eq!(s.toolcall_id, 42);
                assert_eq!(&s.tool_name[..s.name_len as usize], b"Bash");
            }
            other => panic!("wrong view: {other:?}"),
        }
        assert!(!event.truncated());
    }

    /// A name longer than the wire allows is cut and *marked*, never silently
    /// renamed into a different tool.
    #[test]
    fn an_overlong_tool_name_is_truncated_and_says_so() {
        let long = "T".repeat(100);
        let event = declaration_event(1, &long, 0);
        assert!(event.truncated(), "the flag is the whole point");
        match event.payload() {
            Some(Payload::Semantic(s)) => assert_eq!(usize::from(s.name_len), 64),
            other => panic!("wrong view: {other:?}"),
        }
    }

    /// An empty channel is empty, not an error: a tick with no declarations is
    /// the normal case and must cost nothing.
    #[test]
    fn no_declarations_is_zero_events_and_not_a_failure() {
        let (mut sensor, _tx) = DeclarationSensor::new();
        let mut batch = EventBatch::with_capacity(4);
        assert_eq!(sensor.poll(&mut batch, Duration::ZERO).unwrap(), 0);
        assert!(batch.is_empty());
        assert_eq!(sensor.health(), SensorHealth::Healthy);
    }

    /// More declarations than the batch holds are refused and counted, not
    /// dropped in silence: ground truth that never arrived is a correlation
    /// gap, and a gap nobody counted looks like an agent that said nothing.
    #[test]
    fn declarations_beyond_the_batch_are_counted_as_refused() {
        let (mut sensor, tx) = DeclarationSensor::new();
        for id in 0..4 {
            tx.send(declaration_event(id, "Bash", 0)).unwrap();
        }
        let mut batch = EventBatch::with_capacity(2);
        assert_eq!(sensor.poll(&mut batch, Duration::ZERO).unwrap(), 2);
        assert_eq!(sensor.refused(), 1, "the batch filled with more waiting");
        // And the refusal is *read*, not merely counted: the engine polls
        // health, so this is where a dropped declaration becomes visible.
        match sensor.health() {
            SensorHealth::Degraded { lost } => {
                assert!(lost.contains("declaration(s) refused"), "{lost}");
                assert!(lost.contains("ground"), "it names what was lost: {lost}");
            }
            other => panic!("a sensor dropping declarations is degraded, not {other:?}"),
        }
    }
}
