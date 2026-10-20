//! Semantic event page/snapshot queries and the resumable SSE stream.
//!
//! Delivery semantics (design contract A4): the durable `semantic_events`
//! table is the only replay source. The live tail is bounded polling of the
//! same durable read on a fixed interval — polling is delivery cadence, never
//! authority; there is no separate in-memory event channel. SSE event ids are
//! durable sequences; `Last-Event-ID` is the query cursor and the two must
//! agree when both are present. Keepalives are cursor-neutral comment frames.
//! Slow consumers get a bounded buffer; on overflow the poller emits one final
//! `RESYNC_REQUIRED` hint and closes.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::{Semaphore, mpsc};
use uuid::Uuid;

use forge_control::ResolvedWorkspaceScope;

use crate::envelope::StreamResyncHint;
use crate::error::{ErrorCode, ForgeError};

pub mod control;
pub use control::ControlEventQuery;

/// Maximum number of synchronous control-backed semantic reads admitted to
/// the blocking pool at once. HTTP page/snapshot handlers acquire this
/// capacity before spawning; the permit remains owned by the blocking
/// closure until the control worker response is complete.
pub(crate) const MAX_EVENT_READS: usize = 8;

/// One durable semantic event page plus cursor metadata.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventPage {
    pub events: Vec<EventRecord>,
    pub high_water: u64,
    pub retained_low: u64,
}

/// One durable semantic event.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub sequence: u64,
    pub kind: String,
    pub revision: i64,
    pub observed_at_ms: i64,
    pub digest: [u8; 32],
    pub subjects: Option<Subjects>,
}

/// Subject identities carried by one event.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subjects {
    pub goal_id: Option<Uuid>,
    pub dag_revision: Option<i64>,
    pub node_id: Option<Uuid>,
    pub execution_id: Option<Uuid>,
    pub change_set_id: Option<Uuid>,
    pub diff_id: Option<Uuid>,
    pub verification: Option<Uuid>,
}

/// Errors from the durable query boundary.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventQueryError {
    /// The requested Workspace identity is unknown to the control authority.
    UnknownWorkspace,
    /// The submitted scope no longer matches the durable Workspace binding.
    ResyncRequired,
    /// The bounded control/read admission boundary is saturated.
    CapacityExceeded,
    /// Any other bounded read failure; collapsed to `FORGE_UNAVAILABLE`.
    Failed,
}

/// Port over the durable event stream. The production implementation submits
/// the read to the forge-control worker; tests substitute a bounded source.
pub trait EventQuery: std::fmt::Debug + Send + Sync + 'static {
    fn page(
        &self,
        scope: &ResolvedWorkspaceScope,
        after: u64,
        limit: u32,
    ) -> Result<EventPage, EventQueryError>;

    fn snapshot(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<(u64, u64, serde_json::Value), EventQueryError>;
}

/// Validate the page cursor: a cursor behind the retention floor can never be
/// replayed and is rejected with a typed `RESYNC_REQUIRED`.
pub fn page_or_resync(
    query: &dyn EventQuery,
    scope: &ResolvedWorkspaceScope,
    cursor: u64,
    max: u32,
) -> Result<EventPage, ForgeError> {
    if max == 0 || max > crate::config::MAX_EVENT_PAGE_ROWS {
        return Err(ForgeError::invalid_input(format!(
            "max must be within 1..={}",
            crate::config::MAX_EVENT_PAGE_ROWS
        )));
    }
    match query.page(scope, cursor, max) {
        Ok(page) => {
            if cursor < page.retained_low {
                return Err(ForgeError::resync_required(format!(
                    "cursor {cursor} is behind the retained floor {}",
                    page.retained_low
                )));
            }
            if cursor > page.high_water {
                return Err(ForgeError::resync_required(format!(
                    "cursor {cursor} is ahead of the durable high water {}",
                    page.high_water
                )));
            }
            Ok(page)
        }
        Err(EventQueryError::UnknownWorkspace) => Err(ForgeError::resync_required(
            "the requested Workspace is unknown",
        )),
        Err(EventQueryError::ResyncRequired) => Err(ForgeError::resync_required(
            "the requested Workspace scope is stale; resynchronize from a snapshot",
        )),
        Err(EventQueryError::CapacityExceeded) => Err(ForgeError::capacity_exceeded(
            "semantic event read admission",
        )),
        Err(EventQueryError::Failed) => Err(ForgeError::internal()),
    }
}

/// Serialize one event page for the page endpoint and SSE replay.
#[must_use]
pub fn event_page_json(page: &EventPage) -> serde_json::Value {
    json!({
        "events": page.events.iter().map(event_json).collect::<Vec<_>>(),
        "high_water": page.high_water,
        "retained_low": page.retained_low,
    })
}

pub fn event_json(event: &EventRecord) -> serde_json::Value {
    let subjects = match &event.subjects {
        Some(subjects) => json!({
            "goal_id": subjects.goal_id,
            "dag_revision": subjects.dag_revision,
            "node_id": subjects.node_id,
            "execution_id": subjects.execution_id,
            "change_set_id": subjects.change_set_id,
            "diff_id": subjects.diff_id,
            "verification": subjects.verification,
        }),
        None => json!(null),
    };
    json!({
        "sequence": event.sequence,
        "kind": event.kind,
        "revision": event.revision,
        "observed_at_ms": event.observed_at_ms,
        "digest": hex_encode(&event.digest),
        "subjects": subjects,
    })
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0F), 16).unwrap_or('0'));
    }
    out
}

/// Bounded SSE subscriber admission. One permit per stream; saturation is a
/// typed rejection before any stream work starts.
#[must_use]
#[derive(Debug)]
pub struct SubscriberGuard {
    permits: Arc<Semaphore>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl SubscriberGuard {
    pub fn acquire(permits: Arc<Semaphore>, max: usize) -> Result<Self, ForgeError> {
        let available = permits.available_permits();
        if available == 0 {
            return Err(ForgeError::capacity_exceeded(&format!(
                "sse subscriber bound ({max})"
            )));
        }
        match permits.clone().try_acquire_owned() {
            Ok(permit) => Ok(Self {
                permits,
                _permit: permit,
            }),
            Err(_) => Err(ForgeError::capacity_exceeded(&format!(
                "sse subscriber bound ({max})"
            ))),
        }
    }

    #[must_use]
    pub fn shared(&self) -> Arc<Semaphore> {
        Arc::clone(&self.permits)
    }
}

/// Frames delivered from the poller to the SSE response stream over one
/// bounded channel. Overflow at this boundary is the slow-consumer signal.
#[must_use]
#[derive(Debug, Clone)]
pub enum Frame {
    /// One replayed or live semantic event with its durable sequence id.
    Event { sequence: u64, data: String },
    /// Cursor-neutral keepalive comment.
    KeepAlive,
    /// Final in-stream resync hint before a close.
    Resync(StreamResyncHint),
}

/// Outcome of one stream loop.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEnd {
    Completed,
    SlowConsumerClosed,
    UnknownWorkspace,
}

/// Replay + tail loop for one subscriber. Runs the durable poll on the caller
/// context (a blocking worker); frames cross to the response stream over a
/// bounded channel. The poll source is the durable table — polling is
/// delivery cadence, not authority.
pub fn replay_and_tail(
    query: &dyn EventQuery,
    scope: &ResolvedWorkspaceScope,
    cursor: u64,
    frames: mpsc::Sender<Frame>,
    poll_interval: Duration,
    exit: &dyn Fn() -> bool,
) -> StreamEnd {
    #![allow(clippy::needless_pass_by_value)]
    let mut cursor = cursor;
    let mut first_page = true;
    loop {
        if exit() {
            return StreamEnd::Completed;
        }
        match query.page(scope, cursor, crate::config::MAX_EVENT_PAGE_ROWS) {
            Ok(page) => {
                if let Some(end) = initial_cursor_error(&frames, first_page, cursor, &page) {
                    return end;
                }
                first_page = false;
                for event in &page.events {
                    let data = event_json(event).to_string();
                    if let Err(end) = send_frame(
                        &frames,
                        Frame::Event {
                            sequence: event.sequence,
                            data,
                        },
                        exit,
                    ) {
                        return match end {
                            StreamEnd::SlowConsumerClosed => {
                                slow_consumer_close(&frames, page.high_water)
                            }
                            other => other,
                        };
                    }
                    cursor = event.sequence;
                }
                if page.events.is_empty() && cursor < page.high_water {
                    // Rows existed but were outside this page window; catch up
                    // on the next tick.
                }
                if let Err(end) = send_frame(&frames, Frame::KeepAlive, exit) {
                    return match end {
                        StreamEnd::SlowConsumerClosed => {
                            slow_consumer_close(&frames, page.high_water)
                        }
                        other => other,
                    };
                }
            }
            Err(EventQueryError::UnknownWorkspace) => {
                let _ = frames.try_send(Frame::Resync(StreamResyncHint {
                    resync_required: true,
                    reason: "the requested Workspace is unknown".into(),
                    high_water: None,
                }));
                return StreamEnd::UnknownWorkspace;
            }
            Err(EventQueryError::ResyncRequired) => {
                let _ = frames.try_send(Frame::Resync(StreamResyncHint {
                    resync_required: true,
                    reason: "the Workspace scope is stale; reconnect from a fresh snapshot".into(),
                    high_water: None,
                }));
                return StreamEnd::Completed;
            }
            Err(EventQueryError::CapacityExceeded) => {
                let _ = frames.try_send(Frame::Resync(StreamResyncHint {
                    resync_required: true,
                    reason: "the durable event read is at capacity; reconnect and resynchronize"
                        .into(),
                    high_water: None,
                }));
                return StreamEnd::Completed;
            }
            Err(EventQueryError::Failed) => {
                let _ = frames.try_send(Frame::Resync(StreamResyncHint {
                    resync_required: true,
                    reason: "the durable event read failed; resynchronize from a snapshot".into(),
                    high_water: None,
                }));
                return StreamEnd::Completed;
            }
        }
        let total_ms = u64::try_from(poll_interval.as_millis()).unwrap_or(1).max(1);
        let mut waited = 0_u64;
        while waited < total_ms {
            if exit() {
                return StreamEnd::Completed;
            }
            std::thread::sleep(Duration::from_millis(5));
            waited += 5;
        }
        let _ = first_page;
    }
}

fn initial_cursor_error(
    frames: &mpsc::Sender<Frame>,
    first_page: bool,
    cursor: u64,
    page: &EventPage,
) -> Option<StreamEnd> {
    if !first_page {
        return None;
    }
    let reason = if cursor < page.retained_low {
        Some("the requested cursor is older than the retained event history")
    } else if cursor > page.high_water {
        Some("the requested cursor is ahead of the durable event history")
    } else {
        None
    }?;
    let _ = frames.try_send(Frame::Resync(StreamResyncHint {
        resync_required: true,
        reason: reason.into(),
        high_water: Some(page.high_water),
    }));
    Some(StreamEnd::Completed)
}

fn slow_consumer_close(frames: &mpsc::Sender<Frame>, high_water: u64) -> StreamEnd {
    // The bounded buffer is full or the receiver is gone. Emit one final
    // hint when possible; either way the stream terminates.
    let _ = frames.try_send(Frame::Resync(StreamResyncHint {
        resync_required: true,
        reason: "the subscriber buffer overflowed; reconnect and replay from your last sequence"
            .into(),
        high_water: Some(high_water),
    }));
    StreamEnd::SlowConsumerClosed
}

const SLOW_CONSUMER_GRACE: Duration = Duration::from_secs(1);

fn send_frame(
    frames: &mpsc::Sender<Frame>,
    mut frame: Frame,
    exit: &dyn Fn() -> bool,
) -> Result<(), StreamEnd> {
    let deadline = Instant::now() + SLOW_CONSUMER_GRACE;
    loop {
        match frames.try_send(frame) {
            Ok(()) => return Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => return Err(StreamEnd::Completed),
            Err(mpsc::error::TrySendError::Full(returned)) => {
                frame = returned;
                if exit() {
                    return Err(StreamEnd::Completed);
                }
                if Instant::now() >= deadline {
                    return Err(StreamEnd::SlowConsumerClosed);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

/// Validate Last-Event-ID vs the query cursor contract.
pub fn validate_cursor_pair(
    last_event_id: Option<&str>,
    query_cursor: Option<u64>,
) -> Result<Option<u64>, ForgeError> {
    let header = match last_event_id {
        Some(value) => Some(value.parse::<u64>().map_err(|_| {
            ForgeError::invalid_input("Last-Event-ID must be a semantic sequence number")
        })?),
        None => None,
    };
    match (header, query_cursor) {
        (Some(header), Some(cursor)) if header != cursor => Err(ForgeError::invalid_input(
            "Last-Event-ID and cursor must reference the same sequence",
        )),
        (Some(header), _) => Ok(Some(header)),
        (None, cursor) => Ok(cursor),
    }
}

/// Typed error code check used by tests to assert resync mapping.
pub const fn is_resync(error: &ForgeError) -> bool {
    matches!(error.code(), ErrorCode::ResyncRequired)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct OneEvent;

    impl EventQuery for OneEvent {
        fn page(
            &self,
            _scope: &ResolvedWorkspaceScope,
            after: u64,
            _limit: u32,
        ) -> Result<EventPage, EventQueryError> {
            Ok(EventPage {
                events: if after == 0 {
                    vec![EventRecord {
                        sequence: 1,
                        kind: "goal_created".into(),
                        revision: 1,
                        observed_at_ms: 1,
                        digest: [0; 32],
                        subjects: None,
                    }]
                } else {
                    Vec::new()
                },
                high_water: 1,
                retained_low: 0,
            })
        }

        fn snapshot(
            &self,
            _scope: &ResolvedWorkspaceScope,
        ) -> Result<(u64, u64, serde_json::Value), EventQueryError> {
            Ok((1, 0, serde_json::json!({})))
        }
    }

    #[test]
    fn saturated_replay_sender_closes_within_the_slow_consumer_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let (frames, _receiver) = mpsc::channel(1);
        assert!(frames.try_send(Frame::KeepAlive).is_ok());
        let started = Instant::now();
        let result = replay_and_tail(
            &OneEvent,
            &test_scope()?,
            0,
            frames,
            Duration::from_millis(1),
            &|| false,
        );
        assert_eq!(result, StreamEnd::SlowConsumerClosed);
        assert!(started.elapsed() < SLOW_CONSUMER_GRACE + Duration::from_secs(1));
        Ok(())
    }

    fn test_scope() -> Result<ResolvedWorkspaceScope, Box<dyn std::error::Error>> {
        let locator = forge_control::WorkspaceLocator::new(
            forge_domain::LocationId::from_uuid(Uuid::from_u128(1)),
            forge_domain::LocationRevision::INITIAL,
            std::path::Path::new("."),
        )?;
        Ok(ResolvedWorkspaceScope::from_observation(
            forge_domain::WorkspaceId::from_uuid(Uuid::from_u128(1)),
            forge_domain::WorkspaceRevision::INITIAL,
            locator,
        ))
    }
}
