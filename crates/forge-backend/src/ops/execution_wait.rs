//! Bounded observation parameters and projections for the native async waiter.

use std::time::Duration;

use forge_control::{ExecutionWaitParameters, ExecutionWaitResult};
use forge_domain::{ExecutionId, ExecutionOutputCursor};
use serde::Deserialize;
use serde_json::{Value, json};

use super::execution::{self, ExecutionAuthorityDto, ExecutionReadCommand, ExecutionReadDto};
use crate::error::ForgeError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitDto {
    authority: ExecutionAuthorityDto,
    #[serde(default)]
    after_sequence: u64,
    #[serde(default = "execution::default_max_bytes")]
    max_bytes: u64,
    #[serde(default = "execution::default_max_events")]
    max_events: usize,
    timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionWaitCommand {
    read: ExecutionReadCommand,
    timeout: Duration,
}

impl ExecutionWaitCommand {
    pub(crate) const fn execution_id(&self) -> ExecutionId {
        self.read.authority.execution_id
    }

    pub(crate) const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub(crate) fn parameters(&self) -> Result<ExecutionWaitParameters, ForgeError> {
        let cursor = if self.read.after_sequence == 0 {
            ExecutionOutputCursor::initial(self.execution_id())
        } else {
            ExecutionOutputCursor::from_sequence(
                self.execution_id(),
                super::decode_sequence(self.read.after_sequence)?,
            )
        };
        Ok(ExecutionWaitParameters::new(
            self.read.authority.agent_authority.clone(),
            self.execution_id(),
            cursor,
            self.read.max_bytes,
            self.read.max_events,
            self.timeout,
        ))
    }
}

pub(crate) fn parse(payload: &Value) -> Result<ExecutionWaitCommand, ForgeError> {
    let dto: WaitDto = super::parse_body(payload, "execution.wait payload is invalid")?;
    if dto.timeout_ms > 30_000 {
        return Err(ForgeError::invalid_input("execution wait exceeds 30000ms"));
    }
    Ok(ExecutionWaitCommand {
        read: execution::parse_read_fields(ExecutionReadDto {
            authority: dto.authority,
            after_sequence: dto.after_sequence,
            max_bytes: dto.max_bytes,
            max_events: dto.max_events,
        })?,
        timeout: Duration::from_millis(dto.timeout_ms),
    })
}

pub(crate) fn project(id: ExecutionId, result: &ExecutionWaitResult) -> Value {
    json!({
        "execution_id": id.into_uuid(),
        "state": format!("{:?}", result.state()),
        "revision": result.revision().get(),
        "terminal": result.state().is_terminal(),
        "timed_out": result.timed_out(),
        "changed": result.changed(),
        "next_sequence": result.output().next_cursor().after_sequence(),
        "truncated": result.output().truncated(),
        "event_count": result.output().events().len(),
        "events": result.output().events().iter().map(execution::output_event_json).collect::<Vec<_>>(),
    })
}
