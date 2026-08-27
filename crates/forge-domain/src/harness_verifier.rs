//! Durable Harness declared-verifier run projections.
//!
//! Process execution, approval decisions, filesystem inspection, and clock
//! acquisition belong to adapters/coordinators. This module owns only bounded
//! verifier identity, item/result state, aggregate state, and revision/CAS
//! invariants.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{
    ActivityId, ApprovalRequestId, ExecutionId, ExecutionRequestDigest, HarnessBundleId,
    HarnessContentHash, MAX_HARNESS_VERIFIERS, RuntimeInstanceId, TimestampMillis, WorkspaceId,
};

pub const MAX_HARNESS_VERIFIER_NAME_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessVerifierRunId(Uuid);

impl HarnessVerifierRunId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for HarnessVerifierRunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for HarnessVerifierRunId {
    type Err = HarnessVerifierRunIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(HarnessVerifierRunIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum HarnessVerifierRunIdParseError {
    #[error("Harness verifier run id is not a UUID")]
    InvalidUuid(#[source] uuid::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessVerifierRunRevision(i64);

impl HarnessVerifierRunRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, HarnessVerifierRunRevisionError> {
        if value < 1 {
            Err(HarnessVerifierRunRevisionError::Invalid(value))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, HarnessVerifierRunRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Self::new(value),
            None => Err(HarnessVerifierRunRevisionError::Overflow),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HarnessVerifierRunRevisionError {
    #[error("Harness verifier run revision must be positive: {0}")]
    Invalid(i64),
    #[error("Harness verifier run revision overflowed")]
    Overflow,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessVerifierName(String);

impl HarnessVerifierName {
    pub fn new(value: String) -> Result<Self, HarnessVerifierNameError> {
        if value.trim().is_empty() {
            return Err(HarnessVerifierNameError::Empty);
        }
        if value.len() > MAX_HARNESS_VERIFIER_NAME_BYTES {
            return Err(HarnessVerifierNameError::TooLong {
                actual: value.len(),
                maximum: MAX_HARNESS_VERIFIER_NAME_BYTES,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(HarnessVerifierNameError::ControlCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HarnessVerifierNameError {
    #[error("Harness verifier name must not be empty")]
    Empty,
    #[error("Harness verifier name has {actual} bytes; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
    #[error("Harness verifier name contains a control character")]
    ControlCharacter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarnessVerifierItemState {
    PendingApproval,
    Running,
    Passed,
    Failed,
    Rejected,
}

impl HarnessVerifierItemState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Passed | Self::Failed | Self::Rejected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarnessVerifierRunState {
    PendingApproval,
    Running,
    Passed,
    Failed,
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HarnessVerifierRunAttribution {
    id: HarnessVerifierRunId,
    workspace_id: WorkspaceId,
    bundle_id: HarnessBundleId,
    content_hash: HarnessContentHash,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
}

impl HarnessVerifierRunAttribution {
    pub const fn new(
        id: HarnessVerifierRunId,
        workspace_id: WorkspaceId,
        bundle_id: HarnessBundleId,
        content_hash: HarnessContentHash,
        activity_id: ActivityId,
        runtime_instance_id: RuntimeInstanceId,
    ) -> Self {
        Self {
            id,
            workspace_id,
            bundle_id,
            content_hash,
            activity_id,
            runtime_instance_id,
        }
    }

    pub const fn id(self) -> HarnessVerifierRunId {
        self.id
    }

    pub const fn workspace_id(self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn bundle_id(self) -> HarnessBundleId {
        self.bundle_id
    }

    pub const fn content_hash(self) -> HarnessContentHash {
        self.content_hash
    }

    pub const fn activity_id(self) -> ActivityId {
        self.activity_id
    }

    pub const fn runtime_instance_id(self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HarnessVerifierRunTimestamps {
    started_at: TimestampMillis,
    completed_at: Option<TimestampMillis>,
}

impl HarnessVerifierRunTimestamps {
    pub fn new(
        started_at: TimestampMillis,
        completed_at: Option<TimestampMillis>,
    ) -> Result<Self, HarnessVerifierDomainError> {
        if completed_at.is_some_and(|value| value.get() < started_at.get()) {
            return Err(HarnessVerifierDomainError::InvalidRunTimestamps);
        }
        Ok(Self {
            started_at,
            completed_at,
        })
    }

    pub const fn started_at(self) -> TimestampMillis {
        self.started_at
    }

    pub const fn completed_at(self) -> Option<TimestampMillis> {
        self.completed_at
    }
}

impl HarnessVerifierRunState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Passed | Self::Failed)
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessVerifierItem {
    ordinal: u16,
    name: HarnessVerifierName,
    approval_id: ApprovalRequestId,
    execution_id: ExecutionId,
    request_digest: ExecutionRequestDigest,
    state: HarnessVerifierItemState,
    exit_code: Option<i32>,
    duration_millis: Option<u64>,
}

impl HarnessVerifierItem {
    pub fn new(
        ordinal: u16,
        name: HarnessVerifierName,
        approval_id: ApprovalRequestId,
        execution_id: ExecutionId,
        request_digest: ExecutionRequestDigest,
        state: HarnessVerifierItemState,
        exit_code: Option<i32>,
        duration_millis: Option<u64>,
    ) -> Result<Self, HarnessVerifierDomainError> {
        if usize::from(ordinal) >= usize::from(MAX_HARNESS_VERIFIERS) {
            return Err(HarnessVerifierDomainError::OrdinalOutOfRange(ordinal));
        }
        let terminal = state.is_terminal();
        if (!terminal && (exit_code.is_some() || duration_millis.is_some()))
            || (state == HarnessVerifierItemState::Passed && exit_code != Some(0))
            || (state == HarnessVerifierItemState::Rejected
                && (exit_code.is_some() || duration_millis.is_some()))
        {
            return Err(HarnessVerifierDomainError::InvalidItemEvidence);
        }
        Ok(Self {
            ordinal,
            name,
            approval_id,
            execution_id,
            request_digest,
            state,
            exit_code,
            duration_millis,
        })
    }

    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn name(&self) -> &HarnessVerifierName {
        &self.name
    }

    pub const fn approval_id(&self) -> ApprovalRequestId {
        self.approval_id
    }

    pub const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    pub const fn request_digest(&self) -> ExecutionRequestDigest {
        self.request_digest
    }

    pub const fn state(&self) -> HarnessVerifierItemState {
        self.state
    }

    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub const fn duration_millis(&self) -> Option<u64> {
        self.duration_millis
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessVerifierRun {
    attribution: HarnessVerifierRunAttribution,
    state: HarnessVerifierRunState,
    timestamps: HarnessVerifierRunTimestamps,
    revision: HarnessVerifierRunRevision,
    items: Vec<HarnessVerifierItem>,
}

impl HarnessVerifierRun {
    pub fn from_parts(
        attribution: HarnessVerifierRunAttribution,
        state: HarnessVerifierRunState,
        timestamps: HarnessVerifierRunTimestamps,
        revision: HarnessVerifierRunRevision,
        items: Vec<HarnessVerifierItem>,
    ) -> Result<Self, HarnessVerifierDomainError> {
        validate_items(&items)?;
        let expected_state = aggregate_state(&items);
        if state != expected_state {
            return Err(HarnessVerifierDomainError::AggregateMismatch);
        }
        if state.is_terminal() != timestamps.completed_at().is_some() {
            return Err(HarnessVerifierDomainError::InvalidRunTimestamps);
        }
        Ok(Self {
            attribution,
            state,
            timestamps,
            revision,
            items,
        })
    }

    pub fn starting(
        attribution: HarnessVerifierRunAttribution,
        started_at: TimestampMillis,
        items: Vec<HarnessVerifierItem>,
    ) -> Result<Self, HarnessVerifierDomainError> {
        Self::from_parts(
            attribution,
            aggregate_state(&items),
            HarnessVerifierRunTimestamps::new(started_at, None)?,
            HarnessVerifierRunRevision::INITIAL,
            items,
        )
    }

    pub fn reconcile(
        &self,
        items: Vec<HarnessVerifierItem>,
        observed_at: TimestampMillis,
    ) -> Result<Self, HarnessVerifierDomainError> {
        if self.state.is_terminal() {
            if items == self.items {
                return Ok(self.clone());
            }
            return Err(HarnessVerifierDomainError::TerminalMutation);
        }
        validate_items(&items)?;
        if items.len() != self.items.len()
            || items.iter().zip(&self.items).any(|(next, current)| {
                next.ordinal != current.ordinal
                    || next.name != current.name
                    || next.approval_id != current.approval_id
                    || next.execution_id != current.execution_id
                    || next.request_digest != current.request_digest
            })
        {
            return Err(HarnessVerifierDomainError::ItemIdentityChanged);
        }
        if observed_at.get() < self.timestamps.started_at().get() {
            return Err(HarnessVerifierDomainError::InvalidRunTimestamps);
        }
        let state = aggregate_state(&items);
        Self::from_parts(
            self.attribution,
            state,
            HarnessVerifierRunTimestamps::new(
                self.timestamps.started_at(),
                state.is_terminal().then_some(observed_at),
            )?,
            self.revision
                .checked_next()
                .map_err(HarnessVerifierDomainError::Revision)?,
            items,
        )
    }

    pub const fn id(&self) -> HarnessVerifierRunId {
        self.attribution.id()
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.attribution.workspace_id()
    }

    pub const fn bundle_id(&self) -> HarnessBundleId {
        self.attribution.bundle_id()
    }

    pub const fn content_hash(&self) -> HarnessContentHash {
        self.attribution.content_hash()
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.attribution.activity_id()
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.attribution.runtime_instance_id()
    }

    pub const fn attribution(&self) -> HarnessVerifierRunAttribution {
        self.attribution
    }

    pub const fn state(&self) -> HarnessVerifierRunState {
        self.state
    }

    pub const fn started_at(&self) -> TimestampMillis {
        self.timestamps.started_at()
    }

    pub const fn completed_at(&self) -> Option<TimestampMillis> {
        self.timestamps.completed_at()
    }

    pub const fn timestamps(&self) -> HarnessVerifierRunTimestamps {
        self.timestamps
    }

    pub const fn revision(&self) -> HarnessVerifierRunRevision {
        self.revision
    }

    pub fn items(&self) -> &[HarnessVerifierItem] {
        &self.items
    }

    pub fn passed_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.state == HarnessVerifierItemState::Passed)
            .count()
    }

    pub fn failed_count(&self) -> usize {
        self.items
            .iter()
            .filter(|item| {
                matches!(
                    item.state,
                    HarnessVerifierItemState::Failed | HarnessVerifierItemState::Rejected
                )
            })
            .count()
    }
}

fn validate_items(items: &[HarnessVerifierItem]) -> Result<(), HarnessVerifierDomainError> {
    if items.is_empty() || items.len() > usize::from(MAX_HARNESS_VERIFIERS) {
        return Err(HarnessVerifierDomainError::InvalidItemCount(items.len()));
    }
    if items
        .iter()
        .enumerate()
        .any(|(index, item)| usize::from(item.ordinal) != index)
    {
        return Err(HarnessVerifierDomainError::NonCanonicalOrdinal);
    }
    Ok(())
}

fn aggregate_state(items: &[HarnessVerifierItem]) -> HarnessVerifierRunState {
    if items.iter().all(|item| item.state.is_terminal()) {
        if items
            .iter()
            .all(|item| item.state == HarnessVerifierItemState::Passed)
        {
            HarnessVerifierRunState::Passed
        } else {
            HarnessVerifierRunState::Failed
        }
    } else if items
        .iter()
        .any(|item| item.state == HarnessVerifierItemState::Running)
    {
        HarnessVerifierRunState::Running
    } else {
        HarnessVerifierRunState::PendingApproval
    }
}

#[derive(Debug, Error)]
pub enum HarnessVerifierDomainError {
    #[error("Harness verifier item count is invalid: {0}")]
    InvalidItemCount(usize),
    #[error("Harness verifier ordinal is outside the declared verifier bound: {0}")]
    OrdinalOutOfRange(u16),
    #[error("Harness verifier item ordinals are not canonical")]
    NonCanonicalOrdinal,
    #[error("Harness verifier item evidence does not match its state")]
    InvalidItemEvidence,
    #[error("Harness verifier aggregate state does not match item states")]
    AggregateMismatch,
    #[error("Harness verifier run timestamps are invalid")]
    InvalidRunTimestamps,
    #[error("Harness verifier terminal run cannot be mutated")]
    TerminalMutation,
    #[error("Harness verifier item identity changed during reconciliation")]
    ItemIdentityChanged,
    #[error("Harness verifier run revision is invalid")]
    Revision(#[source] HarnessVerifierRunRevisionError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(
        ordinal: u16,
        state: HarnessVerifierItemState,
        exit_code: Option<i32>,
    ) -> Result<HarnessVerifierItem, Box<dyn std::error::Error>> {
        Ok(HarnessVerifierItem::new(
            ordinal,
            HarnessVerifierName::new(format!("verifier-{ordinal}"))?,
            ApprovalRequestId::from_uuid(Uuid::from_u128(100 + u128::from(ordinal))),
            ExecutionId::from_uuid(Uuid::from_u128(200 + u128::from(ordinal))),
            ExecutionRequestDigest::from_bytes([u8::try_from(ordinal).unwrap_or(u8::MAX); 32]),
            state,
            exit_code,
            state.is_terminal().then_some(10),
        )?)
    }

    #[test]
    fn verifier_run_reconcile_is_cas_friendly_and_aggregate_is_derived()
    -> Result<(), Box<dyn std::error::Error>> {
        let run = HarnessVerifierRun::starting(
            HarnessVerifierRunAttribution::new(
                HarnessVerifierRunId::from_uuid(Uuid::from_u128(1)),
                WorkspaceId::from_uuid(Uuid::from_u128(2)),
                HarnessBundleId::from_uuid(Uuid::from_u128(3)),
                HarnessContentHash::from_bytes([4; HarnessContentHash::BYTE_LEN]),
                ActivityId::from_uuid(Uuid::from_u128(5)),
                RuntimeInstanceId::from_uuid(Uuid::from_u128(6)),
            ),
            TimestampMillis::new(10)?,
            vec![
                item(0, HarnessVerifierItemState::PendingApproval, None)?,
                item(1, HarnessVerifierItemState::PendingApproval, None)?,
            ],
        )?;
        assert_eq!(run.state(), HarnessVerifierRunState::PendingApproval);
        let running = run.reconcile(
            vec![
                item(0, HarnessVerifierItemState::Running, None)?,
                item(1, HarnessVerifierItemState::PendingApproval, None)?,
            ],
            TimestampMillis::new(20)?,
        )?;
        assert_eq!(running.state(), HarnessVerifierRunState::Running);
        assert_eq!(running.revision().get(), 2);
        let passed = running.reconcile(
            vec![
                item(0, HarnessVerifierItemState::Passed, Some(0))?,
                item(1, HarnessVerifierItemState::Passed, Some(0))?,
            ],
            TimestampMillis::new(30)?,
        )?;
        assert_eq!(passed.state(), HarnessVerifierRunState::Passed);
        assert_eq!(passed.passed_count(), 2);
        assert_eq!(passed.failed_count(), 0);
        assert_eq!(passed.completed_at(), Some(TimestampMillis::new(30)?));
        Ok(())
    }
}
