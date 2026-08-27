use forge_domain::{
    ActivityId, ChangeSetId, ChangeSetState, DiffArtifactHealth, DiffId, DiffListLimit,
    DiffPayloadProjection, RegisteredDiffEvidence,
};
use forge_persistence::WorkspaceStore;
use forge_workspace::{ConfinedWorkspace, DiffArtifactExpectation, ExistingWorkspaceStateLayout};

use crate::error::{ControlError, ControlErrorCode};
use crate::filesystem::{map_diff_artifact_error, map_filesystem_error};
use crate::service::{ForgeControl, ResolvedWorkspaceScope, map_activity_store_error};

/// Bounded Activity-scoped Diff metadata query.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffListRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity_id: ActivityId,
    pub limit: DiffListLimit,
}

/// Bounded, remote-safe Diff metadata projection.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffListResult {
    scope: ResolvedWorkspaceScope,
    diffs: Vec<RegisteredDiffEvidence>,
}

impl DiffListResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub fn diffs(&self) -> &[RegisteredDiffEvidence] {
        &self.diffs
    }
}

/// Identity-scoped Diff read request. History reads intentionally require no
/// live Activity lease.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub diff_id: DiffId,
}

/// Verified redacted Diff content when available, plus caller-time health.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffReadResult {
    scope: ResolvedWorkspaceScope,
    evidence: RegisteredDiffEvidence,
    health: DiffArtifactHealth,
    content: Option<String>,
}

impl DiffReadResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn evidence(&self) -> &RegisteredDiffEvidence {
        &self.evidence
    }

    pub const fn health(&self) -> DiffArtifactHealth {
        self.health
    }

    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }
}

/// Identity-scoped artifact health request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDoctorRequest {
    pub scope: ResolvedWorkspaceScope,
    pub diff_id: DiffId,
}

/// Caller-time health separated from durable Diff lifecycle state.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDoctorResult {
    scope: ResolvedWorkspaceScope,
    evidence: RegisteredDiffEvidence,
    health: DiffArtifactHealth,
}

impl DiffDoctorResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn evidence(&self) -> &RegisteredDiffEvidence {
        &self.evidence
    }

    pub const fn health(&self) -> DiffArtifactHealth {
        self.health
    }
}

impl ForgeControl {
    pub fn diff_list(&self, request: &DiffListRequest) -> Result<DiffListResult, ControlError> {
        let (scope, _layout, store) = self.open_diff_workspace(&request.scope)?;
        store
            .get_activity(request.activity_id)
            .map_err(map_activity_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityNotFound))?;
        let diffs = store
            .list_diffs(request.activity_id, request.limit)
            .map_err(map_activity_store_error)?;
        Ok(DiffListResult { scope, diffs })
    }

    pub fn diff_read(&self, request: &DiffReadRequest) -> Result<DiffReadResult, ControlError> {
        let (scope, layout, store) = self.open_diff_workspace(&request.scope)?;
        let evidence = require_diff(&store, request.diff_id, scope.workspace_id())?;
        let artifact_store = artifact_store_if_needed(&layout, evidence.payload())?;
        let health = observe_health(artifact_store.as_ref(), &evidence)?;
        let content = if health == DiffArtifactHealth::Available
            && matches!(evidence.payload(), DiffPayloadProjection::Ready { .. })
        {
            let expectation = artifact_expectation(&evidence)?;
            let bytes = artifact_store
                .as_ref()
                .ok_or_else(|| ControlError::new(ControlErrorCode::DiffUnavailable))?
                .read(&expectation)
                .map_err(map_diff_artifact_error)?;
            Some(String::from_utf8(bytes).map_err(|error| {
                ControlError::with_source(ControlErrorCode::DiffUnavailable, error)
            })?)
        } else {
            None
        };
        Ok(DiffReadResult {
            scope,
            evidence,
            health,
            content,
        })
    }

    pub fn diff_doctor(
        &self,
        request: &DiffDoctorRequest,
    ) -> Result<DiffDoctorResult, ControlError> {
        let (scope, layout, store) = self.open_diff_workspace(&request.scope)?;
        let evidence = require_diff(&store, request.diff_id, scope.workspace_id())?;
        let artifact_store = artifact_store_if_needed(&layout, evidence.payload())?;
        let health = observe_health(artifact_store.as_ref(), &evidence)?;
        Ok(DiffDoctorResult {
            scope,
            evidence,
            health,
        })
    }

    pub(crate) fn open_diff_workspace(
        &self,
        requested: &ResolvedWorkspaceScope,
    ) -> Result<
        (
            ResolvedWorkspaceScope,
            ExistingWorkspaceStateLayout,
            WorkspaceStore,
        ),
        ControlError,
    > {
        let (scope, layout, store) = self.open_resolved_workspace_with_layout(
            requested.locator().location_id(),
            requested.locator().expected_revision(),
            requested.locator(),
        )?;
        if scope != *requested {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        Ok((scope, layout, store))
    }
}

fn require_diff(
    store: &WorkspaceStore,
    id: DiffId,
    workspace_id: forge_domain::WorkspaceId,
) -> Result<RegisteredDiffEvidence, ControlError> {
    let Some(evidence) = store.get_diff(id).map_err(map_activity_store_error)? else {
        let change_set_id = ChangeSetId::from_uuid(id.into_uuid());
        let legacy = store
            .get_file_mutation(change_set_id)
            .map_err(map_activity_store_error)?
            .is_some_and(|record| {
                record.change_set().workspace_id() == workspace_id
                    && record.change_set().state() == ChangeSetState::Applied
            });
        let code = if legacy {
            ControlErrorCode::DiffLegacyUnavailable
        } else {
            ControlErrorCode::DiffNotFound
        };
        return Err(ControlError::new(code));
    };
    if evidence.workspace_id() != workspace_id {
        return Err(ControlError::new(ControlErrorCode::DiffNotFound));
    }
    Ok(evidence)
}

fn artifact_store_if_needed(
    layout: &ExistingWorkspaceStateLayout,
    payload: &DiffPayloadProjection,
) -> Result<Option<forge_workspace::DiffArtifactStore>, ControlError> {
    if matches!(
        payload,
        DiffPayloadProjection::IntentText { .. }
            | DiffPayloadProjection::Ready { .. }
            | DiffPayloadProjection::PurgePending { .. }
    ) {
        ConfinedWorkspace::open(layout)
            .map_err(map_filesystem_error)?
            .diff_artifact_store()
            .map(Some)
            .map_err(map_filesystem_error)
    } else {
        Ok(None)
    }
}

fn observe_health(
    artifacts: Option<&forge_workspace::DiffArtifactStore>,
    evidence: &RegisteredDiffEvidence,
) -> Result<DiffArtifactHealth, ControlError> {
    match evidence.payload() {
        DiffPayloadProjection::IntentText { .. } => {
            let artifacts =
                artifacts.ok_or_else(|| ControlError::new(ControlErrorCode::DiffUnavailable))?;
            let expected = artifact_expectation(evidence)?;
            let pending = artifacts
                .doctor_pending(&expected)
                .map_err(map_diff_artifact_error)?;
            if pending == DiffArtifactHealth::Missing {
                artifacts.doctor(&expected).map_err(map_diff_artifact_error)
            } else {
                Ok(pending)
            }
        }
        DiffPayloadProjection::Ready { .. } | DiffPayloadProjection::PurgePending { .. } => {
            artifacts
                .ok_or_else(|| ControlError::new(ControlErrorCode::DiffUnavailable))?
                .doctor(&artifact_expectation(evidence)?)
                .map_err(map_diff_artifact_error)
        }
        DiffPayloadProjection::Tombstoned { .. } => Ok(DiffArtifactHealth::Archived),
        DiffPayloadProjection::IntentSummary { .. }
        | DiffPayloadProjection::SummaryOnly { .. }
        | DiffPayloadProjection::Abandoned { .. } => Ok(DiffArtifactHealth::NotApplicable),
    }
}

pub(crate) fn artifact_expectation(
    evidence: &RegisteredDiffEvidence,
) -> Result<DiffArtifactExpectation, ControlError> {
    let (compressed_hash, uncompressed_hash, compressed_size, uncompressed_size) =
        match evidence.payload() {
            DiffPayloadProjection::IntentText {
                compressed_hash,
                uncompressed_hash,
                compressed_size,
                uncompressed_size,
                ..
            }
            | DiffPayloadProjection::Ready {
                compressed_hash,
                uncompressed_hash,
                compressed_size,
                uncompressed_size,
                ..
            }
            | DiffPayloadProjection::PurgePending {
                compressed_hash,
                uncompressed_hash,
                compressed_size,
                uncompressed_size,
                ..
            } => (
                *compressed_hash,
                *uncompressed_hash,
                *compressed_size,
                *uncompressed_size,
            ),
            DiffPayloadProjection::IntentSummary { .. }
            | DiffPayloadProjection::SummaryOnly { .. }
            | DiffPayloadProjection::Abandoned { .. }
            | DiffPayloadProjection::Tombstoned { .. } => {
                return Err(ControlError::new(ControlErrorCode::DiffUnavailable));
            }
        };
    Ok(DiffArtifactExpectation::new(
        evidence.id(),
        compressed_hash,
        uncompressed_hash,
        compressed_size,
        uncompressed_size,
    ))
}
