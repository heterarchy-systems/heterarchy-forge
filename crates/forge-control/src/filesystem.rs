use std::path::Path;

use forge_domain::{
    AbandonDiffEvidence, ActivityId, ActivityState, BeginDiffEvidence, BeginFileMutation,
    BeginFileMutationResult, BeginFileMutationStatus, ChangeSetId, ChangeSetState,
    CompleteDiffEvidence, CompleteFileMutation, DiffAttribution, DiffChangeKind,
    DiffContractVersions, DiffEvidenceState, DiffFileSummary, DiffId, DiffPayloadProjection,
    DiffRenderKind, FailFileMutation, FileContentHash, FileMutationId, FileMutationIdentity,
    FileMutationKind, FileMutationPlan, FileMutationRecord, FileMutationScope, GoalWorkAttribution,
    RegisteredDiffEvidence, RuntimeInstanceId, TimestampMillis, WorkspaceRelativePath,
};
use forge_persistence::{BeginFileMutationDiffResult, WorkspaceStore};
use forge_workspace::{
    ConfinedFileRead, ConfinedFilesystemError, ConfinedWorkspace, DiffArtifactStore,
    DiffArtifactStoreError, DiffRenderError, PreparedFileMutation, RenderedDiffEvidence,
    StagedDiffArtifact, WorkspaceStateLayout, bounded_write_content_hash, render_diff_evidence,
};

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{
    ForgeControl, ResolvedWorkspaceScope, map_activity_store_error, map_location_error,
    map_state_layout_error,
};

const MAX_EFFECT_LOCATIONS: u32 = 1_000;
const MAX_EFFECT_LOCATIONS_USIZE: usize = 1_000;

/// Live Activity attribution required for one file request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileActivityScope {
    pub activity_id: ActivityId,
    pub runtime_instance_id: RuntimeInstanceId,
    pub observed_at: TimestampMillis,
}

/// Explicit transport/UI-neutral request for one confined file read.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
    pub path: WorkspaceRelativePath,
}

/// Confined read result. It exposes no absolute root or runtime lease owner.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReadResult {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    path: WorkspaceRelativePath,
    read: ConfinedFileRead,
}

impl FileReadResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn read(&self) -> &ConfinedFileRead {
        &self.read
    }
}

/// Explicit one-file V1 mutation request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMutationRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
    pub goal: Option<GoalWorkAttribution>,
    pub change_set_id: ChangeSetId,
    pub mutation_id: FileMutationId,
    pub plan: FileMutationPlan,
    pub content: Option<Vec<u8>>,
}

/// Durable/effect outcome without exposing adapter paths or errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileMutationStatus {
    Applied,
    AlreadyApplied,
    RecoveryRequired,
    TerminalFailed,
    CommittedButUnconfirmed,
}

/// Activity-attributed mutation record returned by the control boundary.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMutationResult {
    scope: ResolvedWorkspaceScope,
    record: FileMutationRecord,
    status: FileMutationStatus,
}

impl FileMutationResult {
    fn new(
        scope: ResolvedWorkspaceScope,
        record: FileMutationRecord,
        status: FileMutationStatus,
    ) -> Self {
        Self {
            scope,
            record,
            status,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn record(&self) -> &FileMutationRecord {
        &self.record
    }

    pub const fn status(&self) -> FileMutationStatus {
        self.status
    }
}

#[derive(Debug)]
enum PreparedDiffEvidence {
    Text {
        file: DiffFileSummary,
        staged: StagedDiffArtifact,
    },
    SummaryOnly {
        file: DiffFileSummary,
        render_kind: DiffRenderKind,
    },
}

struct AdmittedFileMutation<'a> {
    scope: ResolvedWorkspaceScope,
    layout: forge_workspace::ExistingWorkspaceStateLayout,
    store: WorkspaceStore,
    request: &'a FileMutationRequest,
    identity: FileMutationIdentity,
    prepared: PreparedFileMutation,
    diff_artifacts: DiffArtifactStore,
    prepared_diff: PreparedDiffEvidence,
    begin: &'a BeginFileMutationDiffResult,
}

struct DefiniteFileMutationFailure<'a> {
    scope: ResolvedWorkspaceScope,
    store: &'a mut WorkspaceStore,
    request: &'a FileMutationRequest,
    identity: FileMutationIdentity,
    diff_artifacts: &'a DiffArtifactStore,
    prepared_diff: PreparedDiffEvidence,
    begin: &'a BeginFileMutationDiffResult,
}

impl PreparedDiffEvidence {
    fn begin_command(
        &self,
        scope: &ResolvedWorkspaceScope,
        request: &FileMutationRequest,
    ) -> Result<BeginDiffEvidence, ControlError> {
        let payload = match self {
            Self::Text { staged, .. } => DiffPayloadProjection::IntentText {
                pending_relative_path: staged
                    .pending_relative_path()
                    .map_err(map_diff_artifact_error)?,
                final_relative_path: staged
                    .final_relative_path()
                    .map_err(map_diff_artifact_error)?,
                compressed_hash: staged.compressed_hash(),
                uncompressed_hash: staged.uncompressed_hash(),
                compressed_size: staged.compressed_size(),
                uncompressed_size: staged.uncompressed_size(),
            },
            Self::SummaryOnly { render_kind, .. } => DiffPayloadProjection::IntentSummary {
                render_kind: *render_kind,
            },
        };
        BeginDiffEvidence::new(
            DiffAttribution::new(
                DiffId::for_change_set(request.change_set_id),
                scope.workspace_id(),
                request.activity.activity_id,
                request.change_set_id,
                request.mutation_id,
            ),
            self.file().clone(),
            payload,
            request.activity.observed_at,
            DiffContractVersions::V1,
        )
        .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))
    }

    const fn file(&self) -> &DiffFileSummary {
        match self {
            Self::Text { file, .. } | Self::SummaryOnly { file, .. } => file,
        }
    }

    fn publish(self, store: &DiffArtifactStore) -> Result<DiffPayloadProjection, ControlError> {
        match self {
            Self::Text { staged, .. } => {
                let published = store.publish(staged).map_err(map_diff_artifact_error)?;
                let expected = published.expectation();
                Ok(DiffPayloadProjection::Ready {
                    relative_path: published.relative_path().map_err(map_diff_artifact_error)?,
                    compressed_hash: expected.compressed_hash(),
                    uncompressed_hash: expected.uncompressed_hash(),
                    compressed_size: expected.compressed_size(),
                    uncompressed_size: expected.uncompressed_size(),
                })
            }
            Self::SummaryOnly { render_kind, .. } => {
                Ok(DiffPayloadProjection::SummaryOnly { render_kind })
            }
        }
    }

    fn abandon(self, store: &DiffArtifactStore) -> Result<(), ControlError> {
        match self {
            Self::Text { staged, .. } => store.abandon(staged).map_err(map_diff_artifact_error),
            Self::SummaryOnly { .. } => Ok(()),
        }
    }
}

impl ForgeControl {
    /// Read one regular file only after fresh Workspace, overlap, and live
    /// Activity ownership validation.
    pub fn file_read(&self, request: &FileReadRequest) -> Result<FileReadResult, ControlError> {
        let (scope, layout, store) = self.open_effect_workspace(&request.scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        authorize_activity(&store, request.activity)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let read = filesystem
            .read(&request.path)
            .map_err(map_filesystem_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(FileReadResult {
            scope,
            activity_id: request.activity.activity_id,
            path: request.path.clone(),
            read,
        })
    }

    /// Execute one one-path mutation using durable-intent -> confined effect
    /// -> durable terminal metadata. No automatic replay occurs on uncertainty.
    pub fn file_mutate(
        &self,
        request: &FileMutationRequest,
    ) -> Result<FileMutationResult, ControlError> {
        self.file_mutate_with_hook(request, || {})
    }

    fn file_mutate_with_hook<Hook>(
        &self,
        request: &FileMutationRequest,
        after_initial_check: Hook,
    ) -> Result<FileMutationResult, ControlError>
    where
        Hook: FnOnce(),
    {
        let (scope, layout, mut store) = self.open_effect_workspace(&request.scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        let activity = authorize_activity(&store, request.activity)?;
        let identity = FileMutationIdentity::new(request.change_set_id, request.mutation_id);
        let intended_hash = intended_content_hash(request)?;
        if let Some(existing) = find_existing_mutation(&store, request, intended_hash, &scope)? {
            return Ok(existing);
        }
        after_initial_check();

        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let diff_artifacts = filesystem
            .diff_artifact_store()
            .map_err(map_filesystem_error)?;
        let prepared = match filesystem.prepare_mutation(&request.plan) {
            Ok(prepared) => prepared,
            Err(error)
                if matches!(
                    error,
                    ConfinedFilesystemError::NotFound
                        | ConfinedFilesystemError::PathConflict
                        | ConfinedFilesystemError::StaleWrite
                ) =>
            {
                if let Some(existing) =
                    find_existing_mutation(&store, request, intended_hash, &scope)?
                {
                    return Ok(existing);
                }
                return Err(map_filesystem_error(error));
            }
            Err(error) => return Err(map_filesystem_error(error)),
        };
        if let Some(existing) = find_existing_mutation(&store, request, intended_hash, &scope)? {
            return Ok(existing);
        }
        let prepared_diff = prepare_diff_evidence(&diff_artifacts, &prepared, request)?;
        let command = BeginFileMutation::new(
            identity,
            FileMutationScope::new(
                scope.workspace_id(),
                scope.workspace_revision(),
                activity.id(),
                request.activity.runtime_instance_id,
                activity.lease_revision(),
            ),
            request.plan.clone(),
            intended_hash,
            prepared.pre_state(),
            request.activity.observed_at,
        )
        .map_err(|error| ControlError::with_source(ControlErrorCode::FileConflict, error))?;
        let diff_command = prepared_diff.begin_command(&scope, request)?;
        let begin = store
            .begin_file_mutation_for_goal(&command, &diff_command, request.goal)
            .map_err(map_activity_store_error)?;
        if let Some(result) = resumed_begin_result(&scope, begin.file()) {
            cleanup_resumed_diff(&diff_artifacts, prepared_diff, begin.status());
            return Ok(result);
        }
        self.finish_prepared_mutation(AdmittedFileMutation {
            scope,
            layout,
            store,
            request,
            identity,
            prepared,
            diff_artifacts,
            prepared_diff,
            begin: &begin,
        })
    }

    fn finish_prepared_mutation(
        &self,
        execution: AdmittedFileMutation<'_>,
    ) -> Result<FileMutationResult, ControlError> {
        let AdmittedFileMutation {
            scope,
            layout,
            mut store,
            request,
            identity,
            prepared,
            diff_artifacts,
            prepared_diff,
            begin,
        } = execution;
        let mut checkpoint = begin_best_effort_checkpoint(&layout, &mut store, &scope, request);
        let applied = match prepared.apply(request.mutation_id, request.content.as_deref()) {
            Ok(applied) => applied,
            Err(error) if error.effect_may_have_committed() => {
                tracing::warn!(
                    changeset_id = %request.change_set_id,
                    mutation_id = %request.mutation_id,
                    failure_code = ?error.failure_code(),
                    "file effect committed but POST evidence is unconfirmed"
                );
                if checkpoint.is_some() {
                    tracing::warn!(
                        changeset_id = %request.change_set_id,
                        "mutation unconfirmed; captured checkpoint remains Starting"
                    );
                }
                return Ok(recovery_required_result(scope, begin));
            }
            Err(error) => {
                return finish_definite_file_mutation_failure(
                    DefiniteFileMutationFailure {
                        scope,
                        store: &mut store,
                        request,
                        identity,
                        diff_artifacts: &diff_artifacts,
                        prepared_diff,
                        begin,
                    },
                    error,
                );
            }
        };
        let terminal_diff = match prepared_diff.publish(&diff_artifacts) {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    changeset_id = %request.change_set_id,
                    mutation_id = %request.mutation_id,
                    code = error.code().as_str(),
                    "file effect committed but Diff artifact publish is unconfirmed"
                );
                return Ok(recovery_required_result(scope, begin));
            }
        };
        let complete = CompleteFileMutation::new(
            identity,
            begin.record().change_set().revision(),
            begin.record().mutation().revision(),
            applied.post_state(),
            request.activity.observed_at,
        );
        let diff_revision = begin
            .diff()
            .filter(|diff| diff.state() == DiffEvidenceState::Intent)
            .map(RegisteredDiffEvidence::revision)
            .ok_or_else(|| ControlError::new(ControlErrorCode::Internal))?;
        let complete_diff = CompleteDiffEvidence::new(
            DiffId::for_change_set(request.change_set_id),
            diff_revision,
            terminal_diff,
            request.activity.observed_at,
        )
        .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
        let record = match store.complete_file_mutation(&complete, &complete_diff) {
            Ok(record) => record,
            Err(store_error) => {
                let code = map_activity_store_error(store_error).code();
                tracing::warn!(
                    changeset_id = %request.change_set_id,
                    mutation_id = %request.mutation_id,
                    code = code.as_str(),
                    "file effect committed but terminal ChangeSet persistence is unconfirmed"
                );
                return Ok(recovery_required_result(scope, begin));
            }
        };
        complete_best_effort_checkpoint(&mut checkpoint, &mut store, request);
        let status = if self.committed_scope_matches_with_store(&scope, &store) {
            FileMutationStatus::Applied
        } else {
            FileMutationStatus::CommittedButUnconfirmed
        };
        Ok(FileMutationResult::new(
            scope,
            record.file().clone(),
            status,
        ))
    }

    pub(crate) fn open_effect_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<
        (
            ResolvedWorkspaceScope,
            forge_workspace::ExistingWorkspaceStateLayout,
            WorkspaceStore,
        ),
        ControlError,
    > {
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        Ok((fresh_scope, layout, store))
    }

    pub(crate) fn ensure_non_overlapping_effect_scope(
        &self,
        scope: &ResolvedWorkspaceScope,
        selected_root: &Path,
    ) -> Result<(), ControlError> {
        let limit = forge_domain::LocationListLimit::new(MAX_EFFECT_LOCATIONS)
            .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
        let locations = self
            .locations
            .list_locations(limit)
            .map_err(map_location_error)?;
        validate_effect_location_count(locations.len())?;
        for location in locations {
            if location.id() == scope.locator().location_id()
                || location.state() != forge_domain::LocationState::Enabled
            {
                continue;
            }
            if paths_overlap(selected_root, location.root().as_path()) {
                return Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap));
            }
        }

        let discovery = self
            .locations
            .discover_current(
                scope.locator().location_id(),
                scope.locator().expected_revision(),
            )
            .map_err(map_location_error)?;
        for candidate in discovery.candidates() {
            if candidate.absolute_root() == selected_root
                || !paths_overlap(selected_root, candidate.absolute_root())
            {
                continue;
            }
            if WorkspaceStateLayout::inspect_existing(candidate.absolute_root())
                .map_err(map_state_layout_error)?
                .is_some()
            {
                return Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap));
            }
        }
        Ok(())
    }
}

fn begin_best_effort_checkpoint(
    layout: &forge_workspace::ExistingWorkspaceStateLayout,
    store: &mut WorkspaceStore,
    scope: &ResolvedWorkspaceScope,
    request: &FileMutationRequest,
) -> Option<crate::checkpoint::MutationCheckpoint> {
    let checkpoint = crate::checkpoint::capture_pre(
        layout,
        forge_domain::CheckpointAttribution::new(
            forge_domain::CheckpointId::from_uuid(uuid::Uuid::now_v7()),
            request.change_set_id,
            scope.workspace_id(),
            scope.workspace_revision(),
            request.activity.activity_id,
        ),
        request.plan.path().clone(),
        request.activity.observed_at,
    )?;
    if crate::checkpoint::persist_starting(&checkpoint, store) {
        return Some(checkpoint);
    }
    tracing::warn!(
        changeset_id = %request.change_set_id,
        mutation_id = %request.mutation_id,
        "checkpoint PRE persistence failed; proceeding without a checkpoint row"
    );
    None
}

fn complete_best_effort_checkpoint(
    checkpoint: &mut Option<crate::checkpoint::MutationCheckpoint>,
    store: &mut WorkspaceStore,
    request: &FileMutationRequest,
) {
    let Some(checkpoint) = checkpoint.as_mut() else {
        return;
    };
    if let Err(error) =
        crate::checkpoint::complete_post(checkpoint, store, request.activity.observed_at)
    {
        tracing::warn!(
            changeset_id = %request.change_set_id,
            mutation_id = %request.mutation_id,
            error = ?error,
            "checkpoint POST completion failed; row remains Starting"
        );
    }
}

fn finish_definite_file_mutation_failure(
    context: DefiniteFileMutationFailure<'_>,
    error: ConfinedFilesystemError,
) -> Result<FileMutationResult, ControlError> {
    let DefiniteFileMutationFailure {
        scope,
        store,
        request,
        identity,
        diff_artifacts,
        prepared_diff,
        begin,
    } = context;
    if let Err(cleanup_error) = prepared_diff.abandon(diff_artifacts) {
        tracing::warn!(
            changeset_id = %request.change_set_id,
            mutation_id = %request.mutation_id,
            code = cleanup_error.code().as_str(),
            "file effect failed but pending Diff cleanup is unconfirmed"
        );
        return Ok(FileMutationResult::new(
            scope,
            begin.record().clone(),
            FileMutationStatus::RecoveryRequired,
        ));
    }
    let failure = FailFileMutation::new(
        identity,
        begin.record().change_set().revision(),
        begin.record().mutation().revision(),
        error.failure_code(),
        request.activity.observed_at,
    );
    let abandon = AbandonDiffEvidence::new(
        DiffId::for_change_set(request.change_set_id),
        begin.diff().map_or(
            forge_domain::DiffRevision::INITIAL,
            RegisteredDiffEvidence::revision,
        ),
        request.activity.observed_at,
    );
    if let Err(store_error) = store.fail_file_mutation(&failure, abandon) {
        let code = map_activity_store_error(store_error).code();
        tracing::warn!(
            changeset_id = %request.change_set_id,
            mutation_id = %request.mutation_id,
            code = code.as_str(),
            "file effect failed and terminal ChangeSet persistence is unconfirmed"
        );
        return Err(ControlError::committed());
    }
    Err(map_filesystem_error(error))
}

fn prepare_diff_evidence(
    artifacts: &DiffArtifactStore,
    prepared: &PreparedFileMutation,
    request: &FileMutationRequest,
) -> Result<PreparedDiffEvidence, ControlError> {
    let post = prepared
        .intended_post_source(request.content.as_deref())
        .map_err(map_filesystem_error)?;
    let kind = match request.plan.kind() {
        FileMutationKind::Create => DiffChangeKind::Created,
        FileMutationKind::Replace => DiffChangeKind::Modified,
        FileMutationKind::Delete => DiffChangeKind::Deleted,
    };
    let rendered = render_diff_evidence(request.plan.path(), kind, prepared.pre_source(), &post)
        .map_err(map_diff_render_error)?;
    let file = DiffFileSummary::new(
        request.plan.path().clone(),
        kind,
        rendered.additions(),
        rendered.deletions(),
    );
    match rendered {
        RenderedDiffEvidence::Text(rendered) => {
            let staged = artifacts
                .stage(DiffId::for_change_set(request.change_set_id), &rendered)
                .map_err(map_diff_artifact_error)?;
            Ok(PreparedDiffEvidence::Text { file, staged })
        }
        RenderedDiffEvidence::SummaryOnly { render_kind } => {
            Ok(PreparedDiffEvidence::SummaryOnly { file, render_kind })
        }
    }
}

fn cleanup_resumed_diff(
    artifacts: &DiffArtifactStore,
    prepared: PreparedDiffEvidence,
    status: BeginFileMutationStatus,
) {
    if matches!(
        status,
        BeginFileMutationStatus::AlreadyApplied | BeginFileMutationStatus::TerminalFailed
    ) && let Err(error) = prepared.abandon(artifacts)
    {
        tracing::warn!(
            code = error.code().as_str(),
            "terminal file mutation retry left an unconfirmed pending Diff cleanup"
        );
    }
}

fn resumed_begin_result(
    scope: &ResolvedWorkspaceScope,
    begin: &BeginFileMutationResult,
) -> Option<FileMutationResult> {
    let status = match begin.status() {
        BeginFileMutationStatus::Started => return None,
        BeginFileMutationStatus::AlreadyApplied => FileMutationStatus::AlreadyApplied,
        BeginFileMutationStatus::RecoveryRequired => FileMutationStatus::RecoveryRequired,
        BeginFileMutationStatus::TerminalFailed => FileMutationStatus::TerminalFailed,
    };
    Some(FileMutationResult::new(
        scope.clone(),
        begin.record().clone(),
        status,
    ))
}

fn recovery_required_result(
    scope: ResolvedWorkspaceScope,
    begin: &BeginFileMutationDiffResult,
) -> FileMutationResult {
    FileMutationResult::new(
        scope,
        begin.record().clone(),
        FileMutationStatus::RecoveryRequired,
    )
}

fn map_diff_render_error(error: DiffRenderError) -> ControlError {
    ControlError::with_source(ControlErrorCode::Internal, error)
}

pub(crate) fn map_diff_artifact_error(error: DiffArtifactStoreError) -> ControlError {
    let code = match &error {
        DiffArtifactStoreError::Scope(source) => match source {
            ConfinedFilesystemError::WorkspaceUnavailable
            | ConfinedFilesystemError::PathChanged
            | ConfinedFilesystemError::CommittedPathChanged => {
                ControlErrorCode::WorkspaceRootConflict
            }
            ConfinedFilesystemError::FileTooLarge { .. }
            | ConfinedFilesystemError::WriteTooLarge { .. }
            | ConfinedFilesystemError::LockBusy => ControlErrorCode::FileCapacityExceeded,
            _ => ControlErrorCode::PersistenceFailure,
        },
        DiffArtifactStoreError::DirectoryPathChanged => ControlErrorCode::WorkspaceRootConflict,
        DiffArtifactStoreError::CompressedTooLarge { .. }
        | DiffArtifactStoreError::RenderedTooLarge { .. } => ControlErrorCode::FileCapacityExceeded,
        DiffArtifactStoreError::IdentityCollision => ControlErrorCode::FileConflict,
        DiffArtifactStoreError::AtomicPublishUnsupported
        | DiffArtifactStoreError::Missing
        | DiffArtifactStoreError::CorruptPayload
        | DiffArtifactStoreError::SizeOverflow
        | DiffArtifactStoreError::InvalidRelativePath(_)
        | DiffArtifactStoreError::InvalidInventoryName
        | DiffArtifactStoreError::Syscall { .. }
        | DiffArtifactStoreError::Io { .. } => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

pub(crate) fn authorize_activity(
    store: &WorkspaceStore,
    scope: FileActivityScope,
) -> Result<forge_domain::RegisteredActivity, ControlError> {
    let activity = store
        .get_activity(scope.activity_id)
        .map_err(map_activity_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityNotFound))?;
    if activity.state() != ActivityState::Open
        || activity.lease_owner_id() != Some(scope.runtime_instance_id)
        || activity
            .lease_until()
            .is_none_or(|until| until.get() <= scope.observed_at.get())
    {
        return Err(ControlError::new(ControlErrorCode::ActivityLeaseConflict));
    }
    Ok(activity)
}

fn validate_existing_request(
    record: &FileMutationRecord,
    request: &FileMutationRequest,
    intended_hash: Option<FileContentHash>,
) -> Result<(), ControlError> {
    let matches = record.change_set().id() == request.change_set_id
        && record.change_set().workspace_id() == request.scope.workspace_id()
        && record.change_set().workspace_revision() == request.scope.workspace_revision()
        && record.change_set().activity_id() == request.activity.activity_id
        && record.change_set().runtime_instance_id() == request.activity.runtime_instance_id
        && record.mutation().id() == request.mutation_id
        && record.mutation().path() == request.plan.path()
        && record.mutation().kind() == request.plan.kind()
        && record.mutation().precondition() == request.plan.precondition()
        && record.mutation().intended_content_hash() == intended_hash;
    if matches {
        Ok(())
    } else {
        Err(ControlError::new(ControlErrorCode::FileConflict))
    }
}

fn find_existing_mutation(
    store: &WorkspaceStore,
    request: &FileMutationRequest,
    intended_hash: Option<FileContentHash>,
    scope: &ResolvedWorkspaceScope,
) -> Result<Option<FileMutationResult>, ControlError> {
    let Some(record) = store
        .get_file_mutation(request.change_set_id)
        .map_err(map_activity_store_error)?
    else {
        return Ok(None);
    };
    validate_existing_request(&record, request, intended_hash)?;
    Ok(Some(existing_result(scope.clone(), record)))
}

fn intended_content_hash(
    request: &FileMutationRequest,
) -> Result<Option<FileContentHash>, ControlError> {
    match (request.plan.kind(), request.content.as_deref()) {
        (FileMutationKind::Create | FileMutationKind::Replace, Some(content)) => {
            bounded_write_content_hash(content)
                .map(Some)
                .map_err(map_filesystem_error)
        }
        (FileMutationKind::Delete, None) => Ok(None),
        (FileMutationKind::Create | FileMutationKind::Replace, None)
        | (FileMutationKind::Delete, Some(_)) => {
            Err(ControlError::new(ControlErrorCode::FileConflict))
        }
    }
}

fn validate_effect_location_count(count: usize) -> Result<(), ControlError> {
    if count >= MAX_EFFECT_LOCATIONS_USIZE {
        Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap))
    } else {
        Ok(())
    }
}

fn existing_result(
    scope: ResolvedWorkspaceScope,
    record: FileMutationRecord,
) -> FileMutationResult {
    let status = match record.change_set().state() {
        ChangeSetState::Starting => FileMutationStatus::RecoveryRequired,
        ChangeSetState::Applied => FileMutationStatus::AlreadyApplied,
        ChangeSetState::Failed => FileMutationStatus::TerminalFailed,
    };
    FileMutationResult::new(scope, record, status)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

pub(crate) fn map_filesystem_error(error: ConfinedFilesystemError) -> ControlError {
    let code = match error {
        ConfinedFilesystemError::ProtectedPath
        | ConfinedFilesystemError::InvalidPath
        | ConfinedFilesystemError::TooManyComponents
        | ConfinedFilesystemError::SymlinkRejected
        | ConfinedFilesystemError::NonDirectoryAncestor
        | ConfinedFilesystemError::NonRegularLeaf
        | ConfinedFilesystemError::HardlinkRejected => ControlErrorCode::FilePathDenied,
        ConfinedFilesystemError::NotFound => ControlErrorCode::FileNotFound,
        ConfinedFilesystemError::PathConflict
        | ConfinedFilesystemError::StaleWrite
        | ConfinedFilesystemError::PathChanged
        | ConfinedFilesystemError::CommittedPathChanged
        | ConfinedFilesystemError::CommittedObservationFailed
        | ConfinedFilesystemError::PostStateMismatch => ControlErrorCode::FileConflict,
        ConfinedFilesystemError::FileTooLarge { .. }
        | ConfinedFilesystemError::WriteTooLarge { .. }
        | ConfinedFilesystemError::LockBusy => ControlErrorCode::FileCapacityExceeded,
        ConfinedFilesystemError::WorkspaceUnavailable
        | ConfinedFilesystemError::WorkspaceRootTooDeep => ControlErrorCode::WorkspaceRootConflict,
        ConfinedFilesystemError::InvalidPayload
        | ConfinedFilesystemError::AtomicCreateUnsupported
        | ConfinedFilesystemError::Syscall { .. }
        | ConfinedFilesystemError::StdIo { .. } => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        ActivityLeaseRevision, BootstrapActivity, DiffEvidenceState, DiffListLimit,
        DiffPayloadProjection, EstablishWorkspace, FileContentHash, FileMutationKind, LocationId,
        LocationRevision, RuntimeInstanceId, TimestampMillis, WorkspaceId, WorkspaceRevision,
        WorkspaceRoot,
    };
    use forge_persistence::GlobalRegistry;
    use forge_workspace::{
        ConfinedWorkspace, DiffArtifactExpectation, GitCheckpointStore, LocationService,
        WorkspaceLocator, WorkspaceStateLayout,
    };
    use uuid::Uuid;

    use super::*;
    use crate::worker::ForgeControlWorker;
    use crate::{
        DiffDoctorRequest, DiffListRequest, DiffReadRequest, WorkspaceCheckpointStoreStatus,
        WorkspaceDoctorAggregateOutcome, WorkspaceDoctorObservationConsistency,
        WorkspaceDoctorRequest,
    };

    struct Fixture {
        root: PathBuf,
        control: ForgeControl,
        scope: ResolvedWorkspaceScope,
        activity: FileActivityScope,
    }

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-control-file-{label}-{unique}"));
        let location_root = root.join("location");
        fixture_at(root, &location_root)
    }

    fn fixture_at(
        root: PathBuf,
        location_root: &Path,
    ) -> Result<Fixture, Box<dyn std::error::Error>> {
        let workspace_root = location_root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let registry = GlobalRegistry::open(root.join("registry.sqlite3"))?;
        let mut locations = LocationService::new(registry);
        let location_id = LocationId::from_uuid(id(0xC100));
        locations.register_selected_path(location_id, "Location", location_root, timestamp(1)?)?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let workspace_id = WorkspaceId::from_uuid(id(0xC101));
        let activity_id = ActivityId::from_uuid(id(0xC102));
        let runtime_id = RuntimeInstanceId::from_uuid(id(0xC103));
        let mut store = WorkspaceStore::open(
            &layout,
            EstablishWorkspace::new(
                workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
                layout.root_fingerprint()?,
                timestamp(2)?,
            ),
        )?;
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            runtime_id,
            timestamp(1_000)?,
            timestamp(3)?,
        ))?;
        drop(store);
        let control = ForgeControl::from_location_service(locations);
        let locator = WorkspaceLocator::new(
            location_id,
            LocationRevision::INITIAL,
            Path::new("workspace"),
        )?;
        let scope = control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
        Ok(Fixture {
            root,
            control,
            scope,
            activity: FileActivityScope {
                activity_id,
                runtime_instance_id: runtime_id,
                observed_at: timestamp(10)?,
            },
        })
    }

    fn workspace_root(fixture: &Fixture) -> PathBuf {
        fixture.root.join("location/workspace")
    }

    fn fixture_with_git(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-control-file-{label}-{unique}"));
        let location_root = root.join("location");
        fs::create_dir_all(&location_root)?;
        let output = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&location_root)
            .args(["init", "-q"])
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        if !output.status.success() {
            return Err("git init failed for fixture".into());
        }
        fixture_at(root, &location_root)
    }

    fn create_mutation_request(
        fixture: &Fixture,
        change_set: u128,
        mutation: u128,
        name: &str,
        content: &[u8],
    ) -> Result<FileMutationRequest, Box<dyn std::error::Error>> {
        Ok(FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            change_set_id: ChangeSetId::from_uuid(id(change_set)),
            mutation_id: FileMutationId::from_uuid(id(mutation)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from(name))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(content.to_vec()),
        })
    }

    fn checkpoint_for_change_set(
        store: &WorkspaceStore,
        workspace_id: WorkspaceId,
        change_set: u128,
    ) -> Result<forge_domain::RegisteredCheckpoint, Box<dyn std::error::Error>> {
        store
            .list_checkpoints(workspace_id, 16)?
            .into_iter()
            .find(|checkpoint| checkpoint.change_set_id() == ChangeSetId::from_uuid(id(change_set)))
            .ok_or_else(|| "checkpoint missing".into())
    }

    fn direct_restore_request(
        fixture: &Fixture,
        checkpoint_id: forge_domain::CheckpointId,
        initiator: RuntimeInstanceId,
        observed_at: i64,
    ) -> Result<crate::checkpoint::CheckpointRestoreRequest, Box<dyn std::error::Error>> {
        Ok(crate::checkpoint::CheckpointRestoreRequest {
            scope: fixture.scope.clone(),
            checkpoint_id,
            initiator,
            activity_id: fixture.activity.activity_id,
            observed_at: timestamp(observed_at)?,
            approval_request_id: None,
        })
    }

    fn assert_direct_restore_provenance(
        fixture: &Fixture,
        restore: &forge_domain::RegisteredCheckpointRestore,
        checkpoint_id: forge_domain::CheckpointId,
    ) {
        assert_eq!(restore.checkpoint_id(), checkpoint_id);
        assert_eq!(restore.workspace_id(), fixture.scope.workspace_id());
        assert_eq!(
            restore.attribution().initiator(),
            fixture.activity.runtime_instance_id
        );
        assert_eq!(
            restore.attribution().activity_id(),
            fixture.activity.activity_id
        );
        assert!(restore.attribution().approval_request_id().is_none());
        assert_eq!(
            restore.attribution().fence(),
            forge_domain::CheckpointRestoreFence::Direct
        );
    }

    #[test]
    fn control_file_read_requires_live_owner_and_redacts_scope_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("read")?;
        fs::write(workspace_root(&fixture).join("read.txt"), b"hello")?;
        let request = FileReadRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            path: WorkspaceRelativePath::new(PathBuf::from("read.txt"))?,
        };
        assert_eq!(
            fixture.control.file_read(&request)?.read().content(),
            b"hello"
        );
        let mut wrong = request;
        wrong.activity.runtime_instance_id = RuntimeInstanceId::from_uuid(id(0xFFFF));
        assert_eq!(
            fixture
                .control
                .file_read(&wrong)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::ActivityLeaseConflict)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn control_mutation_is_durable_activity_attributed_and_retry_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("mutate")?;
        let request = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            change_set_id: ChangeSetId::from_uuid(id(0xC200)),
            mutation_id: FileMutationId::from_uuid(id(0xC201)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"token = actual-secret\ncreated\n".to_vec()),
        };
        let applied = fixture.control.file_mutate(&request)?;
        assert_eq!(applied.status(), FileMutationStatus::Applied);
        assert_eq!(
            applied.record().change_set().activity_id(),
            fixture.activity.activity_id
        );
        assert_eq!(
            fs::read(workspace_root(&fixture).join("created.txt"))?,
            b"token = actual-secret\ncreated\n"
        );
        let existing = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("Workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&existing)?;
        let diff = store
            .get_diff_for_change_set(request.change_set_id)?
            .ok_or("Diff Evidence missing")?;
        assert_eq!(diff.state(), DiffEvidenceState::Ready);
        let DiffPayloadProjection::Ready {
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
            ..
        } = diff.payload()
        else {
            return Err("expected ready text Diff".into());
        };
        let expectation = DiffArtifactExpectation::new(
            diff.id(),
            *compressed_hash,
            *uncompressed_hash,
            *compressed_size,
            *uncompressed_size,
        );
        let artifact_store = ConfinedWorkspace::open(&existing)?.diff_artifact_store()?;
        let rendered = artifact_store.read(&expectation)?;
        let rendered = std::str::from_utf8(&rendered)?;
        assert!(rendered.contains("+created"));
        assert!(!rendered.contains("actual-secret"));
        assert!(rendered.contains("[REDACTED]"));
        drop(store);
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::AlreadyApplied
        );
        let mut mismatched_retry = request;
        mismatched_retry.content = Some(b"different".to_vec());
        assert_eq!(
            fixture
                .control
                .file_mutate(&mismatched_retry)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileConflict)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn initialized_parent_workspace_overlap_blocks_child_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("overlap")?;
        let location_root = fixture.root.join("location");
        let parent_layout = WorkspaceStateLayout::initialize(&location_root)?;
        let parent_store = WorkspaceStore::open(
            &parent_layout,
            EstablishWorkspace::new(
                WorkspaceId::from_uuid(id(0xC300)),
                fixture.scope.locator().location_id(),
                WorkspaceRoot::from_canonical(parent_layout.workspace_root().to_path_buf())?,
                parent_layout.root_fingerprint()?,
                timestamp(20)?,
            ),
        )?;
        drop(parent_store);
        let request = FileReadRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            path: WorkspaceRelativePath::new(PathBuf::from("read.txt"))?,
        };
        assert_eq!(
            fixture
                .control
                .file_read(&request)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::WorkspaceScopeOverlap)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn diff_history_surfaces_require_scope_but_not_a_live_lease()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("diff-history")?;
        let change_set_id = ChangeSetId::from_uuid(id(0xC250));
        let applied = fixture.control.file_mutate(&FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            change_set_id,
            mutation_id: FileMutationId::from_uuid(id(0xC251)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("history.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"history\n".to_vec()),
        })?;
        assert_eq!(applied.status(), FileMutationStatus::Applied);
        let diff_id = DiffId::for_change_set(change_set_id);
        let listed = fixture.control.diff_list(&DiffListRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity.activity_id,
            limit: DiffListLimit::new(10)?,
        })?;
        assert_eq!(listed.diffs().len(), 1);
        assert_eq!(listed.diffs()[0].id(), diff_id);
        let read = fixture.control.diff_read(&DiffReadRequest {
            scope: fixture.scope.clone(),
            diff_id,
        })?;
        assert_eq!(read.health(), forge_domain::DiffArtifactHealth::Available);
        assert!(
            read.content()
                .is_some_and(|content| content.contains("+history"))
        );
        let doctor = fixture.control.diff_doctor(&DiffDoctorRequest {
            scope: fixture.scope,
            diff_id,
        })?;
        assert_eq!(doctor.health(), forge_domain::DiffArtifactHealth::Available);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn stale_hash_is_rejected_before_intent_without_overwriting_external_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("stale")?;
        let file = workspace_root(&fixture).join("file.txt");
        fs::write(&file, b"current")?;
        let stale = FileContentHash::from_bytes([1; FileContentHash::BYTE_LEN]);
        let request = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            change_set_id: ChangeSetId::from_uuid(id(0xC400)),
            mutation_id: FileMutationId::from_uuid(id(0xC401)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("file.txt"))?,
                FileMutationKind::Replace,
                forge_domain::FilePrecondition::Matches(stale),
            ),
            content: Some(b"forge".to_vec()),
        };
        assert_eq!(
            fixture
                .control
                .file_mutate(&request)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileConflict)
        );
        assert_eq!(fs::read(&file)?, b"current");
        let existing = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("layout missing")?;
        let store = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(store.get_file_mutation(request.change_set_id)?, None);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn current_lease_revision_is_observed_internally_not_supplied_by_caller()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("lease-revision")?;
        let existing = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("layout missing")?;
        let mut store = WorkspaceStore::open_existing(&existing)?;
        let activity = store
            .get_activity(fixture.activity.activity_id)?
            .ok_or("activity missing")?;
        let renewed = store.renew_activity_lease(&forge_domain::RenewActivityLease::new(
            activity.id(),
            fixture.activity.runtime_instance_id,
            ActivityLeaseRevision::INITIAL,
            timestamp(2_000)?,
            timestamp(11)?,
        ))?;
        drop(store);
        let request = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: FileActivityScope {
                observed_at: timestamp(12)?,
                ..fixture.activity
            },
            goal: None,
            change_set_id: ChangeSetId::from_uuid(id(0xC500)),
            mutation_id: FileMutationId::from_uuid(id(0xC501)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"created".to_vec()),
        };
        let result = fixture.control.file_mutate(&request)?;
        assert_eq!(
            result.record().change_set().activity_lease_revision(),
            renewed.lease_revision()
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn truncated_location_scan_fails_closed_before_effect_authorization() {
        assert!(validate_effect_location_count(MAX_EFFECT_LOCATIONS_USIZE - 1).is_ok());
        assert_eq!(
            validate_effect_location_count(MAX_EFFECT_LOCATIONS_USIZE)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::WorkspaceScopeOverlap)
        );
    }

    #[test]
    fn worker_stamps_file_authorization_at_execution_time() -> Result<(), Box<dyn std::error::Error>>
    {
        let Fixture {
            root,
            control,
            scope,
            activity,
        } = fixture("worker-clock")?;
        fs::write(root.join("location/workspace/read.txt"), b"hello")?;
        let (client, mut worker) = ForgeControlWorker::start(control)?;
        let request = FileReadRequest {
            scope,
            activity: FileActivityScope {
                observed_at: TimestampMillis::new(0)?,
                ..activity
            },
            path: WorkspaceRelativePath::new(PathBuf::from("read.txt"))?,
        };
        assert_eq!(
            client.file_read(request).err().map(|error| error.code()),
            Some(ControlErrorCode::ActivityLeaseConflict)
        );
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn applied_changeset_from_old_workspace_revision_cannot_replay_after_root_rebind()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("rebind-replay")?;
        let request = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            change_set_id: ChangeSetId::from_uuid(id(0xC600)),
            mutation_id: FileMutationId::from_uuid(id(0xC601)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"created".to_vec()),
        };
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::Applied
        );
        let old_root = workspace_root(&fixture);
        let moved_root = fixture.root.join("location/workspace-moved");
        fs::rename(&old_root, &moved_root)?;
        let moved_layout = WorkspaceStateLayout::initialize(&moved_root)?;
        let rebound = WorkspaceStore::open(
            &moved_layout,
            EstablishWorkspace::new(
                fixture.scope.workspace_id(),
                fixture.scope.locator().location_id(),
                WorkspaceRoot::from_canonical(moved_layout.workspace_root().to_path_buf())?,
                moved_layout.root_fingerprint()?,
                timestamp(20)?,
            ),
        )?;
        assert_eq!(rebound.workspace()?.revision().get(), 2);
        drop(rebound);
        let locator = WorkspaceLocator::new(
            fixture.scope.locator().location_id(),
            LocationRevision::INITIAL,
            "workspace-moved",
        )?;
        let rebound_scope = fixture.control.resolve_workspace(
            fixture.scope.locator().location_id(),
            LocationRevision::INITIAL,
            &locator,
        )?;
        let rebound_request = FileMutationRequest {
            scope: rebound_scope,
            ..request
        };
        assert_eq!(
            fixture
                .control
                .file_mutate(&rebound_request)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileConflict)
        );
        assert_eq!(fs::read(moved_root.join("created.txt"))?, b"created");
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn concurrent_identical_mutation_retry_converges_without_spurious_conflict()
    -> Result<(), Box<dyn std::error::Error>> {
        let Fixture {
            root,
            control,
            scope,
            activity,
        } = fixture("concurrent-idempotency")?;
        drop(control);
        let request = FileMutationRequest {
            scope,
            activity,
            goal: None,
            change_set_id: ChangeSetId::from_uuid(id(0xC700)),
            mutation_id: FileMutationId::from_uuid(id(0xC701)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"created".to_vec()),
        };
        let barrier = Arc::new(Barrier::new(2));
        let first_control = ForgeControl::new(GlobalRegistry::open(root.join("registry.sqlite3"))?);
        let second_control =
            ForgeControl::new(GlobalRegistry::open(root.join("registry.sqlite3"))?);
        let first_request = request.clone();
        let second_request = request;
        let first_barrier = Arc::clone(&barrier);
        let second_barrier = Arc::clone(&barrier);
        let first = thread::spawn(move || {
            first_control.file_mutate_with_hook(&first_request, || {
                first_barrier.wait();
            })
        });
        let second = thread::spawn(move || {
            second_control.file_mutate_with_hook(&second_request, || {
                second_barrier.wait();
            })
        });
        let first = first.join().map_err(|_| "first mutation thread panicked")?;
        let second = second
            .join()
            .map_err(|_| "second mutation thread panicked")?;
        let first = first?;
        let second = second?;
        assert!(matches!(
            (first.status(), second.status()),
            (
                FileMutationStatus::Applied,
                FileMutationStatus::AlreadyApplied | FileMutationStatus::RecoveryRequired
            ) | (
                FileMutationStatus::AlreadyApplied | FileMutationStatus::RecoveryRequired,
                FileMutationStatus::Applied
            )
        ));
        assert_eq!(
            fs::read(root.join("location/workspace/created.txt"))?,
            b"created"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn git_backed_mutation_captures_ready_checkpoint_in_owned_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("capture")?;
        let request = create_mutation_request(&fixture, 0xD10, 0xD11, "created.txt", b"v1\n")?;
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::Applied
        );

        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoints = store.list_checkpoints(fixture.scope.workspace_id(), 16)?;
        assert_eq!(checkpoints.len(), 1);
        let ready = &checkpoints[0];
        assert_eq!(ready.state(), forge_domain::CheckpointState::Ready);
        assert_eq!(ready.change_set_id(), ChangeSetId::from_uuid(id(0xD10)));
        let post_blob = match ready.post() {
            Some(forge_domain::CheckpointPathState::Regular { blob, .. }) => *blob,
            other => return Err(format!("unexpected POST state {other:?}").into()),
        };

        let adapter = GitCheckpointStore::new(layout.workspace_root(), layout.checkpoints())?;
        assert_eq!(adapter.read_blob(post_blob)?, b"v1\n");
        // The user repository namespace stays untouched.
        assert!(
            !fixture
                .root
                .join("location/.git/refs/heterarchy-forge")
                .exists()
        );
        drop(store);

        // A second mutation adds a second checkpoint whose PRE captured v1.
        let update = FileMutationRequest {
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Replace,
                forge_domain::FilePrecondition::Matches(
                    forge_workspace::bounded_write_content_hash(b"v1\n")?,
                ),
            ),
            content: Some(b"v2\n".to_vec()),
            change_set_id: ChangeSetId::from_uuid(id(0xD12)),
            mutation_id: FileMutationId::from_uuid(id(0xD13)),
            ..request
        };
        assert_eq!(
            fixture.control.file_mutate(&update)?.status(),
            FileMutationStatus::Applied
        );
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoints = store.list_checkpoints(fixture.scope.workspace_id(), 16)?;
        assert_eq!(checkpoints.len(), 2);
        let pre_blob = match checkpoints
            .iter()
            .find(|checkpoint| checkpoint.change_set_id() == ChangeSetId::from_uuid(id(0xD12)))
            .ok_or("second checkpoint missing")?
            .pre()
        {
            forge_domain::CheckpointPathState::Regular { blob, .. } => *blob,
            forge_domain::CheckpointPathState::Absent => {
                return Err("unexpected absent PRE state".into());
            }
        };
        let adapter = GitCheckpointStore::new(layout.workspace_root(), layout.checkpoints())?;
        assert_eq!(adapter.read_blob(pre_blob)?, b"v1\n");

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn git_backed_checkpoint_restore_round_trips_owned_store_and_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("restore")?;
        let create = create_mutation_request(&fixture, 0xD40, 0xD41, "restore.txt", b"v1\n")?;
        assert_eq!(
            fixture.control.file_mutate(&create)?.status(),
            FileMutationStatus::Applied
        );
        let replace = FileMutationRequest {
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("restore.txt"))?,
                FileMutationKind::Replace,
                forge_domain::FilePrecondition::Matches(
                    forge_workspace::bounded_write_content_hash(b"v1\n")?,
                ),
            ),
            content: Some(b"v2\n".to_vec()),
            change_set_id: ChangeSetId::from_uuid(id(0xD42)),
            mutation_id: FileMutationId::from_uuid(id(0xD43)),
            ..create
        };
        assert_eq!(
            fixture.control.file_mutate(&replace)?.status(),
            FileMutationStatus::Applied
        );
        assert_eq!(
            fs::read(workspace_root(&fixture).join("restore.txt"))?,
            b"v2\n"
        );

        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoint = checkpoint_for_change_set(&store, fixture.scope.workspace_id(), 0xD42)?;
        assert_eq!(checkpoint.state(), forge_domain::CheckpointState::Ready);
        assert!(
            store
                .list_checkpoint_restores(fixture.scope.workspace_id(), 16)?
                .is_empty()
        );
        drop(store);

        let wrong_owner = direct_restore_request(
            &fixture,
            checkpoint.id(),
            RuntimeInstanceId::from_uuid(id(0xD4FF)),
            20,
        )?;
        assert_eq!(
            fixture
                .control
                .checkpoint_restore(&wrong_owner)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::ActivityLeaseConflict)
        );
        let store = WorkspaceStore::open_existing(&layout)?;
        assert!(
            store
                .list_checkpoint_restores(fixture.scope.workspace_id(), 16)?
                .is_empty(),
            "failed admission must not create a restore journal"
        );
        drop(store);

        let request = direct_restore_request(
            &fixture,
            checkpoint.id(),
            fixture.activity.runtime_instance_id,
            21,
        )?;
        let outcome = fixture.control.checkpoint_restore(&request)?;
        assert_eq!(
            outcome.state,
            forge_domain::CheckpointRestoreState::Restored
        );
        assert!(outcome.failure_code.is_none());
        assert_eq!(
            fs::read(workspace_root(&fixture).join("restore.txt"))?,
            b"v1\n"
        );

        let store = WorkspaceStore::open_existing(&layout)?;
        let restore = store
            .get_checkpoint_restore(outcome.restore_id)?
            .ok_or("restore journal missing")?;
        assert_direct_restore_provenance(&fixture, &restore, checkpoint.id());
        assert_eq!(
            restore.state(),
            forge_domain::CheckpointRestoreState::Restored
        );
        assert!(
            !fixture
                .root
                .join("location/.git/refs/heterarchy-forge")
                .exists(),
            "restore must not mutate the user repository namespace"
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn checkpoint_restore_finishes_with_stable_healthy_workspace_doctor()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("restore-doctor")?;
        let create = create_mutation_request(&fixture, 0xD80, 0xD81, "doctor.txt", b"v1\n")?;
        assert_eq!(
            fixture.control.file_mutate(&create)?.status(),
            FileMutationStatus::Applied
        );
        let replace = FileMutationRequest {
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("doctor.txt"))?,
                FileMutationKind::Replace,
                forge_domain::FilePrecondition::Matches(
                    forge_workspace::bounded_write_content_hash(b"v1\n")?,
                ),
            ),
            content: Some(b"v2\n".to_vec()),
            change_set_id: ChangeSetId::from_uuid(id(0xD82)),
            mutation_id: FileMutationId::from_uuid(id(0xD83)),
            ..create
        };
        assert_eq!(
            fixture.control.file_mutate(&replace)?.status(),
            FileMutationStatus::Applied
        );
        assert_eq!(
            fs::read(workspace_root(&fixture).join("doctor.txt"))?,
            b"v2\n"
        );

        let target = workspace_root(&fixture).join("doctor.txt");
        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("Workspace layout missing before restore Doctor")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoint = checkpoint_for_change_set(&store, fixture.scope.workspace_id(), 0xD82)?;
        assert_eq!(checkpoint.state(), forge_domain::CheckpointState::Ready);
        drop(store);
        let restore = direct_restore_request(
            &fixture,
            checkpoint.id(),
            fixture.activity.runtime_instance_id,
            21,
        )?;
        let scope = fixture.scope.clone();
        let root = fixture.root.clone();
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
        let outcome = client.checkpoint_restore(restore)?;
        assert_eq!(
            outcome.state,
            forge_domain::CheckpointRestoreState::Restored
        );
        assert!(outcome.failure_code.is_none());
        assert_eq!(fs::read(&target)?, b"v1\n");

        let doctor = client.workspace_doctor(WorkspaceDoctorRequest {
            scope: scope.clone(),
        })?;
        assert_eq!(
            doctor.observation_consistency(),
            WorkspaceDoctorObservationConsistency::Stable
        );
        assert_eq!(doctor.outcome(), WorkspaceDoctorAggregateOutcome::Healthy);
        assert!(doctor.checkpoint_store().is_complete());
        assert!(
            doctor.checkpoint_store().findings().iter().all(|finding| {
                finding.status() == WorkspaceCheckpointStoreStatus::OwnedAvailable
            })
        );
        worker.shutdown()?;

        let store = WorkspaceStore::open_existing(&layout)?;
        let journal = store
            .get_checkpoint_restore(outcome.restore_id)?
            .ok_or("restore journal missing after stable Doctor")?;
        assert_eq!(
            journal.state(),
            forge_domain::CheckpointRestoreState::Restored
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn created_file_restore_removes_checkpoint_post_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture_with_git("restore-create")?;
        let create =
            create_mutation_request(&fixture, 0xD60, 0xD61, "created-restore.txt", b"new\n")?;
        assert_eq!(
            fixture.control.file_mutate(&create)?.status(),
            FileMutationStatus::Applied
        );
        let target = workspace_root(&fixture).join("created-restore.txt");
        assert_eq!(fs::read(&target)?, b"new\n");

        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoint = store
            .list_checkpoints(fixture.scope.workspace_id(), 16)?
            .into_iter()
            .find(|checkpoint| checkpoint.change_set_id() == ChangeSetId::from_uuid(id(0xD60)))
            .ok_or("create checkpoint missing")?;
        assert!(matches!(
            checkpoint.pre(),
            forge_domain::CheckpointPathState::Absent
        ));
        drop(store);

        let outcome =
            fixture
                .control
                .checkpoint_restore(&crate::checkpoint::CheckpointRestoreRequest {
                    scope: fixture.scope.clone(),
                    checkpoint_id: checkpoint.id(),
                    initiator: fixture.activity.runtime_instance_id,
                    activity_id: fixture.activity.activity_id,
                    observed_at: timestamp(23)?,
                    approval_request_id: None,
                })?;
        assert_eq!(
            outcome.state,
            forge_domain::CheckpointRestoreState::Restored
        );
        assert!(!target.exists());

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn deleted_file_restore_recreates_checkpoint_content_and_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("restore-delete")?;
        let create = create_mutation_request(&fixture, 0xD50, 0xD51, "deleted.txt", b"keep\n")?;
        assert_eq!(
            fixture.control.file_mutate(&create)?.status(),
            FileMutationStatus::Applied
        );
        let target = workspace_root(&fixture).join("deleted.txt");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640))?;

        let delete = FileMutationRequest {
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("deleted.txt"))?,
                FileMutationKind::Delete,
                forge_domain::FilePrecondition::Matches(
                    forge_workspace::bounded_write_content_hash(b"keep\n")?,
                ),
            ),
            content: None,
            change_set_id: ChangeSetId::from_uuid(id(0xD52)),
            mutation_id: FileMutationId::from_uuid(id(0xD53)),
            ..create
        };
        assert_eq!(
            fixture.control.file_mutate(&delete)?.status(),
            FileMutationStatus::Applied
        );
        assert!(!target.exists());

        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoint = store
            .list_checkpoints(fixture.scope.workspace_id(), 16)?
            .into_iter()
            .find(|checkpoint| checkpoint.change_set_id() == ChangeSetId::from_uuid(id(0xD52)))
            .ok_or("delete checkpoint missing")?;
        let expected_mode = match checkpoint.pre() {
            forge_domain::CheckpointPathState::Regular { mode, .. } => *mode,
            forge_domain::CheckpointPathState::Absent => {
                return Err("delete checkpoint PRE unexpectedly absent".into());
            }
        };
        assert_eq!(expected_mode.get(), 0o640);
        drop(store);

        let outcome =
            fixture
                .control
                .checkpoint_restore(&crate::checkpoint::CheckpointRestoreRequest {
                    scope: fixture.scope.clone(),
                    checkpoint_id: checkpoint.id(),
                    initiator: fixture.activity.runtime_instance_id,
                    activity_id: fixture.activity.activity_id,
                    observed_at: timestamp(22)?,
                    approval_request_id: None,
                })?;
        assert_eq!(
            outcome.state,
            forge_domain::CheckpointRestoreState::Restored
        );
        assert_eq!(fs::read(&target)?, b"keep\n");
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o640);

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn non_git_workspace_mutations_skip_checkpoints() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("no-git")?;
        let request = create_mutation_request(&fixture, 0xD20, 0xD21, "created.txt", b"x\n")?;
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::Applied
        );
        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert!(
            store
                .list_checkpoints(fixture.scope.workspace_id(), 16)?
                .is_empty()
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn repeated_identical_mutation_does_not_duplicate_checkpoints()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("retry")?;
        let request = create_mutation_request(&fixture, 0xD30, 0xD31, "created.txt", b"same\n")?;
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::Applied
        );
        let replayed = fixture.control.file_mutate(&request)?;
        assert_eq!(replayed.status(), FileMutationStatus::AlreadyApplied);
        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert_eq!(
            store
                .list_checkpoints(fixture.scope.workspace_id(), 16)?
                .len(),
            1
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
