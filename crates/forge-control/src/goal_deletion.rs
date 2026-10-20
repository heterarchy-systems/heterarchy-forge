//! Bounded control orchestration for permanent Goal/DAG deletion.
//!
//! The durable Goal/DAG transition belongs to `forge-persistence`.  This
//! module only composes that transition with the already-owned, confined
//! artifact adapters.  It keeps the Workspace gate and writer guard alive for
//! the complete bounded step and never accepts a caller-selected artifact
//! path.

use std::os::unix::ffi::OsStrExt;
use std::{
    borrow::Borrow,
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

use forge_domain::{
    ActivityCoordinatorActor, CheckpointId, DeleteOrphanDiffArtifact, DiffArtifactInventoryName,
    DiffByteCount, DiffId, DiffPayloadHash, ExecutionId, GitCommitId, GoalDeletionRequest,
    GoalDeletionTarget, GoalId, GoalRevision, TimestampMillis, VerificationInputFingerprint,
    VerificationInputId, WorkspaceRootFingerprint,
};
use forge_execution::RustCiGeneratedPackageOutput;
use forge_persistence::{
    GoalDeletionAdmission, GoalDeletionArtifact, GoalDeletionArtifactKind,
    GoalDeletionArtifactProof, GoalDeletionArtifactStatus, GoalDeletionCleanupOutcome,
    GoalDeletionCleanupStatus, GoalDeletionStoreError, WorkspaceStore, WorkspaceStoreError,
};
use forge_workspace::{
    CheckpointSide, ConfinedWorkspace, ConfinedWorkspaceWriteGuard, DiffArtifactDeleteStatus,
    ExistingWorkspaceStateLayout, GitCheckpointStore, WorkspaceStateExclusiveGate,
    WorkspaceStateGateError,
};
use uuid::Uuid;

use crate::error::{ControlError, ControlErrorCode};
use crate::filesystem::map_filesystem_error;
use crate::service::{
    ForgeControl, ResolvedWorkspaceScope, map_activity_store_error, map_state_layout_error,
};

pub(crate) fn map_goal_deletion_store_error(error: GoalDeletionStoreError) -> ControlError {
    match error {
        GoalDeletionStoreError::Agent(source) => {
            crate::agent::map_agent_store_error(WorkspaceStoreError::Agent(source))
        }
        GoalDeletionStoreError::Goal(source) => {
            crate::goal::map_goal_store_error(WorkspaceStoreError::Goal(source))
        }
        other => {
            let code = match &other {
                // These variants are handled by the outer match so their
                // nested mappers retain their own semantic error categories.
                GoalDeletionStoreError::DamagedSchema(_) => {
                    ControlErrorCode::WorkspaceStateUnavailable
                }
                GoalDeletionStoreError::Agent(_)
                | GoalDeletionStoreError::Goal(_)
                | GoalDeletionStoreError::Sqlite(_)
                | GoalDeletionStoreError::OperationsMigration(_)
                | GoalDeletionStoreError::AgentEvidenceCountCorrupt { .. }
                | GoalDeletionStoreError::CleanupJournalMissing { .. }
                | GoalDeletionStoreError::CleanupProofMissing { .. }
                | GoalDeletionStoreError::CleanupProofUnknown { .. }
                | GoalDeletionStoreError::CleanupProofDuplicate { .. }
                | GoalDeletionStoreError::InvalidArtifactPath
                | GoalDeletionStoreError::InvalidArtifactHash
                | GoalDeletionStoreError::InvalidArtifactSize => {
                    ControlErrorCode::PersistenceFailure
                }
                GoalDeletionStoreError::GoalMissing { .. } => ControlErrorCode::GoalNotFound,
                GoalDeletionStoreError::WorkspaceMismatch { .. }
                | GoalDeletionStoreError::ActivityMismatch { .. } => {
                    ControlErrorCode::WorkspaceIdentityConflict
                }
                GoalDeletionStoreError::GoalRevisionOverflow
                | GoalDeletionStoreError::ActiveVerificationRun { .. }
                | GoalDeletionStoreError::CreatedAtConflict { .. }
                | GoalDeletionStoreError::GoalRevisionConflict { .. }
                | GoalDeletionStoreError::DagHeadConflict { .. }
                | GoalDeletionStoreError::DagHeadFenceRequired
                | GoalDeletionStoreError::CleanupJournalPending { .. }
                | GoalDeletionStoreError::CleanupRequestConflict { .. }
                | GoalDeletionStoreError::UnresolvableOwnership { .. }
                | GoalDeletionStoreError::OwnershipConflict { .. }
                | GoalDeletionStoreError::ArtifactIdentityPending { .. } => {
                    ControlErrorCode::GoalConflict
                }
                GoalDeletionStoreError::SharedExecutionAuthorityConflict { .. }
                | GoalDeletionStoreError::ActiveExecution { .. } => {
                    ControlErrorCode::ExecutionConflict
                }
                GoalDeletionStoreError::ActiveAgentAssignment { .. }
                | GoalDeletionStoreError::InvalidAgentAssignment { .. }
                | GoalDeletionStoreError::AgentRevisionConflict { .. }
                | GoalDeletionStoreError::AgentRevisionOverflow => ControlErrorCode::AgentConflict,
                GoalDeletionStoreError::DagHeadMissing { .. } => ControlErrorCode::DagNotFound,
                GoalDeletionStoreError::ArtifactOverflow { .. }
                | GoalDeletionStoreError::CleanupProofBatchTooLarge { .. }
                | GoalDeletionStoreError::PendingCleanupLimitInvalid { .. } => {
                    ControlErrorCode::CapacityExceeded
                }
                GoalDeletionStoreError::PendingApproval { .. }
                | GoalDeletionStoreError::ActiveGrant { .. } => ControlErrorCode::ApprovalConflict,
                GoalDeletionStoreError::ActiveWriterLease { .. } => {
                    ControlErrorCode::WriterLeaseConflict
                }
                GoalDeletionStoreError::ActiveCheckpointRestore { .. } => {
                    ControlErrorCode::CheckpointStateConflict
                }
            };
            ControlError::with_source(code, other)
        }
    }
}

/// At most eight artifact groups are effected by one joined Control step.
/// Verification inputs, checkpoints, and both Diff representations are one
/// group per typed identity even when they contain multiple journal rows.
pub const MAX_GOAL_DELETE_GROUPS_PER_CALL: usize = 8;
const MAX_GOAL_DELETE_PROOFS_PER_CALL: usize = 24;

/// A native operator or the exact Coordinator actor that owns the Activity.
///
/// HTTP adapters must expose only the Coordinator proof path.  The DTO
/// deliberately excludes this authority enum; the native Desktop adapter is
/// the only transport allowed to construct the `LocalOperator` variant.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoalDeletionAuthority {
    LocalOperator,
    Coordinator(ActivityCoordinatorActor),
}

impl GoalDeletionAuthority {
    pub const fn coordinator(actor: ActivityCoordinatorActor) -> Self {
        Self::Coordinator(actor)
    }
}

/// One explicitly scoped permanent Goal/DAG deletion request.
///
/// The trusted generated-package cache root is supplied to [`ForgeControl::goal_delete`]
/// by the native Rust host.  It is deliberately not a field on this request,
/// so external callers cannot transport an arbitrary cache path.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalDeleteRequest {
    pub scope: ResolvedWorkspaceScope,
    pub target: GoalDeletionRequest,
    pub authority: GoalDeletionAuthority,
    pub observed_at: TimestampMillis,
}

impl GoalDeleteRequest {
    pub const fn new(
        scope: ResolvedWorkspaceScope,
        target: GoalDeletionRequest,
        authority: GoalDeletionAuthority,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            scope,
            target,
            authority,
            observed_at,
        }
    }
}

/// Coarse phase of one bounded deletion step.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoalDeletePhase {
    Complete,
    Pending,
    Blocked,
}

/// Redacted, bounded issue category returned after SQL admission when an
/// external cleanup effect cannot complete.  No filesystem path, UUID, Git
/// output, or adapter error text crosses this boundary.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GoalDeleteIssue {
    Filesystem,
    RootBinding,
    ArtifactConflict,
    ProductCacheUnavailable,
}

/// Result of one bounded deletion step.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoalDeleteOutcome {
    target: GoalDeletionTarget,
    goal_id: GoalId,
    cleanup_id: Option<Uuid>,
    phase: GoalDeletePhase,
    remaining_count: u16,
    next_goal_revision: Option<GoalRevision>,
    issue: Option<GoalDeleteIssue>,
}

impl GoalDeleteOutcome {
    pub const fn target(self) -> GoalDeletionTarget {
        self.target
    }

    pub const fn goal_id(self) -> GoalId {
        self.goal_id
    }

    pub const fn cleanup_id(self) -> Option<Uuid> {
        self.cleanup_id
    }

    pub const fn phase(self) -> GoalDeletePhase {
        self.phase
    }

    pub const fn remaining_count(self) -> u16 {
        self.remaining_count
    }

    pub const fn next_goal_revision(self) -> Option<GoalRevision> {
        self.next_goal_revision
    }

    pub const fn issue(self) -> Option<GoalDeleteIssue> {
        self.issue
    }

    const fn sql_only(
        request: GoalDeletionRequest,
        next_goal_revision: Option<GoalRevision>,
    ) -> Self {
        Self {
            target: request.target(),
            goal_id: request.goal_id(),
            cleanup_id: None,
            phase: GoalDeletePhase::Complete,
            remaining_count: 0,
            next_goal_revision,
            issue: None,
        }
    }

    const fn with_progress(
        request: GoalDeletionRequest,
        cleanup_id: Uuid,
        status: GoalDeletePhase,
        remaining_count: u16,
        next_goal_revision: Option<GoalRevision>,
    ) -> Self {
        Self {
            target: request.target(),
            goal_id: request.goal_id(),
            cleanup_id: Some(cleanup_id),
            phase: status,
            remaining_count,
            next_goal_revision,
            issue: None,
        }
    }

    const fn blocked(
        request: GoalDeletionRequest,
        cleanup_id: Uuid,
        remaining_count: u16,
        next_goal_revision: Option<GoalRevision>,
        issue: GoalDeleteIssue,
    ) -> Self {
        Self {
            target: request.target(),
            goal_id: request.goal_id(),
            cleanup_id: Some(cleanup_id),
            phase: GoalDeletePhase::Blocked,
            remaining_count,
            next_goal_revision,
            issue: Some(issue),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ArtifactGroupKey {
    Diff([u8; 16]),
    VerificationInput([u8; 16]),
    Checkpoint([u8; 16]),
    GeneratedPackage([u8; 16]),
}

#[derive(Debug)]
struct ArtifactGroup<'a> {
    key: ArtifactGroupKey,
    artifacts: Vec<&'a GoalDeletionArtifact>,
}

impl<'a> ArtifactGroup<'a> {
    fn new(key: ArtifactGroupKey, artifact: &'a GoalDeletionArtifact) -> Self {
        Self {
            key,
            artifacts: vec![artifact],
        }
    }

    fn pending_count(&self) -> usize {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.requires_filesystem())
            .count()
    }
}

#[derive(Debug)]
struct CleanupEffectFailure {
    proofs: Vec<GoalDeletionArtifactProof>,
    issue: GoalDeleteIssue,
}

struct CleanupContext<'a> {
    filesystem: &'a ConfinedWorkspace,
    gate: &'a WorkspaceStateExclusiveGate,
    guard: &'a ConfinedWorkspaceWriteGuard,
    layout: &'a ExistingWorkspaceStateLayout,
    root_fingerprint: WorkspaceRootFingerprint,
    trusted_product_cache_root: Option<&'a Path>,
    workspace_id: forge_domain::WorkspaceId,
}

enum CleanupPlan<'a> {
    SqlOnly(GoalDeleteOutcome),
    Pending(PendingCleanupPlan<'a>),
}

struct PendingCleanupPlan<'a> {
    cleanup_id: Uuid,
    artifacts: &'a [GoalDeletionArtifact],
    next_goal_revision: Option<GoalRevision>,
}

impl CleanupEffectFailure {
    const fn new(issue: GoalDeleteIssue) -> Self {
        Self {
            proofs: Vec::new(),
            issue,
        }
    }

    fn with_proofs(issue: GoalDeleteIssue, proofs: Vec<GoalDeletionArtifactProof>) -> Self {
        Self { proofs, issue }
    }
}

impl ForgeControl {
    /// Read bounded pending Goal deletion headers without opening a writable
    /// Workspace store, migrating an old schema, or creating sidecars.
    pub fn goal_delete_pending(
        &self,
        scope: &ResolvedWorkspaceScope,
        limit: u32,
    ) -> Result<forge_persistence::GoalDeletionPendingInventory, ControlError> {
        let (fresh_scope, layout, _) = self.inspect_resolved_workspace(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        let inventory =
            WorkspaceStore::inspect_pending_goal_deletions_live_read_only(&layout, limit)
                .map_err(map_activity_store_error)?;
        let (post_scope, _, _) = self.inspect_resolved_workspace(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if post_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        Ok(inventory)
    }

    /// Stage one permanent Goal/DAG deletion and advance at most eight
    /// artifact groups through their confined external cleanup boundary.
    ///
    /// The caller provides a known product-cache root from a trusted Rust
    /// host, or None to preserve product artifacts pending cleanup. It is
    /// never obtained from the request payload or a transport
    /// path.  Each call retains the exclusive root gate and mutation guard
    /// until both its filesystem step and durable progress record finish.
    pub fn goal_delete<R>(
        &self,
        request: R,
        trusted_product_cache_root: Option<&Path>,
    ) -> Result<GoalDeleteOutcome, ControlError>
    where
        R: Borrow<GoalDeleteRequest>,
    {
        let request = request.borrow();
        verify_coordinator_session(self, request.authority)?;
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            request.scope.locator().location_id(),
            request.scope.locator().expected_revision(),
            request.scope.locator(),
        )?;
        drop(store);
        validate_requested_scope(request, &fresh_scope)?;

        let root_fingerprint = layout.root_fingerprint().map_err(map_state_layout_error)?;
        let gate = WorkspaceStateExclusiveGate::acquire(layout.workspace_root(), root_fingerprint)
            .map_err(map_gate_error)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let guard = filesystem
            .acquire_write_guard()
            .map_err(map_filesystem_error)?;
        gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
            .map_err(map_gate_error)?;

        let mut deletion_store =
            WorkspaceStore::open_goal_deletion(&layout, &gate).map_err(map_activity_store_error)?;
        validate_deletion_workspace(&deletion_store, &fresh_scope, &layout, root_fingerprint)?;
        let admission = stage_goal_deletion(&mut deletion_store, request)?;
        let plan = cleanup_plan(&admission, request.target, root_fingerprint)?;
        let context = CleanupContext {
            filesystem: &filesystem,
            gate: &gate,
            guard: &guard,
            layout: &layout,
            root_fingerprint,
            trusted_product_cache_root,
            workspace_id: fresh_scope.workspace_id(),
        };
        match plan {
            CleanupPlan::SqlOnly(outcome) => Ok(outcome),
            CleanupPlan::Pending(plan) => {
                process_pending_cleanup(request.target, &plan, &mut deletion_store, &context)
            }
        }
    }
}

fn verify_coordinator_session(
    control: &ForgeControl,
    authority: GoalDeletionAuthority,
) -> Result<(), ControlError> {
    if let GoalDeletionAuthority::Coordinator(actor) = authority {
        let _session = control.agent_session_resolve(crate::AgentSessionResolveRequest {
            session_id: actor.session_id(),
            principal: actor.principal(),
        })?;
    }
    Ok(())
}

fn validate_requested_scope(
    request: &GoalDeleteRequest,
    fresh_scope: &ResolvedWorkspaceScope,
) -> Result<(), ControlError> {
    if fresh_scope != &request.scope {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceRevisionConflict,
        ));
    }
    if fresh_scope.workspace_id() != request.target.workspace_id() {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ));
    }
    Ok(())
}

fn validate_deletion_workspace(
    deletion_store: &forge_persistence::GoalDeletionStore<'_>,
    fresh_scope: &ResolvedWorkspaceScope,
    layout: &ExistingWorkspaceStateLayout,
    root_fingerprint: WorkspaceRootFingerprint,
) -> Result<(), ControlError> {
    let workspace = deletion_store
        .workspace()
        .map_err(map_activity_store_error)?;
    if workspace.id() != fresh_scope.workspace_id()
        || workspace.location_id() != fresh_scope.locator().location_id()
    {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ));
    }
    if workspace.revision() != fresh_scope.workspace_revision() {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceRevisionConflict,
        ));
    }
    if workspace.root().as_path() != layout.workspace_root()
        || workspace.root_fingerprint() != root_fingerprint
    {
        return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
    }
    Ok(())
}

fn stage_goal_deletion(
    deletion_store: &mut forge_persistence::GoalDeletionStore<'_>,
    request: &GoalDeleteRequest,
) -> Result<GoalDeletionAdmission, ControlError> {
    let admission = match request.authority {
        GoalDeletionAuthority::LocalOperator => {
            deletion_store.stage_local(request.target, request.observed_at)
        }
        GoalDeletionAuthority::Coordinator(actor) => {
            deletion_store.stage_authorized(request.target, actor, request.observed_at)
        }
    };
    match admission {
        Ok(admission) => Ok(admission),
        Err(WorkspaceStoreError::GoalDeletionCommittedUnconfirmed { .. }) => {
            drop(deletion_store.pending_for_request(request.target));
            Err(ControlError::committed())
        }
        Err(error) => Err(map_activity_store_error(error)),
    }
}

fn cleanup_plan(
    admission: &GoalDeletionAdmission,
    request: GoalDeletionRequest,
    root_fingerprint: WorkspaceRootFingerprint,
) -> Result<CleanupPlan<'_>, ControlError> {
    match admission {
        GoalDeletionAdmission::Staged(stage) => match stage.cleanup_id() {
            Some(cleanup_id) => Ok(CleanupPlan::Pending(PendingCleanupPlan {
                cleanup_id,
                artifacts: stage.artifacts(),
                next_goal_revision: stage.next_goal_revision(),
            })),
            None => Ok(CleanupPlan::SqlOnly(GoalDeleteOutcome::sql_only(
                request,
                stage.next_goal_revision(),
            ))),
        },
        GoalDeletionAdmission::Resumed(readback) => {
            if readback.root_fingerprint() != root_fingerprint || readback.request() != request {
                return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
            }
            Ok(CleanupPlan::Pending(PendingCleanupPlan {
                cleanup_id: readback.cleanup_id(),
                artifacts: readback.artifacts(),
                next_goal_revision: next_goal_revision_after_resume(request),
            }))
        }
    }
}

fn map_gate_error(error: WorkspaceStateGateError) -> ControlError {
    ControlError::with_source(ControlErrorCode::WorkspaceRootConflict, error)
}

fn next_goal_revision_after_resume(request: GoalDeletionRequest) -> Option<GoalRevision> {
    if request.target().deletes_goal() {
        None
    } else {
        request.expected_goal_revision().checked_next().ok()
    }
}

fn group_artifacts<'a>(artifacts: &'a [GoalDeletionArtifact]) -> Vec<ArtifactGroup<'a>> {
    let mut groups = BTreeMap::<ArtifactGroupKey, ArtifactGroup<'a>>::new();
    for artifact in artifacts {
        let key = match artifact.kind() {
            GoalDeletionArtifactKind::DiffPending | GoalDeletionArtifactKind::DiffCompressed => {
                ArtifactGroupKey::Diff(*artifact.id())
            }
            GoalDeletionArtifactKind::VerificationInputSource
            | GoalDeletionArtifactKind::VerificationInputManifest
            | GoalDeletionArtifactKind::VerificationInputPending => {
                ArtifactGroupKey::VerificationInput(*artifact.id())
            }
            GoalDeletionArtifactKind::CheckpointPre | GoalDeletionArtifactKind::CheckpointPost => {
                ArtifactGroupKey::Checkpoint(*artifact.id())
            }
            GoalDeletionArtifactKind::GeneratedPackage => {
                ArtifactGroupKey::GeneratedPackage(*artifact.id())
            }
        };
        groups
            .entry(key)
            .and_modify(|group| group.artifacts.push(artifact))
            .or_insert_with(|| ArtifactGroup::new(key, artifact));
    }
    groups.into_values().collect()
}

fn pending_artifact_count(groups: &[ArtifactGroup<'_>]) -> usize {
    groups.iter().map(ArtifactGroup::pending_count).sum()
}

fn bounded_count(value: usize) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX)
}

fn cleanup_remaining(status: GoalDeletionCleanupStatus, before: usize, recorded: usize) -> u16 {
    match status {
        GoalDeletionCleanupStatus::Pending { remaining } => remaining,
        GoalDeletionCleanupStatus::Complete => 0,
        GoalDeletionCleanupStatus::SqlOnlyComplete => {
            bounded_count(before.saturating_sub(recorded))
        }
    }
}

fn record_progress(
    store: &mut forge_persistence::GoalDeletionStore<'_>,
    cleanup_id: Uuid,
    proofs: &[GoalDeletionArtifactProof],
) -> Result<GoalDeletionCleanupStatus, WorkspaceStoreError> {
    let outcome: GoalDeletionCleanupOutcome = store.record_cleanup_progress(cleanup_id, proofs)?;
    Ok(outcome.status())
}

fn record_progress_checked(
    store: &mut forge_persistence::GoalDeletionStore<'_>,
    request: GoalDeletionRequest,
    cleanup_id: Uuid,
    proofs: &[GoalDeletionArtifactProof],
) -> Result<GoalDeletionCleanupStatus, ControlError> {
    match record_progress(store, cleanup_id, proofs) {
        Ok(status) => Ok(status),
        Err(WorkspaceStoreError::GoalDeletionCommittedUnconfirmed { .. }) => {
            drop(store.pending_for_request(request));
            Err(ControlError::committed())
        }
        Err(error) => Err(map_activity_store_error(error)),
    }
}

fn process_pending_cleanup(
    request: GoalDeletionRequest,
    plan: &PendingCleanupPlan<'_>,
    deletion_store: &mut forge_persistence::GoalDeletionStore<'_>,
    context: &CleanupContext<'_>,
) -> Result<GoalDeleteOutcome, ControlError> {
    let groups = group_artifacts(plan.artifacts);
    let pending_before = pending_artifact_count(&groups);
    if pending_before == 0 {
        return Ok(GoalDeleteOutcome::blocked(
            request,
            plan.cleanup_id,
            0,
            plan.next_goal_revision,
            GoalDeleteIssue::ArtifactConflict,
        ));
    }
    let proofs = match collect_group_proofs(&groups, context) {
        Ok(proofs) => proofs,
        Err(mut failure) => {
            let proofs = std::mem::take(&mut failure.proofs);
            let status =
                record_progress_checked(deletion_store, request, plan.cleanup_id, &proofs)?;
            let remaining = cleanup_remaining(status, pending_before, proofs.len());
            return Ok(GoalDeleteOutcome::blocked(
                request,
                plan.cleanup_id,
                remaining,
                plan.next_goal_revision,
                failure.issue,
            ));
        }
    };
    if proofs.is_empty() {
        return Ok(GoalDeleteOutcome::blocked(
            request,
            plan.cleanup_id,
            bounded_count(pending_before),
            plan.next_goal_revision,
            GoalDeleteIssue::ArtifactConflict,
        ));
    }
    ensure_root_fence_control(context)?;
    let status = record_progress_checked(deletion_store, request, plan.cleanup_id, &proofs)?;
    ensure_root_fence_control(context)?;
    match status {
        GoalDeletionCleanupStatus::Complete => Ok(GoalDeleteOutcome::with_progress(
            request,
            plan.cleanup_id,
            GoalDeletePhase::Complete,
            0,
            plan.next_goal_revision,
        )),
        GoalDeletionCleanupStatus::Pending { remaining } => Ok(GoalDeleteOutcome::with_progress(
            request,
            plan.cleanup_id,
            GoalDeletePhase::Pending,
            remaining,
            plan.next_goal_revision,
        )),
        GoalDeletionCleanupStatus::SqlOnlyComplete => {
            Err(ControlError::new(ControlErrorCode::Internal))
        }
    }
}

fn collect_group_proofs(
    groups: &[ArtifactGroup<'_>],
    context: &CleanupContext<'_>,
) -> Result<Vec<GoalDeletionArtifactProof>, CleanupEffectFailure> {
    let mut proofs = Vec::new();
    let mut selected_groups = 0_usize;
    for group in groups {
        let group_proofs = group.pending_count();
        if group_proofs == 0 {
            continue;
        }
        if selected_groups >= MAX_GOAL_DELETE_GROUPS_PER_CALL
            || proofs.len().saturating_add(group_proofs) > MAX_GOAL_DELETE_PROOFS_PER_CALL
        {
            break;
        }
        selected_groups = selected_groups.saturating_add(1);
        match process_group(group, context) {
            Ok(mut group_proofs) => proofs.append(&mut group_proofs),
            Err(mut failure) => {
                proofs.append(&mut failure.proofs);
                failure.proofs = proofs;
                return Err(failure);
            }
        }
    }
    Ok(proofs)
}

fn ensure_root_fence_control(context: &CleanupContext<'_>) -> Result<(), ControlError> {
    context
        .gate
        .ensure_root_binding(context.layout.workspace_root(), context.root_fingerprint)
        .map_err(map_gate_error)
}

fn process_group(
    group: &ArtifactGroup<'_>,
    context: &CleanupContext<'_>,
) -> Result<Vec<GoalDeletionArtifactProof>, CleanupEffectFailure> {
    ensure_root_fence(context.gate, context.layout, context.root_fingerprint)?;
    let result = match group.key {
        ArtifactGroupKey::Diff(id) => process_diff_group(group, context.filesystem, id),
        ArtifactGroupKey::VerificationInput(id) => {
            process_verification_group(group, context.filesystem, context.gate, context.guard, id)
        }
        ArtifactGroupKey::Checkpoint(id) => process_checkpoint_group(group, context.layout, id),
        ArtifactGroupKey::GeneratedPackage(id) => process_generated_group(
            group,
            context.trusted_product_cache_root,
            context.workspace_id,
            context.root_fingerprint,
            id,
        ),
    };
    let proofs = result?;
    if let Err(failure) = ensure_root_fence(context.gate, context.layout, context.root_fingerprint)
    {
        return Err(CleanupEffectFailure::with_proofs(failure.issue, proofs));
    }
    Ok(proofs)
}

fn ensure_root_fence(
    gate: &WorkspaceStateExclusiveGate,
    layout: &ExistingWorkspaceStateLayout,
    root_fingerprint: WorkspaceRootFingerprint,
) -> Result<(), CleanupEffectFailure> {
    gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
        .map_err(|_| CleanupEffectFailure::new(GoalDeleteIssue::RootBinding))
}

fn process_diff_group(
    group: &ArtifactGroup<'_>,
    filesystem: &ConfinedWorkspace,
    id_bytes: [u8; 16],
) -> Result<Vec<GoalDeletionArtifactProof>, CleanupEffectFailure> {
    let id = DiffId::from_uuid(Uuid::from_bytes(id_bytes));
    let store = filesystem
        .diff_artifact_store()
        .map_err(|_| CleanupEffectFailure::new(GoalDeleteIssue::Filesystem))?;
    let mut proofs = Vec::with_capacity(group.pending_count());
    for artifact in &group.artifacts {
        if !artifact.requires_filesystem() {
            continue;
        }
        let name = canonical_diff_name(artifact.kind(), id);
        let expected_path = Path::new("diffs").join(&name);
        if !path_matches(artifact, &expected_path) {
            return Err(CleanupEffectFailure::with_proofs(
                GoalDeleteIssue::ArtifactConflict,
                proofs,
            ));
        }
        let hash = match expected_hash_32(artifact) {
            Ok(hash) => DiffPayloadHash::from_bytes(hash),
            Err(issue) => return Err(CleanupEffectFailure::with_proofs(issue, proofs)),
        };
        let Some(size) = artifact.expected_size() else {
            return Err(CleanupEffectFailure::with_proofs(
                GoalDeleteIssue::ArtifactConflict,
                proofs,
            ));
        };
        let Ok(name) = DiffArtifactInventoryName::new(name.into_bytes()) else {
            return Err(CleanupEffectFailure::with_proofs(
                GoalDeleteIssue::ArtifactConflict,
                proofs,
            ));
        };
        let command = DeleteOrphanDiffArtifact::new(name, hash, DiffByteCount::new(size));
        let status = match store.delete_orphan(&command) {
            Ok(DiffArtifactDeleteStatus::Deleted) => GoalDeletionArtifactStatus::Deleted,
            Ok(DiffArtifactDeleteStatus::AlreadyMissing) => {
                GoalDeletionArtifactStatus::AlreadyMissing
            }
            Err(_) => {
                return Err(CleanupEffectFailure::with_proofs(
                    GoalDeleteIssue::Filesystem,
                    proofs,
                ));
            }
        };
        proofs.push(GoalDeletionArtifactProof::new(artifact.ordinal(), status));
    }
    Ok(proofs)
}

fn process_verification_group(
    group: &ArtifactGroup<'_>,
    filesystem: &ConfinedWorkspace,
    gate: &WorkspaceStateExclusiveGate,
    guard: &ConfinedWorkspaceWriteGuard,
    id_bytes: [u8; 16],
) -> Result<Vec<GoalDeletionArtifactProof>, CleanupEffectFailure> {
    let id = VerificationInputId::from_uuid(Uuid::from_bytes(id_bytes));
    let mut fingerprint = None;
    let mut total_bytes = None;
    for artifact in &group.artifacts {
        let expected_path = canonical_verification_path(artifact.kind(), id);
        if !path_matches(artifact, &expected_path) {
            return Err(CleanupEffectFailure::new(GoalDeleteIssue::ArtifactConflict));
        }
        let hash = match expected_hash_32(artifact) {
            Ok(hash) => hash,
            Err(issue) => return Err(CleanupEffectFailure::new(issue)),
        };
        if let Some(previous) = fingerprint
            && previous != hash
        {
            return Err(CleanupEffectFailure::new(GoalDeleteIssue::ArtifactConflict));
        }
        fingerprint = Some(hash);
        if let Some(size) = artifact.expected_size() {
            if let Some(previous) = total_bytes
                && previous != size
            {
                return Err(CleanupEffectFailure::new(GoalDeleteIssue::ArtifactConflict));
            }
            total_bytes = Some(size);
        }
    }
    let Some(fingerprint) = fingerprint else {
        return Err(CleanupEffectFailure::new(GoalDeleteIssue::ArtifactConflict));
    };
    let Some(total_bytes) = total_bytes else {
        return Err(CleanupEffectFailure::new(GoalDeleteIssue::ArtifactConflict));
    };
    let cancellation = AtomicBool::new(false);
    if filesystem
        .purge_verification_input(
            gate,
            guard,
            id,
            VerificationInputFingerprint::from_bytes(fingerprint),
            total_bytes,
            &cancellation,
        )
        .is_err()
    {
        return Err(CleanupEffectFailure::new(GoalDeleteIssue::Filesystem));
    }
    Ok(group
        .artifacts
        .iter()
        .filter(|artifact| artifact.requires_filesystem())
        .map(|artifact| {
            GoalDeletionArtifactProof::new(artifact.ordinal(), GoalDeletionArtifactStatus::Deleted)
        })
        .collect())
}

fn process_checkpoint_group(
    group: &ArtifactGroup<'_>,
    layout: &ExistingWorkspaceStateLayout,
    id_bytes: [u8; 16],
) -> Result<Vec<GoalDeletionArtifactProof>, CleanupEffectFailure> {
    let id = CheckpointId::from_uuid(Uuid::from_bytes(id_bytes));
    for artifact in &group.artifacts {
        if artifact.relative_path().is_some() || artifact.expected_size().is_some() {
            return Err(CleanupEffectFailure::new(GoalDeleteIssue::ArtifactConflict));
        }
        if artifact.expected_hash().is_none_or(|hash| hash.len() != 20) {
            return Err(CleanupEffectFailure::new(GoalDeleteIssue::ArtifactConflict));
        }
    }
    let store = match GitCheckpointStore::inspect_existing_read_only(layout) {
        Ok(Some(store)) => Some(store),
        Ok(None) => None,
        Err(_) => return Err(CleanupEffectFailure::new(GoalDeleteIssue::Filesystem)),
    };
    let mut proofs = Vec::with_capacity(group.pending_count());
    for artifact in &group.artifacts {
        if !artifact.requires_filesystem() {
            continue;
        }
        let Some(expected_hash) = artifact.expected_hash() else {
            return Err(CleanupEffectFailure::with_proofs(
                GoalDeleteIssue::ArtifactConflict,
                proofs,
            ));
        };
        let mut bytes = [0_u8; 20];
        bytes.copy_from_slice(expected_hash);
        let expected = GitCommitId::from_sha1_bytes(bytes);
        let side = match artifact.kind() {
            GoalDeletionArtifactKind::CheckpointPre => CheckpointSide::Pre,
            GoalDeletionArtifactKind::CheckpointPost => CheckpointSide::Post,
            _ => {
                return Err(CleanupEffectFailure::with_proofs(
                    GoalDeleteIssue::ArtifactConflict,
                    proofs,
                ));
            }
        };
        let status = match &store {
            None => GoalDeletionArtifactStatus::AlreadyMissing,
            Some(store) => match store.read_ref(id, side) {
                Ok(None) => GoalDeletionArtifactStatus::AlreadyMissing,
                Ok(Some(actual)) if actual == expected => {
                    if store.delete_snapshot(id, side, expected).is_err() {
                        return Err(CleanupEffectFailure::with_proofs(
                            GoalDeleteIssue::Filesystem,
                            proofs,
                        ));
                    }
                    GoalDeletionArtifactStatus::Deleted
                }
                Ok(Some(_)) | Err(_) => {
                    return Err(CleanupEffectFailure::with_proofs(
                        GoalDeleteIssue::ArtifactConflict,
                        proofs,
                    ));
                }
            },
        };
        proofs.push(GoalDeletionArtifactProof::new(artifact.ordinal(), status));
    }
    Ok(proofs)
}

fn process_generated_group(
    group: &ArtifactGroup<'_>,
    trusted_product_cache_root: Option<&Path>,
    workspace_id: forge_domain::WorkspaceId,
    root_fingerprint: WorkspaceRootFingerprint,
    id_bytes: [u8; 16],
) -> Result<Vec<GoalDeletionArtifactProof>, CleanupEffectFailure> {
    let trusted_product_cache_root = trusted_product_cache_root.ok_or_else(|| {
        CleanupEffectFailure::with_proofs(GoalDeleteIssue::ProductCacheUnavailable, Vec::new())
    })?;
    let execution_id = ExecutionId::from_uuid(Uuid::from_bytes(id_bytes));
    let mut proofs = Vec::with_capacity(group.pending_count());
    for artifact in &group.artifacts {
        if !artifact.requires_filesystem() {
            continue;
        }
        if artifact.relative_path().is_some() {
            return Err(CleanupEffectFailure::with_proofs(
                GoalDeleteIssue::ArtifactConflict,
                proofs,
            ));
        }
        let expected_hash = match expected_hash_32(artifact) {
            Ok(hash) => hash,
            Err(issue) => return Err(CleanupEffectFailure::with_proofs(issue, proofs)),
        };
        let Some(expected_size) = artifact.expected_size() else {
            return Err(CleanupEffectFailure::with_proofs(
                GoalDeleteIssue::ArtifactConflict,
                proofs,
            ));
        };
        let output = RustCiGeneratedPackageOutput::open_existing(
            trusted_product_cache_root,
            workspace_id,
            root_fingerprint,
            execution_id,
        )
        .map_err(|_| {
            CleanupEffectFailure::with_proofs(GoalDeleteIssue::Filesystem, proofs.clone())
        })?;
        let status = match output {
            None => GoalDeletionArtifactStatus::AlreadyMissing,
            Some(output) => {
                if output
                    .cleanup_verified(expected_hash, expected_size)
                    .is_err()
                {
                    return Err(CleanupEffectFailure::with_proofs(
                        GoalDeleteIssue::Filesystem,
                        proofs,
                    ));
                }
                GoalDeletionArtifactStatus::Deleted
            }
        };
        proofs.push(GoalDeletionArtifactProof::new(artifact.ordinal(), status));
    }
    Ok(proofs)
}

fn expected_hash_32(artifact: &GoalDeletionArtifact) -> Result<[u8; 32], GoalDeleteIssue> {
    let Some(hash) = artifact.expected_hash() else {
        return Err(GoalDeleteIssue::ArtifactConflict);
    };
    hash.try_into()
        .map_err(|_| GoalDeleteIssue::ArtifactConflict)
}

fn path_matches(artifact: &GoalDeletionArtifact, expected: &Path) -> bool {
    artifact.relative_path() == Some(expected.as_os_str().as_bytes())
}

fn canonical_diff_name(kind: GoalDeletionArtifactKind, id: DiffId) -> String {
    match kind {
        GoalDeletionArtifactKind::DiffPending => format!(".diff-{id}.pending"),
        GoalDeletionArtifactKind::DiffCompressed => format!("diff_{id}.diff.zst"),
        _ => String::new(),
    }
}

fn canonical_verification_path(kind: GoalDeletionArtifactKind, id: VerificationInputId) -> PathBuf {
    let suffix = match kind {
        GoalDeletionArtifactKind::VerificationInputSource => "source",
        GoalDeletionArtifactKind::VerificationInputManifest => "manifest",
        GoalDeletionArtifactKind::VerificationInputPending => {
            return PathBuf::from(format!("artifacts/verification/.pending-{id}"));
        }
        _ => "",
    };
    PathBuf::from(format!("artifacts/verification/{id}/{suffix}"))
}

#[cfg(test)]
mod tests;
