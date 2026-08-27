//! Typed, deterministic domain models for Heterarchy Forge.

mod approval;
mod checkpoint;
mod dag;
mod diff;
mod diff_retention;
mod execution;
mod filesystem;
mod goal;
mod harness;
mod harness_verifier;
mod location;
mod recovery;
mod runtime;
mod workspace;

pub use approval::{
    ApprovalDecision, ApprovalRequestId, ApprovalRequestState, ApprovalRevision,
    AuthorizationSource, AutoApprovalScope, AutoApprovalScopeId, AutoApprovalScopeRevision,
    AutoApprovalScopeState, AutoApprovalUseLimit, EffectiveExecutionPermissions,
    ExecutionActionClass, ExecutionAuthorization, ExecutionAuthorizationDecision,
    ExecutionAuthorizationRequest, ExecutionGrant, ExecutionGrantId, ExecutionGrantRevision,
    ExecutionGrantState, ExecutionPolicyDisposition, ExecutionPolicyRule, PolicyRevision,
    RegisteredApprovalRequest, RequestedExecutionPermissions, WorkspacePolicy,
    evaluate_execution_authorization,
};
pub use checkpoint::{
    CheckpointAttribution, CheckpointFileMode, CheckpointFileModeError, CheckpointId,
    CheckpointIdParseError, CheckpointObservedPathState, CheckpointPathState,
    CheckpointRestoreAttribution, CheckpointRestoreFailureCode, CheckpointRestoreFence,
    CheckpointRestoreId, CheckpointRestoreIdParseError, CheckpointRestoreRevision,
    CheckpointRestoreRevisionError, CheckpointRestoreState, CheckpointRestoreTimestamps,
    CheckpointRestoreTransitionError, CheckpointRevision, CheckpointRevisionError,
    CheckpointSnapshots, CheckpointState, CheckpointTimestamps, CheckpointTransitionError,
    GitBlobId, GitCommitId, GitObjectFormat, GitObjectId, GitObjectIdParseError,
    RegisteredCheckpoint, RegisteredCheckpointRestore, RestoreEffect, RestorePlan,
    RestorePlanError, plan_restore,
};
pub use dag::{
    DagAcceptanceCriterion, DagBoundError, DagEdge, DagHeadRevision, DagHeadRevisionError,
    DagLineageKind, DagNodeDefinition, DagNodeId, DagNodeIdParseError, DagNodeLifecycle,
    DagNodeLineage, DagNodeObjective, DagNodeOrdinal, DagNodeProjection, DagNodeRevision,
    DagNodeRevisionError, DagNodeStatus, DagNodeTitle, DagNodeTransitionError, DagReadinessError,
    DagRevision, DagRevisionId, DagRevisionIdParseError, DagRevisionNumber, DagRevisionNumberError,
    DagStructureError, DagTextError, GoalNodeAttribution, GoalWorkAttribution,
    MAX_DAG_ACCEPTANCE_BYTES, MAX_DAG_EDGES, MAX_DAG_NODE_OBJECTIVE_BYTES,
    MAX_DAG_NODE_TITLE_BYTES, MAX_DAG_NODES, RegisteredDagNode,
};
pub use diff::{
    AbandonDiffEvidence, BeginDiffEvidence, CompleteDiffEvidence, DiffArtifactHealth,
    DiffArtifactRelativePath, DiffArtifactRelativePathError, DiffAttribution, DiffByteCount,
    DiffChangeKind, DiffContractVersions, DiffEvidenceState, DiffEvidenceTimestamps,
    DiffFileSummary, DiffId, DiffIdParseError, DiffLineCount, DiffListLimit, DiffListLimitError,
    DiffPayloadHash, DiffPayloadProjection, DiffRedactionPolicyVersion, DiffRenderKind,
    DiffRendererVersion, DiffRevision, DiffRevisionError, DiffTransitionError, DiffVersionError,
    RegisteredDiffEvidence,
};
pub use diff_retention::{
    BeginDiffPurge, CompleteDiffPurge, DeleteOrphanDiffArtifact, DiffArtifactInvalidInventoryEntry,
    DiffArtifactInvalidReason, DiffArtifactInventoryEntry, DiffArtifactInventoryKind,
    DiffArtifactInventoryLimit, DiffArtifactInventoryName, DiffArtifactInventoryNameError,
    DiffPurgeRecord, DiffPurgeStatus, DiffRetentionBoundError, DiffRetentionKeepCount,
    DiffRetentionPlan, DiffRetentionPlanLimit,
};
pub use execution::{
    BeginExecution, BoundedExecutionOutput, CompleteExecution, ExecutionArgument,
    ExecutionArgumentError, ExecutionAttribution, ExecutionCompletionStatus, ExecutionFailureCode,
    ExecutionId, ExecutionIdParseError, ExecutionKind, ExecutionLimits, ExecutionListLimit,
    ExecutionListLimitError, ExecutionMode, ExecutionOutcome, ExecutionOutputLimit,
    ExecutionOutputLimitError, ExecutionPermissions, ExecutionProgram, ExecutionProgramError,
    ExecutionRecordError, ExecutionRequest, ExecutionRequestDigest, ExecutionRequestError,
    ExecutionRevision, ExecutionRevisionError, ExecutionScript, ExecutionScriptError,
    ExecutionState, ExecutionTermination, ExecutionTimeoutError, ExecutionTimeoutMillis,
    ExecutionTimestamps, FailExecution, MarkExecutionRunning, RegisteredExecution,
    execution_state_for_outcome,
};
pub use filesystem::{
    BeginFileMutation, BeginFileMutationError, BeginFileMutationResult, BeginFileMutationStatus,
    ChangeSetAttribution, ChangeSetId, ChangeSetIdParseError, ChangeSetRevision,
    ChangeSetRevisionError, ChangeSetState, ChangeSetTimestamps, CompleteFileMutation,
    FailFileMutation, FileByteCount, FileContentHash, FileContentHashParseError,
    FileMutationFailureCode, FileMutationId, FileMutationIdParseError, FileMutationIdentity,
    FileMutationKind, FileMutationPlan, FileMutationRecord, FileMutationRevision,
    FileMutationRevisionError, FileMutationScope, FilePathState, FilePrecondition,
    MAX_WORKSPACE_RELATIVE_PATH_BYTES, RegisteredChangeSet, RegisteredFileMutation,
    WorkspaceRelativePath, WorkspaceRelativePathError,
};
pub use goal::{
    GoalAttribution, GoalBlocker, GoalBlockerKind, GoalCompletionBlocker, GoalContract,
    GoalContractError, GoalEvidenceKind, GoalEvidenceRef, GoalFailure, GoalHardCheck, GoalId,
    GoalIdParseError, GoalListLimit, GoalListLimitError, GoalObjective, GoalPublicReason,
    GoalReview, GoalReviewError, GoalRevision, GoalRevisionError, GoalStatement, GoalStatus,
    GoalStatusKind, GoalTextError, GoalTimestamps, GoalTransitionError,
    GoalVerificationRequirement, MAX_GOAL_CONTRACT_BYTES, MAX_GOAL_LIST_RESULTS,
    MAX_GOAL_OBJECTIVE_BYTES, MAX_GOAL_REASON_BYTES, MAX_GOAL_REVIEW_CHECKS,
    MAX_GOAL_STATEMENT_BYTES, MAX_GOAL_STATEMENTS_PER_KIND, MAX_GOAL_VERIFICATION_REQUIREMENTS,
    RegisteredGoal,
};
pub use harness::{
    AppliedHarness, AppliedHarnessError, HarnessBundleDescriptor, HarnessBundleError,
    HarnessBundleId, HarnessBundleIdParseError, HarnessContentHash, HarnessContentHashParseError,
    HarnessName, HarnessNameError, HarnessRevision, HarnessRevisionError,
    HarnessVerificationOutcome, HarnessVerificationState, HarnessVersion, HarnessVersionError,
    MAX_HARNESS_MANAGED_FILES, MAX_HARNESS_NAME_BYTES, MAX_HARNESS_SKILLS, MAX_HARNESS_VERIFIERS,
    MAX_HARNESS_VERSION_BYTES, RegisteredHarnessBundle, RegisteredHarnessBundleError,
};
pub use harness_verifier::{
    HarnessVerifierDomainError, HarnessVerifierItem, HarnessVerifierItemState, HarnessVerifierName,
    HarnessVerifierNameError, HarnessVerifierRun, HarnessVerifierRunAttribution,
    HarnessVerifierRunId, HarnessVerifierRunIdParseError, HarnessVerifierRunRevision,
    HarnessVerifierRunRevisionError, HarnessVerifierRunState, HarnessVerifierRunTimestamps,
    MAX_HARNESS_VERIFIER_NAME_BYTES,
};
pub use location::{
    LocationId, LocationIdParseError, LocationListLimit, LocationListLimitError, LocationName,
    LocationNameError, LocationRevision, LocationRevisionError, LocationRoot, LocationRootError,
    LocationState, RegisterLocation, RegisteredLocation, SetLocationState, TimestampMillis,
    TimestampMillisError,
};
pub use recovery::{
    ClaimRecoveryLease, MAX_RECOVERY_LEASE_DURATION_MILLIS, MIN_RECOVERY_LEASE_DURATION_MILLIS,
    RecoveryLeaseClaimDecision, RecoveryLeaseDurationError, RecoveryLeaseDurationMillis,
    RecoveryLeaseEpoch, RecoveryLeaseEpochError, RecoveryLeaseReleaseDecision,
    RecoveryLeaseRenewDecision, RecoveryLeaseRevision, RecoveryLeaseRevisionError,
    RecoveryLeaseTransitionError, RecoveryMaintenanceLease, RecoveryMaintenanceLeaseError,
    ReleaseRecoveryLease, RenewRecoveryLease, decide_recovery_lease_claim,
    decide_recovery_lease_release, decide_recovery_lease_renew,
};
pub use runtime::{
    RuntimeCommand, RuntimeEvent, RuntimeFailureCode, RuntimeGeneration, RuntimeLifecycle,
    RuntimePhase, RuntimeProjection, RuntimeTransitionError,
};
pub use workspace::{
    ActivityId, ActivityIdParseError, ActivityLeaseBatchLimit, ActivityLeaseBatchLimitError,
    ActivityLeaseProjection, ActivityLeaseProjectionError, ActivityLeaseRevision,
    ActivityLeaseRevisionError, ActivityListLimit, ActivityListLimitError, ActivityLiveness,
    ActivityProjection, ActivityRevision, ActivityRevisionError, ActivityState, BootstrapActivity,
    BootstrapActivityDecision, CloseActivity, CloseActivityDecision, CreateActivity,
    EstablishWorkspace, MAX_ACTIVITY_LEASE_BATCH, ReconcileExpiredActivities, RegisteredActivity,
    RegisteredWorkspace, ReleaseActivityLease, RenewActivityLease, RenewActivityLeaseDecision,
    RuntimeInstanceId, RuntimeInstanceIdParseError, SetActivityState, WorkspaceId,
    WorkspaceIdParseError, WorkspaceRevision, WorkspaceRevisionError, WorkspaceRoot,
    WorkspaceRootDecision, WorkspaceRootDecisionError, WorkspaceRootError,
    WorkspaceRootFingerprint, decide_activity_bootstrap, decide_bootstrap_activity,
    decide_close_activity, decide_renew_activity_lease, decide_workspace_root,
};
