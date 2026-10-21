//! Durable persistence adapters for Heterarchy Forge.

mod agent_session_catalog;
mod global_registry;
mod queue_settings_catalog;
mod workspace_activity_successors;
mod workspace_admission_envelopes;
mod workspace_agent_assignments;
mod workspace_agent_binding_activation;
mod workspace_agent_binding_rejections;
mod workspace_agent_binding_reservations;
mod workspace_agent_dag;
mod workspace_agent_delegation;
mod workspace_agent_departure_reconciliation;
mod workspace_agent_effect_outbox;
mod workspace_agent_events;
mod workspace_agent_migration;
mod workspace_agent_session_reconciliation;
mod workspace_agents;
mod workspace_approvals;
mod workspace_changesets;
mod workspace_checkpoints;
mod workspace_coordinators;
mod workspace_dag_node_evidence;
mod workspace_dags;
mod workspace_diffs;
mod workspace_effect_fact_outbox;
mod workspace_execution_stops;
mod workspace_executions;
mod workspace_expired_activity_recovery;
mod workspace_goal_creation_watermarks;
mod workspace_goal_deletion;
mod workspace_goal_mutations;
mod workspace_goals;
mod workspace_quiescent_activity_lease_resumes;
mod workspace_recovery_runs;
mod workspace_started_activity_lease_resumes;
mod workspace_unstarted_activity_continuation;
pub use workspace_recovery_runs::{
    RecoveryActivityFact, RecoveryExecutionFact, RecoveryRunReceipt, RecoveryRunRequest,
    RecoveryRunStoreError,
};

pub use workspace_agent_assignments::{
    AgentAssignmentOfferSealAuthority, AgentAssignmentOfferSealSnapshot, AgentAssignmentStoreError,
    DagNodeAssignmentSnapshot,
};
pub use workspace_approvals::cleanup::stop_receipts::{
    AuthorityStopReceipt, AuthorityStopTarget, AuthorityStopTargetKind,
};
pub use workspace_goal_deletion::{
    GoalDeletionArtifact, GoalDeletionArtifactKind, GoalDeletionArtifactProof,
    GoalDeletionArtifactStatus, GoalDeletionCleanupOutcome, GoalDeletionCleanupReadback,
    GoalDeletionCleanupStatus, GoalDeletionPendingInventory, GoalDeletionPendingSummary,
    GoalDeletionStage, GoalDeletionStoreError,
};
pub use workspace_store::OwnedWorkspaceStopCapture;
pub use workspace_store::{GoalDeletionAdmission, GoalDeletionStore};
mod workspace_queue_settings;
mod workspace_recovery;
mod workspace_semantic_events;
mod workspace_source_tree_requests;
mod workspace_store;
mod workspace_verification;
mod workspace_work_cuts;
mod workspace_work_inventory;
mod workspace_writer_leases;

#[cfg(test)]
#[path = "legacy_agent_seed.rs"]
pub(crate) mod legacy_agent_seed;

pub use agent_session_catalog::{
    AGENT_SESSION_APPLICATION_ID, AGENT_SESSION_SCHEMA_VERSION, AgentSessionCatalog,
    AgentSessionCatalogError,
};
pub use forge_domain::AuthorizedExecutionRead;
pub use forge_domain::{AgentBindingRejectionReceipt, AgentBindingRejectionRequest};
pub use global_registry::{GlobalRegistry, RegistryError, RegistryHealth};
pub use queue_settings_catalog::{
    QueueSettings, QueueSettingsCatalog, QueueSettingsCatalogError, QueueSettingsRevision,
    QueueSettingsRevisionError, QueueSettingsTransitionError, RegisteredQueueSettings,
};
pub use workspace_activity_successors::ActivitySuccessorStoreError;
pub use workspace_admission_envelopes::{
    AdmissionConsumeOutcome, AdmissionEnvelopeConsumption, AdmissionEnvelopeError,
};
pub use workspace_agent_binding_activation::{
    AgentBindingActivation, AgentBindingActivationError, AgentBindingActivationRequest,
};
pub use workspace_agent_binding_rejections::{
    AgentBindingRejectionOperation, AgentBindingRejectionStoreError,
    AgentBindingRejectionStoreRequest, agent_binding_rejection_delegation_digest,
    agent_binding_rejection_intent_digest, agent_binding_rejection_intent_digest_for_attestation,
};
pub use workspace_agent_dag::{AgentDagPlanCommitResult, AgentDagPlanRecord, AgentDagStoreError};
pub use workspace_agent_delegation::{AgentOperationsDelegation, AgentOperationsDelegationError};
pub use workspace_agent_departure_reconciliation::{
    AgentDepartureCommand, AgentDepartureKind, AgentDepartureReconciliation,
    AgentDepartureReconciliationError, AgentDepartureReconciliationRequest,
};
pub use workspace_agent_effect_outbox::{
    AgentEffectFact, AgentEffectOutboxEntry, AgentEffectOutboxError,
};
pub use workspace_agent_events::AgentEventStoreError;
pub use workspace_agent_migration::{
    AgentOperationsExportCursor, AgentOperationsExportError, AgentOperationsExportPage,
    AgentOperationsExportRecord, AgentOperationsFreeze, AgentOperationsFreezeRequest,
    AgentOperationsFreezeState, AgentOperationsInboxKey, AgentOperationsInboxReceipt,
    AgentOperationsMigrationError, AgentOperationsPresenceRow,
};
pub use workspace_agent_session_reconciliation::{
    AgentSessionReconciliation, AgentSessionReconciliationError, AgentSessionReconciliationRequest,
};
pub use workspace_agents::AgentStoreError;
pub use workspace_approvals::ExecutionAdmissionContext;
pub use workspace_approvals::{
    ApprovalAuthorityCleanupReport, ApprovalCleanupApplyOutcome, ApprovalCleanupAttemptId,
    ApprovalCleanupMode, ApprovalCleanupPlan, ApprovalCleanupReadback, ApprovalCleanupRejection,
    ApprovalCleanupSelector, ApprovalStoreError, AutoApprovalExecutionRecord,
};
pub use workspace_changesets::ChangeSetStoreError;
pub use workspace_checkpoints::{
    CHECKPOINT_DOCTOR_MAX_REFERENCES, CheckpointDoctorReference, CheckpointDoctorReport,
    CheckpointDoctorSnapshotReference, CheckpointStoreError,
};
pub use workspace_coordinators::CoordinatorStoreError;
pub use workspace_dag_node_evidence::{
    DagNodeEvidenceCursor, DagNodeEvidenceEntry, DagNodeEvidenceError, DagNodeEvidencePage,
    DagNodeEvidenceScope, MAX_DAG_NODE_EVIDENCE_PAGE_SIZE,
};
pub use workspace_dags::{
    DAG_DOCTOR_MAX_CURRENT_DAGS, DagDoctorFinding, DagDoctorIssue, DagDoctorNodeSummary,
    DagDoctorReport, DagDoctorState, DagHead, DagNodeEvidenceSummary, DagNodeTransition,
    DagStoreError, DagTransitionScope, StoredDagRevision,
};
pub use workspace_diffs::{
    DIFF_DOCTOR_MAX_REFERENCES, DiffDoctorArtifactReference, DiffDoctorReference, DiffDoctorReport,
    DiffStoreError,
};
pub use workspace_effect_fact_outbox::{
    AssignmentOfferedEffectFact, AssignmentReviewedEffectFact, AssignmentReviewedOutcome,
    AssignmentSourceRefError, AssignmentSubmittedEffectFact, AssignmentSubmittedSourceRef,
    ChangeSetTerminalEffectFact, EffectFact, EffectFactOutboxEntry, EffectFactOutboxError,
    EffectFactVerificationEvidence, ExecutionTerminalEffectFact,
};
pub use workspace_execution_stops::{
    ExecutionStopCapture, ExecutionStopCaptureStatus, ExecutionStopRecord, ExecutionStopRequest,
    ExecutionStopStatus, ExecutionStopStoreError, ExecutionStopTarget, ExecutionStopTargetStatus,
    MAX_EXECUTION_STOP_TARGETS,
};
pub use workspace_executions::{
    BeginExecutionRecord, BeginExecutionStatus, ExecutionEvidenceInventory, ExecutionEvidenceRead,
    ExecutionEvidenceRecord, ExecutionStoreError,
};
pub use workspace_goals::{GoalCompletionReceipt, GoalEvidenceRecord, GoalStoreError};
pub use workspace_queue_settings::WorkspaceQueueSettingsStoreError;
pub use workspace_recovery::{
    RecoveryLeaseClaimResult, RecoveryLeaseClaimStatus, RecoveryStoreError,
};
pub use workspace_semantic_events::{
    GoalSnapshotState, GoalSnapshotSummary, MAX_WORKSPACE_SNAPSHOT_GOAL_SUMMARIES,
    SemanticEventAppend, SemanticEventError, SemanticEventKind, SemanticEventPage,
    SemanticEventRecord, SemanticEventSubjects, WorkspaceSemanticSnapshot,
};
pub use workspace_store::{
    BeginFileMutationDiffResult, FileMutationDiffRecord, FileMutationReadSnapshot,
    RecoveryRunOperation, RootRecoveryAuthorityBlocker, RootRecoveryIdentityObservation,
    RootRecoveryOperation, RootRecoveryProbe, RootRecoveryReceipt, RootRecoveryStoreError,
    SourceTreeReadSnapshot, WORKSPACE_APPLICATION_ID, WorkspaceDoctorCount,
    WorkspaceDoctorIntegrity, WorkspaceDoctorOutcome, WorkspaceDoctorReport,
    WorkspaceDoctorSourceObservation, WorkspaceJournalBinding, WorkspaceStateRemovalBlocker,
    WorkspaceStore, WorkspaceStoreError, WorkspaceStoreHealth, delegated_authority_digest,
};
pub use workspace_store::{
    ExpiredActivityRecoveryOperation, ExpiredActivityRecoveryReadback,
    ExpiredActivityRecoveryReceipt, ExpiredActivityRecoveryStoreError,
    ExpiredActivityRecoveryStoreRequest,
};
pub use workspace_store::{
    QuiescentActivityLeaseResumeReadback, QuiescentActivityLeaseResumeStoreError,
};
pub use workspace_store::{
    StartedActivityLeaseResumeOperation, StartedActivityLeaseResumeReadback,
    StartedActivityLeaseResumeStoreError,
};
pub use workspace_store::{
    UnstartedActivityContinuationOperation, UnstartedActivityContinuationReadback,
    UnstartedActivityContinuationReceipt, UnstartedActivityContinuationStoreError,
    UnstartedActivityContinuationStoreRequest,
};
pub use workspace_verification::{VerificationBeginResult, VerificationStoreError};
pub use workspace_work_cuts::{
    AssignmentContinuationAcknowledgeOutcome, AssignmentContinuationAcknowledgment,
    AssignmentContinuationIntent, AssignmentContinuationIntentError,
    AssignmentContinuationPrepareOutcome, AssignmentContinuationProposal, WorkCutDrainObservation,
    WorkCutEffect, WorkCutEffectKind, WorkCutEffectProgress, WorkCutEffectSettlement, WorkCutError,
    WorkCutPrepareOutcome, WorkCutRecord, WorkCutState,
};
pub use workspace_work_inventory::{
    WorkCutInventory, WorkInventoryAgent, WorkInventoryAssignment, WorkInventoryError,
    WorkInventoryNode,
};
pub use workspace_writer_leases::{MAX_ACTIVE_WRITER_LEASES, WriterLeaseStoreError};

pub use workspace_agent_binding_reservations::{
    AgentBindingReservation, AgentBindingReservationError, AgentBindingReservationRequest,
};

pub use workspace_goal_mutations::{GoalMutationResult, GoalMutationStoreError};

pub use workspace_executions::AuthorizedExecutionSnapshot;
pub use workspace_executions::native_closure::ExecutionNativeClosureSnapshot;

mod workspace_coordinator_recovery;
pub use workspace_coordinator_recovery::CoordinatorRecoveryStoreError;
