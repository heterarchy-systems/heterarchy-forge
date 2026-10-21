//! Typed closed command enum: wire payload parsing, operation classification,
//! and the synchronous forge-control dispatch table.
//!
//! Dispatch is a closed enum plus one exhaustive match per direction. The
//! transport adapter never interprets domain policy; each op forwards the
//! parsed transport DTO to exactly one existing forge-control capability and
//! projects the typed result into a bounded JSON readback.

use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use forge_control::{
    DagNodeCompleteRequest, DagNodeStartRequest, ForgeControlClient, ProjectCommandListRequest,
    ResolvedWorkspaceScope,
};
use forge_domain::{
    ActivityId, DagNodeId, DagNodeRevision, DagRevisionNumber, ExecutionGrantRevision, ExecutionId,
    ExecutionRequestDigest, ForgeBackendId, GoalId, GoalRevision, OrchestrationIssuerId,
    RuntimeInstanceId, TimestampMillis, WorkspaceId,
};

use crate::error::ForgeError;

pub mod activity_lease_continuation;
pub mod activity_leases;
pub mod activity_lifecycle;
mod activity_projection;
pub mod activity_recovery;
pub mod agent_operations_migration;
pub mod agents;
mod approval;
mod assignment_offer_seal;
mod assignments;
pub mod binding_lifecycle;
mod binding_rejection;
mod dag_plan;
mod diff_inventory;
pub mod effect_facts;
pub mod execution;
pub mod execution_evidence;
pub mod execution_observation;
pub mod execution_wait;
pub mod goal_cleanup;
mod goals;
pub mod lease;
pub mod location_removal;
mod mutation;
mod observability;
mod plan;
mod planning;
pub mod queue_observation;
pub mod queue_preference;
pub mod recovery_leases;
mod recovery_maintenance;
mod work_cuts;
pub mod workspace_root_recovery;
pub mod workspace_stop;

#[cfg(test)]
mod authority_metadata_tests;
mod registry;
mod source;
pub(crate) use source::scope_json;
mod activity_lease_resume;
mod activity_quiescent_lease_resume;
mod source_write;
mod tree;

/// One source for the closed operation names, parser and capability ordering.
macro_rules! define_command_ops {
    ($( $variant:ident => $name:literal, )+) => {
        /// Closed operation set over existing Forge control capabilities.
        #[must_use]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum CommandOp {
            $( $variant, )+
        }

        impl CommandOp {
            /// Canonical operation string in the envelope and capability document.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $name, )+
                }
            }

            pub fn parse(value: &str) -> Option<Self> {
                match value {
                    $( $name => Some(Self::$variant), )+
                    _ => None,
                }
            }

            /// All supported operations in capability-document order.
            pub const ALL: [Self; [$( stringify!($variant), )+].len()] = [
                $( Self::$variant, )+
            ];
        }
    };
}

define_command_ops! {
    LocationRemovalProbe => "location.removal_probe",
    LocationRemove => "location.remove",
    RecoveryLeaseGet => "recovery.lease.get",
    RecoveryMaintenanceRun => "recovery.maintenance.run",
    RecoveryMaintenanceGet => "recovery.maintenance.get",
    WorkCutInventory => "work_cut.inventory",
    WorkCutPrepare => "work_cut.prepare",
    WorkCutGet => "work_cut.get",
    WorkCutDrain => "work_cut.drain",
    RecoveryLeaseClaim => "recovery.lease.claim",
    RecoveryLeaseRenew => "recovery.lease.renew",
    RecoveryLeaseRelease => "recovery.lease.release",
    ActivityLeaseRenew => "activity.lease.renew",
    ActivityLeaseRelease => "activity.lease.release",
    ActivityLeaseRenewBatch => "activity.lease.renew_batch",
    ActivityLeaseReleaseBatch => "activity.lease.release_batch",
    AgentOperationsDelegate => "agent.operations.delegate",
    AgentOperationsDelegationGet => "agent.operations.delegation_get",
    AgentOperationsFreeze => "agent.operations.freeze",
    AgentOperationsFreezeGet => "agent.operations.freeze_get",
    AgentOperationsExport => "agent.operations.export",
    AgentOperationsFreezeRelease => "agent.operations.freeze_release",
    AgentBindingReserve => "agent.binding.reserve",
    AgentBindingReservationGet => "agent.binding.reservation_get",
    AgentBindingActivate => "agent.binding.activate",
    AgentBindingActivationGet => "agent.binding.activation_get",
    AgentBindingReject => "agent.binding.reject",
    AgentBindingRejectionGet => "agent.binding.rejection_get",
    AgentSessionReconcile => "agent.session.reconcile",
    AgentSessionReconciliationGet => "agent.session.reconciliation_get",
    AgentDepartureReconcile => "agent.departure.reconcile",
    AgentDepartureReconciliationGet => "agent.departure.reconciliation_get",
    ActivityGet => "activity.get",
    ActivityClose => "activity.close",
    QueueStatus => "queue.status",
    WorkspaceQueueStatus => "workspace.queue.status",
    WorkspaceQueueSettings => "workspace.queue.settings",
    WorkspaceQueueSettingsReplace => "workspace.queue.settings.replace",
    GoalList => "goal.list",
    GoalDelete => "goal.delete",
    GoalDeletePending => "goal.delete_pending",
    EffectFactOutbox => "effect_fact.outbox",
    LocationList => "location.list",
    WorkspaceList => "workspace.list",
    WorkspaceDiscover => "workspace.discover",
    WorkspaceResolve => "workspace.resolve",
    WorkspaceRegister => "workspace.register",
    WorkspaceRegistrationProbe => "workspace.registration_probe",
    WorkspaceRootRecoveryProbe => "workspace.root_recovery.probe",
    WorkspaceRootRecoveryPrepare => "workspace.root_recovery.prepare",
    WorkspaceRootRecoveryCommit => "workspace.root_recovery.commit",
    WorkspaceRootRecoveryReadback => "workspace.root_recovery.readback",
    WorkspaceInventory => "workspace.inventory",
    ActivityList => "activity.list",
    GoalRead => "goal.read",
    DagReadCurrent => "dag.read_current",
    NodeAssignmentRead => "node.assignment_read",
    AgentAssignmentOfferSeal => "agent.assignment_offer_seal",
    AgentAssignmentOfferSealGet => "agent.assignment_offer_seal_get",
    NodeStart => "node.start",
    NodeComplete => "node.complete",
    CommandList => "command.list",
    ExecutionBegin => "execution.begin",
    WorkspaceStop => "execution.stop_workspace",
    WorkspaceStopGet => "execution.stop_workspace_get",
    ExecutionCancel => "execution.cancel",
    ExecutionRead => "execution.read",
    ExecutionOutput => "execution.output",
    ExecutionWait => "execution.wait",
    ExecutionGet => "execution.get",
    DiffRead => "diff.read",
    FileList => "file.list",
    TextSearch => "text.search",
    FileReadSlice => "file.read_slice",
    WriterLeaseAcquire => "writer_lease.acquire",
    WriterLeaseRenew => "writer_lease.renew",
    WriterLeaseRelease => "writer_lease.release",
    WriterLeaseGet => "writer_lease.get",
    WriterLeaseList => "writer_lease.list",
    FileMutationReadback => "file.mutation_readback",
    FileApplyPatch => "file.apply_patch",
    SourceTreeApply => "source_tree.apply",
    SourceTreeReadback => "source_tree.readback",
    GoalCreate => "goal.create",
    GoalRevise => "goal.revise",
    GoalTransition => "goal.transition",
    GoalComplete => "goal.complete",
    GoalMutationReadback => "goal.mutation_readback",
    GoalReview => "goal.review",
    DagPlanCommit => "dag.plan_commit",
    DagPlanReadback => "dag.plan_readback",
    LocationRegister => "location.register",
    LocationState => "location.state",
    WorkspaceDoctor => "workspace.doctor",
    VerificationProjection => "verification.projection",
    ExecutionInventory => "execution.inventory",
    ExecutionObserve => "execution.observe",
    ActivityBootstrap => "activity.bootstrap",
    ApprovalGet => "approval.get",
    ApprovalApproveOnce => "approval.approve_once",
    ApprovalReject => "approval.reject",
    ApprovalPending => "approval.pending",
    DiffList => "diff.list",
    DiffInventory => "diff.inventory",
    DiffDoctor => "diff.doctor",
    DiffRetentionPlan => "diff.retention_plan",
    DiffArtifactDoctor => "diff.artifact_doctor",
    WriterLeaseRecoveryRelease => "writer_lease.recovery_release",
    ActivitySuccessorCreate => "activity.successor_create",
    ActivitySuccessorGet => "activity.successor_get",
    ActivityExpiredSuccessorRecoveryProbe => "activity.expired_successor_recovery_probe",
    ActivityExpiredSuccessorRecover => "activity.expired_successor_recover",
    ActivityExpiredSuccessorRecoveryGet => "activity.expired_successor_recovery_get",
    ActivityUnstartedContinuationProbe => "activity.unstarted_continuation_probe",
    ActivityUnstartedContinuationRun => "activity.unstarted_continuation_run",
    ActivityUnstartedContinuationGet => "activity.unstarted_continuation_get",
    ActivityStartedLeaseResumeProbe => "activity.started_lease_resume_probe",
    ActivityStartedLeaseResumeRun => "activity.started_lease_resume_run",
    ActivityStartedLeaseResumeGet => "activity.started_lease_resume_get",
    ActivityQuiescentLeaseResumeProbe => "activity.quiescent_lease_resume_probe",
    ActivityQuiescentLeaseResumeRun => "activity.quiescent_lease_resume_run",
    ActivityQuiescentLeaseResumeGet => "activity.quiescent_lease_resume_get",
    ActivityCoordinatorGet => "activity.coordinator_get",
    ActivityCoordinatorActorGet => "activity.coordinator_actor_get",
    ActivityCoordinatorClaim => "activity.coordinator_claim",
    AgentList => "agent.list",
    AgentGetContext => "agent.get_context",
    AgentCoordinationGet => "agent.coordination_get",
    AgentInboxList => "agent.inbox_list",
    AgentSetFocus => "agent.set_focus",
    AgentPublishWork => "agent.publish_work",
    AgentAssignmentMutate => "agent.assignment.mutate",
    AgentAssignmentGet => "agent.assignment.get",
    AgentAssignmentList => "agent.assignment.list",
    CommandSubmit => "command.submit",
    ShellSubmit => "shell.submit",
}

impl CommandOp {
    /// Session-bound commands carry an Orchestration session identity and
    /// require the Forge control session authority. Historical `WorkCut` reads
    /// remain issuer-only; live inventory resolves its declared bindings.
    pub const fn requires_session_authority(self) -> bool {
        matches!(
            self,
            Self::GoalDelete
                | Self::WorkCutInventory
                | Self::WorkCutPrepare
                | Self::AgentBindingReserve
                | Self::AgentBindingReservationGet
                | Self::AgentBindingActivate
                | Self::AgentBindingActivationGet
                | Self::AgentBindingReject
                | Self::AgentBindingRejectionGet
                | Self::AgentSessionReconcile
                | Self::AgentSessionReconciliationGet
                | Self::AgentDepartureReconcile
                | Self::AgentDepartureReconciliationGet
                | Self::AgentAssignmentOfferSeal
                | Self::AgentAssignmentOfferSealGet
                | Self::NodeStart
                | Self::NodeComplete
                | Self::ExecutionBegin
                | Self::WorkspaceStop
                | Self::WorkspaceStopGet
                | Self::WriterLeaseAcquire
                | Self::WriterLeaseRenew
                | Self::WriterLeaseRelease
                | Self::FileApplyPatch
                | Self::SourceTreeApply
                | Self::GoalCreate
                | Self::GoalRevise
                | Self::GoalTransition
                | Self::GoalComplete
                | Self::DagPlanCommit
                | Self::ExecutionCancel
                | Self::ExecutionRead
                | Self::ExecutionGet
                | Self::ExecutionWait
                | Self::ExecutionOutput
                | Self::ActivitySuccessorCreate
                | Self::ActivityExpiredSuccessorRecover
                | Self::ActivityUnstartedContinuationRun
                | Self::ActivityStartedLeaseResumeProbe
                | Self::ActivityStartedLeaseResumeRun
                | Self::ActivityStartedLeaseResumeGet
                | Self::ActivityQuiescentLeaseResumeProbe
                | Self::ActivityQuiescentLeaseResumeRun
                | Self::ActivityQuiescentLeaseResumeGet
                | Self::ActivityCoordinatorClaim
                | Self::AgentInboxList
                | Self::AgentSetFocus
                | Self::AgentPublishWork
                | Self::AgentAssignmentMutate
                | Self::AgentAssignmentGet
                | Self::AgentAssignmentList
                | Self::CommandSubmit
                | Self::ShellSubmit
        )
    }
}

/// Shared Workspace scope DTO. The scope is correlation data revalidated by
/// forge-control; the adapter only decodes it.
#[must_use]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ScopeDto {
    pub workspace_id: Uuid,
    pub workspace_revision: i64,
    pub locator: LocatorDto,
}

/// Shared Activity attribution DTO.
#[must_use]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActivityDto {
    pub activity_id: Uuid,
    pub runtime_instance_id: Uuid,
    pub observed_at_ms: i64,
}

#[must_use]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocatorDto {
    pub location_id: Uuid,
    pub expected_revision: i64,
    pub relative_root: String,
}

/// Stable authenticated principal identity carried by command payloads.
/// Raw bearer/access-token material never crosses this boundary; token and
/// OAuth variants contain only their durable identity UUID. The flat object
/// shape preserves borrowed `serde_json::Value` decoding without cloning the
/// complete command payload.
#[must_use]
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrincipalDto {
    kind: PrincipalKindDto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant_id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PrincipalKindDto {
    TrustedStdio,
    DirectToken,
    #[serde(rename = "oauth_grant")]
    OAuthGrant,
}

/// Session actor identity inside session-bound payloads.
#[must_use]
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionActorDto {
    pub session_id: Uuid,
    pub principal: PrincipalDto,
    pub workspace_id: Uuid,
}

/// One typed command ready for the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    ActivityStartedLeaseResume {
        request_id: Uuid,
        request: Box<activity_lease_resume::ResumeCommand>,
    },
    ActivityQuiescentLeaseResume {
        request_id: Uuid,
        request: Box<activity_quiescent_lease_resume::ResumeCommand>,
    },
    WorkspaceStop {
        request_id: Uuid,
        request: Box<workspace_stop::WorkspaceStopCommand>,
    },
    LocationRemoval {
        request_id: Uuid,
        request: Box<location_removal::LocationRemovalCommand>,
    },
    RecoveryLease {
        request_id: Uuid,
        request: Box<recovery_leases::RecoveryLeaseCommand>,
    },
    RecoveryMaintenance {
        request_id: Uuid,
        request: Box<recovery_maintenance::RecoveryMaintenanceCommand>,
    },
    WorkCut {
        request_id: Uuid,
        request: Box<work_cuts::WorkCutCommand>,
    },
    ActivityLeases {
        request_id: Uuid,
        request: Box<activity_leases::ActivityLeaseCommand>,
    },
    QueuePreference {
        request_id: Uuid,
        request: Box<queue_preference::QueuePreferenceCommand>,
    },
    BindingLifecycle {
        request_id: Uuid,
        request: Box<binding_lifecycle::BindingLifecycleCommand>,
    },
    BindingRejection {
        request_id: Uuid,
        request: Box<binding_rejection::BindingRejectionCommand>,
    },
    AgentOperationsMigration {
        request_id: Uuid,
        request: Box<agent_operations_migration::AgentOperationsMigrationCommand>,
    },
    ActivityLifecycle {
        request_id: Uuid,
        request: activity_lifecycle::ActivityLifecycleRequest,
    },
    QueueObservation {
        request_id: Uuid,
        request: queue_observation::QueueObservationRequest,
    },
    ActivityList {
        request_id: Uuid,
        request: Box<forge_control::WorkspaceActivityProjectionRequest>,
    },
    WorkspaceInventory {
        request_id: Uuid,
        location_id: forge_domain::LocationId,
        expected_revision: forge_domain::LocationRevision,
    },
    WorkspaceRegister {
        request_id: Uuid,
        request: Box<forge_control::WorkspaceRegistrationRequest>,
    },
    WorkspaceRegistrationProbe {
        request_id: Uuid,
        locator: forge_control::WorkspaceLocator,
    },
    WorkspaceRootRecoveryProbe {
        request_id: Uuid,
        request: Box<forge_control::WorkspaceRootRecoveryProbeRequest>,
    },
    WorkspaceRootRecoveryPrepare {
        request_id: Uuid,
        request: Box<forge_control::WorkspaceRootRecoveryPrepareRequest>,
    },
    WorkspaceRootRecoveryCommit {
        request_id: Uuid,
        request: Box<forge_control::WorkspaceRootRecoveryCommitRequest>,
    },
    WorkspaceRootRecoveryReadback {
        request_id: Uuid,
        request: Box<forge_control::WorkspaceRootRecoveryReadbackRequest>,
    },
    GoalList {
        request_id: Uuid,
        request: Box<goal_cleanup::GoalListCommand>,
    },
    GoalDelete {
        request_id: Uuid,
        request: Box<goal_cleanup::GoalDeleteCommand>,
    },
    GoalDeletePending {
        request_id: Uuid,
        request: Box<goal_cleanup::GoalDeletionPendingCommand>,
    },
    EffectFactOutbox {
        request_id: Uuid,
        request: Box<effect_facts::EffectFactOutboxCommand>,
    },
    LocationList {
        request_id: Uuid,
    },
    WorkspaceList {
        request_id: Uuid,
        location_id: forge_domain::LocationId,
        expected_revision: forge_domain::LocationRevision,
    },
    WorkspaceDiscover {
        request_id: Uuid,
        location_id: forge_domain::LocationId,
        expected_revision: forge_domain::LocationRevision,
    },
    WorkspaceResolve {
        request_id: Uuid,
        location_id: Uuid,
        expected_revision: i64,
        relative_root: String,
    },
    GoalRead {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        goal_id: GoalId,
    },
    DagReadCurrent {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        goal_id: GoalId,
    },
    NodeAssignmentRead {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        node_scope: forge_persistence::DagNodeEvidenceScope,
    },
    AgentAssignmentOfferSeal {
        request_id: Uuid,
        request: Box<assignment_offer_seal::AssignmentOfferSealCommand>,
    },
    AgentAssignmentOfferSealGet {
        request_id: Uuid,
        request: Box<assignment_offer_seal::AssignmentOfferSealCommand>,
    },
    NodeStart {
        request_id: Uuid,
        request: DagNodeStartRequest,
    },
    NodeComplete {
        request_id: Uuid,
        request: DagNodeCompleteRequest,
    },
    CommandList {
        request_id: Uuid,
        request: ProjectCommandListRequest,
    },
    ExecutionBegin {
        request_id: Uuid,
        request: Box<execution::ExecutionBeginCommand>,
        execution_id: ExecutionId,
    },
    ExecutionCancel {
        request_id: Uuid,
        request: Box<execution::ExecutionCancelCommand>,
        execution_id: ExecutionId,
    },
    ExecutionRead {
        request_id: Uuid,
        request: Box<execution::ExecutionReadCommand>,
        execution_id: ExecutionId,
        after_sequence: u64,
        max_bytes: u64,
        max_events: usize,
    },
    ExecutionOutput {
        request_id: Uuid,
        request: Box<execution::ExecutionReadCommand>,
        execution_id: ExecutionId,
        after_sequence: u64,
        max_bytes: u64,
        max_events: usize,
    },
    ExecutionGet {
        request_id: Uuid,
        request: Box<execution_evidence::ExecutionGetCommand>,
        execution_id: ExecutionId,
    },
    ExecutionWait {
        request_id: Uuid,
        request: Box<execution_wait::ExecutionWaitCommand>,
        execution_id: ExecutionId,
    },
    DiffRead {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        diff_id: forge_domain::DiffId,
    },
    FileList {
        request_id: Uuid,
        request: Box<forge_control::FileListRequest>,
    },
    TextSearch {
        request_id: Uuid,
        request: Box<forge_control::TextSearchRequest>,
    },
    FileReadSlice {
        request_id: Uuid,
        request: Box<forge_control::FileReadSliceRequest>,
    },
    WriterLeaseAcquire {
        request_id: Uuid,
        request: Box<forge_control::WriterLeaseAcquireRequest>,
    },
    WriterLeaseRenew {
        request_id: Uuid,
        request: Box<forge_control::WriterLeaseRenewRequest>,
    },
    WriterLeaseRelease {
        request_id: Uuid,
        request: Box<forge_control::WriterLeaseReleaseRequest>,
    },
    WriterLeaseGet {
        request_id: Uuid,
        request: Box<lease::LeaseGetCommand>,
    },
    WriterLeaseList {
        request_id: Uuid,
        request: Box<forge_control::WriterLeaseListRequest>,
    },
    FileApplyPatch {
        request_id: Uuid,
        request: Box<forge_control::FileApplyPatchRequest>,
    },
    SourceTreeApply {
        request_id: Uuid,
        request: Box<forge_control::SourceTreeTransactionRequest>,
    },
    SourceTreeReadback {
        request_id: Uuid,
        request: Box<forge_control::SourceTreeReadbackRequest>,
    },
    GoalMutation {
        request_id: Uuid,
        request: Box<forge_control::GoalMutationRequest>,
    },
    GoalMutationReadback {
        request_id: Uuid,
        request: Box<forge_control::GoalMutationReadbackRequest>,
    },
    GoalReview {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        goal_id: GoalId,
    },
    DagPlanCommit {
        request_id: Uuid,
        request: Box<forge_control::AgentDagPlanCommitRequest>,
    },
    DagPlanReadback {
        request_id: Uuid,
        request: Box<forge_control::DagPlanReadbackRequest>,
    },
    FileMutationReadback {
        request_id: Uuid,
        request: Box<forge_control::FileMutationReadbackRequest>,
    },
    LocationRegister {
        request_id: Uuid,
        request: Box<forge_control::RegisterLocationRequest>,
    },
    LocationState {
        request_id: Uuid,
        request: Box<forge_domain::SetLocationState>,
    },
    WorkspaceDoctor {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
    },
    VerificationProjection {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
    },
    ExecutionInventory {
        request_id: Uuid,
        command: Box<execution_observation::InventoryCommand>,
    },
    ExecutionObserve {
        request_id: Uuid,
        command: Box<execution_observation::ObserveCommand>,
    },
    ActivityBootstrap {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        runtime_instance_id: forge_domain::RuntimeInstanceId,
        observed_at: TimestampMillis,
        lease_until: TimestampMillis,
    },
    ApprovalGet {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        approval_id: forge_domain::ApprovalRequestId,
    },
    ApprovalApproveOnce {
        request_id: Uuid,
        request: Box<forge_control::ApprovalOnceRequest>,
    },
    ApprovalReject {
        request_id: Uuid,
        request: Box<forge_control::ApprovalDecisionRequest>,
    },
    ApprovalPending {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
    },
    DiffList {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
    },
    DiffInventory {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
    },
    DiffDoctor {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        diff_id: forge_domain::DiffId,
    },
    DiffRetentionPlan {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        keep_recent: forge_domain::DiffRetentionKeepCount,
    },
    DiffArtifactDoctor {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
    },
    WriterLeaseRecoveryRelease {
        request_id: Uuid,
        request: Box<forge_control::WriterLeaseRecoveryReleaseRequest>,
    },
    ActivitySuccessorCreate {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        command: Box<forge_domain::CreateActivitySuccessor>,
        principal: forge_domain::AuthenticatedPrincipal,
    },
    ActivitySuccessorGet {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        predecessor_activity_id: ActivityId,
    },
    ActivityExpiredSuccessorRecoveryProbe {
        request_id: Uuid,
        request: Box<forge_control::ExpiredActivityRecoveryProbeRequest>,
    },
    ActivityExpiredSuccessorRecover {
        request_id: Uuid,
        request: Box<forge_control::DurableExpiredActivityRecoveryRequest>,
    },
    ActivityExpiredSuccessorRecoveryGet {
        request_id: Uuid,
        request: Box<forge_control::ExpiredActivityRecoveryGetRequest>,
    },
    ActivityUnstartedContinuationProbe {
        request_id: Uuid,
        command: Box<activity_lease_continuation::ProbeCommand>,
    },
    ActivityUnstartedContinuationRun {
        request_id: Uuid,
        command: Box<activity_lease_continuation::RunCommand>,
    },
    ActivityUnstartedContinuationGet {
        request_id: Uuid,
        request: Box<forge_control::UnstartedActivityContinuationGetRequest>,
    },
    ActivityCoordinatorGet {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
    },
    ActivityCoordinatorActorGet {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        principal: forge_domain::AuthenticatedPrincipal,
    },
    ActivityCoordinatorClaim {
        request_id: Uuid,
        request: Box<forge_control::CoordinatorClaimRequest>,
    },
    AgentList {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
    },
    AgentGetContext {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        agent_id: forge_domain::AgentInstanceId,
    },
    AgentCoordinationGet {
        request_id: Uuid,
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
    },
    AgentInboxList {
        request_id: Uuid,
        request: Box<forge_control::AgentInboxListRequest>,
    },
    AgentSetFocus {
        request_id: Uuid,
        request: Box<forge_control::AgentFocusRequest>,
    },
    AgentPublishWork {
        request_id: Uuid,
        request: Box<forge_control::AgentWorkUpdateRequest>,
    },
    AgentAssignmentMutate {
        request_id: Uuid,
        request: Box<forge_control::AgentAssignmentMutationRequest>,
    },
    AgentAssignmentGet {
        request_id: Uuid,
        request: Box<forge_control::AgentAssignmentGetRequest>,
    },
    AgentAssignmentList {
        request_id: Uuid,
        request: Box<forge_control::AgentAssignmentListRequest>,
    },
    CommandSubmit {
        request_id: Uuid,
        request: Box<execution::ExecutionSubmissionCommand>,
    },
    ShellSubmit {
        request_id: Uuid,
        request: Box<execution::ExecutionSubmissionCommand>,
    },
}

impl Command {
    pub const fn uses_activity_lease_lane(&self) -> bool {
        matches!(
            self,
            Self::ActivityLeases { .. }
                | Self::ActivityLifecycle { .. }
                | Self::ActivityBootstrap { .. }
        )
    }
    #[expect(
        clippy::too_many_lines,
        reason = "One arm per closed command preserves the transport request identity table."
    )]
    pub const fn request_id(&self) -> Uuid {
        match self {
            Self::ActivityStartedLeaseResume { request_id, .. }
            | Self::ActivityQuiescentLeaseResume { request_id, .. }
            | Self::LocationRemoval { request_id, .. }
            | Self::RecoveryLease { request_id, .. }
            | Self::RecoveryMaintenance { request_id, .. }
            | Self::WorkCut { request_id, .. }
            | Self::ActivityLeases { request_id, .. }
            | Self::QueuePreference { request_id, .. }
            | Self::BindingLifecycle { request_id, .. }
            | Self::BindingRejection { request_id, .. }
            | Self::AgentOperationsMigration { request_id, .. }
            | Self::WorkspaceStop { request_id, .. }
            | Self::ActivityLifecycle { request_id, .. }
            | Self::QueueObservation { request_id, .. }
            | Self::WorkspaceRegister { request_id, .. }
            | Self::ActivityList { request_id, .. }
            | Self::WorkspaceInventory { request_id, .. }
            | Self::WorkspaceRegistrationProbe { request_id, .. }
            | Self::WorkspaceRootRecoveryProbe { request_id, .. }
            | Self::WorkspaceRootRecoveryPrepare { request_id, .. }
            | Self::WorkspaceRootRecoveryCommit { request_id, .. }
            | Self::WorkspaceRootRecoveryReadback { request_id, .. }
            | Self::EffectFactOutbox { request_id, .. }
            | Self::GoalDelete { request_id, .. }
            | Self::GoalDeletePending { request_id, .. }
            | Self::GoalList { request_id, .. }
            | Self::LocationList { request_id, .. }
            | Self::WorkspaceList { request_id, .. }
            | Self::WorkspaceDiscover { request_id, .. }
            | Self::WorkspaceResolve { request_id, .. }
            | Self::GoalRead { request_id, .. }
            | Self::DagReadCurrent { request_id, .. }
            | Self::NodeAssignmentRead { request_id, .. }
            | Self::AgentAssignmentOfferSeal { request_id, .. }
            | Self::AgentAssignmentOfferSealGet { request_id, .. }
            | Self::NodeStart { request_id, .. }
            | Self::NodeComplete { request_id, .. }
            | Self::CommandList { request_id, .. }
            | Self::ExecutionBegin { request_id, .. }
            | Self::ExecutionCancel { request_id, .. }
            | Self::ExecutionRead { request_id, .. }
            | Self::ExecutionOutput { request_id, .. }
            | Self::ExecutionGet { request_id, .. }
            | Self::ExecutionWait { request_id, .. }
            | Self::DiffRead { request_id, .. }
            | Self::FileList { request_id, .. }
            | Self::TextSearch { request_id, .. }
            | Self::FileReadSlice { request_id, .. }
            | Self::WriterLeaseAcquire { request_id, .. }
            | Self::WriterLeaseRenew { request_id, .. }
            | Self::WriterLeaseRelease { request_id, .. }
            | Self::WriterLeaseGet { request_id, .. }
            | Self::WriterLeaseList { request_id, .. }
            | Self::FileMutationReadback { request_id, .. }
            | Self::FileApplyPatch { request_id, .. }
            | Self::SourceTreeApply { request_id, .. }
            | Self::SourceTreeReadback { request_id, .. }
            | Self::GoalMutation { request_id, .. }
            | Self::GoalMutationReadback { request_id, .. }
            | Self::GoalReview { request_id, .. }
            | Self::DagPlanCommit { request_id, .. }
            | Self::DagPlanReadback { request_id, .. }
            | Self::LocationRegister { request_id, .. }
            | Self::LocationState { request_id, .. }
            | Self::WorkspaceDoctor { request_id, .. }
            | Self::VerificationProjection { request_id, .. }
            | Self::ExecutionInventory { request_id, .. }
            | Self::ExecutionObserve { request_id, .. }
            | Self::ActivityBootstrap { request_id, .. }
            | Self::ApprovalGet { request_id, .. }
            | Self::ApprovalApproveOnce { request_id, .. }
            | Self::ApprovalReject { request_id, .. }
            | Self::ApprovalPending { request_id, .. }
            | Self::DiffList { request_id, .. }
            | Self::DiffInventory { request_id, .. }
            | Self::DiffDoctor { request_id, .. }
            | Self::DiffRetentionPlan { request_id, .. }
            | Self::DiffArtifactDoctor { request_id, .. }
            | Self::WriterLeaseRecoveryRelease { request_id, .. }
            | Self::ActivitySuccessorCreate { request_id, .. }
            | Self::ActivitySuccessorGet { request_id, .. }
            | Self::ActivityExpiredSuccessorRecoveryProbe { request_id, .. }
            | Self::ActivityExpiredSuccessorRecover { request_id, .. }
            | Self::ActivityExpiredSuccessorRecoveryGet { request_id, .. }
            | Self::ActivityUnstartedContinuationProbe { request_id, .. }
            | Self::ActivityUnstartedContinuationRun { request_id, .. }
            | Self::ActivityUnstartedContinuationGet { request_id, .. }
            | Self::ActivityCoordinatorGet { request_id, .. }
            | Self::ActivityCoordinatorActorGet { request_id, .. }
            | Self::ActivityCoordinatorClaim { request_id, .. }
            | Self::AgentList { request_id, .. }
            | Self::AgentGetContext { request_id, .. }
            | Self::AgentCoordinationGet { request_id, .. }
            | Self::AgentInboxList { request_id, .. }
            | Self::AgentSetFocus { request_id, .. }
            | Self::AgentPublishWork { request_id, .. }
            | Self::AgentAssignmentMutate { request_id, .. }
            | Self::AgentAssignmentGet { request_id, .. }
            | Self::AgentAssignmentList { request_id, .. }
            | Self::CommandSubmit { request_id, .. }
            | Self::ShellSubmit { request_id, .. } => *request_id,
        }
    }

    /// The durable operation/readback identity when the command carries one.
    pub const fn execution_id(&self) -> Option<ExecutionId> {
        match self {
            Self::ExecutionBegin { execution_id, .. }
            | Self::ExecutionCancel { execution_id, .. }
            | Self::ExecutionRead { execution_id, .. }
            | Self::ExecutionGet { execution_id, .. }
            | Self::ExecutionWait { execution_id, .. }
            | Self::ExecutionOutput { execution_id, .. } => Some(*execution_id),
            _ => None,
        }
    }

    /// Durable identity retained from this validated request across a lost reply.
    #[allow(clippy::too_many_lines)]
    pub fn readback_hint(&self) -> Option<crate::error::ReadbackHint> {
        if let Self::ActivityStartedLeaseResume { request, .. } = self {
            return request.readback_hint();
        }
        if let Self::ActivityQuiescentLeaseResume { request, .. } = self {
            return request.readback_hint();
        }
        if let Self::WorkspaceStop { request, .. } = self {
            return Some(workspace_stop::readback_hint(request));
        }
        if matches!(
            self,
            Self::LocationState { .. }
                | Self::LocationRemoval { .. }
                | Self::RecoveryLease { .. }
                | Self::RecoveryMaintenance { .. }
                | Self::WorkCut { .. }
        ) {
            return self.recovery_readback_hint();
        }
        if let Self::ActivityLeases { request, .. } = self {
            return Some(activity_leases::readback_hint(request));
        }
        if let Self::ActivityExpiredSuccessorRecover { request, .. } = self {
            return Some(activity_recovery::readback_hint(request));
        }
        if let Self::ActivityUnstartedContinuationRun { command, .. } = self {
            return Some(activity_lease_continuation::readback_hint(command));
        }
        if let Self::ActivityBootstrap {
            scope,
            activity_id,
            runtime_instance_id,
            ..
        } = self
        {
            return Some(observability::bootstrap_readback_hint(
                scope,
                *activity_id,
                *runtime_instance_id,
            ));
        }
        let approval_readback = match self {
            Self::ApprovalApproveOnce { request, .. } => {
                Some(crate::error::ReadbackHint::approval(
                    request.scope.workspace_id().into_uuid(),
                    request.approval_id.into_uuid(),
                    Some(request.grant_id.into_uuid()),
                ))
            }
            Self::ApprovalReject { request, .. } => Some(crate::error::ReadbackHint::approval(
                request.scope.workspace_id().into_uuid(),
                request.approval_id.into_uuid(),
                None,
            )),
            _ => None,
        };
        if approval_readback.is_some() {
            return approval_readback;
        }
        if let Self::QueuePreference { request, .. } = self {
            return Some(queue_preference::readback_hint(request));
        }
        if let Self::BindingLifecycle { request, .. } = self {
            return binding_lifecycle::readback_hint(request);
        }
        if let Self::BindingRejection { request, .. } = self {
            return binding_rejection::readback_hint(request);
        }
        if let Self::AgentOperationsMigration { request, .. } = self {
            return agent_operations_migration::readback_hint(request);
        }
        if let Self::ActivityLifecycle {
            request: activity_lifecycle::ActivityLifecycleRequest::Close(request),
            ..
        } = self
        {
            return Some(activity_lifecycle::close_readback_hint(request));
        }
        if let Self::WorkspaceRegister { request, .. } = self {
            return Some(registry::workspace_registration_readback_hint(request));
        }
        if let Self::WorkspaceRootRecoveryCommit { request, .. } = self {
            return Some(workspace_root_recovery::readback_hint(request));
        }
        if let Self::GoalDelete { request, .. } = self {
            return Some(crate::error::ReadbackHint::goal_deletion(request.request));
        }
        if let Self::GoalMutation { request, .. } = self {
            let command = &request.command;
            return Some(crate::error::ReadbackHint::GoalMutation {
                workspace_id: request.scope.workspace_id().into_uuid(),
                activity_id: command.actor().activity_id().into_uuid(),
                goal_id: command.goal_id().into_uuid(),
                mutation_request_id: command.request_id().into_uuid(),
                request_digest: encode_hex(command.digest().as_bytes()),
            });
        }
        if let Self::DagPlanCommit { request, .. } = self {
            return Some(crate::error::ReadbackHint::DagPlan {
                workspace_id: request.scope.workspace_id().into_uuid(),
                activity_id: request.request.actor().activity_id().into_uuid(),
                goal_id: request.request.goal().goal_id().into_uuid(),
                plan_request_id: request.request.id().into_uuid(),
                draft_digest: encode_hex(request.request.digest().as_bytes()),
            });
        }
        if let Self::SourceTreeApply { request, .. } = self {
            return Some(crate::error::ReadbackHint::TreeChangeSet {
                workspace_id: request.scope.workspace_id().into_uuid(),
                activity_id: request.activity.activity_id.into_uuid(),
                change_set_id: request.change_set_id.into_uuid(),
                request_digest: encode_hex(request.request_digest.as_bytes()),
            });
        }
        if let Self::FileApplyPatch { request, .. } = self {
            return Some(crate::error::ReadbackHint::FileMutation {
                workspace_id: request.scope.workspace_id().into_uuid(),
                activity_id: request.activity.activity_id.into_uuid(),
                change_set_id: request.change_set_id.into_uuid(),
                mutation_id: request.mutation_id.into_uuid(),
            });
        }
        let lease_id = match self {
            Self::WriterLeaseAcquire { request, .. } => Some(request.command.lease_id()),
            Self::WriterLeaseRenew { request, .. } => Some(request.command.lease_id()),
            Self::WriterLeaseRelease { request, .. } => Some(request.command.lease_id()),
            Self::WriterLeaseGet { request, .. } => Some(request.request.lease_id),
            _ => None,
        };
        if let Some(id) = lease_id {
            return Some(crate::error::ReadbackHint::WriterLease {
                writer_lease_id: id.into_uuid(),
            });
        }
        self.execution_id()
            .map(|id| crate::error::ReadbackHint::Execution {
                execution_id: id.into_uuid(),
            })
    }

    fn recovery_readback_hint(&self) -> Option<crate::error::ReadbackHint> {
        match self {
            Self::LocationState { request, .. } => {
                Some(registry::location_state_readback_hint(request))
            }
            Self::RecoveryLease { request, .. } => request.readback_hint(),
            Self::LocationRemoval { request, .. } => request.readback_hint(),
            Self::WorkCut { request, .. } => request.readback_hint(),
            Self::RecoveryMaintenance { request, .. }
                if request.op() == CommandOp::RecoveryMaintenanceRun =>
            {
                Some(request.readback_hint())
            }
            _ => None,
        }
    }

    #[allow(clippy::too_many_lines)]
    pub const fn op(&self) -> CommandOp {
        match self {
            Self::ActivityStartedLeaseResume { request, .. } => request.op(),
            Self::ActivityQuiescentLeaseResume { request, .. } => request.op(),
            Self::WorkspaceStop { request, .. } => request.op(),
            Self::LocationRemoval { request, .. } => request.op(),
            Self::RecoveryLease { request, .. } => request.op(),
            Self::RecoveryMaintenance { request, .. } => request.op(),
            Self::WorkCut { request, .. } => request.op(),
            Self::ActivityLeases { request, .. } => request.op(),
            Self::QueuePreference { .. } => CommandOp::WorkspaceQueueSettingsReplace,
            Self::BindingLifecycle { request, .. } => request.op(),
            Self::BindingRejection { request, .. } => request.op(),
            Self::AgentOperationsMigration { request, .. } => request.op(),
            Self::ActivityLifecycle { request, .. } => match request {
                activity_lifecycle::ActivityLifecycleRequest::Read(_) => CommandOp::ActivityGet,
                activity_lifecycle::ActivityLifecycleRequest::Close(_) => CommandOp::ActivityClose,
            },
            Self::QueueObservation { request, .. } => request.op(),
            Self::WorkspaceRegister { .. } => CommandOp::WorkspaceRegister,
            Self::WorkspaceRegistrationProbe { .. } => CommandOp::WorkspaceRegistrationProbe,
            Self::WorkspaceRootRecoveryProbe { .. } => CommandOp::WorkspaceRootRecoveryProbe,
            Self::WorkspaceRootRecoveryPrepare { .. } => CommandOp::WorkspaceRootRecoveryPrepare,
            Self::WorkspaceRootRecoveryCommit { .. } => CommandOp::WorkspaceRootRecoveryCommit,
            Self::WorkspaceRootRecoveryReadback { .. } => CommandOp::WorkspaceRootRecoveryReadback,
            Self::WorkspaceInventory { .. } => CommandOp::WorkspaceInventory,
            Self::ActivityList { .. } => CommandOp::ActivityList,
            Self::GoalList { .. } => CommandOp::GoalList,
            Self::GoalDelete { .. } => CommandOp::GoalDelete,
            Self::GoalDeletePending { .. } => CommandOp::GoalDeletePending,
            Self::EffectFactOutbox { .. } => CommandOp::EffectFactOutbox,
            Self::LocationList { .. } => CommandOp::LocationList,
            Self::WorkspaceList { .. } => CommandOp::WorkspaceList,
            Self::WorkspaceDiscover { .. } => CommandOp::WorkspaceDiscover,
            Self::WorkspaceResolve { .. } => CommandOp::WorkspaceResolve,
            Self::GoalRead { .. } => CommandOp::GoalRead,
            Self::DagReadCurrent { .. } => CommandOp::DagReadCurrent,
            Self::NodeAssignmentRead { .. } => CommandOp::NodeAssignmentRead,
            Self::AgentAssignmentOfferSeal { .. } => CommandOp::AgentAssignmentOfferSeal,
            Self::AgentAssignmentOfferSealGet { .. } => CommandOp::AgentAssignmentOfferSealGet,
            Self::NodeStart { .. } => CommandOp::NodeStart,
            Self::NodeComplete { .. } => CommandOp::NodeComplete,
            Self::CommandList { .. } => CommandOp::CommandList,
            Self::ExecutionBegin { .. } => CommandOp::ExecutionBegin,
            Self::ExecutionCancel { .. } => CommandOp::ExecutionCancel,
            Self::ExecutionRead { .. } => CommandOp::ExecutionRead,
            Self::ExecutionOutput { .. } => CommandOp::ExecutionOutput,
            Self::ExecutionWait { .. } => CommandOp::ExecutionWait,
            Self::ExecutionGet { .. } => CommandOp::ExecutionGet,
            Self::DiffRead { .. } => CommandOp::DiffRead,
            Self::FileList { .. } => CommandOp::FileList,
            Self::TextSearch { .. } => CommandOp::TextSearch,
            Self::FileReadSlice { .. } => CommandOp::FileReadSlice,
            Self::WriterLeaseAcquire { .. } => CommandOp::WriterLeaseAcquire,
            Self::WriterLeaseRenew { .. } => CommandOp::WriterLeaseRenew,
            Self::WriterLeaseRelease { .. } => CommandOp::WriterLeaseRelease,
            Self::WriterLeaseGet { .. } => CommandOp::WriterLeaseGet,
            Self::WriterLeaseList { .. } => CommandOp::WriterLeaseList,
            Self::FileMutationReadback { .. } => CommandOp::FileMutationReadback,
            Self::FileApplyPatch { .. } => CommandOp::FileApplyPatch,
            Self::SourceTreeApply { .. } => CommandOp::SourceTreeApply,
            Self::SourceTreeReadback { .. } => CommandOp::SourceTreeReadback,
            Self::GoalMutation { request, .. } => match request.command.kind() {
                forge_domain::GoalMutationKind::Create => CommandOp::GoalCreate,
                forge_domain::GoalMutationKind::Revise => CommandOp::GoalRevise,
                forge_domain::GoalMutationKind::Complete => CommandOp::GoalComplete,
                forge_domain::GoalMutationKind::Pause
                | forge_domain::GoalMutationKind::Resume
                | forge_domain::GoalMutationKind::Block
                | forge_domain::GoalMutationKind::Fail
                | forge_domain::GoalMutationKind::Cancel => CommandOp::GoalTransition,
            },
            Self::GoalMutationReadback { .. } => CommandOp::GoalMutationReadback,
            Self::GoalReview { .. } => CommandOp::GoalReview,
            Self::DagPlanCommit { .. } => CommandOp::DagPlanCommit,
            Self::DagPlanReadback { .. } => CommandOp::DagPlanReadback,
            Self::LocationRegister { .. } => CommandOp::LocationRegister,
            Self::LocationState { .. } => CommandOp::LocationState,
            Self::WorkspaceDoctor { .. } => CommandOp::WorkspaceDoctor,
            Self::VerificationProjection { .. } => CommandOp::VerificationProjection,
            Self::ExecutionInventory { .. } => CommandOp::ExecutionInventory,
            Self::ExecutionObserve { .. } => CommandOp::ExecutionObserve,
            Self::ActivityBootstrap { .. } => CommandOp::ActivityBootstrap,
            Self::ApprovalGet { .. } => CommandOp::ApprovalGet,
            Self::ApprovalApproveOnce { .. } => CommandOp::ApprovalApproveOnce,
            Self::ApprovalReject { .. } => CommandOp::ApprovalReject,
            Self::ApprovalPending { .. } => CommandOp::ApprovalPending,
            Self::DiffList { .. } => CommandOp::DiffList,
            Self::DiffInventory { .. } => CommandOp::DiffInventory,
            Self::DiffDoctor { .. } => CommandOp::DiffDoctor,
            Self::DiffRetentionPlan { .. } => CommandOp::DiffRetentionPlan,
            Self::DiffArtifactDoctor { .. } => CommandOp::DiffArtifactDoctor,
            Self::WriterLeaseRecoveryRelease { .. } => CommandOp::WriterLeaseRecoveryRelease,
            Self::ActivitySuccessorCreate { .. } => CommandOp::ActivitySuccessorCreate,
            Self::ActivitySuccessorGet { .. } => CommandOp::ActivitySuccessorGet,
            Self::ActivityExpiredSuccessorRecoveryProbe { .. } => {
                CommandOp::ActivityExpiredSuccessorRecoveryProbe
            }
            Self::ActivityExpiredSuccessorRecover { .. } => {
                CommandOp::ActivityExpiredSuccessorRecover
            }
            Self::ActivityExpiredSuccessorRecoveryGet { .. } => {
                CommandOp::ActivityExpiredSuccessorRecoveryGet
            }
            Self::ActivityUnstartedContinuationProbe { .. } => {
                CommandOp::ActivityUnstartedContinuationProbe
            }
            Self::ActivityUnstartedContinuationRun { .. } => {
                CommandOp::ActivityUnstartedContinuationRun
            }
            Self::ActivityUnstartedContinuationGet { .. } => {
                CommandOp::ActivityUnstartedContinuationGet
            }
            Self::ActivityCoordinatorGet { .. } => CommandOp::ActivityCoordinatorGet,
            Self::ActivityCoordinatorActorGet { .. } => CommandOp::ActivityCoordinatorActorGet,
            Self::ActivityCoordinatorClaim { .. } => CommandOp::ActivityCoordinatorClaim,
            Self::AgentList { .. } => CommandOp::AgentList,
            Self::AgentGetContext { .. } => CommandOp::AgentGetContext,
            Self::AgentCoordinationGet { .. } => CommandOp::AgentCoordinationGet,
            Self::AgentInboxList { .. } => CommandOp::AgentInboxList,
            Self::AgentSetFocus { .. } => CommandOp::AgentSetFocus,
            Self::AgentPublishWork { .. } => CommandOp::AgentPublishWork,
            Self::AgentAssignmentMutate { .. } => CommandOp::AgentAssignmentMutate,
            Self::AgentAssignmentGet { .. } => CommandOp::AgentAssignmentGet,
            Self::AgentAssignmentList { .. } => CommandOp::AgentAssignmentList,
            Self::CommandSubmit { .. } => CommandOp::CommandSubmit,
            Self::ShellSubmit { .. } => CommandOp::ShellSubmit,
        }
    }
}

/// Decode failure while parsing one typed command payload.
pub type ParseResult = Result<Command, ForgeError>;

/// Parse one typed command from the envelope op + payload.
#[allow(
    clippy::too_many_lines,
    reason = "One arm per op keeps the closed parse dispatch reviewable."
)]
pub fn parse_command(op: CommandOp, request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    match op {
        CommandOp::ActivityStartedLeaseResumeProbe
        | CommandOp::ActivityStartedLeaseResumeRun
        | CommandOp::ActivityStartedLeaseResumeGet => {
            activity_lease_resume::parse(op, request_id, payload)
        }
        CommandOp::ActivityQuiescentLeaseResumeProbe
        | CommandOp::ActivityQuiescentLeaseResumeRun
        | CommandOp::ActivityQuiescentLeaseResumeGet => {
            activity_quiescent_lease_resume::parse(op, request_id, payload)
        }
        CommandOp::WorkspaceStop | CommandOp::WorkspaceStopGet => {
            if request_id.is_nil() {
                return Err(ForgeError::invalid_input(
                    "transport request identity must be non-nil",
                ));
            }
            Ok(Command::WorkspaceStop {
                request_id,
                request: Box::new(workspace_stop::parse(op, payload)?),
            })
        }
        CommandOp::LocationRemovalProbe | CommandOp::LocationRemove => {
            Ok(Command::LocationRemoval {
                request_id,
                request: Box::new(location_removal::parse(op, payload)?),
            })
        }
        CommandOp::RecoveryLeaseGet
        | CommandOp::RecoveryLeaseClaim
        | CommandOp::RecoveryLeaseRenew
        | CommandOp::RecoveryLeaseRelease => Ok(Command::RecoveryLease {
            request_id,
            request: Box::new(recovery_leases::parse(op, payload)?),
        }),
        CommandOp::RecoveryMaintenanceRun | CommandOp::RecoveryMaintenanceGet => {
            Ok(Command::RecoveryMaintenance {
                request_id,
                request: Box::new(recovery_maintenance::parse(op, payload)?),
            })
        }
        CommandOp::WorkCutInventory
        | CommandOp::WorkCutPrepare
        | CommandOp::WorkCutGet
        | CommandOp::WorkCutDrain => Ok(Command::WorkCut {
            request_id,
            request: Box::new(work_cuts::parse(op, payload)?),
        }),
        CommandOp::ActivityLeaseRenew
        | CommandOp::ActivityLeaseRelease
        | CommandOp::ActivityLeaseRenewBatch
        | CommandOp::ActivityLeaseReleaseBatch => Ok(Command::ActivityLeases {
            request_id,
            request: Box::new(activity_leases::parse(op, payload)?),
        }),
        CommandOp::WorkspaceQueueSettingsReplace => Ok(Command::QueuePreference {
            request_id,
            request: Box::new(queue_preference::parse(payload)?),
        }),
        CommandOp::AgentOperationsDelegate
        | CommandOp::AgentOperationsDelegationGet
        | CommandOp::AgentBindingReserve
        | CommandOp::AgentBindingReservationGet
        | CommandOp::AgentBindingActivate
        | CommandOp::AgentBindingActivationGet
        | CommandOp::AgentSessionReconcile
        | CommandOp::AgentSessionReconciliationGet
        | CommandOp::AgentDepartureReconcile
        | CommandOp::AgentDepartureReconciliationGet => Ok(Command::BindingLifecycle {
            request_id,
            request: Box::new(binding_lifecycle::parse(op, payload)?),
        }),
        CommandOp::AgentBindingReject | CommandOp::AgentBindingRejectionGet => {
            Ok(Command::BindingRejection {
                request_id,
                request: Box::new(binding_rejection::parse(op, request_id, payload)?),
            })
        }
        CommandOp::AgentOperationsFreeze
        | CommandOp::AgentOperationsFreezeGet
        | CommandOp::AgentOperationsExport
        | CommandOp::AgentOperationsFreezeRelease => Ok(Command::AgentOperationsMigration {
            request_id,
            request: Box::new(agent_operations_migration::parse(op, payload)?),
        }),
        CommandOp::ActivityGet | CommandOp::ActivityClose => Ok(Command::ActivityLifecycle {
            request_id,
            request: activity_lifecycle::parse(op, payload)?,
        }),
        CommandOp::QueueStatus
        | CommandOp::WorkspaceQueueStatus
        | CommandOp::WorkspaceQueueSettings => Ok(Command::QueueObservation {
            request_id,
            request: queue_observation::parse(op, payload)?,
        }),
        CommandOp::GoalList | CommandOp::GoalDelete | CommandOp::GoalDeletePending => {
            parse_goal_cleanup(op, request_id, payload)
        }
        CommandOp::EffectFactOutbox => Ok(Command::EffectFactOutbox {
            request_id,
            request: Box::new(effect_facts::parse(payload)?),
        }),
        CommandOp::LocationList => parse_location_list(request_id, payload),
        CommandOp::WorkspaceList => parse_workspace_list(request_id, payload),
        CommandOp::WorkspaceDiscover => parse_workspace_discover(request_id, payload),
        CommandOp::WorkspaceResolve => parse_workspace_resolve(request_id, payload),
        CommandOp::ActivityList => activity_projection::parse_activity_list(request_id, payload),
        CommandOp::WorkspaceInventory => registry::parse_workspace_inventory(request_id, payload),
        CommandOp::WorkspaceRegister => registry::parse_workspace_register(request_id, payload),
        CommandOp::WorkspaceRegistrationProbe => {
            registry::parse_workspace_registration_probe(request_id, payload)
        }
        CommandOp::WorkspaceRootRecoveryProbe => {
            workspace_root_recovery::parse_probe(request_id, payload)
        }
        CommandOp::WorkspaceRootRecoveryPrepare => {
            workspace_root_recovery::parse_prepare(request_id, payload)
        }
        CommandOp::WorkspaceRootRecoveryCommit => {
            workspace_root_recovery::parse_commit(request_id, payload)
        }
        CommandOp::WorkspaceRootRecoveryReadback => {
            workspace_root_recovery::parse_readback(request_id, payload)
        }
        CommandOp::GoalCreate
        | CommandOp::GoalRevise
        | CommandOp::GoalTransition
        | CommandOp::GoalComplete => parse_goal_mutation(op, request_id, payload),
        CommandOp::GoalMutationReadback => Ok(Command::GoalMutationReadback {
            request_id,
            request: Box::new(goals::parse_readback(payload)?),
        }),
        CommandOp::GoalReview => parse_goal_review(request_id, payload),
        CommandOp::DagPlanCommit => {
            require_payload_bound(payload, crate::config::MAX_BODY_BYTES, op.as_str())?;
            Ok(Command::DagPlanCommit {
                request_id,
                request: Box::new(dag_plan::parse_commit(payload)?),
            })
        }
        CommandOp::DagPlanReadback => Ok(Command::DagPlanReadback {
            request_id,
            request: Box::new(dag_plan::parse_readback(payload)?),
        }),
        CommandOp::GoalRead => parse_goal_read(request_id, payload),
        CommandOp::DagReadCurrent => parse_dag_read(request_id, payload),
        CommandOp::NodeAssignmentRead => parse_node_assignment_read(request_id, payload),
        CommandOp::AgentAssignmentOfferSeal => Ok(Command::AgentAssignmentOfferSeal {
            request_id,
            request: Box::new(assignment_offer_seal::parse(payload)?),
        }),
        CommandOp::AgentAssignmentOfferSealGet => Ok(Command::AgentAssignmentOfferSealGet {
            request_id,
            request: Box::new(assignment_offer_seal::parse(payload)?),
        }),
        CommandOp::NodeStart => parse_node_start(request_id, payload),
        CommandOp::NodeComplete => parse_node_complete(request_id, payload),
        CommandOp::CommandList => parse_command_list(request_id, payload),
        CommandOp::ExecutionBegin
        | CommandOp::ExecutionCancel
        | CommandOp::ExecutionRead
        | CommandOp::ExecutionOutput
        | CommandOp::ExecutionGet
        | CommandOp::ExecutionWait => parse_execution_command(op, request_id, payload),
        CommandOp::DiffRead => parse_diff_read(request_id, payload),
        CommandOp::FileList => Ok(Command::FileList {
            request_id,
            request: Box::new(source::parse_file_list(payload)?),
        }),
        CommandOp::TextSearch => Ok(Command::TextSearch {
            request_id,
            request: Box::new(source::parse_text_search(payload)?),
        }),
        CommandOp::WriterLeaseAcquire
        | CommandOp::WriterLeaseRenew
        | CommandOp::WriterLeaseRelease
        | CommandOp::WriterLeaseGet
        | CommandOp::WriterLeaseList => parse_writer_lease_command(op, request_id, payload),
        CommandOp::SourceTreeApply => {
            require_payload_bound(payload, crate::config::MAX_BODY_BYTES, "source_tree.apply")?;
            Ok(Command::SourceTreeApply {
                request_id,
                request: Box::new(tree::parse_apply(payload)?),
            })
        }
        CommandOp::SourceTreeReadback => Ok(Command::SourceTreeReadback {
            request_id,
            request: Box::new(tree::parse_readback(payload)?),
        }),
        CommandOp::FileApplyPatch => {
            require_payload_bound(
                payload,
                MAX_SOURCE_MUTATION_PAYLOAD_BYTES,
                "file.apply_patch",
            )?;
            Ok(Command::FileApplyPatch {
                request_id,
                request: Box::new(source_write::parse_apply_patch(payload)?),
            })
        }
        CommandOp::FileMutationReadback => Ok(Command::FileMutationReadback {
            request_id,
            request: Box::new(mutation::parse_readback(payload)?),
        }),
        CommandOp::FileReadSlice => Ok(Command::FileReadSlice {
            request_id,
            request: Box::new(source::parse_file_read_slice(payload)?),
        }),
        CommandOp::LocationRegister => Ok(Command::LocationRegister {
            request_id,
            request: Box::new(registry::parse_location_register_payload(payload)?),
        }),
        CommandOp::LocationState => Ok(Command::LocationState {
            request_id,
            request: Box::new(registry::parse_location_state_payload(payload)?),
        }),
        CommandOp::WorkspaceDoctor => registry::parse_workspace_doctor(request_id, payload),
        CommandOp::VerificationProjection => {
            registry::parse_verification_projection(request_id, payload)
        }
        CommandOp::ExecutionInventory => Ok(Command::ExecutionInventory {
            request_id,
            command: Box::new(execution_observation::parse_inventory(payload)?),
        }),
        CommandOp::ExecutionObserve => Ok(Command::ExecutionObserve {
            request_id,
            command: Box::new(execution_observation::parse_observe(payload)?),
        }),
        CommandOp::ActivityBootstrap => {
            observability::parse_activity_bootstrap(request_id, payload)
        }
        CommandOp::ApprovalGet => observability::parse_approval_get(request_id, payload),
        CommandOp::ApprovalApproveOnce => approval::parse_approve_once(request_id, payload),
        CommandOp::ApprovalReject => approval::parse_reject(request_id, payload),
        CommandOp::ApprovalPending => observability::parse_approval_pending(request_id, payload),
        CommandOp::DiffList => observability::parse_diff_list(request_id, payload),
        CommandOp::DiffInventory => diff_inventory::parse(request_id, payload),
        CommandOp::DiffDoctor => observability::parse_diff_doctor(request_id, payload),
        CommandOp::DiffRetentionPlan => {
            observability::parse_diff_retention_plan(request_id, payload)
        }
        CommandOp::DiffArtifactDoctor => {
            observability::parse_diff_artifact_doctor(request_id, payload)
        }
        CommandOp::WriterLeaseRecoveryRelease => Ok(Command::WriterLeaseRecoveryRelease {
            request_id,
            request: Box::new(lease::parse_recovery_release(payload)?),
        }),
        CommandOp::ActivitySuccessorCreate => {
            agents::parse_activity_successor_create(request_id, payload)
        }
        CommandOp::ActivitySuccessorGet => {
            agents::parse_activity_successor_get(request_id, payload)
        }
        CommandOp::ActivityExpiredSuccessorRecoveryProbe => {
            activity_recovery::parse_probe(request_id, payload)
        }
        CommandOp::ActivityExpiredSuccessorRecover => {
            activity_recovery::parse_recover(request_id, payload)
        }
        CommandOp::ActivityExpiredSuccessorRecoveryGet => {
            activity_recovery::parse_get(request_id, payload)
        }
        CommandOp::ActivityUnstartedContinuationProbe => {
            activity_lease_continuation::parse_probe(request_id, payload)
        }
        CommandOp::ActivityUnstartedContinuationRun => {
            activity_lease_continuation::parse_run(request_id, payload)
        }
        CommandOp::ActivityUnstartedContinuationGet => {
            activity_lease_continuation::parse_get(request_id, payload)
        }
        CommandOp::ActivityCoordinatorGet => {
            agents::parse_activity_coordinator_get(request_id, payload)
        }
        CommandOp::ActivityCoordinatorActorGet => {
            agents::parse_activity_coordinator_actor_get(request_id, payload)
        }
        CommandOp::ActivityCoordinatorClaim => Ok(Command::ActivityCoordinatorClaim {
            request_id,
            request: Box::new(agents::parse_activity_coordinator_claim_payload(payload)?),
        }),
        CommandOp::AgentList => agents::parse_agent_list(request_id, payload),
        CommandOp::AgentGetContext => agents::parse_agent_get_context(request_id, payload),
        CommandOp::AgentCoordinationGet => {
            agents::parse_agent_coordination_get(request_id, payload)
        }
        CommandOp::AgentInboxList => Ok(Command::AgentInboxList {
            request_id,
            request: Box::new(agents::parse_agent_inbox_list_payload(payload)?),
        }),
        CommandOp::AgentSetFocus => agents::parse_agent_set_focus(request_id, payload),
        CommandOp::AgentPublishWork => agents::parse_agent_publish_work(request_id, payload),
        CommandOp::AgentAssignmentMutate => {
            assignments::parse_agent_assignment_mutate(request_id, payload)
        }
        CommandOp::AgentAssignmentGet => {
            assignments::parse_agent_assignment_get(request_id, payload)
        }
        CommandOp::AgentAssignmentList => {
            assignments::parse_agent_assignment_list(request_id, payload)
        }
        CommandOp::CommandSubmit => Ok(Command::CommandSubmit {
            request_id,
            request: Box::new(execution::parse_submission(
                payload,
                execution::SubmissionKind::SealedProjectCommand,
            )?),
        }),
        CommandOp::ShellSubmit => Ok(Command::ShellSubmit {
            request_id,
            request: Box::new(execution::parse_submission(
                payload,
                execution::SubmissionKind::Shell,
            )?),
        }),
    }
}

fn parse_goal_cleanup(op: CommandOp, request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    match op {
        CommandOp::GoalList => Ok(Command::GoalList {
            request_id,
            request: Box::new(goal_cleanup::parse_list(payload)?),
        }),
        CommandOp::GoalDelete => Ok(Command::GoalDelete {
            request_id,
            request: Box::new(goal_cleanup::parse_delete(payload)?),
        }),
        CommandOp::GoalDeletePending => Ok(Command::GoalDeletePending {
            request_id,
            request: Box::new(goal_cleanup::parse_pending(payload)?),
        }),
        _ => Err(ForgeError::internal()),
    }
}

fn parse_writer_lease_command(
    op: CommandOp,
    request_id: Uuid,
    payload: &serde_json::Value,
) -> ParseResult {
    match op {
        CommandOp::WriterLeaseAcquire => Ok(Command::WriterLeaseAcquire {
            request_id,
            request: Box::new(lease::parse_acquire(payload)?),
        }),
        CommandOp::WriterLeaseRenew => Ok(Command::WriterLeaseRenew {
            request_id,
            request: Box::new(lease::parse_renew(payload)?),
        }),
        CommandOp::WriterLeaseRelease => Ok(Command::WriterLeaseRelease {
            request_id,
            request: Box::new(lease::parse_release(payload)?),
        }),
        CommandOp::WriterLeaseGet => Ok(Command::WriterLeaseGet {
            request_id,
            request: Box::new(lease::parse_get(payload)?),
        }),
        CommandOp::WriterLeaseList => Ok(Command::WriterLeaseList {
            request_id,
            request: Box::new(lease::parse_list(payload)?),
        }),
        _ => Err(ForgeError::internal()),
    }
}

fn parse_execution_command(
    op: CommandOp,
    request_id: Uuid,
    payload: &serde_json::Value,
) -> ParseResult {
    match op {
        CommandOp::ExecutionBegin => parse_execution_begin(request_id, payload),
        CommandOp::ExecutionCancel => parse_execution_cancel(request_id, payload),
        CommandOp::ExecutionRead => parse_execution_read(request_id, payload),
        CommandOp::ExecutionOutput => parse_execution_output(request_id, payload),
        CommandOp::ExecutionGet => {
            let request = execution_evidence::parse(payload)?;
            Ok(Command::ExecutionGet {
                request_id,
                execution_id: request.execution_id(),
                request: Box::new(request),
            })
        }
        CommandOp::ExecutionWait => {
            let request = execution_wait::parse(payload)?;
            Ok(Command::ExecutionWait {
                request_id,
                execution_id: request.execution_id(),
                request: Box::new(request),
            })
        }
        _ => Err(ForgeError::internal()),
    }
}

fn parse_goal_mutation(
    op: CommandOp,
    request_id: Uuid,
    payload: &serde_json::Value,
) -> ParseResult {
    require_payload_bound(payload, crate::config::MAX_BODY_BYTES, op.as_str())?;
    let request = match op {
        CommandOp::GoalCreate => goals::parse_create(payload)?,
        CommandOp::GoalRevise => goals::parse_revise(payload)?,
        CommandOp::GoalTransition => goals::parse_transition(payload)?,
        CommandOp::GoalComplete => goals::parse_complete(payload)?,
        _ => return Err(ForgeError::internal()),
    };
    Ok(Command::GoalMutation {
        request_id,
        request: Box::new(request),
    })
}

fn parse_workspace_resolve(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        location_id: Uuid,
        expected_revision: i64,
        relative_root: String,
    }
    let body: Body = parse_body(payload, "workspace.resolve payload is invalid")?;
    Ok(Command::WorkspaceResolve {
        request_id,
        location_id: body.location_id,
        expected_revision: body.expected_revision,
        relative_root: body.relative_root,
    })
}

fn parse_location_list(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {}

    let _: Body = parse_body(payload, "location.list payload is invalid")?;
    Ok(Command::LocationList { request_id })
}

fn parse_workspace_list(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        location_id: Uuid,
        expected_revision: i64,
    }

    let body: Body = parse_body(payload, "workspace.list payload is invalid")?;
    Ok(Command::WorkspaceList {
        request_id,
        location_id: forge_domain::LocationId::from_uuid(body.location_id),
        expected_revision: decode_location_revision(body.expected_revision)?,
    })
}

fn parse_workspace_discover(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        location_id: Uuid,
        expected_revision: i64,
    }

    let body: Body = parse_body(payload, "workspace.discover payload is invalid")?;
    Ok(Command::WorkspaceDiscover {
        request_id,
        location_id: forge_domain::LocationId::from_uuid(body.location_id),
        expected_revision: decode_location_revision(body.expected_revision)?,
    })
}

fn parse_goal_read(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        goal_id: Uuid,
    }
    let body: Body = parse_body(payload, "goal.read payload is invalid")?;
    Ok(Command::GoalRead {
        request_id,
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
        goal_id: GoalId::from_uuid(body.goal_id),
    })
}

fn parse_goal_review(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        goal_id: Uuid,
    }
    let body: Body = parse_body(payload, "goal.review payload is invalid")?;
    Ok(Command::GoalReview {
        request_id,
        scope: decode_scope(&body.scope)?,
        activity_id: ActivityId::from_uuid(body.activity_id),
        goal_id: GoalId::from_uuid(body.goal_id),
    })
}

fn parse_dag_read(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        goal_id: Uuid,
    }
    let body: Body = parse_body(payload, "dag.read_current payload is invalid")?;
    Ok(Command::DagReadCurrent {
        request_id,
        scope: decode_scope(&body.scope)?,
        goal_id: GoalId::from_uuid(body.goal_id),
    })
}

fn parse_node_assignment_read(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        goal_id: Uuid,
        dag_revision: i64,
        node_id: Uuid,
    }
    let body: Body = parse_body(payload, "node.assignment_read payload is invalid")?;
    let revision = DagRevisionNumber::new(body.dag_revision)
        .map_err(|_| ForgeError::invalid_input("node.assignment_read DAG revision is invalid"))?;
    Ok(Command::NodeAssignmentRead {
        request_id,
        scope: decode_scope(&body.scope)?,
        node_scope: forge_persistence::DagNodeEvidenceScope::new(
            GoalId::from_uuid(body.goal_id),
            revision,
            DagNodeId::from_uuid(body.node_id),
        ),
    })
}

fn parse_node_start(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        actor: SessionActorDto,
        goal_id: Uuid,
        expected_goal_revision: i64,
        expected_dag_revision: i64,
        node_id: Uuid,
        expected_node_revision: i64,
        observed_at_ms: i64,
    }
    let body: Body = parse_body(payload, "node.start payload is invalid")?;
    if body.actor.workspace_id != body.scope.workspace_id {
        return Err(ForgeError::invalid_input(
            "actor Workspace does not match command scope",
        ));
    }
    Ok(Command::NodeStart {
        request_id,
        request: DagNodeStartRequest {
            scope: decode_scope(&body.scope)?,
            activity_id: ActivityId::from_uuid(body.activity_id),
            session_id: forge_domain::AgentSessionId::from_uuid(body.actor.session_id),
            principal: decode_principal(&body.actor.principal)?,
            goal_id: GoalId::from_uuid(body.goal_id),
            expected_goal_revision: decode_goal_revision(body.expected_goal_revision)?,
            expected_dag_revision: decode_dag_revision(body.expected_dag_revision)?,
            node_id: DagNodeId::from_uuid(body.node_id),
            expected_revision: decode_node_revision(body.expected_node_revision)?,
            observed_at: decode_timestamp(body.observed_at_ms)?,
        },
    })
}

fn parse_node_complete(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity_id: Uuid,
        actor: SessionActorDto,
        goal_id: Uuid,
        expected_goal_revision: i64,
        expected_dag_revision: i64,
        node_id: Uuid,
        expected_node_revision: i64,
        observed_at_ms: i64,
    }
    let body: Body = parse_body(payload, "node.complete payload is invalid")?;
    if body.actor.workspace_id != body.scope.workspace_id {
        return Err(ForgeError::invalid_input(
            "actor Workspace does not match command scope",
        ));
    }
    Ok(Command::NodeComplete {
        request_id,
        request: DagNodeCompleteRequest {
            scope: decode_scope(&body.scope)?,
            activity_id: ActivityId::from_uuid(body.activity_id),
            session_id: forge_domain::AgentSessionId::from_uuid(body.actor.session_id),
            principal: decode_principal(&body.actor.principal)?,
            goal_id: GoalId::from_uuid(body.goal_id),
            expected_goal_revision: decode_goal_revision(body.expected_goal_revision)?,
            expected_dag_revision: decode_dag_revision(body.expected_dag_revision)?,
            node_id: DagNodeId::from_uuid(body.node_id),
            expected_revision: decode_node_revision(body.expected_node_revision)?,
            observed_at: decode_timestamp(body.observed_at_ms)?,
        },
    })
}

fn parse_command_list(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        activity: ActivityDto,
    }
    let body: Body = parse_body(payload, "command.list payload is invalid")?;
    Ok(Command::CommandList {
        request_id,
        request: ProjectCommandListRequest {
            scope: decode_scope(&body.scope)?,
            activity: decode_file_activity(&body.activity)?,
        },
    })
}

fn parse_execution_begin(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    let request = execution::parse_begin(payload)?;
    let execution_id = request.authority.execution_id;
    Ok(Command::ExecutionBegin {
        request_id,
        request: Box::new(request),
        execution_id,
    })
}

fn parse_execution_read(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    let request = execution::parse_read(payload)?;
    let execution_id = request.authority.execution_id;
    Ok(Command::ExecutionRead {
        request_id,
        after_sequence: request.after_sequence,
        max_bytes: request.max_bytes,
        max_events: request.max_events,
        request: Box::new(request),
        execution_id,
    })
}

fn parse_execution_cancel(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    let request = execution::parse_cancel(payload)?;
    let execution_id = request.authority.execution_id;
    Ok(Command::ExecutionCancel {
        request_id,
        request: Box::new(request),
        execution_id,
    })
}

fn parse_execution_output(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    let request = execution::parse_output(payload)?;
    let execution_id = request.authority.execution_id;
    Ok(Command::ExecutionOutput {
        request_id,
        after_sequence: request.after_sequence,
        max_bytes: request.max_bytes,
        max_events: request.max_events,
        request: Box::new(request),
        execution_id,
    })
}

fn parse_diff_read(request_id: Uuid, payload: &serde_json::Value) -> ParseResult {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        diff_id: Uuid,
    }
    let body: Body = parse_body(payload, "diff.read payload is invalid")?;
    Ok(Command::DiffRead {
        request_id,
        scope: decode_scope(&body.scope)?,
        diff_id: forge_domain::DiffId::from_uuid(body.diff_id),
    })
}

fn parse_body<T: for<'de> Deserialize<'de>>(
    payload: &serde_json::Value,
    message: &'static str,
) -> Result<T, ForgeError> {
    T::deserialize(payload).map_err(|_| ForgeError::invalid_input(message))
}

/// Maximum compact JSON payload size before decoding a source mutation.
pub(crate) const MAX_SOURCE_MUTATION_PAYLOAD_BYTES: usize = 16 * 1024;

fn require_payload_bound(
    payload: &serde_json::Value,
    max_bytes: usize,
    operation: &'static str,
) -> Result<(), ForgeError> {
    // Count serialized bytes without allocating a second copy of the payload.
    struct PayloadBudget(usize);
    impl std::io::Write for PayloadBudget {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_sub(bytes.len())
                .ok_or_else(|| std::io::Error::other("source mutation payload exceeds bound"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(PayloadBudget(max_bytes), payload).map_err(|_| {
        ForgeError::invalid_input(format!("{operation} payload exceeds {max_bytes} bytes"))
    })
}

/// The synchronous dispatch table: one command -> one forge-control client
/// call, projected into a bounded JSON result. Runs on bridge worker threads.
#[allow(
    clippy::too_many_lines,
    reason = "One arm per op keeps the closed control dispatch reviewable."
)]
/// Client-side execution dependencies threaded through the bridge workers.
#[derive(Debug, Clone)]
pub struct BridgeClients {
    pub control: ForgeControlClient,
    pub execution: forge_control::ForgeExecutionCoordinatorClient,
    pub approval: forge_control::ForgeApprovalCoordinatorClient,
    pub runtime_instance_id: RuntimeInstanceId,
    pub backend_id: ForgeBackendId,
    pub issuer: OrchestrationIssuerId,
    pub product_cache_root: std::path::PathBuf,
    pub destination_id: Uuid,
}

pub(crate) fn execute_on_activity_lease(
    client: &forge_control::ActivityLeaseClient,
    command: &Command,
) -> Result<serde_json::Value, ForgeError> {
    match command {
        Command::ActivityLeases { request, .. } => activity_leases::execute(client, request),
        Command::ActivityLifecycle { request, .. } => {
            activity_lifecycle::execute_on_lease(client, request)
        }
        Command::ActivityBootstrap {
            scope,
            activity_id,
            runtime_instance_id,
            observed_at,
            lease_until,
            ..
        } => observability::execute_activity_bootstrap(
            client,
            scope,
            *activity_id,
            *runtime_instance_id,
            *observed_at,
            *lease_until,
        ),
        _ => Err(ForgeError::invalid_input(
            "command is outside the Activity lease lane",
        )),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "The dispatch table is one reviewed seam over the closed command family."
)]
pub fn execute_on_bridge(
    clients: &BridgeClients,
    command: &Command,
) -> Result<serde_json::Value, ForgeError> {
    match command {
        Command::ActivityStartedLeaseResume { request, .. } => {
            return activity_lease_resume::execute(clients, request);
        }
        Command::ActivityQuiescentLeaseResume { request, .. } => {
            return activity_quiescent_lease_resume::execute(clients, request);
        }
        Command::ActivityExpiredSuccessorRecoveryProbe { request, .. } => {
            return activity_recovery::execute_probe(clients, request);
        }
        Command::ActivityExpiredSuccessorRecover { request, .. } => {
            return activity_recovery::execute_recover(clients, request);
        }
        Command::ActivityExpiredSuccessorRecoveryGet { request, .. } => {
            return activity_recovery::execute_get(clients, request);
        }
        Command::ActivityUnstartedContinuationProbe { command, .. } => {
            return activity_lease_continuation::execute_probe(clients, command);
        }
        Command::ActivityUnstartedContinuationRun { command, .. } => {
            return activity_lease_continuation::execute_run(clients, command);
        }
        Command::ActivityUnstartedContinuationGet { request, .. } => {
            return activity_lease_continuation::execute_get(clients, request);
        }
        _ => {}
    }
    if let Command::WorkspaceStop { request, .. } = command {
        return workspace_stop::execute(clients, request);
    }
    if let Command::RecoveryMaintenance { request, .. } = command {
        return recovery_maintenance::execute(clients, request);
    }
    if let Command::WorkCut { request, .. } = command {
        return work_cuts::execute(clients, request);
    }
    let BridgeClients {
        control: client,
        execution,
        approval,
        runtime_instance_id,
        backend_id,
        issuer,
        product_cache_root,
        destination_id,
    } = clients;
    execute_on_bridge_inner(
        client,
        execution,
        approval,
        *runtime_instance_id,
        *backend_id,
        *issuer,
        product_cache_root,
        *destination_id,
        command,
    )
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "The dispatch table is one reviewed seam over the closed command family."
)]
fn execute_on_bridge_inner(
    client: &ForgeControlClient,
    execution: &forge_control::ForgeExecutionCoordinatorClient,
    approval: &forge_control::ForgeApprovalCoordinatorClient,
    runtime_instance_id: RuntimeInstanceId,
    backend_id: ForgeBackendId,
    issuer: OrchestrationIssuerId,
    product_cache_root: &std::path::Path,
    destination_id: Uuid,
    command: &Command,
) -> Result<serde_json::Value, ForgeError> {
    match command {
        Command::ActivityStartedLeaseResume { .. } => Err(ForgeError::invalid_input(
            "Started Activity recovery requires the configured bridge owner",
        )),
        Command::ActivityQuiescentLeaseResume { .. } => Err(ForgeError::invalid_input(
            "Quiescent Activity recovery requires the configured bridge owner",
        )),
        Command::WorkspaceStop { .. } => Err(ForgeError::invalid_input(
            "Workspace stop requires the configured bridge owner",
        )),
        Command::RecoveryMaintenance { .. } => Err(ForgeError::invalid_input(
            "recovery maintenance requires configured bridge owner",
        )),
        Command::WorkCut { .. } => Err(ForgeError::invalid_input(
            "work cut requires configured issuer bridge",
        )),
        Command::LocationRemoval { request, .. } => location_removal::execute(client, request),
        Command::RecoveryLease { request, .. } => recovery_leases::execute(client, request),
        Command::ActivityLeases { .. }
        | Command::ActivityLifecycle { .. }
        | Command::ActivityBootstrap { .. } => Err(ForgeError::invalid_input(
            "Activity lease commands require the dedicated lane",
        )),
        Command::QueuePreference { request, .. } => queue_preference::execute(client, request),
        Command::BindingLifecycle { request, .. } => {
            binding_lifecycle::execute(client, issuer, destination_id, request)
        }
        Command::BindingRejection { request, .. } => {
            binding_rejection::execute(client, issuer, destination_id, request)
        }
        Command::AgentOperationsMigration { request, .. } => {
            agent_operations_migration::execute(client, backend_id, destination_id, request)
        }
        Command::QueueObservation { request, .. } => queue_observation::execute(client, request),
        Command::GoalList { request, .. } => goal_cleanup::execute_list(client, request),
        Command::GoalDelete { request, .. } => {
            goal_cleanup::execute_delete(client, product_cache_root, request)
        }
        Command::GoalDeletePending { request, .. } => {
            goal_cleanup::execute_pending(client, request)
        }
        Command::EffectFactOutbox { request, .. } => {
            effect_facts::execute(client, backend_id, destination_id, request)
        }
        Command::LocationList { .. } => execute_location_list(client),
        Command::ActivityList { request, .. } => {
            activity_projection::execute_activity_list(client, request)
        }
        Command::WorkspaceInventory {
            location_id,
            expected_revision,
            ..
        } => registry::execute_workspace_inventory(client, *location_id, *expected_revision),
        Command::WorkspaceRegister { request, .. } => {
            registry::execute_workspace_register(client, request)
        }
        Command::WorkspaceRegistrationProbe { locator, .. } => {
            registry::execute_workspace_registration_probe(client, locator)
        }
        Command::WorkspaceRootRecoveryProbe { request, .. } => {
            workspace_root_recovery::execute_probe(client, request)
        }
        Command::WorkspaceRootRecoveryPrepare { request, .. } => {
            workspace_root_recovery::execute_prepare(client, request)
        }
        Command::WorkspaceRootRecoveryCommit { request, .. } => {
            workspace_root_recovery::execute_commit(client, request)
        }
        Command::WorkspaceRootRecoveryReadback { request, .. } => {
            workspace_root_recovery::execute_readback(client, request)
        }
        Command::WorkspaceList {
            location_id,
            expected_revision,
            ..
        } => execute_workspace_list(client, *location_id, *expected_revision),
        Command::WorkspaceDiscover {
            location_id,
            expected_revision,
            ..
        } => execute_workspace_discover(client, *location_id, *expected_revision),
        Command::WorkspaceResolve {
            location_id,
            expected_revision,
            relative_root,
            ..
        } => execute_workspace_resolve(client, *location_id, *expected_revision, relative_root),
        Command::GoalRead {
            scope,
            activity_id,
            goal_id,
            ..
        } => execute_goal_read(client, scope, *activity_id, *goal_id),
        Command::DagReadCurrent { scope, goal_id, .. } => execute_dag_read(client, scope, *goal_id),
        Command::NodeAssignmentRead {
            scope, node_scope, ..
        } => execute_node_assignment_read(client, scope, *node_scope),
        Command::AgentAssignmentOfferSeal { request, .. } => {
            assignment_offer_seal::execute_seal(client, request)
        }
        Command::AgentAssignmentOfferSealGet { request, .. } => {
            assignment_offer_seal::execute_get(client, request)
        }
        Command::NodeStart { request, .. } => execute_node_start(client, request),
        Command::NodeComplete { request, .. } => execute_node_complete(client, request),
        Command::CommandList { request, .. } => execute_command_list(client, request),
        Command::ExecutionBegin { request, .. } => {
            execution::execute_begin(client, approval, backend_id, issuer, request)
        }
        Command::ExecutionCancel { request, .. } => execution::execute_cancel(execution, request),
        Command::ExecutionRead { request, .. } | Command::ExecutionOutput { request, .. } => {
            execution::execute_read(client, request)
        }
        Command::ExecutionGet { request, .. } => execution_evidence::execute_get(client, request),
        Command::ExecutionWait { .. } => Err(ForgeError::invalid_input(
            "execution.wait requires async admission",
        )),
        Command::DiffRead { scope, diff_id, .. } => execute_diff_read(client, scope, *diff_id),
        Command::FileList { request, .. } => source::execute_file_list(client, request),
        Command::TextSearch { request, .. } => source::execute_text_search(client, request),
        Command::FileReadSlice { request, .. } => source::execute_file_read_slice(client, request),
        Command::WriterLeaseAcquire { request, .. } => lease::execute_acquire(client, request),
        Command::WriterLeaseRenew { request, .. } => lease::execute_renew(client, request),
        Command::WriterLeaseRelease { request, .. } => lease::execute_release(client, request),
        Command::WriterLeaseGet { request, .. } => lease::execute_get(client, request),
        Command::WriterLeaseList { request, .. } => lease::execute_list(client, request),
        Command::GoalMutation { request, .. } => goals::execute_mutation(client, request),
        Command::GoalMutationReadback { request, .. } => goals::execute_readback(client, request),
        Command::GoalReview {
            scope,
            activity_id,
            goal_id,
            ..
        } => goals::execute_review(client, scope, *activity_id, *goal_id),
        Command::DagPlanCommit { request, .. } => dag_plan::execute_commit(client, request),
        Command::DagPlanReadback { request, .. } => dag_plan::execute_readback(client, request),
        Command::SourceTreeApply { request, .. } => tree::execute_apply(client, request),
        Command::SourceTreeReadback { request, .. } => tree::execute_readback(client, request),
        Command::FileApplyPatch { request, .. } => {
            source_write::execute_apply_patch(client, request)
        }
        Command::FileMutationReadback { request, .. } => {
            mutation::execute_readback(client, request)
        }
        Command::LocationRegister { request, .. } => {
            registry::execute_location_register(client, request)
        }
        Command::LocationState { request, .. } => registry::execute_location_state(client, request),
        Command::WorkspaceDoctor { scope, .. } => registry::execute_workspace_doctor(client, scope),
        Command::VerificationProjection { scope, .. } => {
            registry::execute_verification_projection(client, scope)
        }
        Command::ExecutionInventory { command, .. } => {
            execution_observation::execute_inventory(client, command)
        }
        Command::ExecutionObserve { command, .. } => {
            execution_observation::execute_observe(client, command)
        }
        Command::ApprovalGet {
            scope, approval_id, ..
        } => observability::execute_approval_get(client, scope, *approval_id),
        Command::ApprovalApproveOnce { request, .. } => {
            approval::execute_approve_once(client, request)
        }
        Command::ApprovalReject { request, .. } => approval::execute_reject(client, request),
        Command::ApprovalPending { scope, .. } => {
            observability::execute_approval_pending(approval, scope)
        }
        Command::DiffInventory {
            scope, activity_id, ..
        } => diff_inventory::execute(client, scope, *activity_id),
        Command::DiffList {
            scope, activity_id, ..
        } => observability::execute_diff_list(client, scope, *activity_id),
        Command::DiffDoctor { scope, diff_id, .. } => {
            observability::execute_diff_doctor(client, scope, *diff_id)
        }
        Command::DiffRetentionPlan {
            scope, keep_recent, ..
        } => observability::execute_diff_retention_plan(client, scope, *keep_recent),
        Command::DiffArtifactDoctor { scope, .. } => {
            observability::execute_diff_artifact_doctor(client, scope)
        }
        Command::WriterLeaseRecoveryRelease { request, .. } => {
            lease::execute_recovery_release(client, request)
        }
        Command::ActivitySuccessorCreate {
            scope,
            command,
            principal,
            ..
        } => agents::execute_activity_successor_create(
            client,
            forge_control::ActivitySuccessorCreateRequest {
                scope: scope.clone(),
                command: **command,
                principal: *principal,
            },
        ),
        Command::ActivitySuccessorGet {
            scope,
            predecessor_activity_id,
            ..
        } => agents::execute_activity_successor_get(client, scope, *predecessor_activity_id),
        Command::ActivityExpiredSuccessorRecoveryProbe { .. }
        | Command::ActivityExpiredSuccessorRecover { .. }
        | Command::ActivityExpiredSuccessorRecoveryGet { .. }
        | Command::ActivityUnstartedContinuationProbe { .. }
        | Command::ActivityUnstartedContinuationRun { .. }
        | Command::ActivityUnstartedContinuationGet { .. } => Err(ForgeError::invalid_input(
            "expired Activity recovery requires the configured BridgeClients owner",
        )),
        Command::ActivityCoordinatorGet {
            scope, activity_id, ..
        } => agents::execute_activity_coordinator_get(client, scope, *activity_id),
        Command::ActivityCoordinatorActorGet {
            scope,
            activity_id,
            principal,
            ..
        } => {
            agents::execute_activity_coordinator_actor_get(client, scope, *activity_id, *principal)
        }
        Command::ActivityCoordinatorClaim { request, .. } => {
            agents::execute_activity_coordinator_claim(client, (**request).clone())
        }
        Command::AgentList {
            scope, activity_id, ..
        } => agents::execute_agent_list(client, scope, *activity_id),
        Command::AgentGetContext {
            scope,
            activity_id,
            agent_id,
            ..
        } => agents::execute_agent_get_context(client, scope, *activity_id, *agent_id),
        Command::AgentCoordinationGet {
            scope, activity_id, ..
        } => agents::execute_agent_coordination_get(client, scope, *activity_id),
        Command::AgentInboxList { request, .. } => {
            agents::execute_agent_inbox_list(client, (**request).clone())
        }
        Command::AgentSetFocus { request, .. } => {
            agents::execute_agent_set_focus(client, (**request).clone())
        }
        Command::AgentPublishWork { request, .. } => {
            agents::execute_agent_publish_work(client, (**request).clone())
        }
        Command::AgentAssignmentMutate { request, .. } => {
            assignments::execute_agent_assignment_mutate(client, (**request).clone())
        }
        Command::AgentAssignmentGet { request, .. } => {
            assignments::execute_agent_assignment_get(client, (**request).clone())
        }
        Command::AgentAssignmentList { request, .. } => {
            assignments::execute_agent_assignment_list(client, (**request).clone())
        }
        Command::CommandSubmit { request, .. } | Command::ShellSubmit { request, .. } => {
            execution::execute_submission(client, execution, approval, runtime_instance_id, request)
        }
    }
}

fn execute_location_list(client: &ForgeControlClient) -> Result<serde_json::Value, ForgeError> {
    let locations = client
        .location_list()
        .map_err(|error| forge_error_of_client(&error))?;
    Ok(json!({
        "entries": locations
            .iter()
            .map(|location| {
                json!({
                    "location_id": location.id().into_uuid(),
                    "display_name": location.name().as_str(),
                    "revision": location.revision().get(),
                    "state": match location.state() {
                        forge_domain::LocationState::Enabled => "enabled",
                        forge_domain::LocationState::Disabled => "disabled",
                    },
                })
            })
            .collect::<Vec<_>>(),
    }))
}

fn execute_workspace_list(
    client: &ForgeControlClient,
    location_id: forge_domain::LocationId,
    expected_revision: forge_domain::LocationRevision,
) -> Result<serde_json::Value, ForgeError> {
    let entries = client
        .workspace_list(location_id, expected_revision)
        .map_err(|error| forge_error_of_client(&error))?;
    Ok(json!({
        "entries": entries
            .iter()
            .map(|entry| {
                json!({
                    "locator": entry.locator().encode(),
                    "display_name": entry.display_name(),
                    "workspace_id": entry.workspace_id().into_uuid(),
                    "workspace_revision": entry.workspace_revision().get(),
                })
            })
            .collect::<Vec<_>>(),
    }))
}

fn execute_workspace_discover(
    client: &ForgeControlClient,
    location_id: forge_domain::LocationId,
    expected_revision: forge_domain::LocationRevision,
) -> Result<serde_json::Value, ForgeError> {
    let entries = client
        .workspace_discover(location_id, expected_revision)
        .map_err(|error| forge_error_of_client(&error))?;
    Ok(json!({
        "entries": entries
            .iter()
            .map(|entry| {
                let signals = workspace_discovery_signals(entry.signals());
                json!({
                    "locator": entry.locator().encode(),
                    "kind": workspace_candidate_kind_wire(entry.kind()),
                    "display_name": entry.display_name(),
                    "signals": { "present": signals },
                    "disposition": workspace_discovery_disposition_wire(entry.disposition()),
                    "reason": workspace_discovery_reason_wire(entry.reason()),
                })
            })
            .collect::<Vec<_>>(),
    }))
}

fn workspace_candidate_kind_wire(kind: forge_workspace::WorkspaceCandidateKind) -> &'static str {
    match kind {
        forge_workspace::WorkspaceCandidateKind::LocationRoot => "location_root",
        forge_workspace::WorkspaceCandidateKind::DirectChild => "direct_child",
    }
}

fn workspace_discovery_signals(signals: forge_workspace::WorkspaceSignals) -> Vec<&'static str> {
    let mut present = Vec::with_capacity(4);
    if signals.cargo_workspace() {
        present.push("cargo_workspace");
    }
    if signals.git_repository() {
        present.push("git_repository");
    }
    if signals.agent_instructions() {
        present.push("agent_instructions");
    }
    if signals.forge_state() {
        present.push("forge_state");
    }
    present
}

fn workspace_discovery_disposition_wire(
    disposition: forge_workspace::WorkspaceDiscoveryDisposition,
) -> &'static str {
    match disposition {
        forge_workspace::WorkspaceDiscoveryDisposition::Candidate => "candidate",
        forge_workspace::WorkspaceDiscoveryDisposition::Ignored => "ignored",
        forge_workspace::WorkspaceDiscoveryDisposition::NotWorkspace => "not_workspace",
    }
}

fn workspace_discovery_reason_wire(
    reason: forge_workspace::WorkspaceDiscoveryReason,
) -> &'static str {
    match reason {
        forge_workspace::WorkspaceDiscoveryReason::RegisteredLocationRoot => {
            "registered_location_root"
        }
        forge_workspace::WorkspaceDiscoveryReason::ForgeState => "forge_state",
        forge_workspace::WorkspaceDiscoveryReason::CargoWorkspace => "cargo_workspace",
        forge_workspace::WorkspaceDiscoveryReason::GitRepository => "git_repository",
        forge_workspace::WorkspaceDiscoveryReason::AgentInstructions => "agent_instructions",
        forge_workspace::WorkspaceDiscoveryReason::VcsMetadata => "vcs_metadata",
        forge_workspace::WorkspaceDiscoveryReason::ForgeInternalState => "forge_internal_state",
        forge_workspace::WorkspaceDiscoveryReason::BuildOutput => "build_output",
        forge_workspace::WorkspaceDiscoveryReason::DependencyCache => "dependency_cache",
        forge_workspace::WorkspaceDiscoveryReason::FrameworkCache => "framework_cache",
        forge_workspace::WorkspaceDiscoveryReason::CoverageOutput => "coverage_output",
        forge_workspace::WorkspaceDiscoveryReason::Cache => "cache",
        forge_workspace::WorkspaceDiscoveryReason::Temporary => "temporary",
        forge_workspace::WorkspaceDiscoveryReason::PythonCache => "python_cache",
        forge_workspace::WorkspaceDiscoveryReason::VirtualEnvironment => "virtual_environment",
        forge_workspace::WorkspaceDiscoveryReason::HiddenMetadata => "hidden_metadata",
        forge_workspace::WorkspaceDiscoveryReason::NoWorkspaceSignals => "no_workspace_signals",
    }
}

fn execute_workspace_resolve(
    client: &ForgeControlClient,
    location_id: Uuid,
    expected_revision: i64,
    relative_root: &str,
) -> Result<serde_json::Value, ForgeError> {
    let locator = forge_control::WorkspaceLocator::new(
        forge_domain::LocationId::from_uuid(location_id),
        decode_location_revision(expected_revision)?,
        std::path::Path::new(relative_root),
    )
    .map_err(|_| ForgeError::invalid_input("workspace.resolve locator is invalid"))?;
    let scope = client
        .resolve_workspace(
            forge_domain::LocationId::from_uuid(location_id),
            decode_location_revision(expected_revision)?,
            locator,
        )
        .map_err(|error| forge_error_of_client(&error))?;
    Ok(json!({
        "workspace_id": scope.workspace_id().into_uuid(),
        "workspace_revision": scope.workspace_revision().get(),
    }))
}

fn execute_goal_read(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
    goal_id: GoalId,
) -> Result<serde_json::Value, ForgeError> {
    let goal = client
        .goal_get(scope.clone(), activity_id, goal_id)
        .map_err(|error| forge_error_of_client(&error))?;
    Ok(match goal {
        Some(goal) => plan::goal_json(&goal),
        None => json!({ "found": false }),
    })
}

fn execute_dag_read(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    goal_id: GoalId,
) -> Result<serde_json::Value, ForgeError> {
    let revision = client
        .dag_get_current(scope.clone(), goal_id)
        .map_err(|error| forge_error_of_client(&error))?;
    Ok(match revision {
        Some(revision) => plan::dag_json(&revision)?,
        None => json!({ "found": false }),
    })
}

fn execute_node_assignment_read(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    node_scope: forge_persistence::DagNodeEvidenceScope,
) -> Result<serde_json::Value, ForgeError> {
    let snapshot = client
        .dag_node_assignment_snapshot(scope.clone(), node_scope)
        .map_err(|error| forge_error_of_client(&error))?;
    let Some(snapshot) = snapshot else {
        return Ok(json!({ "found": false }));
    };
    Ok(json!({
        "found": true,
        "workspace_id": snapshot.workspace_id().into_uuid(),
        "activity_id": snapshot.activity_id().into_uuid(),
        "goal_id": snapshot.scope().goal_id().into_uuid(),
        "goal_created_at_ms": snapshot.goal_created_at().get(),
        "goal_revision": snapshot.goal_revision().get(),
        "dag_base_goal_revision": snapshot.dag_base_goal_revision().get(),
        "dag_revision": snapshot.scope().dag_revision().get(),
        "head_revision": snapshot.head().revision().get(),
        "current_dag_revision": snapshot.head().dag_revision().get(),
        "node_id": snapshot.scope().node_id().into_uuid(),
        "node_revision": snapshot.node_revision().get(),
        "assignment": snapshot.assignment().map(node_assignment_json),
    }))
}

fn node_assignment_json(assignment: forge_domain::AgentAssignmentSummary) -> serde_json::Value {
    use forge_domain::AgentAssignmentState;
    let state = match assignment.state() {
        AgentAssignmentState::Offered => "offered",
        AgentAssignmentState::Running => "running",
        AgentAssignmentState::Submitted => "submitted",
        AgentAssignmentState::Accepted => "accepted",
        AgentAssignmentState::Rejected => "rejected",
        AgentAssignmentState::Cancelled => "cancelled",
        AgentAssignmentState::Interrupted => "interrupted",
    };
    json!({
        "assignment_id": assignment.id().into_uuid(),
        "assignment_revision": assignment.revision().get(),
        "target_agent_id": assignment.target_agent_id().into_uuid(),
        "target_session_id": assignment.target_session_id().into_uuid(),
        "goal_revision": assignment.goal_revision().get(),
        "dag_head_revision": assignment.dag_head_revision().get(),
        "node_revision": assignment.node_revision().get(),
        "state": state,
        "cancellation_requested": assignment.cancellation_requested(),
    })
}

fn execute_node_start(
    client: &ForgeControlClient,
    request: &DagNodeStartRequest,
) -> Result<serde_json::Value, ForgeError> {
    let node = client
        .dag_node_start(request.clone())
        .map_err(|error| forge_error_of_client(&error))?;
    Ok(node_lifecycle_json(&node))
}

fn execute_node_complete(
    client: &ForgeControlClient,
    request: &DagNodeCompleteRequest,
) -> Result<serde_json::Value, ForgeError> {
    let node = client
        .dag_node_complete(request.clone())
        .map_err(|error| forge_error_of_client(&error))?;
    Ok(node_lifecycle_json(&node))
}

/// Full node lifecycle readback from the same in-transaction
/// `RegisteredDagNode` the native projection consumes: identity and DAG
/// references, canonical lifecycle vocabulary with its durable reason, the
/// node revision, and the transition timestamp. The legacy `state` field is
/// retained additively for existing readers.
fn node_lifecycle_json(node: &forge_domain::RegisteredDagNode) -> serde_json::Value {
    json!({
        "node_id": node.id().into_uuid(),
        "state": format!("{:?}", node.lifecycle()),
        "goal_id": node.goal_id().into_uuid(),
        "dag_revision": node.dag_revision().get(),
        "node_revision": node.revision().get(),
        "lifecycle": plan::dag_lifecycle_json(node.lifecycle()),
        "lifecycle_reason": plan::dag_lifecycle_reason_json(node.lifecycle()),
        "updated_at_ms": node.updated_at().get(),
    })
}

fn execute_command_list(
    client: &ForgeControlClient,
    request: &ProjectCommandListRequest,
) -> Result<serde_json::Value, ForgeError> {
    let result = client
        .project_command_list(request.clone())
        .map_err(|error| forge_error_of_client(&error))?;
    let catalog_fingerprint = result.fingerprint().hash().into_bytes();
    let commands = result
        .commands()
        .iter()
        .map(|command| {
            let request_digest = result
                .request_digest(command.id())
                .map_err(|error| ForgeError::from_control_view(&error.view()))?;
            Ok(json!({
                "id": command.id().as_str(),
                "class": project_command_class_json(command.class()),
                "request_digest": encode_hex(request_digest.as_bytes()),
            }))
        })
        .collect::<Result<Vec<_>, ForgeError>>()?;
    Ok(json!({
        "activity_id": result.activity_id().into_uuid(),
        "command_count": result.commands().len(),
        "catalog_fingerprint": encode_hex(&catalog_fingerprint),
        "commands": commands,
    }))
}

/// Canonical per-command classification matching the sealed project-command
/// catalog semantics (`verify` reads the Workspace for disposable CI output;
/// `generated_package` emits a Forge-owned generated artifact).
const fn project_command_class_json(value: forge_domain::ProjectCommandClass) -> &'static str {
    match value {
        forge_domain::ProjectCommandClass::Verify => "verify",
        forge_domain::ProjectCommandClass::GeneratedPackage => "generated_package",
    }
}

fn execute_diff_read(
    client: &ForgeControlClient,
    scope: &ResolvedWorkspaceScope,
    diff_id: forge_domain::DiffId,
) -> Result<serde_json::Value, ForgeError> {
    let result = client
        .diff_read(forge_control::DiffReadRequest {
            scope: scope.clone(),
            diff_id,
        })
        .map_err(|error| forge_error_of_client(&error))?;
    Ok(json!({
        "diff_id": result.evidence().id().into_uuid(),
        "health": diff_health_json(result.health()),
        "has_content": result.content().is_some(),
        "scope": source::scope_json(result.scope())?,
        "diff": diff_evidence_json(result.evidence()),
        "content": result.content(),
    }))
}

/// Full durable Diff evidence projection from the same in-transaction
/// `RegisteredDiffEvidence` the native path reads: attribution, bounded entry
/// summaries with base64 paths, payload state with hash/size metadata when the
/// payload projection carries them, contract versions, timestamps, and
/// revision. The artifact content itself is read once by the same control
/// operation and emitted under `content`; its size stays bounded by the
/// existing control-layer Diff artifact limits and the HTTP response bound.
pub(crate) fn diff_evidence_json(
    value: &forge_domain::RegisteredDiffEvidence,
) -> serde_json::Value {
    let (origin, mutation_id) = match value.origin() {
        forge_domain::DiffOrigin::FileMutation(id) => ("file_mutation", Some(id.into_uuid())),
        forge_domain::DiffOrigin::TreeChangeSet => ("tree_change_set", None),
    };
    let (compressed_hash, uncompressed_hash, compressed_size, uncompressed_size) =
        diff_payload_metadata_json(value.payload());
    let (relative_path, pending_path, final_path) = diff_payload_paths_json(value.payload());
    json!({
        "diff_id": value.id().into_uuid(),
        "workspace_id": value.workspace_id().into_uuid(),
        "activity_id": value.activity_id().into_uuid(),
        "change_set_id": value.change_set_id().into_uuid(),
        "origin": origin,
        "origin_mutation_id": mutation_id,
        "entries": value
            .entries()
            .iter()
            .map(diff_entry_json)
            .collect::<Vec<_>>(),
        "state": diff_state_json(value.state()),
        "render_kind": diff_render_kind_json(value.payload().render_kind()),
        "compressed_hash": compressed_hash,
        "uncompressed_hash": uncompressed_hash,
        "compressed_size_bytes": compressed_size,
        "uncompressed_size_bytes": uncompressed_size,
        "relative_path_base64": relative_path,
        "pending_relative_path_base64": pending_path,
        "final_relative_path_base64": final_path,
        "renderer_version": value.renderer_version().get(),
        "redaction_policy_version": value.redaction_policy_version().get(),
        "created_at_ms": value.created_at().get(),
        "updated_at_ms": value.updated_at().get(),
        "revision": value.revision().get(),
    })
}

fn diff_payload_paths_json(
    payload: &forge_domain::DiffPayloadProjection,
) -> (Option<String>, Option<String>, Option<String>) {
    use base64::Engine as _;
    let encode = |path: &forge_domain::DiffArtifactRelativePath| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(path.as_path().as_os_str().as_encoded_bytes())
    };
    match payload {
        forge_domain::DiffPayloadProjection::IntentText {
            pending_relative_path,
            final_relative_path,
            ..
        } => (
            None,
            Some(encode(pending_relative_path)),
            Some(encode(final_relative_path)),
        ),
        forge_domain::DiffPayloadProjection::Ready { relative_path, .. }
        | forge_domain::DiffPayloadProjection::PurgePending { relative_path, .. } => {
            (Some(encode(relative_path)), None, None)
        }
        forge_domain::DiffPayloadProjection::IntentSummary { .. }
        | forge_domain::DiffPayloadProjection::SummaryOnly { .. }
        | forge_domain::DiffPayloadProjection::Abandoned { .. }
        | forge_domain::DiffPayloadProjection::Tombstoned { .. } => (None, None, None),
    }
}

fn diff_entry_json(entry: &forge_domain::DiffEntrySummary) -> serde_json::Value {
    json!({
        "subject": match entry.subject() { forge_domain::DiffEntrySubject::File => "file", forge_domain::DiffEntrySubject::Directory => "directory" },
        "primary_path_base64":source::encode_relative_path(entry.primary_path()),
        "secondary_path_base64":entry.secondary_path().map(source::encode_relative_path),
        "change_kind":diff_change_kind_json(entry.kind()),
        "additions":entry.additions().get(),"deletions":entry.deletions().get(),
    })
}

const fn diff_change_kind_json(kind: forge_domain::DiffChangeKind) -> &'static str {
    match kind {
        forge_domain::DiffChangeKind::Created => "created",
        forge_domain::DiffChangeKind::Modified => "modified",
        forge_domain::DiffChangeKind::Deleted => "deleted",
        forge_domain::DiffChangeKind::Moved => "moved",
    }
}

/// Hash/size metadata is only present on payload projections that carry the
/// committed artifact reference; summary/tombstone states project nulls.
pub(crate) fn diff_payload_metadata_json(
    value: &forge_domain::DiffPayloadProjection,
) -> (
    serde_json::Value,
    serde_json::Value,
    serde_json::Value,
    serde_json::Value,
) {
    match value {
        forge_domain::DiffPayloadProjection::IntentText {
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
            ..
        }
        | forge_domain::DiffPayloadProjection::Ready {
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
            ..
        }
        | forge_domain::DiffPayloadProjection::PurgePending {
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
            ..
        } => (
            json!(compressed_hash.to_string()),
            json!(uncompressed_hash.to_string()),
            json!(compressed_size.get()),
            json!(uncompressed_size.get()),
        ),
        forge_domain::DiffPayloadProjection::IntentSummary { .. }
        | forge_domain::DiffPayloadProjection::SummaryOnly { .. }
        | forge_domain::DiffPayloadProjection::Abandoned { .. }
        | forge_domain::DiffPayloadProjection::Tombstoned { .. } => (
            serde_json::Value::Null,
            serde_json::Value::Null,
            serde_json::Value::Null,
            serde_json::Value::Null,
        ),
    }
}

const fn diff_state_json(value: forge_domain::DiffEvidenceState) -> &'static str {
    match value {
        forge_domain::DiffEvidenceState::Intent => "intent",
        forge_domain::DiffEvidenceState::Ready => "ready",
        forge_domain::DiffEvidenceState::SummaryOnly => "summary_only",
        forge_domain::DiffEvidenceState::Abandoned => "abandoned",
        forge_domain::DiffEvidenceState::PurgePending => "purge_pending",
        forge_domain::DiffEvidenceState::Tombstoned => "tombstoned",
    }
}

const fn diff_render_kind_json(value: forge_domain::DiffRenderKind) -> &'static str {
    match value {
        forge_domain::DiffRenderKind::Text => "text",
        forge_domain::DiffRenderKind::Binary => "binary",
        forge_domain::DiffRenderKind::Oversized => "oversized",
        forge_domain::DiffRenderKind::Structured => "structured",
    }
}

pub(crate) const fn diff_health_json(value: forge_domain::DiffArtifactHealth) -> &'static str {
    match value {
        forge_domain::DiffArtifactHealth::Available => "available",
        forge_domain::DiffArtifactHealth::NotApplicable => "not_applicable",
        forge_domain::DiffArtifactHealth::Archived => "archived",
        forge_domain::DiffArtifactHealth::Missing => "missing",
        forge_domain::DiffArtifactHealth::Corrupt => "corrupt",
    }
}

fn forge_error_of_client(error: &forge_control::ControlClientError) -> ForgeError {
    ForgeError::from_control_client_error(error)
}

pub(crate) fn decode_scope(scope: &ScopeDto) -> Result<ResolvedWorkspaceScope, ForgeError> {
    let locator = forge_control::WorkspaceLocator::new(
        forge_domain::LocationId::from_uuid(scope.locator.location_id),
        forge_domain::LocationRevision::new(scope.locator.expected_revision)
            .map_err(|_| ForgeError::invalid_input("scope location revision is invalid"))?,
        std::path::Path::new(scope.locator.relative_root.as_str()),
    )
    .map_err(|_| ForgeError::invalid_input("scope locator is invalid"))?;
    Ok(ResolvedWorkspaceScope::from_observation(
        WorkspaceId::from_uuid(scope.workspace_id),
        forge_domain::WorkspaceRevision::new(scope.workspace_revision)
            .map_err(|_| ForgeError::invalid_input("scope revision is invalid"))?,
        locator,
    ))
}

/// Build the exact Started Activity lease-resume digest used by the wire
/// parser so a trusted in-process Source supervisor need not copy the DTO or
/// canonical JSON algorithm.
pub fn started_activity_lease_resume_request_digest(
    scope: &ResolvedWorkspaceScope,
    request_id: Uuid,
    probe: &forge_domain::StartedActivityLeaseResumeProbe,
) -> Result<[u8; 32], ForgeError> {
    let scope_value = source::scope_json(scope)?;
    let scope_dto: ScopeDto =
        serde_json::from_value(scope_value).map_err(|_| ForgeError::internal())?;
    activity_lease_resume::canonical_request_digest_for_probe(&scope_dto, request_id, probe)
}

/// Build the exact Quiescent Activity lease-resume digest used by the wire
/// parser for trusted in-process Source supervisors.
pub fn quiescent_activity_lease_resume_request_digest(
    scope: &ResolvedWorkspaceScope,
    request_id: Uuid,
    probe: &forge_domain::QuiescentActivityLeaseResumeProbe,
) -> Result<[u8; 32], ForgeError> {
    let scope_value = source::scope_json(scope)?;
    let scope_dto: ScopeDto =
        serde_json::from_value(scope_value).map_err(|_| ForgeError::internal())?;
    activity_quiescent_lease_resume::canonical_request_digest_for_probe(
        &scope_dto, request_id, probe,
    )
}

fn decode_file_activity(
    activity: &ActivityDto,
) -> Result<forge_control::FileActivityScope, ForgeError> {
    Ok(forge_control::FileActivityScope {
        activity_id: ActivityId::from_uuid(activity.activity_id),
        runtime_instance_id: forge_domain::RuntimeInstanceId::from_uuid(
            activity.runtime_instance_id,
        ),
        observed_at: decode_timestamp(activity.observed_at_ms)?,
    })
}

fn decode_approval_activity(
    activity: &ActivityDto,
) -> Result<forge_control::ApprovalActivityScope, ForgeError> {
    Ok(forge_control::ApprovalActivityScope {
        activity_id: ActivityId::from_uuid(activity.activity_id),
        runtime_instance_id: forge_domain::RuntimeInstanceId::from_uuid(
            activity.runtime_instance_id,
        ),
        observed_at: decode_timestamp(activity.observed_at_ms)?,
    })
}

fn decode_principal(
    principal: &PrincipalDto,
) -> Result<forge_domain::AuthenticatedPrincipal, ForgeError> {
    match (principal.kind, principal.token_id, principal.grant_id) {
        (PrincipalKindDto::TrustedStdio, None, None) => {
            Ok(forge_domain::AuthenticatedPrincipal::TrustedStdio)
        }
        (PrincipalKindDto::DirectToken, Some(token_id), None) if !token_id.is_nil() => {
            Ok(forge_domain::AuthenticatedPrincipal::DirectToken(
                forge_domain::DirectTokenId::from_uuid(token_id),
            ))
        }
        (PrincipalKindDto::OAuthGrant, None, Some(grant_id)) if !grant_id.is_nil() => {
            Ok(forge_domain::AuthenticatedPrincipal::OAuthGrant(
                forge_domain::OAuthGrantId::from_uuid(grant_id),
            ))
        }
        _ => Err(ForgeError::invalid_input(
            "principal identity fields do not match principal kind",
        )),
    }
}

fn decode_location_revision(value: i64) -> Result<forge_domain::LocationRevision, ForgeError> {
    forge_domain::LocationRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("revision is invalid"))
}

fn decode_goal_revision(value: i64) -> Result<GoalRevision, ForgeError> {
    GoalRevision::new(value).map_err(|_| ForgeError::invalid_input("goal revision is invalid"))
}

fn decode_grant_revision(value: i64) -> Result<ExecutionGrantRevision, ForgeError> {
    ExecutionGrantRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("grant revision is invalid"))
}

fn decode_dag_revision(value: i64) -> Result<DagRevisionNumber, ForgeError> {
    DagRevisionNumber::new(value).map_err(|_| ForgeError::invalid_input("dag revision is invalid"))
}

fn decode_node_revision(value: i64) -> Result<DagNodeRevision, ForgeError> {
    DagNodeRevision::new(value).map_err(|_| ForgeError::invalid_input("node revision is invalid"))
}

fn decode_timestamp(value: i64) -> Result<TimestampMillis, ForgeError> {
    TimestampMillis::new(value).map_err(|_| ForgeError::invalid_input("timestamp is invalid"))
}

fn decode_sequence(value: u64) -> Result<forge_domain::ExecutionOutputSequence, ForgeError> {
    forge_domain::ExecutionOutputSequence::new(value)
        .map_err(|_| ForgeError::invalid_input("output sequence is invalid"))
}

fn decode_digest_hex(value: &str) -> Result<ExecutionRequestDigest, ForgeError> {
    let bytes = decode_hex(value)?;
    let Ok(digest) = <[u8; ExecutionRequestDigest::BYTE_LEN]>::try_from(bytes.as_slice()) else {
        return Err(ForgeError::invalid_input(
            "request digest must be 64 hex characters",
        ));
    };
    Ok(ExecutionRequestDigest::from_bytes(digest))
}

fn decode_catalog_fingerprint(
    value: &str,
) -> Result<forge_domain::ProjectCommandCatalogFingerprint, ForgeError> {
    let bytes = decode_hex(value)?;
    let Ok(hash) = <[u8; forge_domain::FileContentHash::BYTE_LEN]>::try_from(bytes.as_slice())
    else {
        return Err(ForgeError::invalid_input(
            "catalog fingerprint must be 64 hex characters",
        ));
    };
    Ok(forge_domain::ProjectCommandCatalogFingerprint::from_hash(
        forge_domain::FileContentHash::from_bytes(hash),
    ))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ForgeError> {
    let bytes = value.as_bytes();
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ForgeError::invalid_input(
            "hex encoding must have even length",
        ));
    }
    let mut decoded = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let Some(high) = hex_nibble(pair[0]) else {
            return Err(ForgeError::invalid_input("hex encoding is invalid"));
        };
        let Some(low) = hex_nibble(pair[1]) else {
            return Err(ForgeError::invalid_input("hex encoding is invalid"));
        };
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
