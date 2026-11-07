//! Bounded, transaction-local source inventory for a Home transfer.
//!
//! This is a historical capture of exact Forge rows. It deliberately exposes
//! no `ready`, `drained`, or `settled` conclusion; those require separate
//! source-owner receipts and an explicit later decision.

use std::collections::{BTreeMap, BTreeSet};
use std::{
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::PathBuf,
};

use forge_domain::{
    AgentAssignmentState, AgentAttachmentState, AgentInstanceId, AgentSessionId,
    AuthenticatedPrincipal, HomeTransferSourceRequest, RegisteredAgentInstance, TimestampMillis,
    WorkspaceId,
};
use rusqlite::{Connection, Transaction, params, params_from_iter, types::Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    workspace_agent_assignments, workspace_agent_binding_activation,
    workspace_agent_binding_rejections, workspace_agent_binding_reservations, workspace_agents,
};

pub(super) const INVENTORY_VERSION: u8 = 3;
pub(super) const CURRENT_NON_HOME_INVENTORY_VERSION: u8 = 2;
pub(crate) const MAX_HOME_SOURCE_AGENTS: usize = 256;
pub(crate) const MAX_HOME_SOURCE_ENTRIES: usize = 1024;
pub(crate) const MAX_HOME_SOURCE_INVENTORY_BYTES: usize = 512 * 1024;
const MAX_HOME_SOURCE_SESSIONS: usize = 128;
const QUERY_PROBE_EXTRA: usize = 1;

fn source_query_limit(maximum_rows: usize) -> Result<i64, HomeTransferSourceInventoryError> {
    let probe = maximum_rows
        .checked_add(QUERY_PROBE_EXTRA)
        .ok_or(HomeTransferSourceInventoryError::Bounds("query limit"))?;
    i64::try_from(probe).map_err(|_| HomeTransferSourceInventoryError::Bounds("query limit"))
}

/// Failure while capturing or validating one complete Home-transfer source.
#[derive(Debug, Error)]
pub enum HomeTransferSourceInventoryError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Agent(#[from] crate::AgentStoreError),
    #[error(transparent)]
    Assignment(#[from] crate::AgentAssignmentStoreError),
    #[error(transparent)]
    BindingReservation(#[from] crate::AgentBindingReservationError),
    #[error(transparent)]
    BindingActivation(#[from] crate::AgentBindingActivationError),
    #[error(transparent)]
    BindingRejection(#[from] crate::AgentBindingRejectionStoreError),
    #[error(transparent)]
    ReservationRetirement(#[from] crate::workspace_home_transfers::HomeTransferStoreError),
    #[error(transparent)]
    WriterLease(#[from] crate::WriterLeaseStoreError),
    #[error(transparent)]
    Execution(#[from] crate::ExecutionStoreError),
    #[error(transparent)]
    Approval(#[from] crate::ApprovalStoreError),
    #[error(transparent)]
    ChangeSet(#[from] crate::ChangeSetStoreError),
    #[error("Home-transfer source inventory has too many {0}")]
    Bounds(&'static str),
    #[error("Home-transfer source Workspace identity or revision changed")]
    WorkspaceConflict,
    #[error("a known Operations binding is missing or differs from the captured Source Agent")]
    BindingConflict,
    #[error("Home-transfer source row is missing during exact in-transaction readback")]
    SourceRowMissing,
    #[error("Home-transfer source inventory is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("Home-transfer source inventory payload is {actual} bytes; maximum is {maximum}")]
    PayloadTooLarge { actual: usize, maximum: usize },
    #[error("Home-transfer source inventory does not match the supplied request")]
    RequestMismatch,
}
/// A complete immutable Source snapshot captured in the caller's IMMEDIATE
/// transaction. Vectors are sorted by their canonical Source IDs.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HomeTransferSourceInventory {
    pub(crate) version: u8,
    pub(crate) request_digest: [u8; 32],
    pub(crate) workspace_id: Uuid,
    pub(crate) workspace_revision: i64,
    pub(crate) session_ids: Vec<Uuid>,
    pub(crate) agents: Vec<SourceAgent>,
    pub(crate) reservations: Vec<SourceBindingReservation>,
    pub(crate) assignments: Vec<SourceAssignment>,
    pub(crate) writer_leases: Vec<SourceWriterLease>,
    pub(crate) executions: Vec<SourceExecution>,
    pub(crate) closed_execution_count: u64,
    pub(crate) closed_execution_digest: [u8; 32],
    pub(crate) closed_execution_high_water_ms: i64,
    pub(crate) approvals: Vec<SourceApproval>,
    pub(crate) change_sets: Vec<SourceChangeSet>,
    pub(crate) affected_activity_ids: Vec<Uuid>,
    pub(crate) affected_agent_ids: Vec<Uuid>,
    pub(crate) source_high_water_ms: i64,
}

impl HomeTransferSourceInventory {
    /// Capture all target-session Agent rows and their current Activity-owned
    /// work from exactly the caller's SQLite snapshot. Sessions are an Ops
    /// attestation, not a claim that Forge can discover Profile membership.
    #[allow(
        clippy::too_many_lines,
        reason = "the complete source census and related owner captures share one transaction"
    )]
    pub(crate) fn capture(
        tx: &Transaction<'_>,
        request: &HomeTransferSourceRequest,
    ) -> Result<Self, HomeTransferSourceInventoryError> {
        validate_workspace(tx, request)?;

        let session_ids = request
            .sessions()
            .iter()
            .map(|session| session.into_uuid())
            .collect::<Vec<_>>();
        let agents = load_source_agents(tx, request.scope().workspace_id(), request.sessions())?;
        validate_known_bindings(request, &agents)?;

        let mut affected_activities = agents
            .iter()
            .map(|agent| agent.activity_id)
            .collect::<BTreeSet<_>>();
        let agent_ids = agents
            .iter()
            .map(|agent| agent.agent_id)
            .collect::<BTreeSet<_>>();

        let reservations = load_binding_reservations(tx, request, &mut affected_activities)?;
        validate_affected_activities(tx, request.scope().workspace_id(), &affected_activities)?;
        let assignments = load_assignments(tx, request.scope().workspace_id(), &agent_ids)?;
        let writer_leases = load_writer_leases(tx, request.scope().workspace_id(), &agent_ids)?;
        let approvals = load_approvals(
            tx,
            request.scope().workspace_id(),
            &session_ids,
            &agent_ids,
            &affected_activities,
        )?;
        let ExecutionCapture {
            pending: executions,
            closed_count,
            closed_digest,
            closed_high_water_ms,
        } = load_executions(
            tx,
            request.scope().workspace_id(),
            &session_ids,
            &agent_ids,
            &affected_activities,
            &approvals,
        )?;
        let change_sets =
            load_change_sets(tx, request.scope().workspace_id(), &affected_activities)?;

        enforce_entry_bound(source_entry_count(
            agents.len(),
            reservations.len(),
            assignments.len(),
            writer_leases.len(),
            executions.len(),
            &approvals,
            &change_sets,
        )?)?;

        let mut source_high_water_ms = 0_i64;
        for agent in &agents {
            source_high_water_ms = source_high_water_ms.max(agent.updated_at_ms);
        }
        for reservation in &reservations {
            source_high_water_ms = source_high_water_ms
                .max(reservation.requested_at_ms)
                .max(reservation.reserved_at_ms)
                .max(reservation.outcome.observed_at_ms());
        }
        for assignment in &assignments {
            source_high_water_ms = source_high_water_ms.max(assignment.updated_at_ms);
        }
        for lease in &writer_leases {
            source_high_water_ms = source_high_water_ms.max(lease.updated_at_ms);
        }
        for execution in &executions {
            source_high_water_ms = source_high_water_ms.max(execution.updated_at_ms);
            if let SourceNativeClosure::Present { observed_at_ms, .. } = &execution.closure {
                source_high_water_ms = source_high_water_ms.max(*observed_at_ms);
            }
        }
        source_high_water_ms = source_high_water_ms.max(closed_high_water_ms);
        for approval in &approvals {
            source_high_water_ms = source_high_water_ms.max(approval.updated_at_ms);
            if let SourceApprovalGrant::Present {
                consumed_at_ms: Some(consumed_at_ms),
                ..
            } = &approval.grant
            {
                source_high_water_ms = source_high_water_ms.max(*consumed_at_ms);
            }
        }
        for change_set in &change_sets {
            source_high_water_ms = source_high_water_ms.max(change_set.updated_at_ms);
        }

        let inventory = Self {
            version: current_inventory_version(&assignments),
            request_digest: *request.request_digest().as_bytes(),
            workspace_id: request.scope().workspace_id().into_uuid(),
            workspace_revision: request.scope().workspace_revision().get(),
            session_ids,
            agents,
            reservations,
            assignments,
            writer_leases,
            executions,
            closed_execution_count: closed_count,
            closed_execution_digest: closed_digest,
            closed_execution_high_water_ms: closed_high_water_ms,
            approvals,
            change_sets,
            affected_activity_ids: affected_activities.into_iter().collect(),
            affected_agent_ids: agent_ids.into_iter().collect(),
            source_high_water_ms,
        };
        inventory.validate_shape()?;
        Ok(inventory)
    }

    /// Validate a typed inventory decoded by the `HomeJournal`'s bounded binary
    /// codec against the exact immutable Operations request.
    pub(crate) fn validate_for_request(
        &self,
        request: &HomeTransferSourceRequest,
    ) -> Result<(), HomeTransferSourceInventoryError> {
        self.validate_shape()?;
        if !supported_inventory_version(self.version)
            || self.request_digest != *request.request_digest().as_bytes()
            || self.workspace_id != request.scope().workspace_id().into_uuid()
            || self.workspace_revision != request.scope().workspace_revision().get()
            || self.session_ids
                != request
                    .sessions()
                    .iter()
                    .map(|session| session.into_uuid())
                    .collect::<Vec<_>>()
        {
            return Err(HomeTransferSourceInventoryError::RequestMismatch);
        }
        validate_known_bindings(request, &self.agents)?;
        Ok(())
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed typed snapshot is validated as one canonical storage contract"
    )]
    pub(crate) fn validate_shape(&self) -> Result<(), HomeTransferSourceInventoryError> {
        if !supported_inventory_version(self.version)
            || self.workspace_revision < 1
            || self.source_high_water_ms < 0
        {
            return Err(HomeTransferSourceInventoryError::Corrupt("header"));
        }
        if self.version < 2
            && self.reservations.iter().any(|reservation| {
                matches!(
                    &reservation.outcome,
                    SourceReservationOutcome::Retired { .. }
                )
            })
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "retirement requires inventory version 2",
            ));
        }
        if self.version < INVENTORY_VERSION
            && self.assignments.iter().any(|assignment| {
                matches!(
                    assignment.origin,
                    SourceAssignmentOrigin::HomeHandoff { .. }
                )
            })
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "Home handoff origin requires inventory version 3",
            ));
        }
        if self.session_ids.is_empty()
            || self.session_ids.len() > MAX_HOME_SOURCE_SESSIONS
            || self.agents.len() > MAX_HOME_SOURCE_AGENTS
        {
            return Err(HomeTransferSourceInventoryError::Bounds("identity census"));
        }
        if !strictly_sorted(&self.session_ids)
            || !strictly_sorted(&self.affected_activity_ids)
            || !strictly_sorted(&self.affected_agent_ids)
            || !strictly_sorted_by(&self.agents, |entry| entry.agent_id)
            || !strictly_sorted_by(&self.reservations, |entry| entry.request_id)
            || !strictly_sorted_by(&self.assignments, |entry| entry.assignment_id)
            || !strictly_sorted_by(&self.writer_leases, |entry| entry.lease_id)
            || !strictly_sorted_by(&self.executions, |entry| entry.execution_id)
            || !strictly_sorted_by(&self.approvals, |entry| entry.approval_id)
            || !strictly_sorted_by(&self.change_sets, |entry| entry.change_set_id)
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "noncanonical order",
            ));
        }
        let count = source_entry_count(
            self.agents.len(),
            self.reservations.len(),
            self.assignments.len(),
            self.writer_leases.len(),
            self.executions.len(),
            &self.approvals,
            &self.change_sets,
        )?;
        enforce_entry_bound(count)?;
        if self.closed_execution_high_water_ms < 0
            || self.closed_execution_high_water_ms > self.source_high_water_ms
            || (self.closed_execution_count == 0 && self.closed_execution_high_water_ms != 0)
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "closed execution witness",
            ));
        }
        let expected_agents = self
            .agents
            .iter()
            .map(|agent| agent.agent_id)
            .collect::<Vec<_>>();
        let expected_activities = self
            .agents
            .iter()
            .map(|agent| agent.activity_id)
            .chain(self.reservations.iter().filter_map(|record| {
                matches!(&record.outcome, SourceReservationOutcome::Pending)
                    .then_some(record.activity_id)
            }))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if self.affected_agent_ids != expected_agents
            || self.affected_activity_ids != expected_activities
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "affected identity sets",
            ));
        }
        let agent_by_id = self
            .agents
            .iter()
            .map(|agent| (agent.agent_id, agent))
            .collect::<BTreeMap<_, _>>();
        let mut observed_high_water_ms = self.closed_execution_high_water_ms;
        for agent in &self.agents {
            validate_agent(agent, self.workspace_id, &self.session_ids)?;
            observed_high_water_ms = observed_high_water_ms.max(agent.updated_at_ms);
        }
        for reservation in &self.reservations {
            validate_reservation(reservation, self.workspace_id, &self.session_ids)?;
            observed_high_water_ms = observed_high_water_ms
                .max(reservation.requested_at_ms)
                .max(reservation.reserved_at_ms)
                .max(reservation.outcome.observed_at_ms());
        }
        for assignment in &self.assignments {
            validate_assignment(assignment, self.workspace_id, &agent_by_id)?;
            observed_high_water_ms = observed_high_water_ms.max(assignment.updated_at_ms);
        }
        for lease in &self.writer_leases {
            validate_writer_lease(lease, self.workspace_id, &agent_by_id)?;
            observed_high_water_ms = observed_high_water_ms.max(lease.updated_at_ms);
        }
        for execution in &self.executions {
            validate_execution(
                execution,
                self.workspace_id,
                &self.session_ids,
                &agent_by_id,
            )?;
            observed_high_water_ms = observed_high_water_ms.max(execution.updated_at_ms);
            if let SourceNativeClosure::Present { observed_at_ms, .. } = &execution.closure {
                observed_high_water_ms = observed_high_water_ms.max(*observed_at_ms);
            }
        }
        for approval in &self.approvals {
            validate_approval(
                approval,
                self.workspace_id,
                &self.session_ids,
                &self.affected_activity_ids,
                &agent_by_id,
            )?;
            observed_high_water_ms = observed_high_water_ms.max(approval.updated_at_ms);
            if let SourceApprovalGrant::Present {
                consumed_at_ms: Some(consumed_at_ms),
                ..
            } = &approval.grant
            {
                observed_high_water_ms = observed_high_water_ms.max(*consumed_at_ms);
            }
        }
        for change_set in &self.change_sets {
            validate_change_set(change_set, self.workspace_id, &self.affected_activity_ids)?;
            observed_high_water_ms = observed_high_water_ms.max(change_set.updated_at_ms);
        }
        if observed_high_water_ms != self.source_high_water_ms {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "source high-water does not equal captured source facts",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceAgent {
    pub(crate) agent_id: Uuid,
    pub(crate) workspace_id: Uuid,
    pub(crate) activity_id: Uuid,
    pub(crate) session_id: Option<Uuid>,
    pub(crate) principal: SourcePrincipal,
    pub(crate) display_name: String,
    pub(crate) declared_role: String,
    pub(crate) transport: SourceTransport,
    pub(crate) attachment: SourceAttachment,
    pub(crate) revision: i64,
    pub(crate) created_at_ms: i64,
    pub(crate) updated_at_ms: i64,
    pub(crate) focus: SourceFocus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourcePrincipal {
    TrustedStdio,
    DirectToken(Uuid),
    OAuthGrant(Uuid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceTransport {
    Retired,
    Stdio,
    StreamableHttp,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceAttachment {
    Attached,
    Detached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceFocus {
    pub(crate) goal_id: Option<Uuid>,
    pub(crate) goal_revision: Option<i64>,
    pub(crate) dag_revision: Option<i64>,
    pub(crate) node_id: Option<Uuid>,
    pub(crate) node_revision: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceBindingReservation {
    pub(crate) request_id: Uuid,
    pub(crate) workspace_id: Uuid,
    pub(crate) activity_id: Uuid,
    pub(crate) migration_id: Uuid,
    pub(crate) destination_id: Uuid,
    pub(crate) freeze_revision: i64,
    pub(crate) agent_id: Uuid,
    pub(crate) session_id: Uuid,
    pub(crate) principal: SourcePrincipal,
    pub(crate) requested_at_ms: i64,
    pub(crate) reserved_at_ms: i64,
    pub(crate) outcome: SourceReservationOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceReservationOutcome {
    Pending,
    Activated {
        membership_digest: [u8; 32],
        display_name: String,
        declared_role: String,
        transport: SourceTransport,
        activated_at_ms: i64,
    },
    Rejected {
        request_digest: [u8; 32],
        receipt_digest: [u8; 32],
        rejected_at_ms: i64,
        reason: SourceRejectionReason,
    },
    Retired {
        preparation_id: Uuid,
        request_digest: [u8; 32],
        receipt_digest: [u8; 32],
        observed_at_ms: i64,
    },
}

impl SourceReservationOutcome {
    const fn observed_at_ms(&self) -> i64 {
        match self {
            Self::Pending => 0,
            Self::Activated {
                activated_at_ms, ..
            } => *activated_at_ms,
            Self::Rejected { rejected_at_ms, .. } => *rejected_at_ms,
            Self::Retired { observed_at_ms, .. } => *observed_at_ms,
        }
    }
}

pub(super) const fn supported_inventory_version(version: u8) -> bool {
    version >= 1 && version <= INVENTORY_VERSION
}

/// Preserve the schema-v72 v2 writer format unless Home-origin data requires v3.
pub(super) fn current_inventory_version(assignments: &[SourceAssignment]) -> u8 {
    if assignments.iter().any(|assignment| {
        matches!(
            assignment.origin,
            SourceAssignmentOrigin::HomeHandoff { .. }
        )
    }) {
        INVENTORY_VERSION
    } else {
        CURRENT_NON_HOME_INVENTORY_VERSION
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceRejectionReason {
    PrincipalTransportMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceAssignment {
    pub(crate) assignment_id: Uuid,
    pub(crate) origin: SourceAssignmentOrigin,
    pub(crate) workspace_id: Uuid,
    pub(crate) activity_id: Uuid,
    pub(crate) target_agent_id: Uuid,
    pub(crate) target_session_id: Uuid,
    pub(crate) target_principal: SourcePrincipal,
    pub(crate) target_agent_revision: i64,
    pub(crate) coordinator_agent_id: Uuid,
    pub(crate) coordinator_session_id: Uuid,
    pub(crate) coordinator_principal: SourcePrincipal,
    pub(crate) coordinator_revision: i64,
    pub(crate) state: SourceAssignmentState,
    pub(crate) cancellation_requested: bool,
    pub(crate) revision: i64,
    pub(crate) created_at_ms: i64,
    pub(crate) updated_at_ms: i64,
    pub(crate) credit_budget: Option<SourceWorkCreditBudget>,
    pub(crate) result_digest: Option<[u8; 32]>,
    pub(crate) goal_id: Uuid,
    pub(crate) goal_created_at_ms: i64,
    pub(crate) goal_revision: i64,
    pub(crate) dag_revision: i64,
    pub(crate) dag_head_revision: i64,
    pub(crate) node_id: Uuid,
    pub(crate) node_revision: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceWorkCreditBudget {
    One,
    Three,
    Five,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceAssignmentOrigin {
    CoordinatorOffer,
    CutContinuation {
        cut_id: Uuid,
        transfer_id: Uuid,
        predecessor_id: Uuid,
    },
    HomeHandoff {
        preparation_id: Uuid,
        handoff_id: Uuid,
        predecessor_id: Uuid,
        root_assignment_id: Uuid,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceAssignmentState {
    Offered,
    Running,
    Submitted,
    Accepted,
    Rejected,
    Cancelled,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceWriterLease {
    pub(crate) lease_id: Uuid,
    pub(crate) workspace_id: Uuid,
    pub(crate) activity_id: Uuid,
    pub(crate) agent_id: Uuid,
    pub(crate) state: SourceWriterLeaseState,
    pub(crate) revision: i64,
    pub(crate) acquired_at_ms: i64,
    pub(crate) updated_at_ms: i64,
    pub(crate) lease_until_ms: i64,
    pub(crate) entries: Vec<SourceWriterLeaseEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceWriterLeaseState {
    Active,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceWriterLeaseEntry {
    pub(crate) kind: SourceWriterLeaseScopeKind,
    pub(crate) path: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SourceWriterLeaseScopeKind {
    ExactPath,
    DirectorySubtree,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceExecution {
    pub(crate) execution_id: Uuid,
    pub(crate) workspace_id: Uuid,
    pub(crate) activity_id: Uuid,
    pub(crate) state: SourceExecutionState,
    pub(crate) revision: i64,
    pub(crate) request_digest: [u8; 32],
    pub(crate) created_at_ms: i64,
    pub(crate) updated_at_ms: i64,
    pub(crate) agent_id: Option<Uuid>,
    pub(crate) session_id: Option<Uuid>,
    pub(crate) agent_revision: Option<i64>,
    pub(crate) principal: Option<SourcePrincipal>,
    pub(crate) goal_id: Option<Uuid>,
    pub(crate) goal_revision: Option<i64>,
    pub(crate) dag_revision: Option<i64>,
    pub(crate) node_id: Option<Uuid>,
    pub(crate) node_revision: Option<i64>,
    pub(crate) command_id: Option<String>,
    pub(crate) project_command: Option<SourceProjectCommand>,
    pub(crate) closure: SourceNativeClosure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceProjectCommandClass {
    Verify,
    GeneratedPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceProjectCommand {
    pub(crate) class: SourceProjectCommandClass,
    pub(crate) catalog_fingerprint: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceExecutionState {
    Starting,
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Interrupted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceNativeClosure {
    Unknown,
    Present {
        before_revision: i64,
        after_revision: i64,
        observed_at_ms: i64,
        final_output_sequence: u64,
        launch: SourceClosureLaunch,
        runtime: SourceClosureRuntime,
        process: SourceClosureProcess,
    },
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceClosureLaunch {
    Baseline,
    RustCi,
    GeneratedPackage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceClosureRuntime {
    NotApplicable,
    Cleaned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceClosureProcess {
    NoChildSpawned,
    ProcessGroupReaped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceApproval {
    pub(crate) approval_id: Uuid,
    pub(crate) workspace_id: Uuid,
    pub(crate) activity_id: Uuid,
    pub(crate) execution_id: Uuid,
    pub(crate) request_digest: [u8; 32],
    pub(crate) action: SourceExecutionActionClass,
    pub(crate) requested_permissions: SourceExecutionPermissions,
    pub(crate) policy_revision: i64,
    pub(crate) state: SourceApprovalState,
    pub(crate) revision: i64,
    pub(crate) created_at_ms: i64,
    pub(crate) updated_at_ms: i64,
    pub(crate) expires_at_ms: i64,
    pub(crate) agent_binding_digest: Option<Vec<u8>>,
    pub(crate) attribution: SourceApprovalAttribution,
    pub(crate) grant: SourceApprovalGrant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceExecutionActionClass {
    DirectStructured,
    DiscoveredProjectCommand,
    ShellEscape,
    AnalyzedShell,
    GeneratedProjectCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceExecutionPermissions {
    pub(crate) workspace_read: bool,
    pub(crate) workspace_write: bool,
    pub(crate) network: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceApprovalState {
    Pending,
    Approved,
    AutoApproved,
    Rejected,
    Denied,
    Cancelled,
    Expired,
    Superseded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceApprovalAttribution {
    Known {
        agent_id: Uuid,
        session_id: Option<Uuid>,
        agent_revision: i64,
        principal: SourcePrincipal,
        goal_id: Uuid,
        goal_revision: i64,
        dag_revision: i64,
        node_id: Uuid,
        node_revision: i64,
        command_id: String,
        project_command: Option<SourceProjectCommand>,
    },
    LegacyUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceApprovalGrant {
    Unknown,
    Absent,
    Present {
        grant_id: Uuid,
        state: SourceExecutionGrantState,
        revision: i64,
        expires_at_ms: i64,
        consumed_at_ms: Option<i64>,
        request_digest: [u8; 32],
        action: SourceExecutionActionClass,
        effective_permissions: SourceExecutionPermissions,
        policy_revision: i64,
        source: SourceAuthorizationSource,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceExecutionGrantState {
    Active,
    Consumed,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceAuthorizationSource {
    ExplicitGrant,
    AutoApprovalScope,
    LegacyPlan06,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceChangeSet {
    pub(crate) change_set_id: Uuid,
    pub(crate) workspace_id: Uuid,
    pub(crate) activity_id: Uuid,
    pub(crate) runtime_instance_id: Uuid,
    pub(crate) workspace_revision: i64,
    pub(crate) activity_lease_revision: i64,
    pub(crate) state: SourceChangeSetState,
    pub(crate) source_tree_request_digest: Option<[u8; 32]>,
    pub(crate) revision: i64,
    pub(crate) created_at_ms: i64,
    pub(crate) updated_at_ms: i64,
    pub(crate) file_mutation: Option<SourceFileMutation>,
    pub(crate) tree_mutations: Vec<SourceTreeMutation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceChangeSetState {
    Starting,
    Applied,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceFileMutation {
    pub(crate) mutation_id: Uuid,
    pub(crate) path: Vec<u8>,
    pub(crate) kind: SourceFileMutationKind,
    pub(crate) precondition: SourceFilePrecondition,
    pub(crate) intended_hash: Option<[u8; 32]>,
    pub(crate) pre_state: SourceFilePathState,
    pub(crate) post_state: Option<SourceFilePathState>,
    pub(crate) revision: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceFileMutationKind {
    Create,
    Replace,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceFilePrecondition {
    Absent,
    Matches { expected_hash: [u8; 32] },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceFilePathState {
    Absent,
    Regular { hash: [u8; 32], size: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceTreeMutationKind {
    CreateDirectory,
    CreateFile,
    UpdateFile,
    DeleteFile,
    MoveFile,
    MoveDirectory,
    DeleteDirectory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceTreeMutation {
    pub(crate) mutation_id: Uuid,
    pub(crate) ordinal: i64,
    pub(crate) kind: SourceTreeMutationKind,
    pub(crate) primary_path: Vec<u8>,
    pub(crate) secondary_path: Option<Vec<u8>>,
    pub(crate) expected_hash: Option<[u8; 32]>,
    pub(crate) intended_hash: Option<[u8; 32]>,
    pub(crate) applied: bool,
    pub(crate) revision: i64,
}

fn validate_workspace(
    tx: &Transaction<'_>,
    request: &HomeTransferSourceRequest,
) -> Result<(), HomeTransferSourceInventoryError> {
    let (raw_id, raw_length, revision): (Vec<u8>, i64, i64) = tx.query_row(
        "SELECT substr(workspace_id, 1, 17), length(workspace_id), revision
         FROM workspace WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if raw_length != 16 {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "workspace identity length",
        ));
    }
    let workspace = decode_uuid(&raw_id, "workspace identity")?;
    if workspace != request.scope().workspace_id().into_uuid()
        || revision != request.scope().workspace_revision().get()
    {
        return Err(HomeTransferSourceInventoryError::WorkspaceConflict);
    }
    Ok(())
}

fn validate_affected_activities(
    tx: &Transaction<'_>,
    workspace_id: WorkspaceId,
    activities: &BTreeSet<Uuid>,
) -> Result<(), HomeTransferSourceInventoryError> {
    let activity_ids = activities.iter().copied().collect::<Vec<_>>();
    let mut observed = BTreeSet::new();
    for chunk in activity_ids.chunks(128) {
        let malformed: bool = tx.query_row(
            &format!(
                "SELECT EXISTS(
                     SELECT 1 FROM activities
                      WHERE substr(activity_id, 1, 16) IN ({})
                        AND (length(activity_id) != 16 OR length(workspace_id) != 16)
                 )",
                placeholders(chunk.len()),
            ),
            params_from_iter(chunk.iter().map(|id| Value::Blob(id_bytes(*id)))),
            |row| row.get(0),
        )?;
        if malformed {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "Activity identity length",
            ));
        }
        let mut statement = tx.prepare(&format!(
            "SELECT substr(activity_id, 1, 17), substr(workspace_id, 1, 17)
               FROM activities WHERE activity_id IN ({}) ORDER BY activity_id ASC",
            placeholders(chunk.len()),
        ))?;
        let rows = statement
            .query_map(
                params_from_iter(chunk.iter().map(|id| Value::Blob(id_bytes(*id)))),
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        for (raw_activity_id, raw_workspace_id) in rows {
            let activity_id = decode_uuid(&raw_activity_id, "Activity ID")?;
            let actual_workspace = decode_uuid(&raw_workspace_id, "Activity Workspace ID")?;
            if actual_workspace != workspace_id.into_uuid() {
                return Err(HomeTransferSourceInventoryError::BindingConflict);
            }
            observed.insert(activity_id);
        }
    }
    if &observed != activities {
        return Err(HomeTransferSourceInventoryError::SourceRowMissing);
    }
    Ok(())
}

fn load_source_agents(
    tx: &Transaction<'_>,
    workspace_id: WorkspaceId,
    sessions: &[AgentSessionId],
) -> Result<Vec<SourceAgent>, HomeTransferSourceInventoryError> {
    if sessions.is_empty() || sessions.len() > MAX_HOME_SOURCE_SESSIONS {
        return Err(HomeTransferSourceInventoryError::Bounds(
            "session identities",
        ));
    }
    let malformed_session: bool = tx.query_row(
        &format!(
            "SELECT EXISTS(
                 SELECT 1 FROM agent_instances
                  WHERE substr(workspace_id, 1, 16) = ?1
                    AND (length(workspace_id) != 16 OR length(session_id) != 16)
                    AND substr(session_id, 1, 16) IN ({})
             )",
            placeholders(sessions.len())
        ),
        params_from_iter(
            std::iter::once(Value::Blob(id_bytes(workspace_id.into_uuid()))).chain(
                sessions
                    .iter()
                    .map(|session| Value::Blob(id_bytes(session.into_uuid()))),
            ),
        ),
        |row| row.get(0),
    )?;
    if malformed_session {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "Agent workspace or Session identity length",
        ));
    }

    let mut values = Vec::with_capacity(sessions.len() + 2);
    values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
    values.extend(
        sessions
            .iter()
            .map(|session| Value::Blob(id_bytes(session.into_uuid()))),
    );
    values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_AGENTS)?));
    let sql = format!(
        "SELECT substr(agent_id, 1, 17)
           FROM agent_instances
          WHERE workspace_id = ? AND session_id IN ({})
          ORDER BY agent_id ASC LIMIT ?",
        placeholders(sessions.len())
    );
    let mut statement = tx.prepare(&sql)?;
    let raw_ids = statement
        .query_map(params_from_iter(values), |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if raw_ids.len() > MAX_HOME_SOURCE_AGENTS {
        return Err(HomeTransferSourceInventoryError::Bounds("Agent rows"));
    }

    let mut agents = Vec::with_capacity(raw_ids.len());
    for raw_id in raw_ids {
        let agent_id = AgentInstanceId::from_uuid(decode_uuid(&raw_id, "Agent ID")?);
        let agent = workspace_agents::get_in_transaction(tx, agent_id)?
            .ok_or(HomeTransferSourceInventoryError::SourceRowMissing)?;
        if agent.workspace_id() != workspace_id
            || !agent
                .session_id()
                .is_some_and(|session| sessions.contains(&session))
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "Agent census changed inside source transaction",
            ));
        }
        agents.push(source_agent(&agent));
    }
    if !strictly_sorted_by(&agents, |agent| agent.agent_id) {
        return Err(HomeTransferSourceInventoryError::Corrupt("Agent order"));
    }
    Ok(agents)
}

fn validate_known_bindings(
    request: &HomeTransferSourceRequest,
    agents: &[SourceAgent],
) -> Result<(), HomeTransferSourceInventoryError> {
    let by_id = agents
        .iter()
        .map(|agent| (AgentInstanceId::from_uuid(agent.agent_id), agent))
        .collect::<BTreeMap<_, _>>();
    for binding in request.bindings() {
        let Some(agent) = by_id.get(&binding.agent_id()) else {
            return Err(HomeTransferSourceInventoryError::BindingConflict);
        };
        if agent.workspace_id != request.scope().workspace_id().into_uuid()
            || agent.activity_id != binding.activity_id().into_uuid()
            || agent.session_id != Some(binding.session_id().into_uuid())
            || source_principal(binding.principal()) != agent.principal
        {
            return Err(HomeTransferSourceInventoryError::BindingConflict);
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "reservation and terminal receipt must be cross-validated in the same snapshot"
)]
fn load_binding_reservations(
    tx: &Transaction<'_>,
    request: &HomeTransferSourceRequest,
    affected_activities: &mut BTreeSet<Uuid>,
) -> Result<Vec<SourceBindingReservation>, HomeTransferSourceInventoryError> {
    let workspace_id = request.scope().workspace_id();
    let sessions = request.sessions();
    let malformed: bool = tx.query_row(
        &format!(
            "SELECT EXISTS(
                 SELECT 1 FROM agent_binding_reservations
                  WHERE substr(workspace_id, 1, 16) = ?1
                    AND (length(workspace_id) != 16 OR length(session_id) != 16)
                    AND substr(session_id, 1, 16) IN ({})
             )",
            placeholders(sessions.len()),
        ),
        params_from_iter(
            std::iter::once(Value::Blob(id_bytes(workspace_id.into_uuid()))).chain(
                sessions
                    .iter()
                    .map(|session| Value::Blob(id_bytes(session.into_uuid()))),
            ),
        ),
        |row| row.get(0),
    )?;
    if malformed {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "binding reservation identity length",
        ));
    }
    let sql = format!(
        "SELECT substr(request_id, 1, 17)
           FROM agent_binding_reservations
          WHERE workspace_id = ? AND session_id IN ({})
          ORDER BY request_id ASC LIMIT ?",
        placeholders(sessions.len())
    );
    let mut values = Vec::with_capacity(sessions.len() + 2);
    values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
    values.extend(
        sessions
            .iter()
            .map(|session| Value::Blob(id_bytes(session.into_uuid()))),
    );
    values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
    let mut statement = tx.prepare(&sql)?;
    let request_ids = statement
        .query_map(params_from_iter(values), |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if request_ids.len() > MAX_HOME_SOURCE_ENTRIES {
        return Err(HomeTransferSourceInventoryError::Bounds(
            "binding reservations",
        ));
    }

    let mut reservations = Vec::with_capacity(request_ids.len());
    for raw_id in request_ids {
        let request_id = decode_uuid(&raw_id, "binding request ID")?;
        let reservation = workspace_agent_binding_reservations::get(tx, request_id)?
            .ok_or(HomeTransferSourceInventoryError::SourceRowMissing)?;
        let request_row = reservation.request();
        if reservation.workspace_id() != workspace_id
            || !sessions.contains(&request_row.session_id())
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "binding reservation selector",
            ));
        }
        let activation = workspace_agent_binding_activation::get(tx, request_id)?;
        let rejection = workspace_agent_binding_rejections::get(tx, request_id)?;
        if activation.is_some() && rejection.is_some() {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "reservation has both activation and rejection receipts",
            ));
        }
        let retirement =
            crate::workspace_home_transfers::retirements::get_for_reservation(tx, request_id)?;
        if retirement.is_some() && (activation.is_some() || rejection.is_some()) {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "reservation retirement competes with activation or rejection",
            ));
        }
        let retirement_settled = if retirement.is_some() {
            if !crate::workspace_home_transfers::retirements::is_valid_settlement(tx, &reservation)?
            {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "reservation retirement is not a current settlement",
                ));
            }
            true
        } else {
            false
        };
        let outcome = if let Some(retirement) = retirement.filter(|_| retirement_settled) {
            let request = retirement.request();
            if request.reservation_request_id() != request_id {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "retirement reservation identity",
                ));
            }
            SourceReservationOutcome::Retired {
                preparation_id: request.preparation_id(),
                request_digest: *request.request_digest().as_bytes(),
                receipt_digest: *retirement.receipt_digest(),
                observed_at_ms: retirement.observed_at().get(),
            }
        } else if let Some(activation) = activation {
            if activation.reservation() != &reservation {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "activation source reservation",
                ));
            }
            SourceReservationOutcome::Activated {
                membership_digest: activation.membership_digest(),
                display_name: activation.display_name().as_str().to_owned(),
                declared_role: activation.declared_role().as_str().to_owned(),
                transport: source_transport(activation.transport()),
                activated_at_ms: activation.activated_at().get(),
            }
        } else if let Some(rejection) = rejection {
            let rejected_request = rejection.request();
            if rejection.workspace_id() != reservation.workspace_id()
                || rejection.activity_id() != request_row.activity_id()
                || rejection.agent_id() != request_row.agent_id()
                || rejection.session_id() != request_row.session_id()
                || rejection.principal() != request_row.principal()
                || rejected_request.migration_id() != reservation.migration_id()
                || rejected_request.destination_id() != reservation.destination_id()
                || rejected_request.expected_freeze_revision() != reservation.freeze_revision()
                || rejected_request.requested_at() != request_row.requested_at()
                || rejected_request.reserved_at() != reservation.reserved_at()
            {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "rejection source reservation",
                ));
            }
            SourceReservationOutcome::Rejected {
                request_digest: rejection.request_digest(),
                receipt_digest: rejection.receipt_digest(),
                rejected_at_ms: rejection.rejected_at().get(),
                reason: source_rejection_reason(rejection.reason()),
            }
        } else {
            SourceReservationOutcome::Pending
        };
        if matches!(outcome, SourceReservationOutcome::Pending) {
            affected_activities.insert(request_row.activity_id().into_uuid());
        }

        reservations.push(SourceBindingReservation {
            request_id,
            workspace_id: reservation.workspace_id().into_uuid(),
            activity_id: request_row.activity_id().into_uuid(),
            migration_id: reservation.migration_id(),
            destination_id: reservation.destination_id(),
            freeze_revision: i64::try_from(reservation.freeze_revision())
                .map_err(|_| HomeTransferSourceInventoryError::Corrupt("freeze revision"))?,
            agent_id: request_row.agent_id().into_uuid(),
            session_id: request_row.session_id().into_uuid(),
            principal: source_principal(request_row.principal()),
            requested_at_ms: request_row.requested_at().get(),
            reserved_at_ms: reservation.reserved_at().get(),
            outcome,
        });
    }
    reservations.sort_unstable_by_key(|record| record.request_id);
    Ok(reservations)
}

#[allow(
    clippy::too_many_lines,
    reason = "the bounded assignment census keeps target filtering and typed readback together"
)]
fn load_assignments(
    tx: &Transaction<'_>,
    workspace_id: WorkspaceId,
    agents: &BTreeSet<Uuid>,
) -> Result<Vec<SourceAssignment>, HomeTransferSourceInventoryError> {
    if agents.is_empty() {
        return Ok(Vec::new());
    }
    let mut assignment_ids = BTreeSet::new();
    let agent_ids = agents.iter().copied().collect::<Vec<_>>();
    for chunk in agent_ids.chunks(128) {
        let malformed_target: bool = tx.query_row(
            &format!(
                "SELECT EXISTS(
                     SELECT 1 FROM agent_assignments
                      WHERE substr(target_agent_id, 1, 16) IN ({})
                        AND length(target_agent_id) != 16
                 )",
                placeholders(chunk.len()),
            ),
            params_from_iter(chunk.iter().map(|id| Value::Blob(id_bytes(*id)))),
            |row| row.get(0),
        )?;
        let invalid_scope: bool = tx.query_row(
            &format!(
                "SELECT EXISTS(
                     SELECT 1 FROM agent_assignments
                      WHERE target_agent_id IN ({}) AND workspace_id != ?
                 )",
                placeholders(chunk.len()),
            ),
            params_from_iter(chunk.iter().map(|id| Value::Blob(id_bytes(*id))).chain(
                std::iter::once(Value::Blob(id_bytes(workspace_id.into_uuid()))),
            )),
            |row| row.get(0),
        )?;
        let invalid_state: bool = tx.query_row(
            &format!(
                "SELECT EXISTS(
                     SELECT 1 FROM agent_assignments
                      WHERE target_agent_id IN ({}) AND state NOT IN (0, 1, 2, 3, 4, 5, 6)
                 )",
                placeholders(chunk.len()),
            ),
            params_from_iter(chunk.iter().map(|id| Value::Blob(id_bytes(*id)))),
            |row| row.get(0),
        )?;
        if malformed_target || invalid_scope || invalid_state {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "assignment Workspace or state",
            ));
        }
        let sql = format!(
            "SELECT substr(assignment_id, 1, 17)
               FROM agent_assignments
              WHERE workspace_id = ? AND state IN (0, 1, 2)
                AND target_agent_id IN ({})
              ORDER BY assignment_id ASC LIMIT ?",
            placeholders(chunk.len())
        );
        let mut values = Vec::with_capacity(chunk.len() + 2);
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        values.extend(chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
        let mut statement = tx.prepare(&sql)?;
        let raw_ids = statement
            .query_map(params_from_iter(values), |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if raw_ids.len() > MAX_HOME_SOURCE_ENTRIES {
            return Err(HomeTransferSourceInventoryError::Bounds("assignments"));
        }
        for raw_id in raw_ids {
            assignment_ids.insert(decode_uuid(&raw_id, "assignment ID")?);
            enforce_entry_bound(assignment_ids.len())?;
        }
    }

    let mut assignments = Vec::with_capacity(assignment_ids.len());
    for uuid in assignment_ids {
        let id = forge_domain::AgentAssignmentId::from_uuid(uuid);
        let assignment = workspace_agent_assignments::get_in_transaction(tx, id)?
            .ok_or(HomeTransferSourceInventoryError::SourceRowMissing)?;
        let target = assignment.target();
        assignments.push(SourceAssignment {
            assignment_id: assignment.id().into_uuid(),
            origin: source_assignment_origin(assignment.origin()),
            workspace_id: assignment.workspace_id().into_uuid(),
            activity_id: assignment.activity_id().into_uuid(),
            target_agent_id: target.agent_id().into_uuid(),
            target_session_id: target.session_id().into_uuid(),
            target_principal: source_principal(target.principal()),
            target_agent_revision: target.agent_revision().get(),
            coordinator_agent_id: assignment.coordinator().agent_id().into_uuid(),
            coordinator_session_id: assignment.coordinator().session_id().into_uuid(),
            coordinator_principal: source_principal(assignment.coordinator().principal()),
            coordinator_revision: assignment.coordinator().revision().get(),
            state: source_assignment_state(assignment.state()),
            cancellation_requested: assignment.cancellation_requested(),
            revision: assignment.revision().get(),
            created_at_ms: assignment.created_at().get(),
            updated_at_ms: assignment.updated_at().get(),
            credit_budget: assignment.credit_budget().map(source_work_credit_budget),
            result_digest: assignment
                .result()
                .map(assignment_result_digest)
                .transpose()?,
            goal_id: assignment.goal_id().into_uuid(),
            goal_created_at_ms: assignment.goal_created_at().get(),
            goal_revision: assignment.goal_revision().get(),
            dag_revision: assignment.dag_revision().get(),
            dag_head_revision: assignment.dag_head_revision().get(),
            node_id: assignment.node_id().into_uuid(),
            node_revision: assignment.node_revision().get(),
        });
    }
    Ok(assignments)
}

fn load_writer_leases(
    tx: &Transaction<'_>,
    workspace_id: WorkspaceId,
    agents: &BTreeSet<Uuid>,
) -> Result<Vec<SourceWriterLease>, HomeTransferSourceInventoryError> {
    if agents.is_empty() {
        return Ok(Vec::new());
    }
    let agent_ids = agents.iter().copied().collect::<Vec<_>>();
    let mut lease_ids = BTreeSet::new();
    for chunk in agent_ids.chunks(128) {
        let malformed_actor: bool = tx.query_row(
            &format!(
                "SELECT EXISTS(
                     SELECT 1 FROM writer_leases
                      WHERE substr(agent_id, 1, 16) IN ({}) AND length(agent_id) != 16
                 )",
                placeholders(chunk.len()),
            ),
            params_from_iter(chunk.iter().map(|id| Value::Blob(id_bytes(*id)))),
            |row| row.get(0),
        )?;
        let sql = format!(
            "SELECT EXISTS(
                     SELECT 1 FROM writer_leases
                      WHERE agent_id IN ({})
                        AND (workspace_id != ? OR state NOT IN (0, 1) OR state IS NULL)
                 )",
            placeholders(chunk.len())
        );
        let mut values = Vec::with_capacity(chunk.len() + 1);
        values.extend(chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        let invalid_state: bool = tx.query_row(&sql, params_from_iter(values), |row| row.get(0))?;
        if malformed_actor || invalid_state {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "Writer Lease state",
            ));
        }

        let sql = format!(
            "SELECT substr(lease_id, 1, 17)
               FROM writer_leases
              WHERE workspace_id = ? AND state = 0 AND agent_id IN ({})
              ORDER BY lease_id ASC LIMIT ?",
            placeholders(chunk.len())
        );
        let mut values = Vec::with_capacity(chunk.len() + 2);
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        values.extend(chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
        let mut statement = tx.prepare(&sql)?;
        let raw_ids = statement
            .query_map(params_from_iter(values), |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if raw_ids.len() > MAX_HOME_SOURCE_ENTRIES {
            return Err(HomeTransferSourceInventoryError::Bounds(
                "active Writer Leases",
            ));
        }
        for raw_id in raw_ids {
            lease_ids.insert(decode_uuid(&raw_id, "Writer Lease ID")?);
            enforce_entry_bound(lease_ids.len())?;
        }
    }

    let mut result = Vec::with_capacity(lease_ids.len());
    for lease_id in lease_ids {
        let lease = crate::workspace_writer_leases::get(
            tx,
            forge_domain::WriterLeaseId::from_uuid(lease_id),
        )?
        .ok_or(HomeTransferSourceInventoryError::SourceRowMissing)?;
        if lease.workspace_id() != workspace_id
            || !agents.contains(&lease.agent_id().into_uuid())
            || lease.state() != forge_domain::WriterLeaseState::Active
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "Writer Lease owner or state",
            ));
        }
        result.push(SourceWriterLease {
            lease_id: lease.id().into_uuid(),
            workspace_id: lease.workspace_id().into_uuid(),
            activity_id: lease.activity_id().into_uuid(),
            agent_id: lease.agent_id().into_uuid(),
            state: source_writer_lease_state(lease.state()),
            revision: lease.revision().get(),
            acquired_at_ms: lease.acquired_at().get(),
            updated_at_ms: lease.updated_at().get(),
            lease_until_ms: lease.lease_until().get(),
            entries: lease
                .scope()
                .entries()
                .iter()
                .map(|entry| SourceWriterLeaseEntry {
                    kind: source_writer_lease_scope_kind(entry.kind()),
                    path: entry.path().as_path().as_os_str().as_bytes().to_vec(),
                })
                .collect(),
        });
    }
    Ok(result)
}

struct ExecutionCapture {
    pending: Vec<SourceExecution>,
    closed_count: u64,
    closed_digest: [u8; 32],
    closed_high_water_ms: i64,
}

fn load_executions(
    tx: &Transaction<'_>,
    workspace_id: WorkspaceId,
    sessions: &[Uuid],
    agents: &BTreeSet<Uuid>,
    activities: &BTreeSet<Uuid>,
    approvals: &[SourceApproval],
) -> Result<ExecutionCapture, HomeTransferSourceInventoryError> {
    if agents.is_empty() && activities.is_empty() && sessions.is_empty() {
        return Ok(empty_execution_capture());
    }
    let mut execution_ids = BTreeSet::new();
    let mut approval_execution_activities = BTreeMap::new();
    for approval in approvals {
        if activities.contains(&approval.activity_id) {
            continue;
        }
        if approval_execution_activities
            .insert(approval.execution_id, approval.activity_id)
            .is_some_and(|previous| previous != approval.activity_id)
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "approval execution scope conflict",
            ));
        }
    }
    if activities.is_empty() {
        collect_actor_execution_ids(tx, workspace_id, sessions, agents, &mut execution_ids)?;
    } else {
        collect_activity_execution_ids(
            tx,
            workspace_id,
            sessions,
            agents,
            activities,
            &mut execution_ids,
        )?;
    }
    if !approval_execution_activities.is_empty() {
        collect_approval_execution_ids(
            tx,
            workspace_id,
            &approval_execution_activities,
            &mut execution_ids,
        )?;
    }

    let mut capture = ExecutionCaptureBuilder::new();
    let scope = ExecutionCaptureScope {
        workspace_id,
        sessions,
        agents,
        activities,
        approval_execution_activities: &approval_execution_activities,
    };
    for execution_id in execution_ids {
        capture_execution_id(tx, execution_id, &scope, &mut capture)?;
    }
    capture
        .pending
        .sort_unstable_by_key(|record| record.execution_id);
    Ok(ExecutionCapture {
        pending: capture.pending,
        closed_count: capture.closed_count,
        closed_digest: capture.closed_hasher.finalize().into(),
        closed_high_water_ms: capture.closed_high_water_ms,
    })
}

fn collect_activity_execution_ids(
    tx: &Connection,
    workspace_id: WorkspaceId,
    sessions: &[Uuid],
    agents: &BTreeSet<Uuid>,
    activities: &BTreeSet<Uuid>,
    execution_ids: &mut BTreeSet<Uuid>,
) -> Result<(), HomeTransferSourceInventoryError> {
    let activity_ids = activities.iter().copied().collect::<Vec<_>>();
    let agent_ids = agents.iter().copied().collect::<Vec<_>>();
    for chunk in activity_ids.chunks(128) {
        let sql = format!(
            "SELECT substr(e.execution_id, 1, 17)
               FROM executions AS e
               LEFT JOIN execution_provenance AS p ON p.execution_id = e.execution_id
              WHERE e.workspace_id = ? AND e.activity_id IN ({})
                AND (p.execution_id IS NULL OR p.agent_id IN ({}) OR p.session_id IN ({}))
              ORDER BY e.execution_id ASC LIMIT ?",
            placeholders(chunk.len()),
            placeholders(agent_ids.len().max(1)),
            placeholders(sessions.len().max(1)),
        );
        let mut values = Vec::with_capacity(chunk.len() + agent_ids.len() + sessions.len() + 3);
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        values.extend(chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        push_id_values(&mut values, &agent_ids);
        push_session_values(&mut values, sessions);
        values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
        collect_execution_ids(tx, &sql, values, execution_ids)?;
    }
    Ok(())
}

fn collect_actor_execution_ids(
    tx: &Connection,
    workspace_id: WorkspaceId,
    sessions: &[Uuid],
    agents: &BTreeSet<Uuid>,
    execution_ids: &mut BTreeSet<Uuid>,
) -> Result<(), HomeTransferSourceInventoryError> {
    for agent_chunk in agents.iter().copied().collect::<Vec<_>>().chunks(128) {
        let sql = format!(
            "SELECT substr(e.execution_id, 1, 17)
               FROM executions AS e
               JOIN execution_provenance AS p ON p.execution_id = e.execution_id
              WHERE e.workspace_id = ? AND p.agent_id IN ({})
              ORDER BY e.execution_id ASC LIMIT ?",
            placeholders(agent_chunk.len()),
        );
        let mut values = Vec::with_capacity(agent_chunk.len() + 2);
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        values.extend(agent_chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
        collect_execution_ids(tx, &sql, values, execution_ids)?;
    }
    for session_chunk in sessions.chunks(128) {
        let sql = format!(
            "SELECT substr(e.execution_id, 1, 17)
               FROM executions AS e
               JOIN execution_provenance AS p ON p.execution_id = e.execution_id
              WHERE e.workspace_id = ? AND p.session_id IN ({})
              ORDER BY e.execution_id ASC LIMIT ?",
            placeholders(session_chunk.len()),
        );
        let mut values = Vec::with_capacity(session_chunk.len() + 2);
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        values.extend(session_chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
        collect_execution_ids(tx, &sql, values, execution_ids)?;
    }
    Ok(())
}

fn collect_approval_execution_ids(
    tx: &Connection,
    workspace_id: WorkspaceId,
    approval_execution_activities: &BTreeMap<Uuid, Uuid>,
    execution_ids: &mut BTreeSet<Uuid>,
) -> Result<(), HomeTransferSourceInventoryError> {
    let approval_execution_ids = approval_execution_activities
        .keys()
        .copied()
        .collect::<Vec<_>>();
    for chunk in approval_execution_ids.chunks(128) {
        let sql = format!(
            "SELECT substr(execution_id, 1, 17)
               FROM executions
              WHERE workspace_id = ? AND execution_id IN ({})
              ORDER BY execution_id ASC LIMIT ?",
            placeholders(chunk.len())
        );
        let mut values = Vec::with_capacity(chunk.len() + 2);
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        values.extend(chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
        collect_execution_ids(tx, &sql, values, execution_ids)?;
    }
    Ok(())
}

fn push_id_values(values: &mut Vec<Value>, ids: &[Uuid]) {
    if ids.is_empty() {
        values.push(Value::Blob(id_bytes(Uuid::nil())));
    } else {
        values.extend(ids.iter().map(|id| Value::Blob(id_bytes(*id))));
    }
}

fn push_session_values(values: &mut Vec<Value>, sessions: &[Uuid]) {
    if sessions.is_empty() {
        values.push(Value::Blob(id_bytes(Uuid::nil())));
    } else {
        values.extend(sessions.iter().map(|id| Value::Blob(id_bytes(*id))));
    }
}

fn collect_execution_ids(
    tx: &Connection,
    sql: &str,
    values: Vec<Value>,
    execution_ids: &mut BTreeSet<Uuid>,
) -> Result<(), HomeTransferSourceInventoryError> {
    let mut statement = tx.prepare(sql)?;
    let mut rows = statement.query(params_from_iter(values))?;
    let mut query_count = 0_usize;
    while let Some(row) = rows.next()? {
        query_count = query_count
            .checked_add(1)
            .ok_or(HomeTransferSourceInventoryError::Bounds("execution scan"))?;
        if query_count > MAX_HOME_SOURCE_ENTRIES {
            return Err(HomeTransferSourceInventoryError::Bounds("execution scan"));
        }
        let raw_id = row.get::<_, Vec<u8>>(0)?;
        let id = decode_uuid(&raw_id, "execution ID")?;
        record_bounded_execution_id(execution_ids, id)?;
    }
    Ok(())
}

fn record_bounded_execution_id(
    execution_ids: &mut BTreeSet<Uuid>,
    id: Uuid,
) -> Result<(), HomeTransferSourceInventoryError> {
    execution_ids.insert(id);
    enforce_entry_bound(execution_ids.len())
}

struct ExecutionCaptureBuilder {
    pending: Vec<SourceExecution>,
    closed_count: u64,
    closed_high_water_ms: i64,
    closed_hasher: Sha256,
}

impl ExecutionCaptureBuilder {
    fn new() -> Self {
        let mut closed_hasher = Sha256::new();
        closed_hasher.update(b"forge.home-transfer.closed-execution-history.v1\0");
        Self {
            pending: Vec::new(),
            closed_count: 0,
            closed_high_water_ms: 0,
            closed_hasher,
        }
    }
}

struct ExecutionCaptureScope<'a> {
    workspace_id: WorkspaceId,
    sessions: &'a [Uuid],
    agents: &'a BTreeSet<Uuid>,
    activities: &'a BTreeSet<Uuid>,
    approval_execution_activities: &'a BTreeMap<Uuid, Uuid>,
}

#[allow(
    clippy::too_many_lines,
    reason = "one execution snapshot is classified and captured with its closure evidence"
)]
fn capture_execution_id(
    tx: &Transaction<'_>,
    execution_uuid: Uuid,
    scope: &ExecutionCaptureScope<'_>,
    capture: &mut ExecutionCaptureBuilder,
) -> Result<(), HomeTransferSourceInventoryError> {
    let execution_id = forge_domain::ExecutionId::from_uuid(execution_uuid);
    let snapshot =
        crate::workspace_executions::native_closure::snapshot_in_transaction(tx, execution_id)?
            .ok_or(HomeTransferSourceInventoryError::SourceRowMissing)?;
    let record = snapshot.record();
    if record.workspace_id() != scope.workspace_id {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "execution Workspace",
        ));
    }
    let provenance = record.provenance();
    let attributed_agent_id = provenance.map(|value| value.agent_id().into_uuid());
    let attributed_session_id = provenance
        .and_then(forge_domain::ExecutionAgentProvenance::session_id)
        .map(AgentSessionId::into_uuid);
    let activity_is_affected = scope.activities.contains(&record.activity_id().into_uuid());
    let approval_activity = scope
        .approval_execution_activities
        .get(&record.id().into_uuid())
        .copied();
    if approval_activity.is_some_and(|activity| activity != record.activity_id().into_uuid()) {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "approval-linked execution Activity",
        ));
    }
    let actor_is_affected = attributed_agent_id.is_some_and(|id| scope.agents.contains(&id))
        || attributed_session_id.is_some_and(|id| scope.sessions.contains(&id));
    if !actor_is_affected && !activity_is_affected && approval_activity.is_none() {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "execution attribution selector",
        ));
    }
    if approval_activity.is_some() && provenance.is_some() && !actor_is_affected {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "approval and execution actor attribution conflict",
        ));
    }
    if provenance.is_some() && activity_is_affected && !actor_is_affected {
        return Ok(());
    }

    let native_closure = snapshot.closure();
    let is_terminal_closed = matches!(
        record.state(),
        forge_domain::ExecutionState::Completed
            | forge_domain::ExecutionState::Failed
            | forge_domain::ExecutionState::TimedOut
            | forge_domain::ExecutionState::Cancelled
    ) && native_closure.is_some();
    if is_terminal_closed {
        let fact = native_closure.ok_or(HomeTransferSourceInventoryError::Corrupt(
            "validated terminal closure disappeared",
        ))?;
        update_closed_execution_digest(&mut capture.closed_hasher, record, fact)?;
        capture.closed_count =
            capture
                .closed_count
                .checked_add(1)
                .ok_or(HomeTransferSourceInventoryError::Bounds(
                    "closed execution evidence",
                ))?;
        capture.closed_high_water_ms = capture
            .closed_high_water_ms
            .max(record.timestamps().updated_at().get())
            .max(fact.observed_at().get());
        return Ok(());
    }
    let closure = match native_closure {
        Some(fact) => {
            let cursor = fact.output_cursor();
            SourceNativeClosure::Present {
                before_revision: fact.before_revision().get(),
                after_revision: fact.after_revision().get(),
                observed_at_ms: fact.observed_at().get(),
                final_output_sequence: cursor.after_sequence(),
                launch: source_closure_launch(fact.launch()),
                runtime: source_closure_runtime(fact.runtime()),
                process: source_closure_process(fact.process()),
            }
        }
        None => SourceNativeClosure::Absent,
    };
    let timestamps = record.timestamps();
    let attribution = provenance.map(forge_domain::ExecutionAgentProvenance::attribution);
    capture.pending.push(SourceExecution {
        execution_id: record.id().into_uuid(),
        workspace_id: record.workspace_id().into_uuid(),
        activity_id: record.activity_id().into_uuid(),
        state: source_execution_state(record.state()),
        revision: record.revision().get(),
        request_digest: *record.request_digest().as_bytes(),
        created_at_ms: timestamps.created_at().get(),
        updated_at_ms: timestamps.updated_at().get(),
        agent_id: attributed_agent_id,
        session_id: attributed_session_id,
        agent_revision: provenance.map(|value| value.agent_revision().get()),
        principal: provenance.map(|value| source_principal(value.principal())),
        goal_id: attribution.map(|value| value.goal_id().into_uuid()),
        goal_revision: attribution.map(|value| value.expected_goal_revision().get()),
        dag_revision: provenance.map(|value| value.attribution().dag_revision().get()),
        node_id: attribution.map(|value| value.node_id().into_uuid()),
        node_revision: attribution.map(|value| value.expected_node_revision().get()),
        command_id: provenance.map(|value| value.command_id().as_str().to_owned()),
        project_command: provenance
            .and_then(forge_domain::ExecutionAgentProvenance::project_command)
            .map(source_project_command),
        closure,
    });
    if capture.pending.len() > MAX_HOME_SOURCE_ENTRIES {
        return Err(HomeTransferSourceInventoryError::Bounds("executions"));
    }
    Ok(())
}

fn empty_execution_capture() -> ExecutionCapture {
    let mut hasher = Sha256::new();
    hasher.update(b"forge.home-transfer.closed-execution-history.v1\0");
    ExecutionCapture {
        pending: Vec::new(),
        closed_count: 0,
        closed_digest: hasher.finalize().into(),
        closed_high_water_ms: 0,
    }
}

fn update_closed_execution_digest(
    hasher: &mut Sha256,
    record: &forge_domain::RegisteredExecution,
    closure: forge_domain::ExecutionNativeClosureFact,
) -> Result<(), HomeTransferSourceInventoryError> {
    hasher.update(record.id().into_uuid().as_bytes());
    hasher.update(record.workspace_id().into_uuid().as_bytes());
    hasher.update(record.activity_id().into_uuid().as_bytes());
    hasher.update(record.revision().get().to_be_bytes());
    hasher.update(record.request_digest().as_bytes());
    let timestamps = record.timestamps();
    hasher.update(timestamps.created_at().get().to_be_bytes());
    hasher.update(timestamps.updated_at().get().to_be_bytes());
    hasher.update([match record.state() {
        forge_domain::ExecutionState::Starting => 0,
        forge_domain::ExecutionState::Running => 1,
        forge_domain::ExecutionState::Completed => 2,
        forge_domain::ExecutionState::Failed => 3,
        forge_domain::ExecutionState::TimedOut => 4,
        forge_domain::ExecutionState::Cancelled => 5,
        forge_domain::ExecutionState::Interrupted => 6,
    }]);
    let provenance = record.provenance();
    match provenance {
        Some(value) => {
            hasher.update([1]);
            hasher.update(value.agent_id().into_uuid().as_bytes());
            hasher.update(value.agent_revision().get().to_be_bytes());
            if let Some(session_id) = value.session_id() {
                hasher.update([1]);
                hasher.update(session_id.into_uuid().as_bytes());
            } else {
                hasher.update([0]);
            }
            match value.principal() {
                AuthenticatedPrincipal::TrustedStdio => {
                    hasher.update([0]);
                }
                AuthenticatedPrincipal::DirectToken(id) => {
                    hasher.update([1]);
                    hasher.update(id.into_uuid().as_bytes());
                }
                AuthenticatedPrincipal::OAuthGrant(id) => {
                    hasher.update([2]);
                    hasher.update(id.into_uuid().as_bytes());
                }
            }
            let attribution = value.attribution();
            hasher.update(attribution.goal_id().into_uuid().as_bytes());
            hasher.update(attribution.expected_goal_revision().get().to_be_bytes());
            hasher.update(attribution.dag_revision().get().to_be_bytes());
            hasher.update(attribution.node_id().into_uuid().as_bytes());
            hasher.update(attribution.expected_node_revision().get().to_be_bytes());
            let command_id = value.command_id().as_str().as_bytes();
            let command_length = stable_length(command_id.len(), "execution command ID")?;
            hasher.update(command_length.to_be_bytes());
            hasher.update(command_id);
            if let Some(project_command) = value.project_command() {
                hasher.update([1]);
                hasher.update([match project_command.class() {
                    forge_domain::ProjectCommandClass::Verify => 0,
                    forge_domain::ProjectCommandClass::GeneratedPackage => 1,
                }]);
                hasher.update(project_command.catalog_fingerprint().hash().as_bytes());
            } else {
                hasher.update([0]);
            }
        }
        None => {
            hasher.update([0]);
        }
    }
    hasher.update(closure.before_revision().get().to_be_bytes());
    hasher.update(closure.after_revision().get().to_be_bytes());
    hasher.update(closure.observed_at().get().to_be_bytes());
    hasher.update(closure.output_cursor().after_sequence().to_be_bytes());
    hasher.update([
        match closure.launch() {
            forge_domain::NativeClosureLaunch::Baseline => 0,
            forge_domain::NativeClosureLaunch::RustCi => 1,
            forge_domain::NativeClosureLaunch::GeneratedPackage => 2,
        },
        match closure.runtime() {
            forge_domain::NativeClosureRuntime::NotApplicable => 0,
            forge_domain::NativeClosureRuntime::Cleaned => 1,
        },
        match closure.process() {
            forge_domain::NativeClosureProcess::NoChildSpawned => 0,
            forge_domain::NativeClosureProcess::ProcessGroupReaped => 1,
        },
    ]);
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "approval selection and provenance/grant preimages are checked as one source census"
)]
fn load_approvals(
    tx: &Transaction<'_>,
    workspace_id: WorkspaceId,
    sessions: &[Uuid],
    agents: &BTreeSet<Uuid>,
    activities: &BTreeSet<Uuid>,
) -> Result<Vec<SourceApproval>, HomeTransferSourceInventoryError> {
    let mut approval_ids = BTreeSet::new();
    let agent_ids = agents.iter().copied().collect::<Vec<_>>();
    let activity_ids = activities.iter().copied().collect::<Vec<_>>();
    let relevant_states = "(a.state IN (0, 1, 3) OR EXISTS(
        SELECT 1 FROM execution_grants AS g
         WHERE g.approval_id = a.approval_id AND g.state = 0
    ))";

    for activity_chunk in activity_ids.chunks(128) {
        let sql = format!(
            "SELECT substr(a.approval_id, 1, 17)
               FROM approval_requests AS a
               LEFT JOIN approval_agent_provenance AS p ON p.approval_id = a.approval_id
              WHERE a.workspace_id = ? AND {relevant_states}
                AND a.activity_id IN ({})
                AND (p.approval_id IS NULL OR p.agent_id IN ({}) OR p.session_id IN ({}))
              ORDER BY a.approval_id ASC LIMIT ?",
            placeholders(activity_chunk.len()),
            placeholders(agent_ids.len().max(1)),
            placeholders(sessions.len().max(1)),
        );
        let mut values =
            Vec::with_capacity(activity_chunk.len() + agent_ids.len() + sessions.len() + 3);
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        values.extend(activity_chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        if agent_ids.is_empty() {
            values.push(Value::Blob(id_bytes(Uuid::nil())));
        } else {
            values.extend(agent_ids.iter().map(|id| Value::Blob(id_bytes(*id))));
        }
        if sessions.is_empty() {
            values.push(Value::Blob(id_bytes(Uuid::nil())));
        } else {
            values.extend(sessions.iter().map(|id| Value::Blob(id_bytes(*id))));
        }
        values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
        add_approval_ids(tx, &sql, values, &mut approval_ids)?;
    }

    for agent_chunk in agent_ids.chunks(128) {
        let sql = format!(
            "SELECT substr(a.approval_id, 1, 17)
               FROM approval_requests AS a
              WHERE a.workspace_id = ? AND {relevant_states}
                AND a.approval_id IN (
                    SELECT approval_id FROM approval_agent_provenance
                     WHERE agent_id IN ({})
                )
              ORDER BY a.approval_id ASC LIMIT ?",
            placeholders(agent_chunk.len()),
        );
        let mut values = Vec::with_capacity(agent_chunk.len() + 2);
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        values.extend(agent_chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
        add_approval_ids(tx, &sql, values, &mut approval_ids)?;
    }
    for session_chunk in sessions.chunks(128) {
        let sql = format!(
            "SELECT substr(a.approval_id, 1, 17)
               FROM approval_requests AS a
              WHERE a.workspace_id = ? AND {relevant_states}
                AND a.approval_id IN (
                    SELECT approval_id FROM approval_agent_provenance
                     WHERE session_id IN ({})
                )
              ORDER BY a.approval_id ASC LIMIT ?",
            placeholders(session_chunk.len()),
        );
        let mut values = Vec::with_capacity(session_chunk.len() + 2);
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        values.extend(session_chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
        add_approval_ids(tx, &sql, values, &mut approval_ids)?;
    }

    let mut records = Vec::with_capacity(approval_ids.len());
    for approval_id in approval_ids {
        let id = forge_domain::ApprovalRequestId::from_uuid(approval_id);
        let (approval, execution, grant) =
            crate::workspace_approvals::get_approval_with_execution_and_grant_in_transaction(
                tx, id,
            )?
            .ok_or(HomeTransferSourceInventoryError::SourceRowMissing)?;
        if approval.request().workspace_id() != workspace_id {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "approval Workspace",
            ));
        }
        if execution.as_ref().is_some_and(|execution| {
            execution.id() != approval.request().execution_id()
                || execution.workspace_id() != workspace_id
                || execution.activity_id() != approval.request().activity_id()
        }) {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "approval execution scope",
            ));
        }
        let activity_is_affected =
            activities.contains(&approval.request().activity_id().into_uuid());
        let provenance =
            crate::workspace_approvals::agent_provenance::get_in_transaction(tx, &approval)?;
        let attribution = if let Some(provenance) = provenance {
            let agent_id = provenance.agent_id().into_uuid();
            let session_id = provenance.session_id().map(AgentSessionId::into_uuid);
            let related =
                agents.contains(&agent_id) || session_id.is_some_and(|id| sessions.contains(&id));
            if !related && activity_is_affected {
                continue;
            }
            if !related {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "approval attribution selector",
                ));
            }
            let node = provenance.attribution();
            SourceApprovalAttribution::Known {
                agent_id,
                session_id,
                agent_revision: provenance.agent_revision().get(),
                principal: source_principal(provenance.principal()),
                goal_id: node.goal_id().into_uuid(),
                goal_revision: node.expected_goal_revision().get(),
                dag_revision: node.dag_revision().get(),
                node_id: node.node_id().into_uuid(),
                node_revision: node.expected_node_revision().get(),
                command_id: provenance.command_id().as_str().to_owned(),
                project_command: provenance.project_command().map(source_project_command),
            }
        } else if activity_is_affected {
            SourceApprovalAttribution::LegacyUnknown
        } else {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "approval lacks attribution outside affected Activity",
            ));
        };
        let decided_at_ms = approval.decided_at().map(TimestampMillis::get);
        let authorization_request = approval.request();
        let requested_permissions = authorization_request.requested().get();
        records.push(SourceApproval {
            approval_id: approval.id().into_uuid(),
            workspace_id: approval.request().workspace_id().into_uuid(),
            activity_id: approval.request().activity_id().into_uuid(),
            execution_id: approval.request().execution_id().into_uuid(),
            request_digest: *authorization_request.request_digest().as_bytes(),
            action: source_execution_action_class(authorization_request.action()),
            requested_permissions: source_execution_permissions(requested_permissions),
            policy_revision: approval.policy_revision().get(),
            state: source_approval_state(approval.state()),
            revision: approval.revision().get(),
            created_at_ms: approval.created_at().get(),
            updated_at_ms: decided_at_ms.unwrap_or_else(|| approval.created_at().get()),
            expires_at_ms: approval.expires_at().get(),
            agent_binding_digest: approval
                .agent_binding()
                .map(|value| value.as_bytes().to_vec()),
            attribution,
            grant: grant
                .as_ref()
                .map_or(SourceApprovalGrant::Absent, source_approval_grant),
        });
    }
    records.sort_unstable_by_key(|record| record.approval_id);
    Ok(records)
}

fn add_approval_ids(
    tx: &Connection,
    sql: &str,
    values: Vec<Value>,
    approval_ids: &mut BTreeSet<Uuid>,
) -> Result<(), HomeTransferSourceInventoryError> {
    let mut statement = tx.prepare(sql)?;
    let raw_ids = statement
        .query_map(params_from_iter(values), |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if raw_ids.len() > MAX_HOME_SOURCE_ENTRIES {
        return Err(HomeTransferSourceInventoryError::Bounds("approvals"));
    }
    for raw_id in raw_ids {
        approval_ids.insert(decode_uuid(&raw_id, "approval ID")?);
        enforce_entry_bound(approval_ids.len())?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "typed file/tree intents and their ChangeSet scope are one source evidence unit"
)]
fn load_change_sets(
    tx: &Transaction<'_>,
    workspace_id: WorkspaceId,
    activities: &BTreeSet<Uuid>,
) -> Result<Vec<SourceChangeSet>, HomeTransferSourceInventoryError> {
    if activities.is_empty() {
        return Ok(Vec::new());
    }
    let mut change_set_ids = BTreeSet::new();
    let activity_ids = activities.iter().copied().collect::<Vec<_>>();
    for chunk in activity_ids.chunks(128) {
        let sql = format!(
            "SELECT substr(changeset_id, 1, 17)
               FROM change_sets
              WHERE workspace_id = ? AND activity_id IN ({}) AND state != 1
              ORDER BY changeset_id ASC LIMIT ?",
            placeholders(chunk.len())
        );
        let mut values = Vec::with_capacity(chunk.len() + 2);
        values.push(Value::Blob(id_bytes(workspace_id.into_uuid())));
        values.extend(chunk.iter().map(|id| Value::Blob(id_bytes(*id))));
        values.push(Value::Integer(source_query_limit(MAX_HOME_SOURCE_ENTRIES)?));
        let mut statement = tx.prepare(&sql)?;
        let raw_ids = statement
            .query_map(params_from_iter(values), |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if raw_ids.len() > MAX_HOME_SOURCE_ENTRIES {
            return Err(HomeTransferSourceInventoryError::Bounds("ChangeSets"));
        }
        for raw_id in raw_ids {
            change_set_ids.insert(decode_uuid(&raw_id, "ChangeSet ID")?);
            enforce_entry_bound(change_set_ids.len())?;
        }
    }

    let mut records = Vec::with_capacity(change_set_ids.len());
    let mut mutation_entries = 0_usize;
    for uuid in change_set_ids {
        let id = forge_domain::ChangeSetId::from_uuid(uuid);
        let file_record = crate::workspace_changesets::get(tx, id)?;
        let tree_record = crate::workspace_changesets::tree_change_set_read_data(tx, id)?;
        if file_record.is_some() && tree_record.is_some() {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "ChangeSet has both file and tree intent",
            ));
        }
        let (change_set, file_mutation, source_tree_request_digest, tree_mutations) =
            if let Some(record) = file_record {
                let change_set = record.change_set().clone();
                let mutation = record.mutation();
                (
                    change_set,
                    Some(source_file_mutation(mutation)),
                    None,
                    Vec::new(),
                )
            } else if let Some(tree) = tree_record {
                let digest = tree.request_digest.map(|digest| *digest.as_bytes());
                let change_set = tree.change_set.clone();
                let mutations = load_tree_mutations(tx, id, &tree.applied_mutations)?;
                if mutations.len() != tree.mutation_count {
                    return Err(HomeTransferSourceInventoryError::Corrupt(
                        "tree mutation count changed in transaction",
                    ));
                }
                (change_set, None, digest, mutations)
            } else {
                return Err(HomeTransferSourceInventoryError::SourceRowMissing);
            };
        if change_set.workspace_id() != workspace_id
            || !activities.contains(&change_set.activity_id().into_uuid())
        {
            return Err(HomeTransferSourceInventoryError::Corrupt("ChangeSet scope"));
        }
        mutation_entries = mutation_entries
            .checked_add(usize::from(file_mutation.is_some()))
            .and_then(|value| value.checked_add(tree_mutations.len()))
            .ok_or(HomeTransferSourceInventoryError::Bounds(
                "ChangeSet mutations",
            ))?;
        enforce_entry_bound(
            records
                .len()
                .checked_add(1)
                .and_then(|value| value.checked_add(mutation_entries))
                .ok_or(HomeTransferSourceInventoryError::Bounds(
                    "ChangeSet mutations",
                ))?,
        )?;
        records.push(SourceChangeSet {
            change_set_id: change_set.id().into_uuid(),
            workspace_id: change_set.workspace_id().into_uuid(),
            activity_id: change_set.activity_id().into_uuid(),
            runtime_instance_id: change_set.runtime_instance_id().into_uuid(),
            workspace_revision: change_set.workspace_revision().get(),
            activity_lease_revision: change_set.activity_lease_revision().get(),
            state: source_change_set_state(change_set.state()),
            source_tree_request_digest,
            revision: change_set.revision().get(),
            created_at_ms: change_set.created_at().get(),
            updated_at_ms: change_set.updated_at().get(),
            file_mutation,
            tree_mutations,
        });
    }
    records.sort_unstable_by_key(|record| record.change_set_id);
    Ok(records)
}

fn load_tree_mutations(
    tx: &Connection,
    change_set_id: forge_domain::ChangeSetId,
    owner_applied_ids: &[forge_domain::TreeMutationId],
) -> Result<Vec<SourceTreeMutation>, HomeTransferSourceInventoryError> {
    let mut statement = tx.prepare(
        "SELECT substr(mutation_id, 1, 17), ordinal, kind, primary_path,
                secondary_path, expected_hash, intended_hash, applied, revision
           FROM tree_mutations
          WHERE changeset_id = ?1 ORDER BY ordinal ASC LIMIT ?2",
    )?;
    let limit = i64::try_from(forge_domain::MAX_TREE_CHANGESET_MUTATIONS + QUERY_PROBE_EXTRA)
        .map_err(|_| HomeTransferSourceInventoryError::Bounds("tree mutations"))?;
    let mut rows = statement.query(params![change_set_id.into_uuid().as_bytes(), limit])?;
    let mut mutations = Vec::new();
    let mut applied_ids = Vec::new();
    while let Some(row) = rows.next()? {
        if mutations.len() >= forge_domain::MAX_TREE_CHANGESET_MUTATIONS {
            return Err(HomeTransferSourceInventoryError::Bounds("tree mutations"));
        }
        let raw_id = row.get::<_, Vec<u8>>(0)?;
        let ordinal = row.get::<_, i64>(1)?;
        let kind = source_tree_mutation_kind(row.get(2)?)?;
        let primary_path: Vec<u8> = row.get(3)?;
        let secondary_path: Option<Vec<u8>> = row.get(4)?;
        let expected_hash = row
            .get::<_, Option<Vec<u8>>>(5)?
            .map(|value| decode_digest(&value, "tree expected hash"))
            .transpose()?;
        let intended_hash = row
            .get::<_, Option<Vec<u8>>>(6)?
            .map(|value| decode_digest(&value, "tree intended hash"))
            .transpose()?;
        let applied = match row.get::<_, i64>(7)? {
            0 => false,
            1 => true,
            _ => {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "tree applied state",
                ));
            }
        };
        let revision = row.get::<_, i64>(8)?;
        if ordinal < 0
            || usize::try_from(ordinal)
                .ok()
                .is_none_or(|value| value >= forge_domain::MAX_TREE_CHANGESET_MUTATIONS)
            || primary_path.is_empty()
            || primary_path.len() > forge_domain::MAX_WORKSPACE_RELATIVE_PATH_BYTES
            || secondary_path.as_ref().is_some_and(|path| {
                path.is_empty() || path.len() > forge_domain::MAX_WORKSPACE_RELATIVE_PATH_BYTES
            })
            || revision < 1
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "tree mutation shape",
            ));
        }
        let mutation_id = decode_uuid(&raw_id, "tree mutation ID")?;
        if applied {
            applied_ids.push(forge_domain::TreeMutationId::from_uuid(mutation_id));
        }
        mutations.push(SourceTreeMutation {
            mutation_id,
            ordinal,
            kind,
            primary_path,
            secondary_path,
            expected_hash,
            intended_hash,
            applied,
            revision,
        });
    }
    let mut actual_applied = applied_ids;
    let mut expected_applied = owner_applied_ids.to_vec();
    actual_applied.sort_unstable();
    expected_applied.sort_unstable();
    if actual_applied != expected_applied {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "tree applied mutation owner readback",
        ));
    }
    Ok(mutations)
}

fn source_agent(agent: &RegisteredAgentInstance) -> SourceAgent {
    let focus = agent.focus();
    let goal = focus.goal();
    let node = focus.node();
    SourceAgent {
        agent_id: agent.id().into_uuid(),
        workspace_id: agent.workspace_id().into_uuid(),
        activity_id: agent.activity_id().into_uuid(),
        session_id: agent.session_id().map(AgentSessionId::into_uuid),
        principal: source_principal(agent.principal()),
        display_name: agent.display_name().as_str().to_owned(),
        declared_role: agent.declared_role().as_str().to_owned(),
        transport: source_transport(agent.transport_kind()),
        attachment: source_attachment(agent.attachment_state()),
        revision: agent.revision().get(),
        created_at_ms: agent.created_at().get(),
        updated_at_ms: agent.updated_at().get(),
        focus: SourceFocus {
            goal_id: goal.map(|value| value.goal_id().into_uuid()),
            goal_revision: goal.map(|value| value.expected_revision().get()),
            dag_revision: focus
                .dag_revision()
                .map(forge_domain::DagRevisionNumber::get),
            node_id: node.map(|value| value.node_id().into_uuid()),
            node_revision: node.map(|value| value.expected_revision().get()),
        },
    }
}

fn source_principal(value: AuthenticatedPrincipal) -> SourcePrincipal {
    match value {
        AuthenticatedPrincipal::TrustedStdio => SourcePrincipal::TrustedStdio,
        AuthenticatedPrincipal::DirectToken(token) => {
            SourcePrincipal::DirectToken(token.into_uuid())
        }
        AuthenticatedPrincipal::OAuthGrant(grant) => SourcePrincipal::OAuthGrant(grant.into_uuid()),
    }
}

fn source_transport(value: forge_domain::AgentTransportKind) -> SourceTransport {
    match value {
        forge_domain::AgentTransportKind::Retired => SourceTransport::Retired,
        forge_domain::AgentTransportKind::Stdio => SourceTransport::Stdio,
        forge_domain::AgentTransportKind::StreamableHttp => SourceTransport::StreamableHttp,
        forge_domain::AgentTransportKind::Other => SourceTransport::Other,
    }
}

fn source_attachment(value: AgentAttachmentState) -> SourceAttachment {
    match value {
        AgentAttachmentState::Attached => SourceAttachment::Attached,
        AgentAttachmentState::Detached => SourceAttachment::Detached,
    }
}

fn source_rejection_reason(
    value: forge_domain::AgentBindingRejectionReason,
) -> SourceRejectionReason {
    match value {
        forge_domain::AgentBindingRejectionReason::PrincipalTransportMismatch => {
            SourceRejectionReason::PrincipalTransportMismatch
        }
    }
}

fn source_assignment_state(value: AgentAssignmentState) -> SourceAssignmentState {
    match value {
        AgentAssignmentState::Offered => SourceAssignmentState::Offered,
        AgentAssignmentState::Running => SourceAssignmentState::Running,
        AgentAssignmentState::Submitted => SourceAssignmentState::Submitted,
        AgentAssignmentState::Accepted => SourceAssignmentState::Accepted,
        AgentAssignmentState::Rejected => SourceAssignmentState::Rejected,
        AgentAssignmentState::Cancelled => SourceAssignmentState::Cancelled,
        AgentAssignmentState::Interrupted => SourceAssignmentState::Interrupted,
    }
}

fn source_assignment_origin(value: forge_domain::AgentAssignmentOrigin) -> SourceAssignmentOrigin {
    match value {
        forge_domain::AgentAssignmentOrigin::CoordinatorOffer => {
            SourceAssignmentOrigin::CoordinatorOffer
        }
        forge_domain::AgentAssignmentOrigin::CutContinuation(origin) => {
            SourceAssignmentOrigin::CutContinuation {
                cut_id: origin.cut_id(),
                transfer_id: origin.transfer_id(),
                predecessor_id: origin.predecessor_id().into_uuid(),
            }
        }
        forge_domain::AgentAssignmentOrigin::HomeHandoff(origin) => {
            SourceAssignmentOrigin::HomeHandoff {
                preparation_id: origin.preparation_id(),
                handoff_id: origin.handoff_id(),
                predecessor_id: origin.predecessor_id().into_uuid(),
                root_assignment_id: origin.root_assignment_id().into_uuid(),
            }
        }
    }
}

fn source_work_credit_budget(value: forge_domain::WorkCreditBudget) -> SourceWorkCreditBudget {
    match value {
        forge_domain::WorkCreditBudget::One => SourceWorkCreditBudget::One,
        forge_domain::WorkCreditBudget::Three => SourceWorkCreditBudget::Three,
        forge_domain::WorkCreditBudget::Five => SourceWorkCreditBudget::Five,
    }
}

fn assignment_result_digest(
    result: &forge_domain::AgentAssignmentResult,
) -> Result<[u8; 32], HomeTransferSourceInventoryError> {
    let mut hasher = Sha256::new();
    hasher.update(b"forge.home-transfer.assignment-result.v1\0");
    hasher.update(stable_length(result.report().len(), "assignment report")?.to_be_bytes());
    hasher.update(result.report().as_bytes());
    hasher.update(stable_length(result.sources().len(), "assignment source count")?.to_be_bytes());
    for source in result.sources() {
        match source {
            forge_domain::AgentAssignmentSourceRef::Url(url) => {
                hasher.update([0]);
                hasher.update(
                    stable_length(url.as_str().len(), "assignment source URL")?.to_be_bytes(),
                );
                hasher.update(url.as_str().as_bytes());
            }
            forge_domain::AgentAssignmentSourceRef::Provenance(evidence) => {
                hasher.update([1]);
                match evidence {
                    forge_domain::GoalEvidenceRef::ChangeSet(id) => {
                        hasher.update([0]);
                        hasher.update(id.into_uuid().as_bytes());
                    }
                    forge_domain::GoalEvidenceRef::Execution(id) => {
                        hasher.update([1]);
                        hasher.update(id.into_uuid().as_bytes());
                    }
                    forge_domain::GoalEvidenceRef::Approval(id) => {
                        hasher.update([2]);
                        hasher.update(id.into_uuid().as_bytes());
                    }
                    forge_domain::GoalEvidenceRef::Checkpoint(id) => {
                        hasher.update([3]);
                        hasher.update(id.into_uuid().as_bytes());
                    }
                }
            }
        }
    }
    if let Some(worktree) = result.worktree() {
        hasher.update([1]);
        hasher.update(worktree.root_fingerprint().as_bytes());
        hasher.update(worktree.repository_fingerprint().as_bytes());
        hasher.update(worktree.baseline().object_id().as_bytes());
    } else {
        hasher.update([0]);
    }
    Ok(hasher.finalize().into())
}

fn stable_length(
    value: usize,
    field: &'static str,
) -> Result<u64, HomeTransferSourceInventoryError> {
    u64::try_from(value).map_err(|_| HomeTransferSourceInventoryError::Bounds(field))
}

fn source_writer_lease_state(value: forge_domain::WriterLeaseState) -> SourceWriterLeaseState {
    match value {
        forge_domain::WriterLeaseState::Active => SourceWriterLeaseState::Active,
        forge_domain::WriterLeaseState::Released => SourceWriterLeaseState::Released,
    }
}

fn source_writer_lease_scope_kind(
    value: forge_domain::WriterLeaseScopeKind,
) -> SourceWriterLeaseScopeKind {
    match value {
        forge_domain::WriterLeaseScopeKind::ExactPath => SourceWriterLeaseScopeKind::ExactPath,
        forge_domain::WriterLeaseScopeKind::DirectorySubtree => {
            SourceWriterLeaseScopeKind::DirectorySubtree
        }
    }
}

fn source_execution_state(value: forge_domain::ExecutionState) -> SourceExecutionState {
    match value {
        forge_domain::ExecutionState::Starting => SourceExecutionState::Starting,
        forge_domain::ExecutionState::Running => SourceExecutionState::Running,
        forge_domain::ExecutionState::Completed => SourceExecutionState::Completed,
        forge_domain::ExecutionState::Failed => SourceExecutionState::Failed,
        forge_domain::ExecutionState::TimedOut => SourceExecutionState::TimedOut,
        forge_domain::ExecutionState::Cancelled => SourceExecutionState::Cancelled,
        forge_domain::ExecutionState::Interrupted => SourceExecutionState::Interrupted,
    }
}

fn source_closure_launch(value: forge_domain::NativeClosureLaunch) -> SourceClosureLaunch {
    match value {
        forge_domain::NativeClosureLaunch::Baseline => SourceClosureLaunch::Baseline,
        forge_domain::NativeClosureLaunch::RustCi => SourceClosureLaunch::RustCi,
        forge_domain::NativeClosureLaunch::GeneratedPackage => {
            SourceClosureLaunch::GeneratedPackage
        }
    }
}

fn source_closure_runtime(value: forge_domain::NativeClosureRuntime) -> SourceClosureRuntime {
    match value {
        forge_domain::NativeClosureRuntime::NotApplicable => SourceClosureRuntime::NotApplicable,
        forge_domain::NativeClosureRuntime::Cleaned => SourceClosureRuntime::Cleaned,
    }
}

fn source_closure_process(value: forge_domain::NativeClosureProcess) -> SourceClosureProcess {
    match value {
        forge_domain::NativeClosureProcess::NoChildSpawned => SourceClosureProcess::NoChildSpawned,
        forge_domain::NativeClosureProcess::ProcessGroupReaped => {
            SourceClosureProcess::ProcessGroupReaped
        }
    }
}

fn source_project_command(value: forge_domain::ProjectCommandEvidence) -> SourceProjectCommand {
    SourceProjectCommand {
        class: match value.class() {
            forge_domain::ProjectCommandClass::Verify => SourceProjectCommandClass::Verify,
            forge_domain::ProjectCommandClass::GeneratedPackage => {
                SourceProjectCommandClass::GeneratedPackage
            }
        },
        catalog_fingerprint: *value.catalog_fingerprint().hash().as_bytes(),
    }
}

fn source_execution_action_class(
    value: forge_domain::ExecutionActionClass,
) -> SourceExecutionActionClass {
    match value {
        forge_domain::ExecutionActionClass::DirectStructured => {
            SourceExecutionActionClass::DirectStructured
        }
        forge_domain::ExecutionActionClass::DiscoveredProjectCommand => {
            SourceExecutionActionClass::DiscoveredProjectCommand
        }
        forge_domain::ExecutionActionClass::ShellEscape => SourceExecutionActionClass::ShellEscape,
        forge_domain::ExecutionActionClass::AnalyzedShell => {
            SourceExecutionActionClass::AnalyzedShell
        }
        forge_domain::ExecutionActionClass::GeneratedProjectCommand => {
            SourceExecutionActionClass::GeneratedProjectCommand
        }
    }
}

fn source_execution_permissions(
    value: forge_domain::ExecutionPermissions,
) -> SourceExecutionPermissions {
    SourceExecutionPermissions {
        workspace_read: value.workspace_read(),
        workspace_write: value.workspace_write(),
        network: value.network(),
    }
}

fn source_authorization_source(
    value: forge_domain::AuthorizationSource,
) -> SourceAuthorizationSource {
    match value {
        forge_domain::AuthorizationSource::ExplicitGrant => {
            SourceAuthorizationSource::ExplicitGrant
        }
        forge_domain::AuthorizationSource::AutoApprovalScope => {
            SourceAuthorizationSource::AutoApprovalScope
        }
        forge_domain::AuthorizationSource::LegacyPlan06 => SourceAuthorizationSource::LegacyPlan06,
    }
}

fn source_approval_grant(grant: &forge_domain::ExecutionGrant) -> SourceApprovalGrant {
    let request = grant.request();
    SourceApprovalGrant::Present {
        grant_id: grant.id().into_uuid(),
        state: match grant.state() {
            forge_domain::ExecutionGrantState::Active => SourceExecutionGrantState::Active,
            forge_domain::ExecutionGrantState::Consumed => SourceExecutionGrantState::Consumed,
            forge_domain::ExecutionGrantState::Expired => SourceExecutionGrantState::Expired,
            forge_domain::ExecutionGrantState::Revoked => SourceExecutionGrantState::Revoked,
        },
        revision: grant.revision().get(),
        expires_at_ms: grant.expires_at().get(),
        consumed_at_ms: grant.consumed_at().map(TimestampMillis::get),
        request_digest: *request.request_digest().as_bytes(),
        action: source_execution_action_class(request.action()),
        effective_permissions: source_execution_permissions(grant.effective().get()),
        policy_revision: grant.policy_revision().get(),
        source: source_authorization_source(grant.source()),
    }
}

fn source_approval_state(value: forge_domain::ApprovalRequestState) -> SourceApprovalState {
    match value {
        forge_domain::ApprovalRequestState::Pending => SourceApprovalState::Pending,
        forge_domain::ApprovalRequestState::Approved => SourceApprovalState::Approved,
        forge_domain::ApprovalRequestState::AutoApproved => SourceApprovalState::AutoApproved,
        forge_domain::ApprovalRequestState::Rejected => SourceApprovalState::Rejected,
        forge_domain::ApprovalRequestState::Denied => SourceApprovalState::Denied,
        forge_domain::ApprovalRequestState::Cancelled => SourceApprovalState::Cancelled,
        forge_domain::ApprovalRequestState::Expired => SourceApprovalState::Expired,
        forge_domain::ApprovalRequestState::Superseded => SourceApprovalState::Superseded,
    }
}

fn source_change_set_state(value: forge_domain::ChangeSetState) -> SourceChangeSetState {
    match value {
        forge_domain::ChangeSetState::Starting => SourceChangeSetState::Starting,
        forge_domain::ChangeSetState::Applied => SourceChangeSetState::Applied,
        forge_domain::ChangeSetState::Failed => SourceChangeSetState::Failed,
    }
}

fn source_file_mutation(mutation: &forge_domain::RegisteredFileMutation) -> SourceFileMutation {
    let kind = match mutation.kind() {
        forge_domain::FileMutationKind::Create => SourceFileMutationKind::Create,
        forge_domain::FileMutationKind::Replace => SourceFileMutationKind::Replace,
        forge_domain::FileMutationKind::Delete => SourceFileMutationKind::Delete,
    };
    let precondition = match mutation.precondition() {
        forge_domain::FilePrecondition::Absent => SourceFilePrecondition::Absent,
        forge_domain::FilePrecondition::Matches(hash) => SourceFilePrecondition::Matches {
            expected_hash: *hash.as_bytes(),
        },
    };
    SourceFileMutation {
        mutation_id: mutation.id().into_uuid(),
        path: mutation.path().as_path().as_os_str().as_bytes().to_vec(),
        kind,
        precondition,
        intended_hash: mutation
            .intended_content_hash()
            .map(|hash| *hash.as_bytes()),
        pre_state: source_file_path_state(mutation.pre_state()),
        post_state: mutation.post_state().map(source_file_path_state),
        revision: mutation.revision().get(),
    }
}

fn source_file_path_state(value: forge_domain::FilePathState) -> SourceFilePathState {
    match value {
        forge_domain::FilePathState::Absent => SourceFilePathState::Absent,
        forge_domain::FilePathState::Regular { hash, size } => SourceFilePathState::Regular {
            hash: *hash.as_bytes(),
            size: size.get(),
        },
    }
}

fn source_tree_mutation_kind(
    value: i64,
) -> Result<SourceTreeMutationKind, HomeTransferSourceInventoryError> {
    match value {
        0 => Ok(SourceTreeMutationKind::CreateDirectory),
        1 => Ok(SourceTreeMutationKind::CreateFile),
        2 => Ok(SourceTreeMutationKind::UpdateFile),
        3 => Ok(SourceTreeMutationKind::DeleteFile),
        4 => Ok(SourceTreeMutationKind::MoveFile),
        5 => Ok(SourceTreeMutationKind::MoveDirectory),
        6 => Ok(SourceTreeMutationKind::DeleteDirectory),
        _ => Err(HomeTransferSourceInventoryError::Corrupt(
            "tree mutation kind",
        )),
    }
}

fn placeholders(count: usize) -> String {
    vec!["?"; count].join(",")
}

fn id_bytes(id: Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}

fn decode_uuid(
    bytes: &[u8],
    field: &'static str,
) -> Result<Uuid, HomeTransferSourceInventoryError> {
    if bytes.len() != 16 {
        return Err(HomeTransferSourceInventoryError::Corrupt(field));
    }
    let id =
        Uuid::from_slice(bytes).map_err(|_| HomeTransferSourceInventoryError::Corrupt(field))?;
    if id.is_nil() {
        return Err(HomeTransferSourceInventoryError::Corrupt(field));
    }
    Ok(id)
}

fn decode_digest(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; 32], HomeTransferSourceInventoryError> {
    bytes
        .try_into()
        .map_err(|_| HomeTransferSourceInventoryError::Corrupt(field))
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn strictly_sorted_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> bool {
    values
        .windows(2)
        .all(|window| key(&window[0]) < key(&window[1]))
}

fn enforce_entry_bound(actual: usize) -> Result<(), HomeTransferSourceInventoryError> {
    if actual > MAX_HOME_SOURCE_ENTRIES {
        Err(HomeTransferSourceInventoryError::Bounds("source entries"))
    } else {
        Ok(())
    }
}

fn source_entry_count(
    agents: usize,
    reservations: usize,
    assignments: usize,
    leases: usize,
    executions: usize,
    approvals: &[SourceApproval],
    change_sets: &[SourceChangeSet],
) -> Result<usize, HomeTransferSourceInventoryError> {
    let mut count = agents
        .checked_add(reservations)
        .and_then(|value| value.checked_add(assignments))
        .and_then(|value| value.checked_add(leases))
        .and_then(|value| value.checked_add(executions))
        .and_then(|value| value.checked_add(approvals.len()))
        .and_then(|value| value.checked_add(change_sets.len()))
        .ok_or(HomeTransferSourceInventoryError::Bounds("source entries"))?;
    for approval in approvals {
        if matches!(&approval.grant, SourceApprovalGrant::Present { .. }) {
            count = count
                .checked_add(1)
                .ok_or(HomeTransferSourceInventoryError::Bounds("source entries"))?;
        }
    }
    for change_set in change_sets {
        let file_entry: usize = usize::from(change_set.file_mutation.is_some());
        let mutation_count = file_entry
            .checked_add(change_set.tree_mutations.len())
            .ok_or(HomeTransferSourceInventoryError::Bounds("source entries"))?;
        count = count
            .checked_add(mutation_count)
            .ok_or(HomeTransferSourceInventoryError::Bounds("source entries"))?;
    }
    Ok(count)
}

fn validate_agent(
    agent: &SourceAgent,
    workspace_id: Uuid,
    sessions: &[Uuid],
) -> Result<(), HomeTransferSourceInventoryError> {
    let Some(session_id) = agent.session_id else {
        return Err(HomeTransferSourceInventoryError::Corrupt("Agent Session"));
    };
    if agent.workspace_id != workspace_id
        || agent.agent_id.is_nil()
        || agent.activity_id.is_nil()
        || session_id.is_nil()
        || !sessions.contains(&session_id)
        || agent.revision < 1
        || agent.created_at_ms < 0
        || agent.updated_at_ms < agent.created_at_ms
        || agent.display_name.is_empty()
        || agent.declared_role.is_empty()
        || forge_domain::AgentDisplayName::new(agent.display_name.clone()).is_err()
        || forge_domain::AgentDeclaredRole::new(agent.declared_role.clone()).is_err()
        || !valid_principal(agent.principal)
        || !principal_transport_matches(agent.principal, agent.transport)
        || !valid_focus(agent.focus)
        || (agent.attachment == SourceAttachment::Detached && !focus_is_empty(agent.focus))
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "Agent identity or state",
        ));
    }
    Ok(())
}

fn validate_reservation(
    reservation: &SourceBindingReservation,
    workspace_id: Uuid,
    sessions: &[Uuid],
) -> Result<(), HomeTransferSourceInventoryError> {
    if reservation.request_id.is_nil()
        || reservation.workspace_id != workspace_id
        || reservation.activity_id.is_nil()
        || reservation.migration_id.is_nil()
        || reservation.destination_id.is_nil()
        || reservation.freeze_revision < 1
        || reservation.agent_id.is_nil()
        || reservation.session_id.is_nil()
        || !sessions.contains(&reservation.session_id)
        || !valid_principal(reservation.principal)
        || reservation.requested_at_ms < 0
        || reservation.reserved_at_ms < reservation.requested_at_ms
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "binding reservation",
        ));
    }
    match &reservation.outcome {
        SourceReservationOutcome::Pending => {}
        SourceReservationOutcome::Activated {
            membership_digest,
            display_name,
            declared_role,
            activated_at_ms,
            ..
        } => {
            if digest_is_zero(membership_digest)
                || *activated_at_ms < reservation.reserved_at_ms
                || display_name.is_empty()
                || declared_role.is_empty()
                || forge_domain::AgentDisplayName::new(display_name.clone()).is_err()
                || forge_domain::AgentDeclaredRole::new(declared_role.clone()).is_err()
            {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "activation receipt",
                ));
            }
        }
        SourceReservationOutcome::Rejected {
            request_digest,
            receipt_digest,
            rejected_at_ms,
            ..
        } => {
            if digest_is_zero(request_digest)
                || digest_is_zero(receipt_digest)
                || *rejected_at_ms < reservation.reserved_at_ms
            {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "rejection receipt",
                ));
            }
        }
        SourceReservationOutcome::Retired {
            preparation_id,
            request_digest,
            receipt_digest,
            observed_at_ms,
        } => {
            if *preparation_id == Uuid::nil()
                || digest_is_zero(request_digest)
                || digest_is_zero(receipt_digest)
                || *observed_at_ms < reservation.reserved_at_ms
            {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "reservation retirement receipt",
                ));
            }
        }
    }
    Ok(())
}

fn validate_assignment(
    assignment: &SourceAssignment,
    workspace_id: Uuid,
    agents: &BTreeMap<Uuid, &SourceAgent>,
) -> Result<(), HomeTransferSourceInventoryError> {
    let Some(agent) = agents.get(&assignment.target_agent_id) else {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "assignment target is outside captured Agents",
        ));
    };
    if assignment.assignment_id.is_nil()
        || assignment.workspace_id != workspace_id
        || assignment.activity_id != agent.activity_id
        || assignment.target_session_id != agent.session_id.unwrap_or(Uuid::nil())
        || assignment.target_principal != agent.principal
        || assignment.target_agent_id == assignment.coordinator_agent_id
        || assignment.target_agent_revision < 1
        || assignment.coordinator_agent_id.is_nil()
        || assignment.coordinator_session_id.is_nil()
        || !valid_principal(assignment.coordinator_principal)
        || assignment.coordinator_revision < 1
        || assignment.revision < 1
        || assignment.created_at_ms < 0
        || assignment.updated_at_ms < assignment.created_at_ms
        || assignment.goal_id.is_nil()
        || assignment.goal_created_at_ms < 0
        || assignment.goal_created_at_ms > assignment.created_at_ms
        || assignment.goal_revision < 1
        || assignment.dag_revision < 1
        || assignment.dag_head_revision < 1
        || assignment.node_id.is_nil()
        || assignment.node_revision < 1
        || !matches!(
            assignment.state,
            SourceAssignmentState::Offered
                | SourceAssignmentState::Running
                | SourceAssignmentState::Submitted
        )
        || (assignment.state == SourceAssignmentState::Submitted)
            != assignment.result_digest.is_some()
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "assignment identity or state",
        ));
    }
    if let SourceAssignmentOrigin::CutContinuation {
        cut_id,
        transfer_id,
        predecessor_id,
    } = assignment.origin
        && (cut_id.is_nil() || transfer_id.is_nil() || predecessor_id.is_nil())
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "assignment continuation origin",
        ));
    }
    if let SourceAssignmentOrigin::HomeHandoff {
        preparation_id,
        handoff_id,
        predecessor_id,
        root_assignment_id,
    } = assignment.origin
        && (preparation_id.is_nil()
            || handoff_id.is_nil()
            || predecessor_id.is_nil()
            || root_assignment_id.is_nil()
            || predecessor_id == assignment.assignment_id
            || root_assignment_id == assignment.assignment_id)
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "assignment Home handoff origin",
        ));
    }
    Ok(())
}

fn validate_writer_lease(
    lease: &SourceWriterLease,
    workspace_id: Uuid,
    agents: &BTreeMap<Uuid, &SourceAgent>,
) -> Result<(), HomeTransferSourceInventoryError> {
    let Some(agent) = agents.get(&lease.agent_id) else {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "Writer Lease actor is outside captured Agents",
        ));
    };
    if lease.lease_id.is_nil()
        || lease.workspace_id != workspace_id
        || lease.activity_id != agent.activity_id
        || lease.revision < 1
        || lease.acquired_at_ms < 0
        || lease.updated_at_ms < lease.acquired_at_ms
        || lease.lease_until_ms <= lease.acquired_at_ms
        || lease.state != SourceWriterLeaseState::Active
        || lease.entries.is_empty()
        || lease.entries.len() > forge_domain::MAX_WRITER_LEASE_SCOPE_ENTRIES
    {
        return Err(HomeTransferSourceInventoryError::Corrupt("Writer Lease"));
    }
    let mut domain_entries = Vec::with_capacity(lease.entries.len());
    for entry in &lease.entries {
        validate_relative_path(&entry.path, "Writer Lease path")?;
        let path = forge_domain::WorkspaceRelativePath::new(PathBuf::from(
            std::ffi::OsString::from_vec(entry.path.clone()),
        ))
        .map_err(|_| HomeTransferSourceInventoryError::Corrupt("Writer Lease path"))?;
        let kind = match entry.kind {
            SourceWriterLeaseScopeKind::ExactPath => forge_domain::WriterLeaseScopeKind::ExactPath,
            SourceWriterLeaseScopeKind::DirectorySubtree => {
                forge_domain::WriterLeaseScopeKind::DirectorySubtree
            }
        };
        domain_entries.push(forge_domain::WriterLeaseScopeEntry::new(kind, path));
    }
    let checked_scope = forge_domain::WriterLeaseScope::new(domain_entries.clone())
        .map_err(|_| HomeTransferSourceInventoryError::Corrupt("Writer Lease scope"))?;
    if checked_scope.entries() != domain_entries.as_slice() {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "Writer Lease scope order",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "execution state, actor preimage, and native closure form one bounded source record"
)]
fn validate_execution(
    execution: &SourceExecution,
    workspace_id: Uuid,
    sessions: &[Uuid],
    agents: &BTreeMap<Uuid, &SourceAgent>,
) -> Result<(), HomeTransferSourceInventoryError> {
    if execution.execution_id.is_nil()
        || execution.workspace_id != workspace_id
        || execution.activity_id.is_nil()
        || execution.revision < 1
        || execution.created_at_ms < 0
        || execution.updated_at_ms < execution.created_at_ms
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "execution identity",
        ));
    }
    match (
        execution.agent_id,
        execution.agent_revision,
        execution.principal,
        execution.goal_id,
        execution.goal_revision,
        execution.dag_revision,
        execution.node_id,
        execution.node_revision,
        execution.command_id.as_deref(),
    ) {
        (None, None, None, None, None, None, None, None, None) => {
            if execution.session_id.is_some() || execution.project_command.is_some() {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "execution session without Agent provenance",
                ));
            }
        }
        (
            Some(agent_id),
            Some(agent_revision),
            Some(principal),
            Some(goal_id),
            Some(goal_revision),
            Some(dag_revision),
            Some(node_id),
            Some(node_revision),
            Some(command_id),
        ) => {
            if agent_id.is_nil()
                || agent_revision < 1
                || !valid_principal(principal)
                || goal_id.is_nil()
                || goal_revision < 1
                || dag_revision < 1
                || node_id.is_nil()
                || node_revision < 1
                || forge_domain::ExecutionCommandId::new(command_id.to_owned()).is_err()
            {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "execution provenance",
                ));
            }
            if let Some(agent) = agents.get(&agent_id) {
                if agent.activity_id != execution.activity_id
                    || execution
                        .session_id
                        .is_some_and(|session| agent.session_id != Some(session))
                    || agent.principal != principal
                {
                    return Err(HomeTransferSourceInventoryError::Corrupt(
                        "execution provenance Agent binding",
                    ));
                }
            } else if execution
                .session_id
                .is_none_or(|session_id| !sessions.contains(&session_id))
            {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "execution provenance actor attribution",
                ));
            }
        }
        _ => {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "partial execution provenance",
            ));
        }
    }
    if execution
        .project_command
        .is_some_and(|command| digest_is_zero(&command.catalog_fingerprint))
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "execution project command fingerprint",
        ));
    }
    if let Some(session_id) = execution.session_id
        && (session_id.is_nil() || !sessions.contains(&session_id))
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "execution Session",
        ));
    }
    match (&execution.state, &execution.closure) {
        (_, SourceNativeClosure::Absent) => {}
        (
            SourceExecutionState::Starting
            | SourceExecutionState::Running
            | SourceExecutionState::Interrupted,
            SourceNativeClosure::Present { .. },
        ) => {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "active execution closure",
            ));
        }
        (
            SourceExecutionState::Completed
            | SourceExecutionState::Failed
            | SourceExecutionState::TimedOut
            | SourceExecutionState::Cancelled,
            SourceNativeClosure::Present { .. },
        ) => {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "closed execution omitted from positive-closure witness",
            ));
        }
        (_, SourceNativeClosure::Unknown) => {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "native closure snapshot is unknown",
            ));
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "approval attribution and unconsumed grant state are validated together"
)]
fn validate_approval(
    approval: &SourceApproval,
    workspace_id: Uuid,
    sessions: &[Uuid],
    activities: &[Uuid],
    agents: &BTreeMap<Uuid, &SourceAgent>,
) -> Result<(), HomeTransferSourceInventoryError> {
    if approval.approval_id.is_nil()
        || approval.workspace_id != workspace_id
        || approval.activity_id.is_nil()
        || approval.execution_id.is_nil()
        || approval.policy_revision < 1
        || approval.revision < 1
        || approval.created_at_ms < 0
        || approval.updated_at_ms < approval.created_at_ms
        || approval.expires_at_ms < approval.created_at_ms
        || approval
            .agent_binding_digest
            .as_ref()
            .is_some_and(|value| value.len() != 32)
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "approval identity or state",
        ));
    }
    validate_approval_binding_digest(approval)?;
    match &approval.attribution {
        SourceApprovalAttribution::LegacyUnknown => {
            if !activities.contains(&approval.activity_id) {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "unattributed approval outside affected Activity",
                ));
            }
        }
        SourceApprovalAttribution::Known {
            agent_id,
            session_id,
            agent_revision,
            principal,
            goal_id,
            goal_revision,
            dag_revision,
            node_id,
            node_revision,
            command_id,
            project_command,
        } => {
            let related = agents.contains_key(agent_id)
                || session_id.is_some_and(|id| sessions.contains(&id));
            if !related
                || agent_id.is_nil()
                || *agent_revision < 1
                || !valid_principal(*principal)
                || goal_id.is_nil()
                || *goal_revision < 1
                || *dag_revision < 1
                || node_id.is_nil()
                || *node_revision < 1
                || forge_domain::ExecutionCommandId::new(command_id.clone()).is_err()
                || session_id.is_some_and(|id| id.is_nil())
            {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "approval provenance",
                ));
            }
            if let Some(agent) = agents.get(agent_id)
                && (agent.activity_id != approval.activity_id
                    || agent.principal != *principal
                    || session_id.is_some_and(|session| agent.session_id != Some(session)))
            {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "approval Agent binding",
                ));
            }
            if project_command.is_some_and(|command| digest_is_zero(&command.catalog_fingerprint)) {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "approval project command fingerprint",
                ));
            }
        }
    }
    match &approval.grant {
        SourceApprovalGrant::Unknown | SourceApprovalGrant::Absent => {}
        SourceApprovalGrant::Present {
            grant_id,
            state,
            revision,
            expires_at_ms,
            consumed_at_ms,
            request_digest,
            action,
            effective_permissions,
            policy_revision,
            source: _,
        } => {
            if grant_id.is_nil()
                || *revision < 1
                || *expires_at_ms < 0
                || consumed_at_ms.is_some_and(|value| value < 0)
                || (*state == SourceExecutionGrantState::Consumed) != consumed_at_ms.is_some()
                || request_digest != &approval.request_digest
                || action != &approval.action
                || effective_permissions != &approval.requested_permissions
                || *policy_revision != approval.policy_revision
            {
                return Err(HomeTransferSourceInventoryError::Corrupt("approval grant"));
            }
            if approval.state == SourceApprovalState::Pending {
                return Err(HomeTransferSourceInventoryError::Corrupt(
                    "pending approval has an execution grant",
                ));
            }
        }
    }
    Ok(())
}

fn validate_approval_binding_digest(
    approval: &SourceApproval,
) -> Result<(), HomeTransferSourceInventoryError> {
    let binding_required = matches!(
        approval.action,
        SourceExecutionActionClass::DiscoveredProjectCommand
            | SourceExecutionActionClass::AnalyzedShell
            | SourceExecutionActionClass::GeneratedProjectCommand
    );
    if binding_required != approval.agent_binding_digest.is_some() {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "approval action binding shape",
        ));
    }
    let SourceApprovalAttribution::Known {
        agent_id,
        session_id,
        agent_revision,
        principal,
        goal_id,
        goal_revision,
        dag_revision,
        node_id,
        node_revision,
        command_id,
        project_command,
    } = &approval.attribution
    else {
        return Ok(());
    };
    if !binding_required {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "known approval provenance without a binding action",
        ));
    }

    let agent_revision = forge_domain::AgentInstanceRevision::new(*agent_revision)
        .map_err(|_| HomeTransferSourceInventoryError::Corrupt("approval Agent revision"))?;
    let goal_revision = forge_domain::GoalRevision::new(*goal_revision)
        .map_err(|_| HomeTransferSourceInventoryError::Corrupt("approval Goal revision"))?;
    let dag_revision = forge_domain::DagRevisionNumber::new(*dag_revision)
        .map_err(|_| HomeTransferSourceInventoryError::Corrupt("approval DAG revision"))?;
    let node_revision = forge_domain::DagNodeRevision::new(*node_revision)
        .map_err(|_| HomeTransferSourceInventoryError::Corrupt("approval node revision"))?;
    let command_id = forge_domain::ExecutionCommandId::new(command_id.clone())
        .map_err(|_| HomeTransferSourceInventoryError::Corrupt("approval command ID"))?;
    let attribution = forge_domain::GoalNodeAttribution::new(
        forge_domain::GoalId::from_uuid(*goal_id),
        goal_revision,
        dag_revision,
        forge_domain::DagNodeId::from_uuid(*node_id),
        node_revision,
    );
    let provenance = forge_domain::ExecutionAgentProvenance::from_parts(
        forge_domain::ExecutionId::from_uuid(approval.execution_id),
        AgentInstanceId::from_uuid(*agent_id),
        agent_revision,
        authenticated_principal(*principal),
        attribution,
        command_id,
        (*session_id).map(AgentSessionId::from_uuid),
    );
    let provenance = match project_command {
        Some(command) => {
            provenance.with_project_command(forge_domain::ProjectCommandEvidence::new(
                match command.class {
                    SourceProjectCommandClass::Verify => forge_domain::ProjectCommandClass::Verify,
                    SourceProjectCommandClass::GeneratedPackage => {
                        forge_domain::ProjectCommandClass::GeneratedPackage
                    }
                },
                forge_domain::ProjectCommandCatalogFingerprint::from_hash(
                    forge_domain::FileContentHash::from_bytes(command.catalog_fingerprint),
                ),
            ))
        }
        None => provenance,
    };
    let expected =
        forge_domain::ApprovalAgentBindingDigest::from_provenance(&provenance).as_bytes();
    if approval
        .agent_binding_digest
        .as_deref()
        .is_none_or(|actual| actual != expected.as_slice())
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "approval provenance preimage does not match parent binding digest",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "file/tree intent identity and state are validated as one captured source record"
)]
fn validate_change_set(
    change_set: &SourceChangeSet,
    workspace_id: Uuid,
    activities: &[Uuid],
) -> Result<(), HomeTransferSourceInventoryError> {
    if change_set.change_set_id.is_nil()
        || change_set.workspace_id != workspace_id
        || !activities.contains(&change_set.activity_id)
        || change_set.runtime_instance_id.is_nil()
        || change_set.workspace_revision < 1
        || change_set.activity_lease_revision < 1
        || change_set.revision < 1
        || change_set.created_at_ms < 0
        || change_set.updated_at_ms < change_set.created_at_ms
        || !matches!(
            change_set.state,
            SourceChangeSetState::Starting | SourceChangeSetState::Failed
        )
        || (change_set.source_tree_request_digest.is_some() && change_set.tree_mutations.is_empty())
        || (change_set.file_mutation.is_some() != change_set.tree_mutations.is_empty())
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "ChangeSet identity or shape",
        ));
    }
    if let Some(digest) = change_set.source_tree_request_digest
        && digest_is_zero(&digest)
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "tree request digest",
        ));
    }
    if let Some(mutation) = &change_set.file_mutation {
        if mutation.mutation_id.is_nil() || mutation.revision < 1 {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "file mutation identity",
            ));
        }
        validate_relative_path(&mutation.path, "file mutation path")?;
        let valid_file_shape = match (mutation.kind, mutation.precondition, mutation.pre_state) {
            (
                SourceFileMutationKind::Create,
                SourceFilePrecondition::Absent,
                SourceFilePathState::Absent,
            ) => mutation.intended_hash.is_some(),
            (
                SourceFileMutationKind::Replace,
                SourceFilePrecondition::Matches { expected_hash },
                SourceFilePathState::Regular { hash, .. },
            ) => mutation.intended_hash.is_some() && expected_hash == hash,
            (
                SourceFileMutationKind::Delete,
                SourceFilePrecondition::Matches { expected_hash },
                SourceFilePathState::Regular { hash, .. },
            ) => mutation.intended_hash.is_none() && expected_hash == hash,
            _ => false,
        };
        if !valid_file_shape {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "file mutation precondition",
            ));
        }
    }
    if change_set.tree_mutations.len() > forge_domain::MAX_TREE_CHANGESET_MUTATIONS
        || !strictly_sorted_by(&change_set.tree_mutations, |mutation| mutation.ordinal)
    {
        return Err(HomeTransferSourceInventoryError::Corrupt(
            "tree mutation order",
        ));
    }
    let mut tree_mutation_ids = BTreeSet::new();
    for mutation in &change_set.tree_mutations {
        if mutation.mutation_id.is_nil()
            || !tree_mutation_ids.insert(mutation.mutation_id)
            || mutation.ordinal < 0
            || usize::try_from(mutation.ordinal)
                .ok()
                .is_none_or(|value| value >= forge_domain::MAX_TREE_CHANGESET_MUTATIONS)
            || mutation.revision < 1
            || (mutation.applied && mutation.revision != 2)
            || (!mutation.applied && mutation.revision != 1)
        {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "tree mutation identity",
            ));
        }
        validate_relative_path(&mutation.primary_path, "tree mutation path")?;
        if let Some(secondary_path) = &mutation.secondary_path {
            validate_relative_path(secondary_path, "tree mutation secondary path")?;
        }
        let valid_shape = match mutation.kind {
            SourceTreeMutationKind::CreateDirectory | SourceTreeMutationKind::DeleteDirectory => {
                mutation.secondary_path.is_none()
                    && mutation.expected_hash.is_none()
                    && mutation.intended_hash.is_none()
            }
            SourceTreeMutationKind::CreateFile => {
                mutation.secondary_path.is_none()
                    && mutation.expected_hash.is_none()
                    && mutation.intended_hash.is_some()
            }
            SourceTreeMutationKind::UpdateFile => {
                mutation.secondary_path.is_none()
                    && mutation.expected_hash.is_some()
                    && mutation.intended_hash.is_some()
            }
            SourceTreeMutationKind::DeleteFile => {
                mutation.secondary_path.is_none()
                    && mutation.expected_hash.is_some()
                    && mutation.intended_hash.is_none()
            }
            SourceTreeMutationKind::MoveFile => {
                mutation.secondary_path.is_some()
                    && mutation.expected_hash.is_some()
                    && mutation.intended_hash.is_none()
            }
            SourceTreeMutationKind::MoveDirectory => {
                mutation.secondary_path.is_some()
                    && mutation.expected_hash.is_none()
                    && mutation.intended_hash.is_none()
            }
        };
        if !valid_shape {
            return Err(HomeTransferSourceInventoryError::Corrupt(
                "tree mutation operation shape",
            ));
        }
    }
    Ok(())
}

fn valid_principal(principal: SourcePrincipal) -> bool {
    match principal {
        SourcePrincipal::TrustedStdio => true,
        SourcePrincipal::DirectToken(id) | SourcePrincipal::OAuthGrant(id) => !id.is_nil(),
    }
}

fn authenticated_principal(principal: SourcePrincipal) -> AuthenticatedPrincipal {
    match principal {
        SourcePrincipal::TrustedStdio => AuthenticatedPrincipal::TrustedStdio,
        SourcePrincipal::DirectToken(id) => {
            AuthenticatedPrincipal::DirectToken(forge_domain::DirectTokenId::from_uuid(id))
        }
        SourcePrincipal::OAuthGrant(id) => {
            AuthenticatedPrincipal::OAuthGrant(forge_domain::OAuthGrantId::from_uuid(id))
        }
    }
}

fn principal_transport_matches(principal: SourcePrincipal, transport: SourceTransport) -> bool {
    match principal {
        SourcePrincipal::TrustedStdio => true,
        SourcePrincipal::DirectToken(_) | SourcePrincipal::OAuthGrant(_) => matches!(
            transport,
            SourceTransport::Retired | SourceTransport::StreamableHttp
        ),
    }
}

fn valid_focus(focus: SourceFocus) -> bool {
    let goal_present = focus.goal_id.is_some();
    let goal_revision_present = focus.goal_revision.is_some();
    let node_present = focus.node_id.is_some();
    let node_revision_present = focus.node_revision.is_some();
    goal_present == goal_revision_present
        && node_present == node_revision_present
        && (goal_present || (focus.dag_revision.is_none() && !node_present))
        && (!node_present || focus.dag_revision.is_some())
        && focus.goal_id.is_none_or(|id| !id.is_nil())
        && focus.goal_revision.is_none_or(|revision| revision >= 1)
        && focus.dag_revision.is_none_or(|revision| revision >= 1)
        && focus.node_id.is_none_or(|id| !id.is_nil())
        && focus.node_revision.is_none_or(|revision| revision >= 1)
}

fn focus_is_empty(focus: SourceFocus) -> bool {
    focus.goal_id.is_none()
        && focus.goal_revision.is_none()
        && focus.dag_revision.is_none()
        && focus.node_id.is_none()
        && focus.node_revision.is_none()
}

fn validate_relative_path(
    bytes: &[u8],
    field: &'static str,
) -> Result<(), HomeTransferSourceInventoryError> {
    if bytes.is_empty() || bytes.len() > forge_domain::MAX_WORKSPACE_RELATIVE_PATH_BYTES {
        return Err(HomeTransferSourceInventoryError::Corrupt(field));
    }
    forge_domain::WorkspaceRelativePath::new(PathBuf::from(std::ffi::OsString::from_vec(
        bytes.to_vec(),
    )))
    .map_err(|_| HomeTransferSourceInventoryError::Corrupt(field))?;
    Ok(())
}

fn digest_is_zero(digest: &[u8; 32]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        error::Error,
        fs,
        path::{Path, PathBuf},
    };

    use forge_domain::{
        AcquireWriterLease, ActivityId, AgentDeclaredRole, AgentDisplayName, AgentEventId,
        AgentInstanceId, AgentSessionId, AgentTransportKind, AuthenticatedPrincipal,
        CreateActivity, EstablishWorkspace, ForgeBackendId, HomeTransferReservationRetirementGrant,
        HomeTransferReservationRetirementRequest, HomeTransferSourceAction,
        HomeTransferSourceBinding, HomeTransferSourceGrant, HomeTransferSourceRequest,
        HomeTransferSourceScope, HomeTransferSourceSubject, HomeTransferSourceWitness, LocationId,
        OrchestrationIssuerId, RegisteredAgentInstance, TimestampMillis, WorkspaceId,
        WorkspaceRelativePath, WorkspaceRoot, WriterLeaseDurationMillis, WriterLeaseId,
        WriterLeaseScope, WriterLeaseScopeEntry, WriterLeaseScopeKind,
    };
    use rusqlite::{Connection, TransactionBehavior};
    use uuid::Uuid;

    use crate::{
        AgentBindingReservationRequest, AgentOperationsFreezeRequest, WorkspaceStore,
        workspace_agents,
    };

    use super::{HomeTransferSourceInventory, SourceReservationOutcome};

    struct TemporaryWorkspaceRoot(PathBuf);

    impl TemporaryWorkspaceRoot {
        fn new() -> Result<Self, Box<dyn Error>> {
            let path = std::env::temp_dir()
                .join(format!("forge-home-transfer-inventory-{}", Uuid::now_v7()));
            fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TemporaryWorkspaceRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn source_clock(value: i64) -> Result<TimestampMillis, crate::HomeTransferStoreError> {
        TimestampMillis::new(value).map_err(|_| crate::HomeTransferStoreError::Clock)
    }

    fn id(seed: u128) -> Uuid {
        Uuid::from_u128(seed)
    }

    fn uuid_for_index(index: usize) -> Result<Uuid, Box<dyn Error>> {
        let value = u128::try_from(index)?
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("fixture UUID index overflow"))?;
        Ok(Uuid::from_u128(value))
    }

    fn store_with_activity() -> Result<
        (
            TemporaryWorkspaceRoot,
            forge_workspace::WorkspaceStateLayout,
            WorkspaceStore,
            forge_domain::RegisteredActivity,
        ),
        Box<dyn Error>,
    > {
        let root = TemporaryWorkspaceRoot::new()?;
        let layout = forge_workspace::WorkspaceStateLayout::initialize(root.path())?;
        let workspace_id = WorkspaceId::from_uuid(id(Uuid::now_v7().as_u128()));
        let command = EstablishWorkspace::new(
            workspace_id,
            LocationId::from_uuid(id(Uuid::now_v7().as_u128())),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            timestamp(1)?,
        );
        let mut store = WorkspaceStore::open(&layout, &command)?;
        let workspace = store.workspace()?;
        let activity = store.create_activity(&CreateActivity::new(
            ActivityId::from_uuid(id(Uuid::now_v7().as_u128())),
            workspace.id(),
            workspace.revision(),
            timestamp(2)?,
        ))?;
        Ok((root, layout, store, activity))
    }

    fn source_request(
        store: &WorkspaceStore,
        destination_id: Uuid,
        sessions: Vec<AgentSessionId>,
        bindings: Vec<HomeTransferSourceBinding>,
        seed: u128,
    ) -> Result<HomeTransferSourceRequest, Box<dyn Error>> {
        let workspace = store.workspace()?;
        let witness = HomeTransferSourceWitness::new(id(seed), [0xA1; 32], [0xB2; 32])?;
        let scope = HomeTransferSourceScope::new(
            workspace.id(),
            workspace.revision(),
            ForgeBackendId::from_uuid(id(seed + 2)),
            destination_id,
        )?;
        let subject = HomeTransferSourceSubject::new(
            id(seed + 3),
            1,
            id(seed + 4),
            id(seed + 5),
            id(seed + 6),
            id(seed + 7),
            1,
            1,
        )?;
        Ok(HomeTransferSourceRequest::new(
            witness, scope, subject, sessions, bindings,
        )?)
    }

    fn source_agent(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        agent_id: AgentInstanceId,
        session_id: AgentSessionId,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredAgentInstance, Box<dyn Error>> {
        Ok(RegisteredAgentInstance::create_bound(
            agent_id,
            workspace_id,
            activity_id,
            session_id,
            AgentDisplayName::new("inventory fixture".to_owned())?,
            AgentDeclaredRole::new("worker".to_owned())?,
            AgentTransportKind::Stdio,
            AuthenticatedPrincipal::TrustedStdio,
            observed_at,
        ))
    }

    struct LiveSourceFixture {
        layout: forge_workspace::WorkspaceStateLayout,
        store: WorkspaceStore,
        workspace_id: WorkspaceId,
        activity: forge_domain::RegisteredActivity,
        agent: RegisteredAgentInstance,
        session_id: AgentSessionId,
        goal_node: forge_domain::GoalNodeAttribution,
        runtime_id: forge_domain::RuntimeInstanceId,
        _root: TemporaryWorkspaceRoot,
    }

    #[allow(
        clippy::too_many_lines,
        reason = "builds one canonical Store with an Agent, coordinator, Goal, DAG, and focus"
    )]
    fn live_source_fixture() -> Result<LiveSourceFixture, Box<dyn Error>> {
        let (root, layout, mut store, _unleased_activity) = store_with_activity()?;
        let workspace = store.workspace()?;
        let workspace_id = workspace.id();
        let runtime_id = forge_domain::RuntimeInstanceId::from_uuid(Uuid::now_v7());
        let activity = store.bootstrap_activity(&forge_domain::BootstrapActivity::new(
            ActivityId::from_uuid(Uuid::now_v7()),
            workspace_id,
            workspace.revision(),
            runtime_id,
            timestamp(1_000)?,
            timestamp(2)?,
        ))?;
        let session_id = AgentSessionId::from_uuid(Uuid::now_v7());
        let agent = source_agent(
            workspace_id,
            activity.id(),
            AgentInstanceId::from_uuid(Uuid::now_v7()),
            session_id,
            timestamp(3)?,
        )?;
        let seed_connection = Connection::open(layout.database_path())?;
        seed_connection.pragma_update(None, "foreign_keys", true)?;
        crate::legacy_agent_seed::seed_agent(
            &seed_connection,
            &agent,
            Some(AgentEventId::from_uuid(Uuid::now_v7())),
        )?;
        drop(seed_connection);

        let coordinator_binding = store.claim_activity_coordinator(
            forge_domain::ClaimActivityCoordinator::new(
                workspace_id,
                activity.id(),
                agent.id(),
                agent.principal(),
                timestamp(4)?,
                session_id,
            ),
            timestamp(99)?,
        )?;
        let coordinator = forge_domain::ActivityCoordinatorActor::new(
            workspace_id,
            activity.id(),
            agent.id(),
            coordinator_binding.revision(),
            agent.principal(),
            session_id,
        );
        let goal = forge_domain::RegisteredGoal::create(
            forge_domain::GoalId::from_uuid(Uuid::now_v7()),
            workspace_id,
            activity.id(),
            forge_domain::GoalContract::new(
                forge_domain::GoalObjective::new("Capture pending source work".to_owned())?,
                vec![forge_domain::GoalStatement::new(
                    "Durable source scope stays visible".to_owned(),
                )?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            timestamp(5)?,
        );
        let _stored_goal = store.insert_goal(coordinator, &goal, timestamp(99)?)?;
        let definition = forge_domain::DagNodeDefinition::new(
            forge_domain::DagNodeId::from_uuid(Uuid::now_v7()),
            forge_domain::DagNodeOrdinal::new(0)?,
            forge_domain::DagNodeTitle::new("Record intent".to_owned())?,
            forge_domain::DagNodeObjective::new("Keep the source scope exact".to_owned())?,
            vec![forge_domain::DagAcceptanceCriterion::new(
                "The durable intent is captured".to_owned(),
            )?],
        )?;
        let dag = forge_domain::DagRevision::new(
            forge_domain::DagRevisionId::from_uuid(Uuid::now_v7()),
            goal.id(),
            goal.revision(),
            forge_domain::DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            timestamp(6)?,
        )?;
        let pending_node = forge_domain::RegisteredDagNode::create(
            goal.id(),
            dag.number(),
            definition,
            timestamp(6)?,
        );
        let _stored_dag =
            store.insert_dag_revision(&dag, std::slice::from_ref(&pending_node), &[], None)?;
        let active_node = store.start_dag_node(crate::DagNodeTransition::new(
            crate::DagTransitionScope::new(
                workspace_id,
                activity.id(),
                goal.id(),
                goal.revision(),
                dag.number(),
            ),
            pending_node.id(),
            pending_node.revision(),
            timestamp(7)?,
        ))?;
        let goal_node = forge_domain::GoalNodeAttribution::new(
            goal.id(),
            goal.revision(),
            dag.number(),
            active_node.id(),
            active_node.revision(),
        );
        let focus = forge_domain::AgentFocus::new(
            Some(forge_domain::GoalAttribution::new(
                goal.id(),
                goal.revision(),
            )),
            Some(dag.number()),
            Some(forge_domain::AgentFocusNode::new(
                active_node.id(),
                active_node.revision(),
            )),
        )?;
        let current_agent = store
            .get_agent(agent.id())?
            .ok_or("source fixture Agent missing before focus")?;
        let agent = store.set_agent_focus(
            coordinator,
            &forge_domain::SetAgentFocus::new(
                agent.id(),
                activity.id(),
                current_agent.revision(),
                focus,
                timestamp(8)?,
            ),
            timestamp(99)?,
        )?;
        Ok(LiveSourceFixture {
            layout,
            store,
            workspace_id,
            activity,
            agent,
            session_id,
            goal_node,
            runtime_id,
            _root: root,
        })
    }

    fn add_unrelated_agent(
        fixture: &mut LiveSourceFixture,
    ) -> Result<RegisteredAgentInstance, Box<dyn Error>> {
        let session_id = AgentSessionId::from_uuid(Uuid::now_v7());
        let agent = source_agent(
            fixture.workspace_id,
            fixture.activity.id(),
            AgentInstanceId::from_uuid(Uuid::now_v7()),
            session_id,
            timestamp(9)?,
        )?;
        let seed_connection = Connection::open(fixture.layout.database_path())?;
        seed_connection.pragma_update(None, "foreign_keys", true)?;
        crate::legacy_agent_seed::seed_agent(
            &seed_connection,
            &agent,
            Some(AgentEventId::from_uuid(Uuid::now_v7())),
        )?;
        drop(seed_connection);
        let current = fixture
            .store
            .get_agent(agent.id())?
            .ok_or("unrelated fixture Agent missing")?;
        let goal = fixture.goal_node;
        let focus = forge_domain::AgentFocus::new(
            Some(forge_domain::GoalAttribution::new(
                goal.goal_id(),
                goal.expected_goal_revision(),
            )),
            Some(goal.dag_revision()),
            Some(forge_domain::AgentFocusNode::new(
                goal.node_id(),
                goal.expected_node_revision(),
            )),
        )?;
        let coordinator = fixture
            .store
            .get_activity_coordinator(fixture.activity.id())?
            .ok_or("source fixture Coordinator missing")?;
        let coordinator_agent = fixture
            .store
            .get_agent(coordinator.agent_id())?
            .ok_or("source fixture Coordinator Agent missing")?;
        let actor = forge_domain::ActivityCoordinatorActor::new(
            fixture.workspace_id,
            fixture.activity.id(),
            coordinator.agent_id(),
            coordinator.revision(),
            coordinator_agent.principal(),
            coordinator_agent
                .session_id()
                .ok_or("source fixture Coordinator Session missing")?,
        );
        Ok(fixture.store.set_agent_focus(
            actor,
            &forge_domain::SetAgentFocus::new(
                agent.id(),
                fixture.activity.id(),
                current.revision(),
                focus,
                timestamp(10)?,
            ),
            timestamp(99)?,
        )?)
    }

    fn execution_provenance(
        fixture: &LiveSourceFixture,
        agent: &RegisteredAgentInstance,
        execution_id: forge_domain::ExecutionId,
        command_id: &str,
    ) -> Result<forge_domain::ExecutionAgentProvenance, Box<dyn Error>> {
        let session_id = agent
            .session_id()
            .ok_or("execution fixture Agent has no Session")?;
        Ok(forge_domain::ExecutionAgentProvenance::new(
            execution_id,
            agent.id(),
            agent.revision(),
            agent.principal(),
            fixture.goal_node,
            forge_domain::ExecutionCommandId::new(command_id.to_owned())?,
            session_id,
        ))
    }

    fn begin_execution_record(
        fixture: &mut LiveSourceFixture,
        execution_id: forge_domain::ExecutionId,
        digest: [u8; 32],
        observed_at: i64,
        provenance: Option<forge_domain::ExecutionAgentProvenance>,
    ) -> Result<(), Box<dyn Error>> {
        let request = forge_domain::ExecutionRequest::new(
            forge_domain::ExecutionAttribution::new(
                execution_id,
                fixture.workspace_id,
                fixture.activity.id(),
            ),
            forge_domain::ExecutionKind::Structured {
                program: forge_domain::ExecutionProgram::new(PathBuf::from("/usr/bin/true"))?,
                arguments: Vec::new(),
            },
            None,
            forge_domain::ExecutionLimits::new(
                forge_domain::ExecutionTimeoutMillis::new(1_000)?,
                forge_domain::ExecutionOutputLimit::new(32)?,
            ),
            forge_domain::ExecutionPermissions::new(true, false, false),
        )?;
        let digest = forge_domain::ExecutionRequestDigest::from_bytes(digest);
        let mut begin =
            forge_domain::BeginExecution::from_request(&request, digest, timestamp(observed_at)?)
                .with_runtime_owner(fixture.runtime_id);
        if let Some(provenance) = provenance {
            begin = begin.with_provenance(provenance)?;
        }
        let _begin = fixture.store.begin_execution(&begin)?;
        Ok(())
    }

    fn pending_agent_approval(
        fixture: &LiveSourceFixture,
        execution_id: forge_domain::ExecutionId,
        execution_digest: [u8; 32],
        approval_id: Uuid,
        observed_at: i64,
        provenance: &forge_domain::ExecutionAgentProvenance,
    ) -> Result<forge_domain::RegisteredApprovalRequest, Box<dyn Error>> {
        let request = forge_domain::ExecutionAuthorizationRequest::new(
            execution_id,
            fixture.workspace_id,
            fixture.activity.id(),
            forge_domain::ExecutionRequestDigest::from_bytes(execution_digest),
            forge_domain::ExecutionActionClass::AnalyzedShell,
            forge_domain::RequestedExecutionPermissions::new(
                forge_domain::ExecutionPermissions::new(true, false, false),
            ),
        );
        Ok(forge_domain::RegisteredApprovalRequest::pending(
            forge_domain::ApprovalRequestId::from_uuid(approval_id),
            request,
            forge_domain::PolicyRevision::INITIAL,
            timestamp(observed_at)?,
            timestamp(observed_at + 100)?,
        )?
        .with_agent_binding(forge_domain::ApprovalAgentBindingDigest::from_provenance(
            provenance,
        )))
    }

    fn source_request_for_live_fixture(
        fixture: &LiveSourceFixture,
        seed: u128,
    ) -> Result<HomeTransferSourceRequest, Box<dyn Error>> {
        source_request(
            &fixture.store,
            Uuid::now_v7(),
            vec![fixture.session_id],
            vec![HomeTransferSourceBinding::new(
                fixture.activity.id(),
                fixture.agent.id(),
                fixture.session_id,
                fixture.agent.principal(),
            )?],
            seed,
        )
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one source snapshot covers cross-Activity, detached, lease, and declared-binding completeness"
    )]
    fn captures_same_session_agents_across_activities_including_detached_extra_and_lease()
    -> Result<(), Box<dyn Error>> {
        let (_root, layout, mut store, first_activity) = store_with_activity()?;
        let workspace = store.workspace()?;
        let second_activity = store.create_activity(&CreateActivity::new(
            ActivityId::from_uuid(id(Uuid::now_v7().as_u128())),
            workspace.id(),
            workspace.revision(),
            timestamp(3)?,
        ))?;
        let session_id = AgentSessionId::from_uuid(id(Uuid::now_v7().as_u128()));
        let first_agent = source_agent(
            workspace.id(),
            first_activity.id(),
            AgentInstanceId::from_uuid(id(Uuid::now_v7().as_u128())),
            session_id,
            timestamp(4)?,
        )?;
        let extra_detached_agent = source_agent(
            workspace.id(),
            second_activity.id(),
            AgentInstanceId::from_uuid(id(Uuid::now_v7().as_u128())),
            session_id,
            timestamp(4)?,
        )?;
        let mut seed_connection = Connection::open(layout.database_path())?;
        seed_connection.pragma_update(None, "foreign_keys", true)?;
        crate::legacy_agent_seed::seed_agent(
            &seed_connection,
            &first_agent,
            Some(AgentEventId::from_uuid(id(Uuid::now_v7().as_u128()))),
        )?;
        crate::legacy_agent_seed::seed_agent(
            &seed_connection,
            &extra_detached_agent,
            Some(AgentEventId::from_uuid(id(Uuid::now_v7().as_u128()))),
        )?;
        let transaction =
            seed_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current =
            workspace_agents::get_in_transaction(&transaction, extra_detached_agent.id())?
                .ok_or("detached fixture Agent missing")?;
        let _detached =
            workspace_agents::detach_in_transaction(&transaction, &current, timestamp(5)?)?;
        transaction.commit()?;
        drop(seed_connection);

        let path = WorkspaceRelativePath::new(PathBuf::from("src/lib.rs"))?;
        let scope = WriterLeaseScope::new(vec![WriterLeaseScopeEntry::new(
            WriterLeaseScopeKind::ExactPath,
            path,
        )])?;
        store.acquire_writer_lease(&AcquireWriterLease::new(
            WriterLeaseId::from_uuid(id(Uuid::now_v7().as_u128())),
            workspace.id(),
            first_activity.id(),
            first_agent.id(),
            scope,
            WriterLeaseDurationMillis::MIN,
            timestamp(6)?,
            session_id,
            AuthenticatedPrincipal::TrustedStdio,
        )?)?;

        let request = source_request(
            &store,
            id(Uuid::now_v7().as_u128()),
            vec![session_id],
            vec![HomeTransferSourceBinding::new(
                first_agent.activity_id(),
                first_agent.id(),
                session_id,
                first_agent.principal(),
            )?],
            Uuid::now_v7().as_u128(),
        )?;
        let mut source_connection = Connection::open(layout.database_path())?;
        source_connection.pragma_update(None, "foreign_keys", true)?;
        let transaction =
            source_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inventory = HomeTransferSourceInventory::capture(&transaction, &request)?;
        inventory.validate_for_request(&request)?;

        assert_eq!(inventory.agents.len(), 2);
        assert_eq!(inventory.affected_agent_ids.len(), 2);
        assert_eq!(inventory.affected_activity_ids.len(), 2);
        assert!(inventory.agents.iter().any(|agent| {
            agent.agent_id == extra_detached_agent.id().into_uuid()
                && agent.attachment == super::SourceAttachment::Detached
        }));
        assert_eq!(inventory.writer_leases.len(), 1);
        assert_eq!(
            inventory.writer_leases[0].agent_id,
            first_agent.id().into_uuid()
        );

        let mut missing_declared_binding = inventory.clone();
        missing_declared_binding
            .agents
            .retain(|agent| agent.agent_id != first_agent.id().into_uuid());
        missing_declared_binding.writer_leases.clear();
        missing_declared_binding.affected_agent_ids = vec![extra_detached_agent.id().into_uuid()];
        missing_declared_binding.affected_activity_ids = vec![second_activity.id().into_uuid()];
        missing_declared_binding.source_high_water_ms = missing_declared_binding
            .agents
            .iter()
            .map(|agent| agent.updated_at_ms)
            .max()
            .unwrap_or(0);
        assert!(matches!(
            missing_declared_binding.validate_for_request(&request),
            Err(super::HomeTransferSourceInventoryError::BindingConflict)
        ));
        transaction.rollback()?;
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one real Prepared retirement proves current projection and preserved original fences"
    )]
    fn captures_current_reservation_retirement_without_rewriting_prepared_source()
    -> Result<(), Box<dyn Error>> {
        let (_root, layout, mut store, activity) = store_with_activity()?;
        let freeze = store.freeze_agent_operations(&AgentOperationsFreezeRequest::new(
            id(Uuid::now_v7().as_u128()),
            id(Uuid::now_v7().as_u128()),
            timestamp(3)?,
        )?)?;
        let session_id = AgentSessionId::from_uuid(id(Uuid::now_v7().as_u128()));
        let reservation_request = AgentBindingReservationRequest::new(
            id(Uuid::now_v7().as_u128()),
            activity.id(),
            AgentInstanceId::from_uuid(id(Uuid::now_v7().as_u128())),
            session_id,
            AuthenticatedPrincipal::TrustedStdio,
            timestamp(4)?,
        )?;
        let _reservation =
            store.reserve_agent_binding(&freeze, &reservation_request, timestamp(5)?)?;
        let delegation = store.delegate_agent_operations(&freeze, [0x4A; 32], timestamp(6)?)?;
        let request = source_request(
            &store,
            delegation.destination_id(),
            vec![session_id],
            Vec::new(),
            Uuid::now_v7().as_u128(),
        )?;
        let mut source_connection = Connection::open(layout.database_path())?;
        source_connection.pragma_update(None, "foreign_keys", true)?;
        let transaction =
            source_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inventory = HomeTransferSourceInventory::capture(&transaction, &request)?;
        inventory.validate_for_request(&request)?;

        assert_eq!(inventory.version, 2);
        assert!(inventory.agents.is_empty());
        assert_eq!(inventory.reservations.len(), 1);
        assert!(matches!(
            &inventory.reservations[0].outcome,
            SourceReservationOutcome::Pending
        ));
        assert_eq!(
            inventory.affected_activity_ids,
            &[activity.id().into_uuid()]
        );
        let mut inflated_high_water = inventory.clone();
        inflated_high_water.source_high_water_ms += 1;
        assert!(matches!(
            inflated_high_water.validate_for_request(&request),
            Err(super::HomeTransferSourceInventoryError::Corrupt(_))
        ));
        transaction.rollback()?;

        let issuer = OrchestrationIssuerId::from_uuid(id(Uuid::now_v7().as_u128()));
        let backend = request.scope().backend_id();
        let destination = request.scope().destination_id();
        let source_grant = HomeTransferSourceGrant::new(
            issuer,
            HomeTransferSourceAction::Prepare,
            request.request_digest(),
            timestamp(8)?,
            timestamp(50)?,
        )?;
        let prepared = store.prepare_home_transfer_source(
            &request,
            source_grant,
            issuer,
            backend,
            destination,
            || source_clock(10),
        )?;
        let preparation_id = request.witness().preparation_id();
        let original_inventory = prepared
            .record()
            .inventory_payload()
            .ok_or("Prepared source has no inventory")?
            .to_vec();

        let retirement_request = HomeTransferReservationRetirementRequest::new(
            request.scope(),
            preparation_id,
            request.request_digest(),
            *prepared.record().outcome_digest(),
            reservation_request.request_id(),
        )?;
        let retirement_grant = HomeTransferReservationRetirementGrant::new(
            issuer,
            retirement_request.request_digest(),
            timestamp(11)?,
            timestamp(50)?,
        )?;
        let retirement = store.retire_home_transfer_unused_reservation(
            &retirement_request,
            retirement_grant,
            issuer,
            backend,
            destination,
            || source_clock(12),
        )?;
        assert_eq!(retirement.record().request(), &retirement_request);

        let current_transaction =
            source_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = HomeTransferSourceInventory::capture(&current_transaction, &request)?;
        current.validate_for_request(&request)?;
        assert_eq!(current.version, 2);
        assert!(current.agents.is_empty());
        assert_eq!(current.reservations.len(), 1);
        assert!(matches!(
            &current.reservations[0].outcome,
            SourceReservationOutcome::Retired {
                preparation_id: actual_preparation_id,
                request_digest,
                receipt_digest,
                observed_at_ms: 12,
            } if *actual_preparation_id == preparation_id
                && request_digest == retirement_request.request_digest().as_bytes()
                && receipt_digest == retirement.record().receipt_digest()
        ));
        assert!(current.affected_activity_ids.is_empty());
        current_transaction.rollback()?;
        assert!(
            crate::workspace_home_transfers::blocks_activity_continuation(
                &source_connection,
                request.scope().workspace_id(),
                activity.id(),
            )?
        );

        let persisted = store
            .get_home_transfer_source(preparation_id, issuer, backend, destination)?
            .ok_or("Prepared source disappeared after retirement")?;
        assert_eq!(
            persisted.inventory_payload(),
            Some(original_inventory.as_slice())
        );
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one source snapshot verifies current, legacy, and unrelated approval/execution attribution"
    )]
    fn captures_real_execution_and_known_or_legacy_approval_rows_only_for_target_actor()
    -> Result<(), Box<dyn Error>> {
        let mut fixture = live_source_fixture()?;

        let known_execution_id = forge_domain::ExecutionId::from_uuid(Uuid::now_v7());
        let known_digest = [0x41; 32];
        let known_provenance =
            execution_provenance(&fixture, &fixture.agent, known_execution_id, "make:ci")?;
        begin_execution_record(
            &mut fixture,
            known_execution_id,
            known_digest,
            12,
            Some(known_provenance.clone()),
        )?;
        let known_approval_id = Uuid::now_v7();
        let known_approval = pending_agent_approval(
            &fixture,
            known_execution_id,
            known_digest,
            known_approval_id,
            13,
            &known_provenance,
        )?;
        let _stored_approval = fixture
            .store
            .insert_pending_approval_for_goal_with_provenance(
                &known_approval,
                None,
                Some(&known_provenance),
            )?;

        let legacy_execution_id = forge_domain::ExecutionId::from_uuid(Uuid::now_v7());
        let legacy_digest = [0x42; 32];
        let legacy_preimage =
            execution_provenance(&fixture, &fixture.agent, legacy_execution_id, "make:test")?;
        begin_execution_record(&mut fixture, legacy_execution_id, legacy_digest, 14, None)?;
        let legacy_approval_id = Uuid::now_v7();
        let legacy_approval = pending_agent_approval(
            &fixture,
            legacy_execution_id,
            legacy_digest,
            legacy_approval_id,
            15,
            &legacy_preimage,
        )?;
        let _legacy_approval = fixture.store.insert_pending_approval(&legacy_approval)?;

        let unrelated_agent = add_unrelated_agent(&mut fixture)?;
        let unrelated_execution_id = forge_domain::ExecutionId::from_uuid(Uuid::now_v7());
        let unrelated_digest = [0x43; 32];
        let unrelated_provenance = execution_provenance(
            &fixture,
            &unrelated_agent,
            unrelated_execution_id,
            "make:other",
        )?;
        begin_execution_record(
            &mut fixture,
            unrelated_execution_id,
            unrelated_digest,
            16,
            Some(unrelated_provenance.clone()),
        )?;
        let unrelated_approval_id = Uuid::now_v7();
        let unrelated_approval = pending_agent_approval(
            &fixture,
            unrelated_execution_id,
            unrelated_digest,
            unrelated_approval_id,
            17,
            &unrelated_provenance,
        )?;
        let _stored_approval = fixture
            .store
            .insert_pending_approval_for_goal_with_provenance(
                &unrelated_approval,
                None,
                Some(&unrelated_provenance),
            )?;

        let request = source_request_for_live_fixture(&fixture, Uuid::now_v7().as_u128())?;
        let mut source_connection = Connection::open(fixture.layout.database_path())?;
        source_connection.pragma_update(None, "foreign_keys", true)?;
        let transaction =
            source_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inventory = HomeTransferSourceInventory::capture(&transaction, &request)?;
        inventory.validate_for_request(&request)?;

        assert_eq!(inventory.executions.len(), 2);
        let execution_ids = inventory
            .executions
            .iter()
            .map(|entry| entry.execution_id)
            .collect::<BTreeSet<_>>();
        assert!(execution_ids.contains(&known_execution_id.into_uuid()));
        assert!(execution_ids.contains(&legacy_execution_id.into_uuid()));
        assert!(!execution_ids.contains(&unrelated_execution_id.into_uuid()));
        let known_execution = inventory
            .executions
            .iter()
            .find(|entry| entry.execution_id == known_execution_id.into_uuid())
            .ok_or("Known execution missing from source capture")?;
        assert_eq!(known_execution.revision, 1);
        assert_eq!(
            known_execution.agent_id,
            Some(fixture.agent.id().into_uuid())
        );
        assert_eq!(
            known_execution.session_id,
            Some(fixture.session_id.into_uuid())
        );
        assert_eq!(
            known_execution.goal_id,
            Some(fixture.goal_node.goal_id().into_uuid())
        );
        assert_eq!(
            known_execution.node_id,
            Some(fixture.goal_node.node_id().into_uuid())
        );
        let legacy_execution = inventory
            .executions
            .iter()
            .find(|entry| entry.execution_id == legacy_execution_id.into_uuid())
            .ok_or("legacy execution missing from source capture")?;
        assert_eq!(legacy_execution.revision, 1);
        assert_eq!(
            legacy_execution.activity_id,
            fixture.activity.id().into_uuid()
        );
        assert_eq!(legacy_execution.agent_id, None);
        assert!(inventory.executions.iter().all(|entry| {
            entry.state == super::SourceExecutionState::Starting
                && matches!(&entry.closure, super::SourceNativeClosure::Absent)
        }));

        assert_eq!(inventory.approvals.len(), 2);
        let known_record = inventory
            .approvals
            .iter()
            .find(|entry| entry.approval_id == known_approval_id)
            .ok_or("Known approval missing from source capture")?;
        assert!(matches!(
            &known_record.attribution,
            super::SourceApprovalAttribution::Known { .. }
        ));
        assert_eq!(known_record.execution_id, known_execution_id.into_uuid());
        assert_eq!(known_record.state, super::SourceApprovalState::Pending);
        assert_eq!(known_record.revision, 1);
        if let super::SourceApprovalAttribution::Known {
            agent_id,
            session_id,
            goal_revision,
            command_id,
            ..
        } = &known_record.attribution
        {
            assert_eq!(*agent_id, fixture.agent.id().into_uuid());
            assert_eq!(*session_id, Some(fixture.session_id.into_uuid()));
            assert_eq!(
                *goal_revision,
                fixture.goal_node.expected_goal_revision().get()
            );
            assert_eq!(command_id, "make:ci");
        }
        assert_eq!(
            known_record.agent_binding_digest.as_ref().map(Vec::len),
            Some(32)
        );
        let legacy_record = inventory
            .approvals
            .iter()
            .find(|entry| entry.approval_id == legacy_approval_id)
            .ok_or("legacy digest-only Approval missing from source capture")?;
        assert!(matches!(
            &legacy_record.attribution,
            super::SourceApprovalAttribution::LegacyUnknown
        ));
        assert_eq!(legacy_record.execution_id, legacy_execution_id.into_uuid());
        assert_eq!(legacy_record.activity_id, fixture.activity.id().into_uuid());
        assert_eq!(legacy_record.state, super::SourceApprovalState::Pending);
        assert_eq!(legacy_record.revision, 1);
        assert_eq!(
            legacy_record.agent_binding_digest.as_ref().map(Vec::len),
            Some(32)
        );
        assert!(
            !inventory
                .approvals
                .iter()
                .any(|entry| entry.approval_id == unrelated_approval_id)
        );
        transaction.rollback()?;
        Ok(())
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one live owner fixture admits both file and tree intents before one source capture"
    )]
    fn captures_real_pending_file_and_tree_changesets_from_owner_transitions()
    -> Result<(), Box<dyn Error>> {
        let mut fixture = live_source_fixture()?;
        let lease_path = WorkspaceRelativePath::new(PathBuf::from("src"))?;
        let lease_scope = WriterLeaseScope::new(vec![WriterLeaseScopeEntry::new(
            WriterLeaseScopeKind::DirectorySubtree,
            lease_path,
        )])?;
        let lease = fixture
            .store
            .acquire_writer_lease(&AcquireWriterLease::new(
                WriterLeaseId::from_uuid(Uuid::now_v7()),
                fixture.workspace_id,
                fixture.activity.id(),
                fixture.agent.id(),
                lease_scope,
                WriterLeaseDurationMillis::MIN,
                timestamp(12)?,
                fixture.session_id,
                fixture.agent.principal(),
            )?)?;
        let source_authority = forge_domain::SourceWriteAuthority::new(
            fixture.agent.id(),
            fixture.agent.revision(),
            fixture.agent.principal(),
            fixture.goal_node,
            lease.id(),
            lease.revision(),
            fixture.session_id,
        );
        let workspace_revision = fixture.store.workspace()?.revision();

        let file_change_set_id = forge_domain::ChangeSetId::from_uuid(Uuid::now_v7());
        let file_mutation_id = forge_domain::FileMutationId::from_uuid(Uuid::now_v7());
        let file_identity =
            forge_domain::FileMutationIdentity::new(file_change_set_id, file_mutation_id);
        let file_path = WorkspaceRelativePath::new(PathBuf::from("src/pending-file.txt"))?;
        let file_hash = forge_domain::FileContentHash::from_bytes([0x61; 32]);
        let file_begin = forge_domain::BeginFileMutation::new(
            file_identity,
            forge_domain::FileMutationScope::new(
                fixture.workspace_id,
                workspace_revision,
                fixture.activity.id(),
                fixture.runtime_id,
                fixture.activity.lease_revision(),
            ),
            forge_domain::FileMutationPlan::new(
                file_path.clone(),
                forge_domain::FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            Some(file_hash),
            forge_domain::FilePathState::Absent,
            timestamp(20)?,
        )?;
        let file_diff = forge_domain::BeginDiffEvidence::new(
            forge_domain::DiffAttribution::for_file_mutation(
                forge_domain::DiffId::for_change_set(file_change_set_id),
                fixture.workspace_id,
                fixture.activity.id(),
                file_change_set_id,
                file_mutation_id,
            ),
            vec![forge_domain::DiffEntrySummary::new(
                forge_domain::DiffEntrySubject::File,
                file_path.clone(),
                None,
                forge_domain::DiffChangeKind::Created,
                forge_domain::DiffLineCount::new(0),
                forge_domain::DiffLineCount::new(0),
            )?],
            forge_domain::DiffPayloadProjection::IntentSummary {
                render_kind: forge_domain::DiffRenderKind::Binary,
            },
            timestamp(20)?,
            forge_domain::DiffContractVersions::V1,
        )?;
        let file_started =
            fixture
                .store
                .begin_file_mutation(&file_begin, &file_diff, source_authority)?;
        assert_eq!(
            file_started.status(),
            forge_domain::BeginFileMutationStatus::Started
        );

        let tree_change_set_id = forge_domain::ChangeSetId::from_uuid(Uuid::now_v7());
        let tree_mutation_id = forge_domain::TreeMutationId::from_uuid(Uuid::now_v7());
        let tree_path = WorkspaceRelativePath::new(PathBuf::from("src/pending-tree"))?;
        let tree_draft =
            forge_domain::TreeChangeSetDraft::new(&[forge_domain::TreeMutationDraft::new(
                tree_mutation_id,
                forge_domain::TreeMutationPlan::create_directory(tree_path.clone()),
            )])?;
        let tree_intent = forge_domain::TreeChangeSetIntent::from_draft(
            forge_domain::ChangeSetAttribution::new(
                tree_change_set_id,
                fixture.workspace_id,
                workspace_revision,
                fixture.activity.id(),
                fixture.runtime_id,
                fixture.activity.lease_revision(),
            ),
            &tree_draft,
            timestamp(21)?,
        )?;
        let tree_diff_id = forge_domain::DiffId::for_change_set(tree_change_set_id);
        let tree_diff = forge_domain::BeginDiffEvidence::new(
            forge_domain::DiffAttribution::for_tree_change_set(
                tree_diff_id,
                fixture.workspace_id,
                fixture.activity.id(),
                tree_change_set_id,
            ),
            tree_intent.diff_entries().to_vec(),
            forge_domain::DiffPayloadProjection::IntentSummary {
                render_kind: forge_domain::DiffRenderKind::Structured,
            },
            timestamp(21)?,
            forge_domain::DiffContractVersions::V1,
        )?;
        let tree_started =
            fixture
                .store
                .begin_tree_change_set(&tree_intent, &tree_diff, source_authority)?;
        assert_eq!(
            tree_started.status(),
            forge_domain::TreeChangeSetAdmissionStatus::Started
        );

        let request = source_request_for_live_fixture(&fixture, Uuid::now_v7().as_u128())?;
        let mut source_connection = Connection::open(fixture.layout.database_path())?;
        source_connection.pragma_update(None, "foreign_keys", true)?;
        let transaction =
            source_connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let inventory = HomeTransferSourceInventory::capture(&transaction, &request)?;
        inventory.validate_for_request(&request)?;

        assert_eq!(inventory.writer_leases.len(), 1);
        assert_eq!(
            inventory.writer_leases[0].agent_id,
            fixture.agent.id().into_uuid()
        );
        assert_eq!(inventory.writer_leases[0].revision, lease.revision().get());
        assert_eq!(
            inventory.writer_leases[0].state,
            super::SourceWriterLeaseState::Active
        );
        assert_eq!(inventory.change_sets.len(), 2);
        let file_record = inventory
            .change_sets
            .iter()
            .find(|record| record.change_set_id == file_change_set_id.into_uuid())
            .ok_or("file ChangeSet missing from source capture")?;
        assert_eq!(file_record.state, super::SourceChangeSetState::Starting);
        let file_mutation = file_record
            .file_mutation
            .as_ref()
            .ok_or("file mutation missing from source capture")?;
        assert_eq!(file_mutation.mutation_id, file_mutation_id.into_uuid());
        assert_eq!(file_mutation.path.as_slice(), b"src/pending-file.txt");
        assert_eq!(file_mutation.revision, 1);

        let tree_record = inventory
            .change_sets
            .iter()
            .find(|record| record.change_set_id == tree_change_set_id.into_uuid())
            .ok_or("tree ChangeSet missing from source capture")?;
        assert_eq!(tree_record.state, super::SourceChangeSetState::Starting);
        assert_eq!(
            tree_record.source_tree_request_digest, None,
            "legacy tree intent must not acquire invented source provenance"
        );
        assert_eq!(tree_record.tree_mutations.len(), 1);
        assert_eq!(
            tree_record.tree_mutations[0].mutation_id,
            tree_mutation_id.into_uuid()
        );
        assert_eq!(
            tree_record.tree_mutations[0].kind,
            super::SourceTreeMutationKind::CreateDirectory
        );
        assert_eq!(
            tree_record.tree_mutations[0].primary_path.as_slice(),
            b"src/pending-tree"
        );
        assert!(!tree_record.tree_mutations[0].applied);
        transaction.rollback()?;
        Ok(())
    }

    fn source_approval_with_valid_binding_digest() -> Result<super::SourceApproval, Box<dyn Error>>
    {
        let execution_id = forge_domain::ExecutionId::from_uuid(id(0xE001));
        let agent_id = AgentInstanceId::from_uuid(id(0xE002));
        let session_id = AgentSessionId::from_uuid(id(0xE003));
        let goal_id = forge_domain::GoalId::from_uuid(id(0xE004));
        let node_id = forge_domain::DagNodeId::from_uuid(id(0xE005));
        let provenance = forge_domain::ExecutionAgentProvenance::new(
            execution_id,
            agent_id,
            forge_domain::AgentInstanceRevision::INITIAL,
            AuthenticatedPrincipal::TrustedStdio,
            forge_domain::GoalNodeAttribution::new(
                goal_id,
                forge_domain::GoalRevision::INITIAL,
                forge_domain::DagRevisionNumber::INITIAL,
                node_id,
                forge_domain::DagNodeRevision::INITIAL,
            ),
            forge_domain::ExecutionCommandId::new("make:ci".to_owned())?,
            session_id,
        );
        let binding_digest =
            forge_domain::ApprovalAgentBindingDigest::from_provenance(&provenance).as_bytes();
        Ok(super::SourceApproval {
            approval_id: id(0xE006),
            workspace_id: id(0xE007),
            activity_id: id(0xE008),
            execution_id: execution_id.into_uuid(),
            request_digest: [0xE9; 32],
            action: super::SourceExecutionActionClass::AnalyzedShell,
            requested_permissions: super::SourceExecutionPermissions {
                workspace_read: true,
                workspace_write: false,
                network: false,
            },
            policy_revision: 1,
            state: super::SourceApprovalState::Pending,
            revision: 1,
            created_at_ms: 1,
            updated_at_ms: 1,
            expires_at_ms: 2,
            agent_binding_digest: Some(binding_digest.to_vec()),
            attribution: super::SourceApprovalAttribution::Known {
                agent_id: agent_id.into_uuid(),
                session_id: Some(session_id.into_uuid()),
                agent_revision: 1,
                principal: super::SourcePrincipal::TrustedStdio,
                goal_id: goal_id.into_uuid(),
                goal_revision: 1,
                dag_revision: 1,
                node_id: node_id.into_uuid(),
                node_revision: 1,
                command_id: "make:ci".to_owned(),
                project_command: None,
            },
            grant: super::SourceApprovalGrant::Absent,
        })
    }

    #[test]
    fn known_approval_preimage_rejects_changed_command_goal_revision_and_digest()
    -> Result<(), Box<dyn Error>> {
        let valid = source_approval_with_valid_binding_digest()?;
        assert!(super::validate_approval_binding_digest(&valid).is_ok());

        let mut changed_command = valid.clone();
        if let super::SourceApprovalAttribution::Known { command_id, .. } =
            &mut changed_command.attribution
        {
            command_id.push_str(":changed");
        }
        assert!(super::validate_approval_binding_digest(&changed_command).is_err());

        let mut changed_goal_revision = valid.clone();
        if let super::SourceApprovalAttribution::Known { goal_revision, .. } =
            &mut changed_goal_revision.attribution
        {
            *goal_revision = 2;
        }
        assert!(super::validate_approval_binding_digest(&changed_goal_revision).is_err());

        let mut changed_digest = valid;
        if let Some(digest) = &mut changed_digest.agent_binding_digest {
            digest[0] ^= 1;
        }
        assert!(super::validate_approval_binding_digest(&changed_digest).is_err());
        Ok(())
    }

    #[test]
    fn execution_scan_budget_deduplicates_and_rejects_a_1025th_distinct_id()
    -> Result<(), Box<dyn Error>> {
        let mut execution_ids = BTreeSet::new();
        for index in 0..super::MAX_HOME_SOURCE_ENTRIES {
            let id = uuid_for_index(index)?;
            assert!(super::record_bounded_execution_id(&mut execution_ids, id).is_ok());
        }
        let duplicate = uuid_for_index(0)?;
        assert!(super::record_bounded_execution_id(&mut execution_ids, duplicate).is_ok());
        let overflow = uuid_for_index(super::MAX_HOME_SOURCE_ENTRIES)?;
        assert!(matches!(
            super::record_bounded_execution_id(&mut execution_ids, overflow),
            Err(super::HomeTransferSourceInventoryError::Bounds(_))
        ));
        Ok(())
    }
}
