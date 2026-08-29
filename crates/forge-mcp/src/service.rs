//! Manual rmcp `ServerHandler` implementation.

use std::borrow::Cow;
use std::sync::Arc;

use forge_control::{
    ActivityBootstrap, ActivityBootstrapStatus, AgentAttachRequest, AgentContextRequest,
    AgentDagGrantDiscoverRequest, AgentDagReplanCommitRequest, AgentDetachRequest,
    AgentFocusRequest, AgentWorkUpdateRequest, ControlClientError, DiffArtifactDoctorRequest,
    DiffArtifactDoctorResult, DiffDoctorRequest, DiffDoctorResult, DiffListRequest, DiffListResult,
    DiffReadRequest, DiffReadResult, DiffRetentionPlanRequest, DiffRetentionPlanResult,
    FileActivityScope, FileMutationRequest, FileMutationResult, FileReadRequest, FileReadResult,
    ForgeControlClient, McpTokenAuthorization, ResolvedWorkspaceScope, WorkspaceCatalogEntry,
};
use forge_domain::{
    ActivityState, AgentAuthoringCredential, AgentDagAuthoringActor, AgentDagReplanRequest,
    AgentInstanceId, AgentTransportKind, AgentWorkUpdate, FileMutationKind, FileMutationPlan,
    FilePrecondition, RuntimeInstanceId,
};
use rmcp::{
    RoleServer, ServerHandler,
    model::{
        CallToolRequestMethod, CallToolRequestParams, CallToolResponse, CallToolResult, ErrorCode,
        ErrorData, Implementation, JsonObject, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
    },
    service::RequestContext,
};
use serde_json::Value;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::process::{
    LeaseTrackerMessage, McpLeasePolicy, OwnedLeaseRegistration, current_timestamp_millis,
};
use crate::protocol::{
    ActivityBootstrapInput, ActivityBootstrapOutput, AgentAttachInput, AgentContextOutput,
    AgentDetachInput, AgentGetContextInput, AgentPublishWorkInput, AgentSetFocusInput,
    AgentWorkOutput, DagAuthoringGrantDiscoverInput, DagAuthoringGrantOutput, DagCurrentOutput,
    DagGetCurrentInput, DagReplanCommitInput, DagReplanCommitOutput, DiffArtifactDoctorInput,
    DiffArtifactDoctorOutput, DiffArtifactDoctorTyped, DiffDoctorInput, DiffDoctorOutput,
    DiffIdentityTyped, DiffListInput, DiffListOutput, DiffListTyped, DiffReadInput, DiffReadOutput,
    DiffRetentionPlanInput, DiffRetentionPlanOutput, DiffRetentionPlanTyped, DiffScopeTyped,
    FileCreateInput, FileDeleteInput, FileMutationOutput, FileMutationTyped, FileReadInput,
    FileReadOutput, FileReplaceInput, FileScopeTyped, GoalGetInput, GoalListInput, GoalListOutput,
    OwnershipTrackingWire, WorkspaceListInput, WorkspaceListOutput, WorkspaceResolveInput,
    WorkspaceResolveOutput, agent_attachment_output, agent_context_output, agent_work_output,
    catalog_output, dag_authoring_grant_output, dag_current_output, dag_replan_commit_output,
    diff_artifact_doctor_output, diff_doctor_output, diff_list_output, diff_read_output,
    diff_retention_plan_output, file_mutation_output, file_read_output, goal_list_output,
    goal_output, scope_output,
};

/// Exact tool names exposed by this handler in deterministic order.
pub const MCP_TOOL_NAMES: [&str; 22] = [
    "workspace_list",
    "workspace_resolve",
    "activity_bootstrap",
    "file_read",
    "file_create",
    "file_replace",
    "file_delete",
    "diff_list",
    "diff_read",
    "diff_doctor",
    "diff_retention_plan",
    "diff_artifact_doctor",
    "agent_attach",
    "agent_set_focus",
    "agent_publish_work",
    "agent_get_context",
    "agent_detach",
    "goal_list",
    "goal_get",
    "dag_get_current",
    "dag_authoring_grant_discover",
    "dag_replan_commit",
];

const MAX_BLOCKING_CALLS: usize = 4;
const CONTROL_TOOL_ERROR_CODE: ErrorCode = ErrorCode(-32_000);

/// Server-side MCP adapter.  The control client is a bounded request handle;
/// it is not an application-state bag.  Runtime-owned lease observations move
/// through a bounded channel to the process tracker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum McpAuthorizationMode {
    TrustedStdio,
    ScopedHttp,
}

#[derive(Debug, Clone)]
pub struct McpServerService {
    control: ForgeControlClient,
    runtime_instance_id: RuntimeInstanceId,
    lease_policy: McpLeasePolicy,
    admission: CancellationToken,
    owned_sender: mpsc::Sender<LeaseTrackerMessage>,
    blocking_slots: Arc<Semaphore>,
    authorization_mode: McpAuthorizationMode,
}

impl McpServerService {
    pub(crate) fn new(
        control: ForgeControlClient,
        runtime_instance_id: RuntimeInstanceId,
        lease_policy: McpLeasePolicy,
        admission: CancellationToken,
        owned_sender: mpsc::Sender<LeaseTrackerMessage>,
    ) -> Self {
        Self {
            control,
            runtime_instance_id,
            lease_policy,
            admission,
            owned_sender,
            blocking_slots: Arc::new(Semaphore::new(MAX_BLOCKING_CALLS)),
            authorization_mode: McpAuthorizationMode::TrustedStdio,
        }
    }

    pub(crate) fn new_scoped_http(
        control: ForgeControlClient,
        runtime_instance_id: RuntimeInstanceId,
        lease_policy: McpLeasePolicy,
        admission: CancellationToken,
        owned_sender: mpsc::Sender<LeaseTrackerMessage>,
    ) -> Self {
        Self {
            control,
            runtime_instance_id,
            lease_policy,
            admission,
            owned_sender,
            blocking_slots: Arc::new(Semaphore::new(MAX_BLOCKING_CALLS)),
            authorization_mode: McpAuthorizationMode::ScopedHttp,
        }
    }

    pub const fn runtime_instance_id(&self) -> RuntimeInstanceId {
        self.runtime_instance_id
    }

    pub(crate) fn control_client(&self) -> ForgeControlClient {
        self.control.clone()
    }

    fn input_error() -> ErrorData {
        ErrorData::invalid_params("tool arguments are invalid", None)
    }

    fn cancelled_error() -> ErrorData {
        ErrorData::invalid_request("tool request was cancelled", None)
    }

    fn unknown_tool_error() -> ErrorData {
        ErrorData::method_not_found::<CallToolRequestMethod>()
    }

    fn authorization_error() -> ErrorData {
        ErrorData::invalid_request(
            "tool request is outside the authorized Workspace scope",
            None,
        )
    }

    fn request_authorization(
        &self,
        context: &RequestContext<RoleServer>,
    ) -> Result<Option<McpTokenAuthorization>, ErrorData> {
        if self.authorization_mode == McpAuthorizationMode::TrustedStdio {
            return Ok(None);
        }
        context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<McpTokenAuthorization>())
            .cloned()
            .map(Some)
            .ok_or_else(Self::authorization_error)
    }

    fn authorize_wire_workspace(
        authorization: Option<&McpTokenAuthorization>,
        location_id: &str,
        workspace_id: &str,
    ) -> Result<(), ErrorData> {
        let Some(authorization) = authorization else {
            return Ok(());
        };
        let location_id = location_id.parse().map_err(|_| Self::input_error())?;
        let workspace_id = workspace_id.parse().map_err(|_| Self::input_error())?;
        if authorization.permits_workspace(location_id, workspace_id) {
            Ok(())
        } else {
            Err(Self::authorization_error())
        }
    }

    fn authorize_argument_scope(
        authorization: Option<&McpTokenAuthorization>,
        arguments: Option<&JsonObject>,
    ) -> Result<(), ErrorData> {
        let Some(authorization) = authorization else {
            return Ok(());
        };
        let arguments = arguments.ok_or_else(Self::input_error)?;
        let location_id = arguments
            .get("location_id")
            .and_then(Value::as_str)
            .ok_or_else(Self::input_error)?;
        let workspace_id = arguments
            .get("workspace_id")
            .and_then(Value::as_str)
            .ok_or_else(Self::input_error)?;
        Self::authorize_wire_workspace(Some(authorization), location_id, workspace_id)
    }

    fn authorize_tool_request(
        &self,
        request: &CallToolRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> Result<Option<McpTokenAuthorization>, ErrorData> {
        if request.name.len() > crate::protocol::MAX_TOOL_NAME_BYTES {
            return Err(Self::unknown_tool_error());
        }
        if context.ct.is_cancelled() || self.admission.is_cancelled() {
            return Err(Self::cancelled_error());
        }
        let authorization = self.request_authorization(context)?;
        if request.name.as_ref() != "workspace_list" {
            Self::authorize_argument_scope(authorization.as_ref(), request.arguments.as_ref())?;
        }
        Ok(authorization)
    }

    fn control_tool_error(error: &ControlClientError) -> ErrorData {
        let code = error.code();
        // ControlError::Display and source are intentionally not forwarded.
        // The stable category and summary are the only remote-visible values.
        ErrorData::new(
            CONTROL_TOOL_ERROR_CODE,
            "the control service rejected the tool request",
            Some(serde_json::json!({
                "code": code.as_str(),
                "message": code.summary(),
                "committed": error.service_error().is_some_and(forge_control::ControlError::is_committed),
            })),
        )
    }

    async fn acquire_blocking_slot(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ErrorData> {
        self.blocking_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ErrorData::internal_error("control admission is unavailable", None))
    }

    async fn run_control<T, F>(
        &self,
        request_cancellation: CancellationToken,
        operation: F,
    ) -> Result<T, ErrorData>
    where
        T: Send + 'static,
        F: FnOnce(ForgeControlClient) -> Result<T, ControlClientError> + Send + 'static,
    {
        if request_cancellation.is_cancelled() || self.admission.is_cancelled() {
            return Err(Self::cancelled_error());
        }
        let permit = tokio::select! {
            permit = self.acquire_blocking_slot() => permit?,
            () = request_cancellation.cancelled() => return Err(Self::cancelled_error()),
            () = self.admission.cancelled() => return Err(Self::cancelled_error()),
        };
        if request_cancellation.is_cancelled() || self.admission.is_cancelled() {
            drop(permit);
            return Err(Self::cancelled_error());
        }
        let client = self.control.clone();
        // The bounded semaphore limits blocking work.  We await this handle
        // even if the request token is cancelled after admission so a durable
        // bootstrap is never left behind by a detached blocking task.
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            operation(client)
        })
        .await
        .map_err(|_| ErrorData::internal_error("control operation failed", None))?;
        result.map_err(|error| Self::control_tool_error(&error))
    }

    async fn workspace_list(
        &self,
        input: WorkspaceListInput,
        authorization: Option<&McpTokenAuthorization>,
        request_cancellation: CancellationToken,
    ) -> Result<WorkspaceListOutput, ErrorData> {
        let (location_id, revision) = input.into_typed().map_err(|_| Self::input_error())?;
        let entries: Vec<WorkspaceCatalogEntry> = self
            .run_control(request_cancellation, move |control| {
                control.workspace_list(location_id, revision)
            })
            .await?;
        if authorization.is_some_and(|authorization| !authorization.permits_location(location_id)) {
            return Err(Self::authorization_error());
        }
        let entries = entries
            .iter()
            .filter_map(|entry| {
                if authorization.is_none_or(|authorization| {
                    entry.status().workspace_id().is_some_and(|workspace_id| {
                        authorization.permits_workspace(location_id, workspace_id)
                    })
                }) {
                    Some(catalog_output(entry))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        Ok(WorkspaceListOutput { entries })
    }

    async fn workspace_resolve(
        &self,
        input: WorkspaceResolveInput,
        request_cancellation: CancellationToken,
    ) -> Result<WorkspaceResolveOutput, ErrorData> {
        let (location_id, revision, workspace_id, workspace_revision, locator) =
            input.into_typed().map_err(|_| Self::input_error())?;
        let scope = self
            .run_control(request_cancellation, move |control| {
                control.resolve_workspace(location_id, revision, locator)
            })
            .await?;
        if scope.workspace_id() != workspace_id || scope.workspace_revision() != workspace_revision
        {
            return Err(Self::input_error());
        }
        Ok(WorkspaceResolveOutput {
            scope: scope_output(&scope),
        })
    }

    async fn activity_bootstrap(
        &self,
        input: ActivityBootstrapInput,
        request_cancellation: CancellationToken,
    ) -> Result<ActivityBootstrapOutput, ErrorData> {
        let (location_id, revision, workspace_id, workspace_revision, locator, activity_id) =
            input.into_typed().map_err(|_| Self::input_error())?;
        let observed_at = current_timestamp_millis()
            .ok_or_else(|| ErrorData::internal_error("runtime clock is unavailable", None))?;
        let scope = self
            .run_control(request_cancellation.clone(), move |control| {
                control.resolve_workspace(location_id, revision, locator)
            })
            .await?;
        if scope.workspace_id() != workspace_id || scope.workspace_revision() != workspace_revision
        {
            return Err(Self::input_error());
        }
        let lease_until = self
            .lease_policy
            .lease_until(observed_at)
            .map_err(|_| Self::input_error())?;
        let runtime_instance_id = self.runtime_instance_id;
        let bootstrap: ActivityBootstrap = self
            .run_control(request_cancellation, move |control| {
                control.bootstrap_activity(
                    scope,
                    activity_id,
                    runtime_instance_id,
                    observed_at,
                    lease_until,
                )
            })
            .await?;

        let ownership_tracking = if let Some(activity) = bootstrap.activity()
            && bootstrap.is_committed()
            && matches!(
                bootstrap.status(),
                ActivityBootstrapStatus::Created | ActivityBootstrapStatus::AlreadyOwned
            )
            && activity.state() == ActivityState::Open
            && activity.lease_owner_id() == Some(runtime_instance_id)
        {
            let registration = OwnedLeaseRegistration {
                scope: bootstrap.scope().clone(),
                activity_id: activity.id(),
                lease_revision: activity.lease_revision(),
                last_observed_at: observed_at,
                recovery_required: false,
            };
            let (response, receiver) = tokio::sync::oneshot::channel();
            match self.owned_sender.try_send(LeaseTrackerMessage::Register {
                registration,
                response,
            }) {
                Ok(()) => match receiver.await {
                    Ok(true) => OwnershipTrackingWire::Tracked,
                    Ok(false) => OwnershipTrackingWire::NotTrackedCapacity,
                    Err(_) => OwnershipTrackingWire::NotTrackedShutdown,
                },
                Err(mpsc::error::TrySendError::Full(_)) => {
                    OwnershipTrackingWire::NotTrackedCapacity
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    OwnershipTrackingWire::NotTrackedShutdown
                }
            }
        } else {
            OwnershipTrackingWire::NotTrackedNotOwned
        };
        Ok(crate::protocol::bootstrap_output(
            &bootstrap,
            ownership_tracking,
        ))
    }

    async fn is_tracked_owner(
        &self,
        scope: forge_control::ResolvedWorkspaceScope,
        activity_id: forge_domain::ActivityId,
    ) -> bool {
        let (response, receiver) = tokio::sync::oneshot::channel();
        if self
            .owned_sender
            .try_send(LeaseTrackerMessage::Check {
                scope,
                activity_id,
                response,
            })
            .is_err()
        {
            return false;
        }
        receiver.await.unwrap_or(false)
    }

    fn ownership_error() -> ErrorData {
        ErrorData::invalid_request(
            "the Activity is not owned by this MCP process",
            Some(serde_json::json!({"code": "ACTIVITY_NOT_TRACKED"})),
        )
    }

    fn agent_transport_kind(&self) -> AgentTransportKind {
        match self.authorization_mode {
            McpAuthorizationMode::TrustedStdio => AgentTransportKind::Stdio,
            McpAuthorizationMode::ScopedHttp => AgentTransportKind::StreamableHttp,
        }
    }

    async fn resolve_agent_scope(
        &self,
        input: &crate::protocol::AgentScopeTyped,
        request_cancellation: CancellationToken,
    ) -> Result<ResolvedWorkspaceScope, ErrorData> {
        let locator = input.locator.clone();
        let location_id = input.location_id;
        let revision = input.location_revision;
        let scope = self
            .run_control(request_cancellation, move |control| {
                control.resolve_workspace(location_id, revision, locator)
            })
            .await?;
        if scope.workspace_id() != input.workspace_id
            || scope.workspace_revision() != input.workspace_revision
        {
            return Err(Self::input_error());
        }
        if !self
            .is_tracked_owner(scope.clone(), input.activity_id)
            .await
        {
            return Err(Self::ownership_error());
        }
        Ok(scope)
    }

    async fn resolve_goal_scope(
        &self,
        input: &crate::protocol::GoalScopeTyped,
        request_cancellation: CancellationToken,
    ) -> Result<ResolvedWorkspaceScope, ErrorData> {
        let locator = input.locator.clone();
        let location_id = input.location_id;
        let revision = input.location_revision;
        let scope = self
            .run_control(request_cancellation, move |control| {
                control.resolve_workspace(location_id, revision, locator)
            })
            .await?;
        if scope.workspace_id() != input.workspace_id
            || scope.workspace_revision() != input.workspace_revision
        {
            return Err(Self::input_error());
        }
        Ok(scope)
    }

    async fn agent_attach(
        &self,
        input: AgentAttachInput,
        authorization: Option<&McpTokenAuthorization>,
        request_cancellation: CancellationToken,
    ) -> Result<crate::protocol::AgentAttachmentOutput, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let activity_id = typed.scope.activity_id;
        let scope = self
            .resolve_agent_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let observed_at = current_timestamp_millis()
            .ok_or_else(|| ErrorData::internal_error("runtime clock is unavailable", None))?;
        let transport_principal = authorization.map(McpTokenAuthorization::token_id);
        let agent = forge_domain::RegisteredAgentInstance::create_with_principal(
            AgentInstanceId::from_uuid(Uuid::now_v7()),
            scope.workspace_id(),
            activity_id,
            typed.display_name,
            typed.declared_role,
            self.agent_transport_kind(),
            transport_principal,
            observed_at,
        );
        let request = AgentAttachRequest {
            scope,
            activity_id,
            agent,
        };
        let result = self
            .run_control(request_cancellation, move |control| {
                control.agent_attach(request)
            })
            .await?;
        Ok(agent_attachment_output(&result, None))
    }

    async fn agent_set_focus(
        &self,
        input: AgentSetFocusInput,
        authorization: Option<&McpTokenAuthorization>,
        request_cancellation: CancellationToken,
    ) -> Result<crate::protocol::AgentAttachmentOutput, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let activity_id = typed.scope.activity_id;
        let scope = self
            .resolve_agent_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let request = AgentFocusRequest {
            scope,
            activity_id,
            agent_id: typed.agent_id,
            expected_revision: typed.expected_revision,
            transport_principal: authorization.map(McpTokenAuthorization::token_id),
            focus: typed.focus,
            observed_at: current_timestamp_millis()
                .ok_or_else(|| ErrorData::internal_error("runtime clock is unavailable", None))?,
        };
        let result = self
            .run_control(request_cancellation, move |control| {
                control.agent_set_focus(request)
            })
            .await?;
        Ok(agent_attachment_output(&result, None))
    }

    async fn agent_publish_work(
        &self,
        input: AgentPublishWorkInput,
        authorization: Option<&McpTokenAuthorization>,
        request_cancellation: CancellationToken,
    ) -> Result<AgentWorkOutput, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let activity_id = typed.scope.activity_id;
        let scope = self
            .resolve_agent_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let update = AgentWorkUpdate::new(
            typed.update_id,
            typed.agent_id,
            scope.workspace_id(),
            activity_id,
            typed.sequence,
            typed.phase,
            typed.summary,
            typed.evidence_refs,
            typed.observed_at,
        )
        .map_err(|_| Self::input_error())?;
        let request = AgentWorkUpdateRequest {
            scope,
            activity_id,
            transport_principal: authorization.map(McpTokenAuthorization::token_id),
            update,
        };
        let result = self
            .run_control(request_cancellation, move |control| {
                control.agent_publish_work_update(request)
            })
            .await?;
        Ok(agent_work_output(&result))
    }

    async fn agent_get_context(
        &self,
        input: AgentGetContextInput,
        request_cancellation: CancellationToken,
    ) -> Result<Option<AgentContextOutput>, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let activity_id = typed.scope.activity_id;
        let scope = self
            .resolve_agent_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let request = AgentContextRequest {
            scope,
            activity_id,
            agent_id: typed.agent_id,
            now: current_timestamp_millis()
                .ok_or_else(|| ErrorData::internal_error("runtime clock is unavailable", None))?,
            focus_event_limit: typed.focus_event_limit,
            work_update_limit: typed.work_update_limit,
        };
        let result = self
            .run_control(request_cancellation, move |control| {
                control.agent_get_context(request)
            })
            .await?;
        Ok(result.as_ref().map(agent_context_output))
    }

    async fn agent_detach(
        &self,
        input: AgentDetachInput,
        authorization: Option<&McpTokenAuthorization>,
        request_cancellation: CancellationToken,
    ) -> Result<crate::protocol::AgentAttachmentOutput, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let activity_id = typed.scope.activity_id;
        let scope = self
            .resolve_agent_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let request = AgentDetachRequest {
            scope,
            activity_id,
            agent_id: typed.agent_id,
            expected_revision: typed.expected_revision,
            transport_principal: authorization.map(McpTokenAuthorization::token_id),
            observed_at: current_timestamp_millis()
                .ok_or_else(|| ErrorData::internal_error("runtime clock is unavailable", None))?,
        };
        let result = self
            .run_control(request_cancellation, move |control| {
                control.agent_detach(request)
            })
            .await?;
        Ok(agent_attachment_output(&result, None))
    }

    async fn goal_list(
        &self,
        input: GoalListInput,
        request_cancellation: CancellationToken,
    ) -> Result<GoalListOutput, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let scope = self
            .resolve_goal_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let result = self
            .run_control(request_cancellation, move |control| {
                control.goal_list(scope, typed.limit)
            })
            .await?;
        Ok(goal_list_output(&result))
    }

    async fn goal_get(
        &self,
        input: GoalGetInput,
        request_cancellation: CancellationToken,
    ) -> Result<Option<crate::protocol::GoalOutput>, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let scope = self
            .resolve_goal_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let goal_id = typed.goal_id;
        let result = self
            .run_control(request_cancellation, move |control| {
                control.goal_get(scope, goal_id)
            })
            .await?;
        Ok(result.as_ref().map(goal_output))
    }

    async fn dag_get_current(
        &self,
        input: DagGetCurrentInput,
        request_cancellation: CancellationToken,
    ) -> Result<Option<DagCurrentOutput>, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let scope = self
            .resolve_goal_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let goal_id = typed.goal_id;
        let result = self
            .run_control(request_cancellation, move |control| {
                control.dag_get_current(scope, goal_id)
            })
            .await?;
        result
            .as_ref()
            .map(dag_current_output)
            .transpose()
            .map_err(|_| ErrorData::internal_error("current DAG projection is unavailable", None))
    }

    async fn dag_authoring_grant_discover(
        &self,
        input: DagAuthoringGrantDiscoverInput,
        authorization: Option<&McpTokenAuthorization>,
        request_cancellation: CancellationToken,
    ) -> Result<Option<DagAuthoringGrantOutput>, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let activity_id = typed.scope.activity_id;
        let workspace_id = typed.scope.workspace_id;
        let scope = self
            .resolve_agent_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let credential = authorization.map_or(AgentAuthoringCredential::TrustedStdio, |value| {
            AgentAuthoringCredential::Token(value.token_id())
        });
        let actor =
            AgentDagAuthoringActor::new(workspace_id, typed.agent_id, activity_id, credential);
        let now = typed.observed_at;
        let request = AgentDagGrantDiscoverRequest {
            scope,
            actor,
            goal: typed.goal,
            expected_dag_revision: typed.expected_dag_revision,
            expected_head_revision: typed.expected_head_revision,
            now,
        };
        let result = self
            .run_control(request_cancellation, move |control| {
                control.agent_dag_grant_discover(request)
            })
            .await?;
        Ok(result
            .as_ref()
            .map(|grant| dag_authoring_grant_output(grant, now)))
    }

    async fn dag_replan_commit(
        &self,
        input: DagReplanCommitInput,
        authorization: Option<&McpTokenAuthorization>,
        request_cancellation: CancellationToken,
    ) -> Result<DagReplanCommitOutput, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let activity_id = typed.scope.activity_id;
        let workspace_id = typed.scope.workspace_id;
        let scope = self
            .resolve_agent_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let credential = authorization.map_or(AgentAuthoringCredential::TrustedStdio, |value| {
            AgentAuthoringCredential::Token(value.token_id())
        });
        let actor =
            AgentDagAuthoringActor::new(workspace_id, typed.agent_id, activity_id, credential);
        let replan = AgentDagReplanRequest::new(
            typed.request_id,
            typed.grant_id,
            typed.expected_grant_revision,
            actor,
            typed.draft,
            typed.history_update_id,
            typed.history_update_sequence,
            typed.observed_at,
        );
        let request = AgentDagReplanCommitRequest {
            scope,
            request: replan,
        };
        let result = self
            .run_control(request_cancellation, move |control| {
                control.agent_dag_replan_commit(request)
            })
            .await?;
        dag_replan_commit_output(&result)
            .map_err(|_| ErrorData::internal_error("committed DAG projection is unavailable", None))
    }

    async fn resolve_file_scope(
        &self,
        input: &FileScopeTyped,
        request_cancellation: CancellationToken,
    ) -> Result<ResolvedWorkspaceScope, ErrorData> {
        let locator = input.locator.clone();
        let location_id = input.location_id;
        let revision = input.location_revision;
        let scope = self
            .run_control(request_cancellation, move |control| {
                control.resolve_workspace(location_id, revision, locator)
            })
            .await?;
        if scope.workspace_id() != input.workspace_id
            || scope.workspace_revision() != input.workspace_revision
        {
            return Err(Self::input_error());
        }
        if !self
            .is_tracked_owner(scope.clone(), input.activity_id)
            .await
        {
            return Err(Self::ownership_error());
        }
        Ok(scope)
    }

    async fn file_read(
        &self,
        input: FileReadInput,
        request_cancellation: CancellationToken,
    ) -> Result<FileReadOutput, ErrorData> {
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        let scope = self
            .resolve_file_scope(&typed, request_cancellation.clone())
            .await?;
        let observed_at = current_timestamp_millis()
            .ok_or_else(|| ErrorData::internal_error("runtime clock is unavailable", None))?;
        let request = FileReadRequest {
            scope,
            activity: FileActivityScope {
                activity_id: typed.activity_id,
                runtime_instance_id: self.runtime_instance_id,
                observed_at,
            },
            path: typed.path,
        };
        let result: FileReadResult = self
            .run_control(request_cancellation, move |control| {
                control.file_read(request)
            })
            .await?;
        Ok(file_read_output(&result))
    }

    async fn file_mutate(
        &self,
        typed: FileMutationTyped,
        kind: FileMutationKind,
        request_cancellation: CancellationToken,
    ) -> Result<FileMutationOutput, ErrorData> {
        let scope = self
            .resolve_file_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let observed_at = current_timestamp_millis()
            .ok_or_else(|| ErrorData::internal_error("runtime clock is unavailable", None))?;
        let precondition = match (kind, typed.expected_hash) {
            (FileMutationKind::Create, None) => FilePrecondition::Absent,
            (FileMutationKind::Replace | FileMutationKind::Delete, Some(expected_hash)) => {
                FilePrecondition::Matches(expected_hash)
            }
            (FileMutationKind::Create, Some(_))
            | (FileMutationKind::Replace | FileMutationKind::Delete, None) => {
                return Err(Self::input_error());
            }
        };
        let request = FileMutationRequest {
            scope,
            activity: FileActivityScope {
                activity_id: typed.scope.activity_id,
                runtime_instance_id: self.runtime_instance_id,
                observed_at,
            },
            goal: None,
            change_set_id: typed.change_set_id,
            mutation_id: typed.mutation_id,
            plan: FileMutationPlan::new(typed.scope.path, kind, precondition),
            content: typed.content,
        };
        let result: FileMutationResult = self
            .run_control(request_cancellation, move |control| {
                control.file_mutate(request)
            })
            .await?;
        Ok(file_mutation_output(&result))
    }

    async fn resolve_diff_scope(
        &self,
        input: &DiffScopeTyped,
        request_cancellation: CancellationToken,
    ) -> Result<ResolvedWorkspaceScope, ErrorData> {
        let locator = input.locator.clone();
        let location_id = input.location_id;
        let revision = input.location_revision;
        let scope = self
            .run_control(request_cancellation, move |control| {
                control.resolve_workspace(location_id, revision, locator)
            })
            .await?;
        if scope.workspace_id() != input.workspace_id
            || scope.workspace_revision() != input.workspace_revision
        {
            return Err(Self::input_error());
        }
        Ok(scope)
    }

    async fn diff_list(
        &self,
        typed: DiffListTyped,
        request_cancellation: CancellationToken,
    ) -> Result<DiffListOutput, ErrorData> {
        let scope = self
            .resolve_diff_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let result: DiffListResult = self
            .run_control(request_cancellation, move |control| {
                control.diff_list(DiffListRequest {
                    scope,
                    activity_id: typed.activity_id,
                    limit: typed.limit,
                })
            })
            .await?;
        Ok(diff_list_output(&result))
    }

    async fn diff_read(
        &self,
        typed: DiffIdentityTyped,
        request_cancellation: CancellationToken,
    ) -> Result<DiffReadOutput, ErrorData> {
        let scope = self
            .resolve_diff_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let result: DiffReadResult = self
            .run_control(request_cancellation, move |control| {
                control.diff_read(DiffReadRequest {
                    scope,
                    diff_id: typed.diff_id,
                })
            })
            .await?;
        Ok(diff_read_output(&result))
    }

    async fn diff_doctor(
        &self,
        typed: DiffIdentityTyped,
        request_cancellation: CancellationToken,
    ) -> Result<DiffDoctorOutput, ErrorData> {
        let scope = self
            .resolve_diff_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let result: DiffDoctorResult = self
            .run_control(request_cancellation, move |control| {
                control.diff_doctor(DiffDoctorRequest {
                    scope,
                    diff_id: typed.diff_id,
                })
            })
            .await?;
        Ok(diff_doctor_output(&result))
    }

    async fn diff_retention_plan(
        &self,
        typed: DiffRetentionPlanTyped,
        request_cancellation: CancellationToken,
    ) -> Result<DiffRetentionPlanOutput, ErrorData> {
        let scope = self
            .resolve_diff_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let result: DiffRetentionPlanResult = self
            .run_control(request_cancellation, move |control| {
                control.plan_diff_retention(DiffRetentionPlanRequest {
                    scope,
                    keep_recent: typed.keep_recent,
                    limit: typed.limit,
                })
            })
            .await?;
        Ok(diff_retention_plan_output(&result))
    }

    async fn diff_artifact_doctor(
        &self,
        typed: DiffArtifactDoctorTyped,
        request_cancellation: CancellationToken,
    ) -> Result<DiffArtifactDoctorOutput, ErrorData> {
        let scope = self
            .resolve_diff_scope(&typed.scope, request_cancellation.clone())
            .await?;
        let result: DiffArtifactDoctorResult = self
            .run_control(request_cancellation, move |control| {
                control.diff_artifact_doctor(DiffArtifactDoctorRequest {
                    scope,
                    limit: typed.limit,
                })
            })
            .await?;
        Ok(diff_artifact_doctor_output(&result))
    }

    fn read_tool(name: &'static str, description: &'static str, schema: Arc<JsonObject>) -> Tool {
        Tool::new(Cow::Borrowed(name), Cow::Borrowed(description), schema)
            .with_annotations(ToolAnnotations::new().read_only(true).open_world(false))
    }

    fn mutation_tool(
        name: &'static str,
        description: &'static str,
        schema: Arc<JsonObject>,
        destructive: bool,
        idempotent: bool,
    ) -> Tool {
        Tool::new(Cow::Borrowed(name), Cow::Borrowed(description), schema).with_annotations(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(destructive)
                .idempotent(idempotent)
                .open_world(false),
        )
    }

    async fn call_diff_retention_plan(
        &self,
        arguments: Option<&JsonObject>,
        cancellation: CancellationToken,
    ) -> Result<serde_json::Result<Value>, ErrorData> {
        let input = crate::protocol::parse_arguments::<DiffRetentionPlanInput>(arguments)
            .map_err(|_| Self::input_error())?;
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        Ok(serde_json::to_value(
            self.diff_retention_plan(typed, cancellation).await?,
        ))
    }

    async fn call_diff_artifact_doctor(
        &self,
        arguments: Option<&JsonObject>,
        cancellation: CancellationToken,
    ) -> Result<serde_json::Result<Value>, ErrorData> {
        let input = crate::protocol::parse_arguments::<DiffArtifactDoctorInput>(arguments)
            .map_err(|_| Self::input_error())?;
        let typed = input.into_typed().map_err(|_| Self::input_error())?;
        Ok(serde_json::to_value(
            self.diff_artifact_doctor(typed, cancellation).await?,
        ))
    }

    fn schema<T: rmcp::schemars::JsonSchema>() -> Arc<JsonObject> {
        let schema = rmcp::schemars::schema_for!(T);
        match serde_json::to_value(schema) {
            Ok(Value::Object(map)) => Arc::new(map),
            Ok(_) | Err(_) => Arc::new(JsonObject::new()),
        }
    }
}

impl ServerHandler for McpServerService {
    #[allow(clippy::too_many_lines)]
    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        // This server intentionally does not implement pagination.  A cursor
        // is a protocol input, not a reason to reorder or hide tools.
        if request
            .as_ref()
            .and_then(|request| request.cursor.as_ref())
            .is_some()
        {
            return Err(ErrorData::invalid_params(
                "tool pagination is unsupported",
                None,
            ));
        }
        let tools = vec![
            Self::read_tool(
                MCP_TOOL_NAMES[0],
                "List explicitly discovered Workspaces for one Location revision.",
                Self::schema::<WorkspaceListInput>(),
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[1],
                "Resolve one explicit Workspace locator into durable scope.",
                Self::schema::<WorkspaceResolveInput>(),
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[2],
                "Durably bootstrap one caller-selected Activity lease.",
                Self::schema::<ActivityBootstrapInput>(),
                false,
                true,
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[3],
                "Read one Activity-scoped, path-confined regular file.",
                Self::schema::<FileReadInput>(),
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[4],
                "Atomically create one Activity-attributed regular file.",
                Self::schema::<FileCreateInput>(),
                false,
                true,
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[5],
                "CAS-replace one Activity-attributed regular file.",
                Self::schema::<FileReplaceInput>(),
                true,
                true,
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[6],
                "CAS-delete one Activity-attributed regular file.",
                Self::schema::<FileDeleteInput>(),
                true,
                true,
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[7],
                "List bounded durable Diff metadata for one Activity.",
                Self::schema::<DiffListInput>(),
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[8],
                "Read one verified redacted Diff artifact when available.",
                Self::schema::<DiffReadInput>(),
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[9],
                "Diagnose one Diff artifact without changing durable state.",
                Self::schema::<DiffDoctorInput>(),
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[10],
                "Dry-run an explicit keep-most-recent Diff retention policy without deleting.",
                Self::schema::<DiffRetentionPlanInput>(),
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[11],
                "Inventory bounded Diff artifacts and classify owned, orphan, or conflicting entries.",
                Self::schema::<DiffArtifactDoctorInput>(),
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[12],
                "Attach one Forge-created Agent instance to a tracked Activity.",
                Self::schema::<AgentAttachInput>(),
                false,
                false,
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[13],
                "Set an exact Goal/DAG/node focus for one attached Agent.",
                Self::schema::<AgentSetFocusInput>(),
                false,
                false,
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[14],
                "Publish one bounded operator-safe Agent work summary.",
                Self::schema::<AgentPublishWorkInput>(),
                false,
                true,
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[15],
                "Read one bounded Agent context snapshot and public work history.",
                Self::schema::<AgentGetContextInput>(),
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[16],
                "Detach one attached Agent through revision-fenced lifecycle state.",
                Self::schema::<AgentDetachInput>(),
                true,
                false,
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[17],
                "List bounded public summaries for the explicitly selected Workspace Goals.",
                Self::schema::<GoalListInput>(),
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[18],
                "Read one explicitly selected Goal public summary.",
                Self::schema::<GoalGetInput>(),
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[19],
                "Read the current immutable DAG for one explicitly selected Goal.",
                Self::schema::<DagGetCurrentInput>(),
            ),
            Self::read_tool(
                MCP_TOOL_NAMES[20],
                "Discover the available operator-issued one-shot DAG authoring grant for this authenticated Agent and exact Goal/DAG head.",
                Self::schema::<DagAuthoringGrantDiscoverInput>(),
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[21],
                "Consume one operator-issued, exact-head authoring grant to atomically commit one immutable successor DAG revision. Exact request retries replay from the durable ledger.",
                Self::schema::<DagReplanCommitInput>(),
                false,
                true,
            ),
        ];
        Ok(ListToolsResult::with_all_items(tools))
    }

    #[allow(clippy::too_many_lines)]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let authorization = self.authorize_tool_request(&request, &context)?;
        let result = match request.name.as_ref() {
            "workspace_list" => {
                let input = crate::protocol::parse_arguments::<WorkspaceListInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(
                    self.workspace_list(input, authorization.as_ref(), context.ct.clone())
                        .await?,
                )
            }
            "workspace_resolve" => {
                let input = crate::protocol::parse_arguments::<WorkspaceResolveInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(self.workspace_resolve(input, context.ct.clone()).await?)
            }
            "activity_bootstrap" => {
                let input = crate::protocol::parse_arguments::<ActivityBootstrapInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(self.activity_bootstrap(input, context.ct.clone()).await?)
            }
            "file_read" => {
                let input =
                    crate::protocol::parse_arguments::<FileReadInput>(request.arguments.as_ref())
                        .map_err(|_| Self::input_error())?;
                serde_json::to_value(self.file_read(input, context.ct.clone()).await?)
            }
            "file_create" => {
                let input =
                    crate::protocol::parse_arguments::<FileCreateInput>(request.arguments.as_ref())
                        .map_err(|_| Self::input_error())?;
                let typed = input.into_typed().map_err(|_| Self::input_error())?;
                serde_json::to_value(
                    self.file_mutate(typed, FileMutationKind::Create, context.ct.clone())
                        .await?,
                )
            }
            "file_replace" => {
                let input = crate::protocol::parse_arguments::<FileReplaceInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                let typed = input.into_typed().map_err(|_| Self::input_error())?;
                serde_json::to_value(
                    self.file_mutate(typed, FileMutationKind::Replace, context.ct.clone())
                        .await?,
                )
            }
            "file_delete" => {
                let input =
                    crate::protocol::parse_arguments::<FileDeleteInput>(request.arguments.as_ref())
                        .map_err(|_| Self::input_error())?;
                let typed = input.into_typed().map_err(|_| Self::input_error())?;
                serde_json::to_value(
                    self.file_mutate(typed, FileMutationKind::Delete, context.ct.clone())
                        .await?,
                )
            }
            "diff_list" => {
                let input =
                    crate::protocol::parse_arguments::<DiffListInput>(request.arguments.as_ref())
                        .map_err(|_| Self::input_error())?;
                let typed = input.into_typed().map_err(|_| Self::input_error())?;
                serde_json::to_value(self.diff_list(typed, context.ct.clone()).await?)
            }
            "diff_read" => {
                let input =
                    crate::protocol::parse_arguments::<DiffReadInput>(request.arguments.as_ref())
                        .map_err(|_| Self::input_error())?;
                let typed = input.into_typed().map_err(|_| Self::input_error())?;
                serde_json::to_value(self.diff_read(typed, context.ct.clone()).await?)
            }
            "diff_doctor" => {
                let input =
                    crate::protocol::parse_arguments::<DiffDoctorInput>(request.arguments.as_ref())
                        .map_err(|_| Self::input_error())?;
                let typed = input.into_typed().map_err(|_| Self::input_error())?;
                serde_json::to_value(self.diff_doctor(typed, context.ct.clone()).await?)
            }
            "diff_retention_plan" => {
                self.call_diff_retention_plan(request.arguments.as_ref(), context.ct.clone())
                    .await?
            }
            "diff_artifact_doctor" => {
                self.call_diff_artifact_doctor(request.arguments.as_ref(), context.ct.clone())
                    .await?
            }
            "agent_attach" => {
                let input = crate::protocol::parse_arguments::<AgentAttachInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(
                    self.agent_attach(input, authorization.as_ref(), context.ct.clone())
                        .await?,
                )
            }
            "agent_set_focus" => {
                let input = crate::protocol::parse_arguments::<AgentSetFocusInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(
                    self.agent_set_focus(input, authorization.as_ref(), context.ct.clone())
                        .await?,
                )
            }
            "agent_publish_work" => {
                let input = crate::protocol::parse_arguments::<AgentPublishWorkInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(
                    self.agent_publish_work(input, authorization.as_ref(), context.ct.clone())
                        .await?,
                )
            }
            "agent_get_context" => {
                let input = crate::protocol::parse_arguments::<AgentGetContextInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(self.agent_get_context(input, context.ct.clone()).await?)
            }
            "agent_detach" => {
                let input = crate::protocol::parse_arguments::<AgentDetachInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(
                    self.agent_detach(input, authorization.as_ref(), context.ct.clone())
                        .await?,
                )
            }
            "goal_list" => {
                let input =
                    crate::protocol::parse_arguments::<GoalListInput>(request.arguments.as_ref())
                        .map_err(|_| Self::input_error())?;
                serde_json::to_value(self.goal_list(input, context.ct.clone()).await?)
            }
            "goal_get" => {
                let input =
                    crate::protocol::parse_arguments::<GoalGetInput>(request.arguments.as_ref())
                        .map_err(|_| Self::input_error())?;
                serde_json::to_value(self.goal_get(input, context.ct.clone()).await?)
            }
            "dag_get_current" => {
                let input = crate::protocol::parse_arguments::<DagGetCurrentInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(self.dag_get_current(input, context.ct.clone()).await?)
            }
            "dag_authoring_grant_discover" => {
                let input = crate::protocol::parse_arguments::<DagAuthoringGrantDiscoverInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(
                    self.dag_authoring_grant_discover(
                        input,
                        authorization.as_ref(),
                        context.ct.clone(),
                    )
                    .await?,
                )
            }
            "dag_replan_commit" => {
                let input = crate::protocol::parse_dag_replan_arguments::<DagReplanCommitInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(
                    self.dag_replan_commit(input, authorization.as_ref(), context.ct.clone())
                        .await?,
                )
            }
            _ => return Err(Self::unknown_tool_error()),
        }
        .map_err(|_| ErrorData::internal_error("tool result serialization failed", None))?;
        Ok(CallToolResult::structured(result).into())
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("heterarchy-forge-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions("Use explicit Location revisions and Workspace locators; no implicit Workspace exists. Agent tools require an Activity tracked by this MCP process. Goal/DAG reads require an explicit Goal id. DAG replans require a live operator-issued one-shot grant bound to the exact Agent, credential, Goal revision, and DAG head.")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;
    use forge_control::{
        AgentDagGrantIssueRequest, FileActivityScope, FileMutationRequest, FileMutationStatus,
        ForgeControl, ForgeControlWorker,
    };
    use forge_domain::{
        ActivityId, AgentDagAuthoringGrantId, AgentDagAuthoringGrantTtl, BootstrapActivity,
        ChangeSetId, DagAcceptanceCriterion, DagHeadRevision, DagNodeDefinition, DagNodeId,
        DagNodeObjective, DagNodeOrdinal, DagNodeTitle, DagRevision, DagRevisionId,
        DagRevisionNumber, DiffArtifactInventoryLimit, DiffId, DiffListLimit,
        DiffRetentionKeepCount, DiffRetentionPlanLimit, EstablishWorkspace, FileMutationId,
        FileMutationKind, FileMutationPlan, FilePrecondition, GoalAttribution, GoalContract,
        GoalId, GoalObjective, GoalRevision, GoalStatement, LocationId, LocationRevision,
        RegisteredDagNode, RegisteredGoal, RuntimeInstanceId, TimestampMillis, WorkspaceId,
        WorkspaceRelativePath, WorkspaceRevision, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceLocator, WorkspaceStateLayout};
    use tokio::sync::{Semaphore, mpsc, oneshot};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    struct ServiceFixture {
        root: std::path::PathBuf,
        service: McpServerService,
        worker: ForgeControlWorker,
    }

    struct DiffServiceFixture {
        root: std::path::PathBuf,
        service: McpServerService,
        worker: ForgeControlWorker,
        scope: DiffScopeTyped,
        activity_id: ActivityId,
        diff_id: DiffId,
        goal_id: GoalId,
    }

    fn service_fixture() -> Result<ServiceFixture, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-mcp-service-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let (client, worker) = ForgeControlWorker::start(ForgeControl::new(GlobalRegistry::open(
            root.join("registry.sqlite3"),
        )?))?;
        let (owned_sender, _owned_receiver) = mpsc::channel(1);
        let service = McpServerService::new(
            client,
            RuntimeInstanceId::from_uuid(Uuid::from_u128(700)),
            McpLeasePolicy::default(),
            CancellationToken::new(),
            owned_sender,
        );
        Ok(ServiceFixture {
            root,
            service,
            worker,
        })
    }

    fn seed_goal_dag(
        store: &mut WorkspaceStore,
        workspace_id: WorkspaceId,
        observed_at: TimestampMillis,
    ) -> Result<GoalId, Box<dyn std::error::Error>> {
        let goal_id = GoalId::from_uuid(Uuid::from_u128(0xD106));
        let goal = RegisteredGoal::create(
            goal_id,
            workspace_id,
            GoalContract::new(
                GoalObjective::new("Replan through MCP".to_owned())?,
                vec![GoalStatement::new("Successor DAG is durable".to_owned())?],
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            observed_at,
        );
        let _ = store.insert_goal(&goal)?;
        let definition = DagNodeDefinition::new(
            DagNodeId::from_uuid(Uuid::from_u128(0xD107)),
            DagNodeOrdinal::new(0)?,
            DagNodeTitle::new("Plan".to_owned())?,
            DagNodeObjective::new("Plan the change".to_owned())?,
            vec![DagAcceptanceCriterion::new(
                "Plan is observable".to_owned(),
            )?],
        )?;
        let revision = DagRevision::new(
            DagRevisionId::from_uuid(Uuid::from_u128(0xD108)),
            goal_id,
            GoalRevision::INITIAL,
            DagRevisionNumber::INITIAL,
            None,
            vec![definition.clone()],
            Vec::new(),
            observed_at,
        )?;
        let node = RegisteredDagNode::create(goal_id, revision.number(), definition, observed_at);
        let _ = store.insert_dag_revision(&revision, &[node], &[], None)?;
        Ok(goal_id)
    }

    fn diff_service_fixture() -> Result<DiffServiceFixture, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-mcp-diff-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        let location_root = root.join("location");
        let workspace_root = location_root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let registry = GlobalRegistry::open(root.join("registry.sqlite3"))?;
        let mut locations = LocationService::new(registry);
        let location_id = LocationId::from_uuid(Uuid::from_u128(0xD100));
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xD101));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xD102));
        let runtime_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(0xD103));
        let now = current_timestamp_millis().ok_or("clock unavailable")?;
        locations.register_selected_path(location_id, "Location", &location_root, now)?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let mut store = WorkspaceStore::open(
            &layout,
            EstablishWorkspace::new(
                workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
                layout.root_fingerprint()?,
                now,
            ),
        )?;
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            runtime_id,
            TimestampMillis::new(now.get() + 60_000)?,
            now,
        ))?;
        let goal_id = seed_goal_dag(&mut store, workspace_id, now)?;
        drop(store);
        let (client, worker) =
            ForgeControlWorker::start(ForgeControl::from_location_service(locations))?;
        let locator = WorkspaceLocator::new(
            location_id,
            LocationRevision::INITIAL,
            Path::new("workspace"),
        )?;
        let resolved =
            client.resolve_workspace(location_id, LocationRevision::INITIAL, locator.clone())?;
        let change_set_id = ChangeSetId::from_uuid(Uuid::from_u128(0xD104));
        let applied = client.file_mutate(FileMutationRequest {
            scope: resolved,
            activity: FileActivityScope {
                activity_id,
                runtime_instance_id: runtime_id,
                observed_at: now,
            },
            goal: None,
            change_set_id,
            mutation_id: FileMutationId::from_uuid(Uuid::from_u128(0xD105)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new("mcp-diff.txt".into())?,
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            content: Some(b"mcp diff\n".to_vec()),
        })?;
        if applied.status() != FileMutationStatus::Applied {
            return Err("file mutation did not apply".into());
        }
        let (owned_sender, _owned_receiver) = mpsc::channel(1);
        let service = McpServerService::new(
            client,
            runtime_id,
            McpLeasePolicy::default(),
            CancellationToken::new(),
            owned_sender,
        );
        Ok(DiffServiceFixture {
            root,
            service,
            worker,
            scope: DiffScopeTyped {
                location_id,
                location_revision: LocationRevision::INITIAL,
                workspace_id,
                workspace_revision: WorkspaceRevision::INITIAL,
                locator,
            },
            activity_id,
            diff_id: DiffId::for_change_set(change_set_id),
            goal_id,
        })
    }

    #[test]
    fn control_error_projection_is_stable_and_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let error = McpServerService::control_tool_error(&ControlClientError::QueueFull);
        assert_eq!(error.code, CONTROL_TOOL_ERROR_CODE);
        let encoded = serde_json::to_string(&error)?;
        assert!(encoded.contains("CONTROL_CAPACITY_EXCEEDED"));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains("SELECT"));
        assert!(!encoded.contains("secret"));
        Ok(())
    }

    #[test]
    fn tool_names_are_deterministic_and_exact() {
        assert_eq!(
            MCP_TOOL_NAMES,
            [
                "workspace_list",
                "workspace_resolve",
                "activity_bootstrap",
                "file_read",
                "file_create",
                "file_replace",
                "file_delete",
                "diff_list",
                "diff_read",
                "diff_doctor",
                "diff_retention_plan",
                "diff_artifact_doctor",
                "agent_attach",
                "agent_set_focus",
                "agent_publish_work",
                "agent_get_context",
                "agent_detach",
                "goal_list",
                "goal_get",
                "dag_get_current",
                "dag_authoring_grant_discover",
                "dag_replan_commit"
            ]
        );
        assert!(MCP_TOOL_NAMES.contains(&"goal_list"));
        assert!(MCP_TOOL_NAMES.contains(&"dag_replan_commit"));
    }

    #[test]
    fn agent_mutation_annotations_match_retry_contract() {
        let schema = Arc::new(JsonObject::new());
        let attach = McpServerService::mutation_tool(
            "agent_attach",
            "attach",
            Arc::clone(&schema),
            false,
            false,
        );
        let focus = McpServerService::mutation_tool(
            "agent_set_focus",
            "focus",
            Arc::clone(&schema),
            false,
            false,
        );
        let publish = McpServerService::mutation_tool(
            "agent_publish_work",
            "publish",
            Arc::clone(&schema),
            false,
            true,
        );
        let detach = McpServerService::mutation_tool("agent_detach", "detach", schema, true, false);
        assert!(
            !attach
                .annotations
                .as_ref()
                .is_some_and(ToolAnnotations::is_idempotent)
        );
        assert!(
            !focus
                .annotations
                .as_ref()
                .is_some_and(ToolAnnotations::is_idempotent)
        );
        assert!(
            publish
                .annotations
                .as_ref()
                .is_some_and(ToolAnnotations::is_idempotent)
        );
        assert!(
            !detach
                .annotations
                .as_ref()
                .is_some_and(ToolAnnotations::is_idempotent)
        );
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn agent_tools_require_tracked_activity_and_use_transport_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let DiffServiceFixture {
            root,
            service: old_service,
            worker,
            scope,
            activity_id,
            goal_id,
            ..
        } = diff_service_fixture()?;
        let client = old_service.control_client();
        let runtime_instance_id = old_service.runtime_instance_id();
        let process = crate::process::McpServerProcess::with_runtime_id(
            client.clone(),
            runtime_instance_id,
            McpLeasePolicy::default(),
        );
        let crate::process::McpServerProcess {
            service,
            cancellation,
            tracker_rx,
            lease_policy,
            ..
        } = process;
        let tracker = tokio::spawn(crate::process::track_owned_leases(
            tracker_rx.ok_or("tracker receiver missing")?,
            cancellation.child_token(),
            client,
            runtime_instance_id,
            lease_policy,
            lease_policy.heartbeat_interval(),
        ));
        drop(old_service);

        let locator = scope.locator.encode();
        let bootstrap = service
            .activity_bootstrap(
                ActivityBootstrapInput {
                    location_id: scope.location_id.to_string(),
                    expected_revision: scope.location_revision.get(),
                    workspace_id: scope.workspace_id.to_string(),
                    workspace_revision: scope.workspace_revision.get(),
                    locator: locator.clone(),
                    activity_id: activity_id.to_string(),
                },
                CancellationToken::new(),
            )
            .await?;
        assert_eq!(bootstrap.ownership_tracking, OwnershipTrackingWire::Tracked);

        let attached = service
            .agent_attach(
                AgentAttachInput {
                    location_id: scope.location_id.to_string(),
                    expected_revision: scope.location_revision.get(),
                    workspace_id: scope.workspace_id.to_string(),
                    workspace_revision: scope.workspace_revision.get(),
                    locator: locator.clone(),
                    activity_id: activity_id.to_string(),
                    display_name: "Planner".to_owned(),
                    declared_role: "planner".to_owned(),
                },
                None,
                CancellationToken::new(),
            )
            .await?;
        assert_eq!(
            attached.transport_kind,
            crate::protocol::AgentTransportKindWire::Stdio
        );
        assert!(attached.activity.is_none());

        let agent_id = attached.agent_id.clone();
        let work_input = AgentPublishWorkInput {
            location_id: scope.location_id.to_string(),
            expected_revision: scope.location_revision.get(),
            workspace_id: scope.workspace_id.to_string(),
            workspace_revision: scope.workspace_revision.get(),
            locator: locator.clone(),
            activity_id: activity_id.to_string(),
            agent_id: agent_id.clone(),
            update_id: Uuid::from_u128(0xA021).to_string(),
            sequence: 1,
            phase: crate::protocol::AgentWorkPhaseWire::Planning,
            summary: "Inspecting the selected node".to_owned(),
            evidence_refs: Vec::new(),
            observed_at_ms: 2,
        };
        let work = service
            .agent_publish_work(work_input.clone(), None, CancellationToken::new())
            .await?;
        assert_eq!(work.summary, "Inspecting the selected node");
        let retried_work = service
            .agent_publish_work(work_input, None, CancellationToken::new())
            .await?;
        assert_eq!(retried_work, work);

        let context = service
            .agent_get_context(
                AgentGetContextInput {
                    location_id: scope.location_id.to_string(),
                    expected_revision: scope.location_revision.get(),
                    workspace_id: scope.workspace_id.to_string(),
                    workspace_revision: scope.workspace_revision.get(),
                    locator: locator.clone(),
                    activity_id: activity_id.to_string(),
                    agent_id: agent_id.clone(),
                    focus_event_limit: 10,
                    work_update_limit: 10,
                },
                CancellationToken::new(),
            )
            .await?
            .ok_or("Agent context missing")?;
        assert_eq!(context.work_updates.len(), 1);
        let encoded_context = serde_json::to_string(&context)?;
        assert!(!encoded_context.contains("prompt"));
        assert!(!encoded_context.contains("reasoning"));

        let focused = service
            .agent_set_focus(
                AgentSetFocusInput {
                    location_id: scope.location_id.to_string(),
                    expected_revision: scope.location_revision.get(),
                    workspace_id: scope.workspace_id.to_string(),
                    workspace_revision: scope.workspace_revision.get(),
                    locator: locator.clone(),
                    activity_id: activity_id.to_string(),
                    agent_id: agent_id.clone(),
                    expected_agent_revision: 1,
                    goal_id: None,
                    goal_revision: None,
                    dag_revision: None,
                    node_id: None,
                    node_revision: None,
                },
                None,
                CancellationToken::new(),
            )
            .await?;
        assert_eq!(focused.revision, 2);

        let agent_identity = agent_id.parse::<AgentInstanceId>()?;
        let now = current_timestamp_millis().ok_or("clock unavailable")?;
        let resolved = service.control_client().resolve_workspace(
            scope.location_id,
            scope.location_revision,
            scope.locator.clone(),
        )?;
        let grant_id = AgentDagAuthoringGrantId::from_uuid(Uuid::from_u128(0xA022));
        let _grant = service
            .control_client()
            .agent_dag_grant_issue(AgentDagGrantIssueRequest {
                scope: resolved,
                grant_id,
                actor: AgentDagAuthoringActor::new(
                    scope.workspace_id,
                    agent_identity,
                    activity_id,
                    AgentAuthoringCredential::TrustedStdio,
                ),
                goal: GoalAttribution::new(goal_id, GoalRevision::INITIAL),
                expected_dag_revision: DagRevisionNumber::INITIAL,
                expected_head_revision: DagHeadRevision::INITIAL,
                issued_at: now,
                ttl: AgentDagAuthoringGrantTtl::DEFAULT,
            })?;
        let discovered = service
            .dag_authoring_grant_discover(
                DagAuthoringGrantDiscoverInput {
                    location_id: scope.location_id.to_string(),
                    expected_revision: scope.location_revision.get(),
                    workspace_id: scope.workspace_id.to_string(),
                    workspace_revision: scope.workspace_revision.get(),
                    locator: locator.clone(),
                    activity_id: activity_id.to_string(),
                    agent_id: agent_id.clone(),
                    goal_id: goal_id.to_string(),
                    goal_revision: GoalRevision::INITIAL.get(),
                    dag_revision: DagRevisionNumber::INITIAL.get(),
                    head_revision: DagHeadRevision::INITIAL.get(),
                    observed_at_ms: now.get(),
                },
                None,
                CancellationToken::new(),
            )
            .await?
            .ok_or("authoring grant discovery missing")?;
        assert_eq!(discovered.grant_id, grant_id.to_string());

        let replan_input = DagReplanCommitInput {
            location_id: scope.location_id.to_string(),
            expected_revision: scope.location_revision.get(),
            workspace_id: scope.workspace_id.to_string(),
            workspace_revision: scope.workspace_revision.get(),
            locator: locator.clone(),
            activity_id: activity_id.to_string(),
            agent_id: agent_id.clone(),
            grant_id: grant_id.to_string(),
            expected_grant_revision: 1,
            request_id: Uuid::from_u128(0xA023).to_string(),
            history_update_id: Uuid::from_u128(0xA024).to_string(),
            history_update_sequence: 2,
            observed_at_ms: now.get(),
            draft: crate::protocol::DagReplanDraftInput {
                revision_id: Uuid::from_u128(0xA025).to_string(),
                goal_id: goal_id.to_string(),
                goal_revision: GoalRevision::INITIAL.get(),
                dag_revision: 2,
                parent_revision: 1,
                nodes: vec![crate::protocol::DagReplanNodeInput {
                    node_id: Uuid::from_u128(0xA026).to_string(),
                    ordinal: 0,
                    title: "Verify".to_owned(),
                    objective: "Verify the committed successor".to_owned(),
                    acceptance: vec!["Successor DAG is observable".to_owned()],
                    lifecycle: crate::protocol::DagReplanNodeLifecycleInput::Pending,
                }],
                edges: Vec::new(),
                lineage: vec![crate::protocol::DagReplanLineageInput {
                    prior_node_id: Uuid::from_u128(0xD107).to_string(),
                    successor_node_id: Uuid::from_u128(0xA026).to_string(),
                    kind: crate::protocol::DagLineageKindWire::Replace,
                }],
            },
        };
        let committed = service
            .dag_replan_commit(replan_input.clone(), None, CancellationToken::new())
            .await?;
        assert_eq!(committed.committed_dag_revision, 2);
        assert!(!committed.replayed);
        let replayed = service
            .dag_replan_commit(replan_input, None, CancellationToken::new())
            .await?;
        assert!(replayed.replayed);
        assert_eq!(replayed.draft_digest, committed.draft_digest);

        let detached = service
            .agent_detach(
                AgentDetachInput {
                    location_id: scope.location_id.to_string(),
                    expected_revision: scope.location_revision.get(),
                    workspace_id: scope.workspace_id.to_string(),
                    workspace_revision: scope.workspace_revision.get(),
                    locator,
                    activity_id: activity_id.to_string(),
                    agent_id,
                    expected_agent_revision: 2,
                },
                None,
                CancellationToken::new(),
            )
            .await?;
        assert_eq!(
            detached.attachment_state,
            crate::protocol::AgentAttachmentStateWire::Detached
        );

        let (sender, _receiver) = mpsc::channel(1);
        let http_service = McpServerService::new_scoped_http(
            service.control_client(),
            runtime_instance_id,
            McpLeasePolicy::default(),
            CancellationToken::new(),
            sender,
        );
        assert_eq!(
            http_service.agent_transport_kind(),
            AgentTransportKind::StreamableHttp
        );

        cancellation.cancel();
        let _ = tracker.await?;
        let mut worker = worker;
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn diff_tools_read_history_without_process_owned_activity_tracking()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = diff_service_fixture()?;
        let listed = fixture
            .service
            .diff_list(
                DiffListTyped {
                    scope: fixture.scope.clone(),
                    activity_id: fixture.activity_id,
                    limit: DiffListLimit::new(10)?,
                },
                CancellationToken::new(),
            )
            .await?;
        assert_eq!(listed.diffs.len(), 1);
        assert_eq!(listed.diffs[0].diff_id, fixture.diff_id.to_string());
        let identity = DiffIdentityTyped {
            scope: fixture.scope.clone(),
            diff_id: fixture.diff_id,
        };
        let read = fixture
            .service
            .diff_read(identity.clone(), CancellationToken::new())
            .await?;
        assert_eq!(
            read.health,
            crate::protocol::DiffArtifactHealthWire::Available
        );
        assert!(
            read.content
                .is_some_and(|content| content.contains("+mcp diff"))
        );
        let doctor = fixture
            .service
            .diff_doctor(identity, CancellationToken::new())
            .await?;
        assert_eq!(
            doctor.health,
            crate::protocol::DiffArtifactHealthWire::Available
        );
        let retention = fixture
            .service
            .diff_retention_plan(
                DiffRetentionPlanTyped {
                    scope: fixture.scope.clone(),
                    keep_recent: DiffRetentionKeepCount::new(0)?,
                    limit: DiffRetentionPlanLimit::new(10)?,
                },
                CancellationToken::new(),
            )
            .await?;
        assert_eq!(retention.candidates.len(), 1);
        assert_eq!(retention.candidates[0].diff_id, fixture.diff_id.to_string());
        let artifact_doctor = fixture
            .service
            .diff_artifact_doctor(
                DiffArtifactDoctorTyped {
                    scope: fixture.scope,
                    limit: DiffArtifactInventoryLimit::new(10)?,
                },
                CancellationToken::new(),
            )
            .await?;
        assert_eq!(artifact_doctor.entries.len(), 1);
        assert_eq!(
            artifact_doctor.entries[0].ownership,
            crate::protocol::DiffArtifactOwnershipWire::Owned
        );
        fixture.worker.shutdown()?;
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_while_waiting_for_semaphore_does_not_admit_control_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let ServiceFixture {
            root,
            mut service,
            mut worker,
        } = service_fixture()?;
        service.blocking_slots = Arc::new(Semaphore::new(0));
        let cancellation = CancellationToken::new();
        let operation_count = Arc::new(AtomicUsize::new(0));
        let cancellation_for_task = cancellation.clone();
        let count_for_task = operation_count.clone();
        let task = tokio::spawn(async move {
            service
                .run_control(cancellation_for_task, move |_client| {
                    count_for_task.fetch_add(1, Ordering::SeqCst);
                    Ok::<usize, ControlClientError>(1)
                })
                .await
        });
        cancellation.cancel();
        let result = task.await?;
        assert_eq!(
            result.map(|_| ()),
            Err(ErrorData::invalid_request(
                "tool request was cancelled",
                None
            ))
        );
        assert_eq!(operation_count.load(Ordering::SeqCst), 0);
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_after_admission_joins_and_returns_exact_completed_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let ServiceFixture {
            root,
            service,
            mut worker,
        } = service_fixture()?;
        let cancellation = CancellationToken::new();
        let operation_count = Arc::new(AtomicUsize::new(0));
        let (started_sender, started_receiver) = oneshot::channel();
        let cancellation_for_task = cancellation.clone();
        let count_for_task = operation_count.clone();
        let task = tokio::spawn(async move {
            service
                .run_control(cancellation_for_task, move |_client| {
                    count_for_task.fetch_add(1, Ordering::SeqCst);
                    let _ = started_sender.send(());
                    std::thread::sleep(Duration::from_millis(25));
                    Ok::<usize, ControlClientError>(1)
                })
                .await
        });
        started_receiver.await?;
        cancellation.cancel();
        let result = task.await?;
        assert_eq!(operation_count.load(Ordering::SeqCst), 1);
        assert_eq!(result, Ok(1));
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
