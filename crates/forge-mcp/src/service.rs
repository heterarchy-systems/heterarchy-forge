//! Manual rmcp `ServerHandler` implementation.

use std::borrow::Cow;
use std::sync::Arc;

use forge_control::{
    ActivityBootstrap, ActivityBootstrapStatus, ControlClientError, DiffArtifactDoctorRequest,
    DiffArtifactDoctorResult, DiffDoctorRequest, DiffDoctorResult, DiffListRequest, DiffListResult,
    DiffReadRequest, DiffReadResult, DiffRetentionPlanRequest, DiffRetentionPlanResult,
    FileActivityScope, FileMutationRequest, FileMutationResult, FileReadRequest, FileReadResult,
    ForgeControlClient, ResolvedWorkspaceScope, WorkspaceCatalogEntry,
};
use forge_domain::{
    ActivityState, FileMutationKind, FileMutationPlan, FilePrecondition, RuntimeInstanceId,
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

use crate::process::{
    LeaseTrackerMessage, McpLeasePolicy, OwnedLeaseRegistration, current_timestamp_millis,
};
use crate::protocol::{
    ActivityBootstrapInput, ActivityBootstrapOutput, DiffArtifactDoctorInput,
    DiffArtifactDoctorOutput, DiffArtifactDoctorTyped, DiffDoctorInput, DiffDoctorOutput,
    DiffIdentityTyped, DiffListInput, DiffListOutput, DiffListTyped, DiffReadInput, DiffReadOutput,
    DiffRetentionPlanInput, DiffRetentionPlanOutput, DiffRetentionPlanTyped, DiffScopeTyped,
    FileCreateInput, FileDeleteInput, FileMutationOutput, FileMutationTyped, FileReadInput,
    FileReadOutput, FileReplaceInput, FileScopeTyped, OwnershipTrackingWire, WorkspaceListInput,
    WorkspaceListOutput, WorkspaceResolveInput, WorkspaceResolveOutput, catalog_output,
    diff_artifact_doctor_output, diff_doctor_output, diff_list_output, diff_read_output,
    diff_retention_plan_output, file_mutation_output, file_read_output, scope_output,
};

/// Exact tool names exposed by this handler in deterministic order.
pub const MCP_TOOL_NAMES: [&str; 12] = [
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
];

const MAX_BLOCKING_CALLS: usize = 4;
const CONTROL_TOOL_ERROR_CODE: ErrorCode = ErrorCode(-32_000);

/// Server-side MCP adapter.  The control client is a bounded request handle;
/// it is not an application-state bag.  Runtime-owned lease observations move
/// through a bounded channel to the process tracker.
#[derive(Debug)]
pub struct McpServerService {
    control: ForgeControlClient,
    runtime_instance_id: RuntimeInstanceId,
    lease_policy: McpLeasePolicy,
    admission: CancellationToken,
    owned_sender: mpsc::Sender<LeaseTrackerMessage>,
    blocking_slots: Arc<Semaphore>,
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
        request_cancellation: CancellationToken,
    ) -> Result<WorkspaceListOutput, ErrorData> {
        let (location_id, revision) = input.into_typed().map_err(|_| Self::input_error())?;
        let entries: Vec<WorkspaceCatalogEntry> = self
            .run_control(request_cancellation, move |control| {
                control.workspace_list(location_id, revision)
            })
            .await?;
        Ok(WorkspaceListOutput {
            entries: entries.iter().map(catalog_output).collect(),
        })
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
    ) -> Tool {
        Tool::new(Cow::Borrowed(name), Cow::Borrowed(description), schema).with_annotations(
            ToolAnnotations::new()
                .read_only(false)
                .destructive(destructive)
                .idempotent(true)
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
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[5],
                "CAS-replace one Activity-attributed regular file.",
                Self::schema::<FileReplaceInput>(),
                true,
            ),
            Self::mutation_tool(
                MCP_TOOL_NAMES[6],
                "CAS-delete one Activity-attributed regular file.",
                Self::schema::<FileDeleteInput>(),
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
        ];
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name.len() > crate::protocol::MAX_TOOL_NAME_BYTES {
            return Err(Self::unknown_tool_error());
        }
        if context.ct.is_cancelled() || self.admission.is_cancelled() {
            return Err(Self::cancelled_error());
        }
        let result = match request.name.as_ref() {
            "workspace_list" => {
                let input = crate::protocol::parse_arguments::<WorkspaceListInput>(
                    request.arguments.as_ref(),
                )
                .map_err(|_| Self::input_error())?;
                serde_json::to_value(self.workspace_list(input, context.ct.clone()).await?)
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
            _ => return Err(Self::unknown_tool_error()),
        }
        .map_err(|_| ErrorData::internal_error("tool result serialization failed", None))?;
        Ok(CallToolResult::structured(result).into())
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("heterarchy-forge-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions("Use explicit Location revisions and Workspace locators; no implicit Workspace exists.")
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
        FileActivityScope, FileMutationRequest, FileMutationStatus, ForgeControl,
        ForgeControlWorker,
    };
    use forge_domain::{
        ActivityId, BootstrapActivity, ChangeSetId, DiffArtifactInventoryLimit, DiffId,
        DiffListLimit, DiffRetentionKeepCount, DiffRetentionPlanLimit, EstablishWorkspace,
        FileMutationId, FileMutationKind, FileMutationPlan, FilePrecondition, LocationId,
        LocationRevision, RuntimeInstanceId, TimestampMillis, WorkspaceId, WorkspaceRelativePath,
        WorkspaceRevision, WorkspaceRoot,
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
                "diff_artifact_doctor"
            ]
        );
        assert!(MCP_TOOL_NAMES.iter().all(|name| !name.starts_with("goal_")));
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
