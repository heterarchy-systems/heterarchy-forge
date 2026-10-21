//! Strict execution command DTOs and authority-preserving dispatch.
//!
//! Execution commands carry the complete Agent/Workspace/Goal/DAG/node
//! authority tuple.  The transport never accepts a caller-selected program,
//! argv, timeout, output root, or permission set.  Shell text is analyzed by
//! forge-control and project commands are resolved from a fenced catalog.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use forge_control::{
    AgentExecutionAuthorityRequest, ApprovalActivityScope, ExecutionAdmissionEnvelope,
    ForgeApprovalCoordinatorClient, ForgeControlClient, ForgeExecutionCoordinatorClient,
    ProjectCommandId, ProjectCommandListRequest, ResolvedWorkspaceScope,
};
use forge_domain::{
    AgentInstanceId, AgentInstanceRevision, AgentSessionId, DagNodeId, ExecutionAdmissionActor,
    ExecutionAdmissionRequest, ExecutionAdmissionScope, ExecutionAttribution, ExecutionCommandId,
    ExecutionId, ExecutionKind, ExecutionLimits, ExecutionOutputCursor, ExecutionOutputLimit,
    ExecutionRequest, ExecutionRequestDigest, ExecutionTimeoutMillis, ForgeBackendId, GoalId,
    GoalNodeAttribution, OrchestrationIssuerId, ProjectCommandCatalogFingerprint,
    ProjectCommandEvidence, RuntimeInstanceId, TimestampMillis, WorkspaceId,
};

use crate::error::ForgeError;
use crate::ops::{
    ActivityDto, PrincipalDto, ScopeDto, decode_catalog_fingerprint, decode_digest_hex,
    decode_grant_revision, decode_principal, decode_scope, decode_timestamp,
};

const DEFAULT_MAX_BYTES: u64 = 64 * 1024;
const DEFAULT_MAX_EVENTS: usize = 128;
const SHELL_TIMEOUT_MILLIS: u64 = 10 * 60 * 1_000;

/// Shared strict authority fields for all Agent execution commands.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionAuthorityDto {
    pub(crate) scope: ScopeDto,
    pub(crate) activity: ActivityDto,
    pub(crate) actor: ExecutionActorDto,
    pub(crate) goal_id: Uuid,
    pub(crate) expected_goal_revision: i64,
    pub(crate) expected_dag_revision: i64,
    pub(crate) node_id: Uuid,
    pub(crate) expected_node_revision: i64,
    pub(crate) command_id: String,
    pub(crate) execution_id: Uuid,
}

/// Exact Agent identity carried by an execution authority payload.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionActorDto {
    pub(crate) session_id: Uuid,
    pub(crate) principal: PrincipalDto,
    pub(crate) workspace_id: Uuid,
    pub(crate) agent_id: Uuid,
    pub(crate) expected_revision: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionAdmissionDto {
    pub(crate) backend_id: Uuid,
    pub(crate) issuer: Uuid,
    pub(crate) expected_digest: String,
    pub(crate) issued_at_ms: i64,
    pub(crate) expires_at_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ExecutionModeDto {
    AnalyzedShell {
        script: String,
    },
    SealedProjectCommand {
        command_id: String,
        expected_catalog_fingerprint: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionBeginDto {
    pub(crate) authority: ExecutionAuthorityDto,
    pub(crate) grant_id: Uuid,
    pub(crate) expected_grant_revision: i64,
    pub(crate) mode: ExecutionModeDto,
    pub(crate) admission: ExecutionAdmissionDto,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionReadDto {
    pub(crate) authority: ExecutionAuthorityDto,
    #[serde(default)]
    pub(crate) after_sequence: u64,
    #[serde(default = "default_max_bytes")]
    pub(crate) max_bytes: u64,
    #[serde(default = "default_max_events")]
    pub(crate) max_events: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionCancelDto {
    pub(crate) authority: ExecutionAuthorityDto,
}

pub(super) fn default_max_bytes() -> u64 {
    DEFAULT_MAX_BYTES
}

pub(super) fn default_max_events() -> usize {
    DEFAULT_MAX_EVENTS
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionAuthoritySpec {
    pub(crate) scope: ResolvedWorkspaceScope,
    pub(crate) activity: ApprovalActivityScope,
    pub(crate) agent_authority: AgentExecutionAuthorityRequest,
    pub(crate) execution_id: ExecutionId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ExecutionModeSpec {
    Shell(String),
    Project {
        command_id: forge_control::ProjectCommandId,
        fingerprint: ProjectCommandCatalogFingerprint,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdmissionSpec {
    pub(crate) backend_id: ForgeBackendId,
    pub(crate) issuer: OrchestrationIssuerId,
    pub(crate) expected_digest: ExecutionRequestDigest,
    pub(crate) issued_at: TimestampMillis,
    pub(crate) expires_at: TimestampMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBeginCommand {
    pub(crate) authority: ExecutionAuthoritySpec,
    pub(crate) grant_id: forge_domain::ExecutionGrantId,
    pub(crate) expected_grant_revision: forge_domain::ExecutionGrantRevision,
    pub(crate) mode: ExecutionModeSpec,
    pub(crate) admission: AdmissionSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReadCommand {
    pub(crate) authority: ExecutionAuthoritySpec,
    pub(crate) after_sequence: u64,
    pub(crate) max_bytes: u64,
    pub(crate) max_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionCancelCommand {
    pub(crate) authority: ExecutionAuthoritySpec,
}

pub(super) fn parse_authority(
    dto: ExecutionAuthorityDto,
) -> Result<ExecutionAuthoritySpec, ForgeError> {
    require_non_nil(dto.scope.workspace_id, "execution workspace id")?;
    require_non_nil(dto.scope.locator.location_id, "execution location id")?;
    require_non_nil(dto.activity.activity_id, "execution activity id")?;
    require_non_nil(
        dto.activity.runtime_instance_id,
        "execution runtime instance id",
    )?;
    require_non_nil(dto.actor.session_id, "execution session id")?;
    require_non_nil(dto.actor.workspace_id, "execution actor workspace id")?;
    require_non_nil(dto.actor.agent_id, "execution agent id")?;
    require_non_nil(dto.goal_id, "execution goal id")?;
    require_non_nil(dto.node_id, "execution node id")?;
    require_non_nil(dto.execution_id, "execution id")?;
    let scope = decode_scope(&dto.scope)?;
    let activity = crate::ops::decode_approval_activity(&dto.activity)?;
    let actor_workspace = WorkspaceId::from_uuid(dto.actor.workspace_id);
    if actor_workspace != scope.workspace_id() {
        return Err(ForgeError::invalid_input(
            "execution actor workspace does not match scope",
        ));
    }
    let principal = decode_principal(&dto.actor.principal)?;
    let attribution = GoalNodeAttribution::new(
        GoalId::from_uuid(dto.goal_id),
        crate::ops::decode_goal_revision(dto.expected_goal_revision)?,
        crate::ops::decode_dag_revision(dto.expected_dag_revision)?,
        DagNodeId::from_uuid(dto.node_id),
        crate::ops::decode_node_revision(dto.expected_node_revision)?,
    );
    let command_id = ExecutionCommandId::new(dto.command_id)
        .map_err(|_| ForgeError::invalid_input("execution command id is invalid"))?;
    let agent_authority = AgentExecutionAuthorityRequest {
        session_id: AgentSessionId::from_uuid(dto.actor.session_id),
        scope: scope.clone(),
        activity_id: activity.activity_id,
        agent_id: AgentInstanceId::from_uuid(dto.actor.agent_id),
        expected_revision: AgentInstanceRevision::new(dto.actor.expected_revision)
            .map_err(|_| ForgeError::invalid_input("agent revision is invalid"))?,
        principal,
        attribution,
        command_id,
    };
    Ok(ExecutionAuthoritySpec {
        scope,
        activity,
        agent_authority,
        execution_id: ExecutionId::from_uuid(dto.execution_id),
    })
}

fn require_non_nil(value: Uuid, label: &str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must be non-nil"
        )));
    }
    Ok(value)
}

pub(crate) fn parse_begin(
    payload: &serde_json::Value,
) -> Result<ExecutionBeginCommand, ForgeError> {
    let dto: ExecutionBeginDto = super::parse_body(payload, "execution.begin payload is invalid")?;
    let authority = parse_authority(dto.authority)?;
    let mode = match dto.mode {
        ExecutionModeDto::AnalyzedShell { script } => ExecutionModeSpec::Shell(script),
        ExecutionModeDto::SealedProjectCommand {
            command_id,
            expected_catalog_fingerprint,
        } => ExecutionModeSpec::Project {
            command_id: forge_control::ProjectCommandId::new(command_id)
                .map_err(|_| ForgeError::invalid_input("project command id is invalid"))?,
            fingerprint: decode_catalog_fingerprint(&expected_catalog_fingerprint)?,
        },
    };
    let admission = AdmissionSpec {
        backend_id: ForgeBackendId::from_uuid(require_non_nil(
            dto.admission.backend_id,
            "execution backend id",
        )?),
        issuer: OrchestrationIssuerId::from_uuid(require_non_nil(
            dto.admission.issuer,
            "execution issuer id",
        )?),
        expected_digest: decode_digest_hex(&dto.admission.expected_digest)?,
        issued_at: decode_timestamp(dto.admission.issued_at_ms)?,
        expires_at: decode_timestamp(dto.admission.expires_at_ms)?,
    };
    if let ExecutionModeSpec::Project { command_id, .. } = &mode
        && authority.agent_authority.command_id.as_str() != command_id.as_str()
    {
        return Err(ForgeError::invalid_input(
            "execution command identity does not match sealed command",
        ));
    }
    Ok(ExecutionBeginCommand {
        authority,
        grant_id: forge_domain::ExecutionGrantId::from_uuid(require_non_nil(
            dto.grant_id,
            "execution grant id",
        )?),
        expected_grant_revision: decode_grant_revision(dto.expected_grant_revision)?,
        mode,
        admission,
    })
}

pub(crate) fn parse_read(payload: &serde_json::Value) -> Result<ExecutionReadCommand, ForgeError> {
    let dto: ExecutionReadDto = super::parse_body(payload, "execution.read payload is invalid")?;
    parse_read_fields(dto)
}

pub(crate) fn parse_output(
    payload: &serde_json::Value,
) -> Result<ExecutionReadCommand, ForgeError> {
    let dto: ExecutionReadDto = super::parse_body(payload, "execution.output payload is invalid")?;
    parse_read_fields(dto)
}

pub(crate) fn parse_cancel(
    payload: &serde_json::Value,
) -> Result<ExecutionCancelCommand, ForgeError> {
    let dto: ExecutionCancelDto =
        super::parse_body(payload, "execution.cancel payload is invalid")?;
    Ok(ExecutionCancelCommand {
        authority: parse_authority(dto.authority)?,
    })
}

pub(super) fn parse_read_fields(dto: ExecutionReadDto) -> Result<ExecutionReadCommand, ForgeError> {
    if !(forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES
        ..=forge_domain::MAX_EXECUTION_OUTPUT_READ_BYTES)
        .contains(&dto.max_bytes)
    {
        return Err(ForgeError::invalid_input(
            "execution output byte bound is invalid",
        ));
    }
    if dto.max_events == 0 || dto.max_events > forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS {
        return Err(ForgeError::invalid_input(
            "execution output event bound is invalid",
        ));
    }
    Ok(ExecutionReadCommand {
        authority: parse_authority(dto.authority)?,
        after_sequence: dto.after_sequence,
        max_bytes: dto.max_bytes,
        max_events: dto.max_events,
    })
}

fn build_shell_request(
    authority: &ExecutionAuthoritySpec,
    script: String,
) -> Result<ExecutionRequest, ForgeError> {
    let analyzed = forge_control::analyze_shell_script(script)
        .map_err(|_| ForgeError::invalid_input("execution shell script is not allowed"))?;
    if analyzed.intent_id() != &authority.agent_authority.command_id {
        return Err(ForgeError::invalid_input(
            "execution shell command identity does not match analysis",
        ));
    }
    if analyzed.permissions().workspace_write() {
        return Err(ForgeError::invalid_input(
            "execution shell command requires the controlled project lane",
        ));
    }
    let timeout = ExecutionTimeoutMillis::new(SHELL_TIMEOUT_MILLIS)
        .map_err(|_| ForgeError::invalid_input("execution timeout is invalid"))?;
    ExecutionRequest::new(
        ExecutionAttribution::new(
            authority.execution_id,
            authority.scope.workspace_id(),
            authority.activity.activity_id,
        ),
        ExecutionKind::Shell {
            script: analyzed.script().clone(),
        },
        None,
        ExecutionLimits::new(timeout, ExecutionOutputLimit::DEFAULT),
        analyzed.permissions(),
    )
    .map_err(|_| ForgeError::invalid_input("execution request is invalid"))
}

fn build_admission(
    authority: &ExecutionAuthoritySpec,
    admission: &AdmissionSpec,
    request: &ExecutionRequest,
) -> Result<ExecutionAdmissionEnvelope, ForgeError> {
    if request.id() != authority.execution_id
        || request.workspace_id() != authority.scope.workspace_id()
        || request.activity_id() != authority.activity.activity_id
    {
        return Err(ForgeError::invalid_input(
            "execution request identity does not match authority",
        ));
    }
    let request = ExecutionAdmissionRequest::new(
        ExecutionAdmissionScope::new(
            admission.backend_id,
            authority.scope.workspace_id(),
            authority.scope.workspace_revision(),
        ),
        authority.activity.activity_id,
        authority.agent_authority.attribution,
        ExecutionAdmissionActor::new(
            authority.agent_authority.agent_id,
            authority.agent_authority.expected_revision,
            authority.agent_authority.session_id,
        ),
        authority.execution_id,
        admission.expected_digest,
    );
    let grant = forge_domain::ExecutionAdmissionGrant::new(
        admission.issuer,
        request,
        admission.issued_at,
        admission.expires_at,
    )
    .map_err(|_| ForgeError::invalid_input("execution admission window is invalid"))?;
    Ok(ExecutionAdmissionEnvelope {
        backend_id: admission.backend_id,
        issuer: admission.issuer,
        grant,
    })
}

fn build_project_request(
    client: &ForgeControlClient,
    authority: &ExecutionAuthoritySpec,
    command_id: &forge_control::ProjectCommandId,
    fingerprint: ProjectCommandCatalogFingerprint,
) -> Result<(ExecutionRequest, ProjectCommandEvidence), ForgeError> {
    if authority.agent_authority.command_id.as_str() != command_id.as_str() {
        return Err(ForgeError::invalid_input(
            "execution command identity does not match sealed command",
        ));
    }
    let resolved = client
        .project_command_execution_request_fenced(
            ProjectCommandListRequest {
                scope: authority.scope.clone(),
                activity: forge_control::FileActivityScope {
                    activity_id: authority.activity.activity_id,
                    runtime_instance_id: authority.activity.runtime_instance_id,
                    observed_at: authority.activity.observed_at,
                },
            },
            command_id.clone(),
            fingerprint,
            authority.execution_id,
        )
        .map_err(|error| ForgeError::from_control_client_error(&error))?;
    let evidence = ProjectCommandEvidence::new(resolved.class(), resolved.fingerprint());
    Ok((resolved.into_request(), evidence))
}

pub(crate) fn execute_begin(
    client: &ForgeControlClient,
    approval: &ForgeApprovalCoordinatorClient,
    trusted_backend_id: ForgeBackendId,
    trusted_issuer: OrchestrationIssuerId,
    command: &ExecutionBeginCommand,
) -> Result<serde_json::Value, ForgeError> {
    if command.admission.backend_id != trusted_backend_id
        || command.admission.issuer != trusted_issuer
    {
        return Err(ForgeError::auth_failed());
    }
    let (request, project_command) = match &command.mode {
        ExecutionModeSpec::Shell(script) => (
            build_shell_request(&command.authority, script.clone())?,
            None,
        ),
        ExecutionModeSpec::Project {
            command_id,
            fingerprint,
        } => {
            let (request, evidence) =
                build_project_request(client, &command.authority, command_id, *fingerprint)?;
            (request, Some(evidence))
        }
    };
    let admission = build_admission(&command.authority, &command.admission, &request)?;
    let result = approval
        .start_approved_agent_execution(forge_control::ApprovedAgentExecutionRequest {
            scope: command.authority.scope.clone(),
            activity: command.authority.activity,
            grant_id: command.grant_id,
            expected_grant_revision: command.expected_grant_revision,
            request,
            agent_authority: command.authority.agent_authority.clone(),
            project_command,
            admission_envelope: admission,
        })
        .map_err(|error| map_preapproved_start_error(&error))?;
    Ok(json!({
        "execution_id": result.execution_id().into_uuid(),
        "status": format!("{:?}", result.disposition()),
    }))
}

fn map_preapproved_start_error(error: &forge_control::ForgeApprovalCoordinatorError) -> ForgeError {
    use forge_control::ForgeApprovalCoordinatorError as Error;
    match error {
        Error::Execution(_)
        | Error::ResponseDropped
        | Error::AlreadyShutdown
        | Error::ThreadPanicked
        | Error::SpawnThread(_)
        | Error::Control(forge_control::ControlClientError::ResponseDropped) => {
            ForgeError::from_admitted_execution_view(&error.view())
        }
        _ => ForgeError::from_control_view(&error.view()),
    }
}

pub(crate) const fn action_class_name(action: forge_domain::ExecutionActionClass) -> &'static str {
    match action {
        forge_domain::ExecutionActionClass::DirectStructured => "direct_structured",
        forge_domain::ExecutionActionClass::DiscoveredProjectCommand => {
            "discovered_project_command"
        }
        forge_domain::ExecutionActionClass::ShellEscape => "shell_escape",
        forge_domain::ExecutionActionClass::AnalyzedShell => "analyzed_shell",
        forge_domain::ExecutionActionClass::GeneratedProjectCommand => "generated_project_command",
    }
}

pub(crate) fn execute_cancel(
    execution: &ForgeExecutionCoordinatorClient,
    command: &ExecutionCancelCommand,
) -> Result<serde_json::Value, ForgeError> {
    let cancellation_requested = execution
        .cancel_agent_execution(
            command.authority.agent_authority.clone(),
            command.authority.execution_id,
        )
        .map_err(|error| ForgeError::from_control_view(&error.view()))?;
    Ok(json!({
        "execution_id": command.authority.execution_id.into_uuid(),
        "cancellation_requested": cancellation_requested,
    }))
}

pub(crate) fn execute_read(
    client: &ForgeControlClient,
    command: &ExecutionReadCommand,
) -> Result<serde_json::Value, ForgeError> {
    // Control admits the current session and checks stored provenance in one
    // worker operation. No separate transport preflight can become stale in
    // the queue before this read.
    let cursor = if command.after_sequence == 0 {
        ExecutionOutputCursor::initial(command.authority.execution_id)
    } else {
        ExecutionOutputCursor::from_sequence(
            command.authority.execution_id,
            super::decode_sequence(command.after_sequence)?,
        )
    };
    let read = client
        .execution_read_authorized(
            command.authority.agent_authority.clone(),
            command.authority.execution_id,
            cursor,
            command.max_bytes,
            command.max_events,
        )
        .map_err(|error| ForgeError::from_control_client_error(&error))?;
    Ok(json!({
        "execution_id": command.authority.execution_id.into_uuid(),
        "state": super::execution_evidence::execution_state_name(read.record().state()),
        "next_sequence": read.output().next_cursor().after_sequence(),
        "truncated": read.output().truncated(),
        "event_count": read.output().events().len(),
        "terminal": read.record().state().is_terminal(),
        "events": read.output().events().iter().map(output_event_json).collect::<Vec<_>>(),
    }))
}

/// Preserve binary output and explicit gaps within the control read bounds.
pub(super) fn output_event_json(event: &forge_domain::ExecutionOutputEvent) -> serde_json::Value {
    use forge_domain::{ExecutionOutputEvent, ExecutionOutputGapCause};
    match event {
        ExecutionOutputEvent::Chunk(chunk) => json!({
            "kind": "chunk",
            "sequence": chunk.sequence().get(),
            "stream": output_stream_name(chunk.stream()),
            "bytes_base64": STANDARD.encode(chunk.bytes()),
        }),
        ExecutionOutputEvent::Gap(gap) => json!({
            "kind": "gap",
            "sequence": gap.sequence().get(),
            "first_missing": gap.first_missing().get(),
            "last_missing": gap.last_missing().get(),
            "stream": gap.stream().map(output_stream_name),
            "omitted_bytes": gap.omitted_bytes(),
            "omitted_chunks": gap.omitted_chunks(),
            "cause": match gap.cause() {
                ExecutionOutputGapCause::Backpressure => "backpressure",
                ExecutionOutputGapCause::OutputLimit => "output_limit",
                ExecutionOutputGapCause::BackpressureAndOutputLimit => "backpressure_and_output_limit",
            },
        }),
    }
}

const fn output_stream_name(stream: forge_domain::ExecutionOutputStream) -> &'static str {
    match stream {
        forge_domain::ExecutionOutputStream::Stdout => "stdout",
        forge_domain::ExecutionOutputStream::Stderr => "stderr",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn preapproved_start_failure_keeps_exact_execution_readback_guidance() {
        use forge_control::{
            ForgeApprovalCoordinatorError as Approval, ForgeExecutionCoordinatorError as Execution,
        };
        let execution_id = uuid::Uuid::from_u128(0xA901);
        for source in [
            Approval::Execution(Execution::JournalFailed),
            Approval::Execution(Execution::ResponseDropped),
            Approval::ResponseDropped,
        ] {
            let error = super::map_preapproved_start_error(&source)
                .with_readback(Some(crate::error::ReadbackHint::execution(execution_id)));
            assert_eq!(error.code(), crate::error::ErrorCode::UnknownOutcome);
            assert!(!error.retryable());
            assert_eq!(error.recovery_action(), "read_back");
            assert_eq!(
                error.readback(),
                Some(&crate::error::ReadbackHint::execution(execution_id))
            );
        }
    }

    #[test]
    fn preapproved_start_closed_before_enqueue_has_no_admitted_readback() {
        let error = super::map_preapproved_start_error(
            &forge_control::ForgeApprovalCoordinatorError::Closed,
        );
        assert_eq!(error.code(), crate::error::ErrorCode::ForgeUnavailable);
        assert!(!error.retryable());
        assert!(error.readback().is_none());
    }

    #[test]
    fn preapproved_start_queue_full_remains_pre_admission_capacity() {
        let error = super::map_preapproved_start_error(
            &forge_control::ForgeApprovalCoordinatorError::QueueFull,
        );
        assert_eq!(error.code(), crate::error::ErrorCode::CapacityExceeded);
        assert!(error.retryable());
        assert!(error.readback().is_none());
    }

    #[test]
    fn preapproved_start_session_dependency_keeps_distinct_no_effect_failure() {
        let error =
            ForgeError::from_admitted_execution_view(&forge_control::ControlErrorView::unknown(
                forge_control::ControlErrorCode::AgentSessionAuthorityUnavailable,
            ));
        assert_eq!(error.code(), crate::error::ErrorCode::DependencyUnavailable);
        assert!(error.retryable());
        assert!(error.readback().is_none());
    }
    use super::*;

    #[test]
    fn wire_output_preserves_binary_bytes_and_gap_cursor() -> Result<(), Box<dyn std::error::Error>>
    {
        use forge_domain::{
            ExecutionOutputChunk, ExecutionOutputEvent, ExecutionOutputGap,
            ExecutionOutputGapCause, ExecutionOutputGapParts, ExecutionOutputSequence,
            ExecutionOutputStream,
        };
        let id = ExecutionId::from_uuid(Uuid::from_u128(1));
        let bytes = [0xff, 0x00, b'\n'];
        let chunk = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            id,
            ExecutionOutputSequence::INITIAL,
            ExecutionOutputStream::Stderr,
            &bytes,
        )?);
        let wire = output_event_json(&chunk);
        assert_eq!(
            STANDARD.decode(
                wire["bytes_base64"]
                    .as_str()
                    .ok_or("missing output bytes")?
            )?,
            bytes
        );
        assert_eq!(wire["stream"], "stderr");
        let gap = ExecutionOutputEvent::Gap(ExecutionOutputGap::new(
            id,
            ExecutionOutputSequence::new(4)?,
            ExecutionOutputGapParts::new(
                ExecutionOutputSequence::new(2)?,
                ExecutionOutputSequence::new(3)?,
                None,
                80,
                2,
                ExecutionOutputGapCause::BackpressureAndOutputLimit,
            ),
        )?);
        let wire = output_event_json(&gap);
        assert_eq!(wire["sequence"], 4);
        assert_eq!(wire["first_missing"], 2);
        assert_eq!(wire["last_missing"], 3);
        assert_eq!(wire["omitted_bytes"], 80);
        assert_eq!(wire["omitted_chunks"], 2);
        assert_eq!(wire["cause"], "backpressure_and_output_limit");
        assert!(wire["stream"].is_null());
        Ok(())
    }

    fn begin_payload() -> serde_json::Value {
        serde_json::json!({
            "authority": {
                "scope": {
                    "workspace_id": Uuid::from_u128(0x101),
                    "workspace_revision": 7,
                    "locator": {
                        "location_id": Uuid::from_u128(0x102),
                        "expected_revision": 3,
                        "relative_root": "."
                    }
                },
                "activity": {
                    "activity_id": Uuid::from_u128(0x103),
                    "runtime_instance_id": Uuid::from_u128(0x104),
                    "observed_at_ms": 19
                },
                "actor": {
                    "session_id": Uuid::from_u128(0x105),
                    "principal": { "kind": "trusted_stdio" },
                    "workspace_id": Uuid::from_u128(0x101),
                    "agent_id": Uuid::from_u128(0x106),
                    "expected_revision": 11
                },
                "goal_id": Uuid::from_u128(0x107),
                "expected_goal_revision": 13,
                "expected_dag_revision": 17,
                "node_id": Uuid::from_u128(0x108),
                "expected_node_revision": 19,
                "command_id": "ci",
                "execution_id": Uuid::from_u128(0x109)
            },
            "grant_id": Uuid::from_u128(0x10a),
            "expected_grant_revision": 23,
            "mode": {
                "kind": "sealed_project_command",
                "command_id": "ci",
                "expected_catalog_fingerprint": "1111111111111111111111111111111111111111111111111111111111111111"
            },
            "admission": {
                "backend_id": Uuid::from_u128(0x10b),
                "issuer": Uuid::from_u128(0x10c),
                "expected_digest": "2222222222222222222222222222222222222222222222222222222222222222",
                "issued_at_ms": 29,
                "expires_at_ms": 31
            }
        })
    }

    #[test]
    fn parser_preserves_explicit_execution_authority_tuple() -> Result<(), ForgeError> {
        let command = parse_begin(&begin_payload())?;
        assert_eq!(
            command.authority.execution_id.into_uuid(),
            Uuid::from_u128(0x109)
        );
        assert_eq!(
            command.authority.scope.workspace_id(),
            WorkspaceId::from_uuid(Uuid::from_u128(0x101))
        );
        assert_eq!(
            command.authority.activity.runtime_instance_id,
            forge_domain::RuntimeInstanceId::from_uuid(Uuid::from_u128(0x104))
        );
        assert_eq!(
            command.authority.agent_authority.agent_id,
            AgentInstanceId::from_uuid(Uuid::from_u128(0x106))
        );
        assert_eq!(
            command.authority.agent_authority.expected_revision.get(),
            11
        );
        assert_eq!(command.authority.agent_authority.command_id.as_str(), "ci");
        assert_eq!(command.admission.expected_digest.as_bytes(), &[0x22; 32]);
        assert_eq!(command.admission.issued_at.get(), 29);
        assert_eq!(command.admission.expires_at.get(), 31);
        Ok(())
    }

    #[test]
    fn parser_preserves_typed_principal_identities_and_rejects_nil_ids() -> Result<(), ForgeError> {
        let token_id = Uuid::from_u128(0x120);
        let mut direct = begin_payload();
        direct["authority"]["actor"]["principal"] =
            serde_json::json!({"kind": "direct_token", "token_id": token_id});
        let direct = parse_begin(&direct)?;
        assert_eq!(
            direct.authority.agent_authority.principal,
            forge_domain::AuthenticatedPrincipal::DirectToken(
                forge_domain::DirectTokenId::from_uuid(token_id,)
            )
        );

        let grant_id = Uuid::from_u128(0x121);
        let mut oauth = begin_payload();
        oauth["authority"]["actor"]["principal"] =
            serde_json::json!({"kind": "oauth_grant", "grant_id": grant_id});
        let oauth = parse_begin(&oauth)?;
        assert_eq!(
            oauth.authority.agent_authority.principal,
            forge_domain::AuthenticatedPrincipal::OAuthGrant(
                forge_domain::OAuthGrantId::from_uuid(grant_id),
            )
        );

        let mut nil_token = begin_payload();
        nil_token["authority"]["actor"]["principal"] =
            serde_json::json!({"kind": "direct_token", "token_id": Uuid::nil()});
        assert!(parse_begin(&nil_token).is_err());

        let mut nil_grant = begin_payload();
        nil_grant["authority"]["actor"]["principal"] =
            serde_json::json!({"kind": "oauth_grant", "grant_id": Uuid::nil()});
        assert!(parse_begin(&nil_grant).is_err());

        let mut mismatched = begin_payload();
        mismatched["authority"]["actor"]["principal"] = serde_json::json!({
            "kind": "direct_token",
            "token_id": token_id,
            "grant_id": grant_id
        });
        assert!(parse_begin(&mismatched).is_err());
        Ok(())
    }

    #[test]
    fn parser_rejects_mismatched_actor_workspace_and_sealed_identity() {
        let mut actor_mismatch = begin_payload();
        actor_mismatch["authority"]["actor"]["workspace_id"] =
            serde_json::json!(Uuid::from_u128(0x999));
        assert!(parse_begin(&actor_mismatch).is_err());

        let mut command_mismatch = begin_payload();
        command_mismatch["mode"]["command_id"] = serde_json::json!("rules");
        assert!(parse_begin(&command_mismatch).is_err());
    }

    #[test]
    fn parser_rejects_unknown_execution_fields_and_legacy_request_shape() {
        let mut unknown = begin_payload();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(parse_begin(&unknown).is_err());

        let mut nil_agent = begin_payload();
        nil_agent["authority"]["actor"]["agent_id"] = serde_json::json!(Uuid::nil());
        assert!(parse_begin(&nil_agent).is_err());

        let legacy = serde_json::json!({
            "scope": begin_payload()["authority"]["scope"].clone(),
            "activity": begin_payload()["authority"]["activity"].clone(),
            "grant_id": Uuid::from_u128(0x10a),
            "expected_grant_revision": 1,
            "request": { "program": "/bin/sh", "arguments": [] },
            "admission": begin_payload()["admission"].clone()
        });
        assert!(parse_begin(&legacy).is_err());
    }
}

/// One approval-submission command. The shell variant carries the analyzed
/// script text; the command variant carries the sealed catalog fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionSubmissionCommand {
    pub(crate) authority: ExecutionAuthoritySpec,
    pub(crate) mode: ExecutionSubmissionMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionSubmissionMode {
    Shell {
        script: String,
    },
    SealedProjectCommand {
        fingerprint: ProjectCommandCatalogFingerprint,
        command_id: ProjectCommandId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmissionKind {
    Shell,
    SealedProjectCommand,
}

/// Parse one approval-submission command (shell.submit / command.submit).
/// Both ingress paths share the execution authority DTO; each op admits
/// exactly its own variant.
pub fn parse_submission(
    payload: &serde_json::Value,
    kind: SubmissionKind,
) -> Result<ExecutionSubmissionCommand, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        authority: ExecutionAuthorityDto,
        #[serde(default)]
        script: Option<String>,
        #[serde(default)]
        expected_catalog_fingerprint: Option<String>,
    }
    let body: Body = super::parse_body(payload, "execution submission payload is invalid")?;
    let authority = parse_authority(body.authority)?;
    match kind {
        SubmissionKind::Shell => {
            let Some(script) = body.script else {
                return Err(ForgeError::invalid_input(
                    "shell.submit requires the script field",
                ));
            };
            Ok(ExecutionSubmissionCommand {
                authority,
                mode: ExecutionSubmissionMode::Shell { script },
            })
        }
        SubmissionKind::SealedProjectCommand => {
            let Some(fingerprint) = body.expected_catalog_fingerprint else {
                return Err(ForgeError::invalid_input(
                    "command.submit requires expected_catalog_fingerprint",
                ));
            };
            let command_id =
                ProjectCommandId::new(authority.agent_authority.command_id.as_str().to_owned())
                    .map_err(|_| ForgeError::invalid_input("project command id is invalid"))?;
            Ok(ExecutionSubmissionCommand {
                authority,
                mode: ExecutionSubmissionMode::SealedProjectCommand {
                    fingerprint: decode_catalog_fingerprint(fingerprint.as_str())?,
                    command_id,
                },
            })
        }
    }
}

fn server_now_millis() -> Result<TimestampMillis, ForgeError> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    decode_timestamp(i64::try_from(millis).unwrap_or(0))
}

#[allow(
    clippy::too_many_lines,
    reason = "The two sealed-ingress flows stay side by side for review."
)]
pub(crate) fn execute_submission(
    client: &ForgeControlClient,
    execution: &ForgeExecutionCoordinatorClient,
    approval: &ForgeApprovalCoordinatorClient,
    runtime_instance_id: RuntimeInstanceId,
    command: &ExecutionSubmissionCommand,
) -> Result<serde_json::Value, ForgeError> {
    let authority = &command.authority;
    client
        .verify_agent_execution_authority(authority.agent_authority.clone())
        .map_err(|error| ForgeError::from_control_view(&error.view()))?;
    let submit = match &command.mode {
        ExecutionSubmissionMode::Shell { script } => {
            let analyzed = forge_control::analyze_shell_script(script.clone())
                .map_err(|_| ForgeError::invalid_input("execution shell script is not allowed"))?;
            if analyzed.intent_id() != &authority.agent_authority.command_id {
                return Err(ForgeError::invalid_input(
                    "execution shell command identity does not match analysis",
                ));
            }
            if analyzed.permissions().workspace_write() {
                return Err(ForgeError::invalid_input(
                    "execution shell command requires the controlled project lane",
                ));
            }
            if analyzed.requires_rust_tooling() && !execution.rust_ci_available() {
                return Err(ForgeError::capacity_exceeded(
                    "the Rust CI toolchain is unavailable",
                ));
            }
            let timeout = ExecutionTimeoutMillis::new(SHELL_TIMEOUT_MILLIS)
                .map_err(|_| ForgeError::invalid_input("execution timeout is invalid"))?;
            let request = ExecutionRequest::new(
                ExecutionAttribution::new(
                    authority.execution_id,
                    authority.scope.workspace_id(),
                    authority.activity.activity_id,
                ),
                ExecutionKind::Shell {
                    script: analyzed.script().clone(),
                },
                None,
                ExecutionLimits::new(timeout, ExecutionOutputLimit::DEFAULT),
                analyzed.permissions(),
            )
            .map_err(|_| ForgeError::invalid_input("execution request is invalid"))?;
            forge_control::SubmitExecutionForApproval::analyzed_shell(
                authority.scope.clone(),
                authority.activity.activity_id,
                runtime_instance_id,
                request,
            )
            .map_err(|_| ForgeError::internal())?
        }
        ExecutionSubmissionMode::SealedProjectCommand {
            fingerprint,
            command_id,
        } => {
            if !execution.rust_ci_available()
                && command_id.as_str() != forge_execution::PACKAGE_V_COMMAND_ID
            {
                return Err(ForgeError::capacity_exceeded(
                    "the Rust CI toolchain is unavailable",
                ));
            }
            let request = forge_control::ProjectCommandListRequest {
                scope: authority.scope.clone(),
                activity: forge_control::FileActivityScope {
                    activity_id: authority.activity.activity_id,
                    runtime_instance_id,
                    observed_at: server_now_millis()?,
                },
            };
            let resolved = client
                .project_command_execution_request_fenced(
                    request.clone(),
                    command_id.clone(),
                    *fingerprint,
                    authority.execution_id,
                )
                .map_err(|error| ForgeError::from_control_view(&error.view()))?;
            let evidence =
                forge_domain::ProjectCommandEvidence::new(resolved.class(), resolved.fingerprint());
            forge_control::SubmitExecutionForApproval::project_command(
                authority.scope.clone(),
                authority.activity.activity_id,
                runtime_instance_id,
                resolved.into_request(),
                evidence,
            )
            .map_err(|_| ForgeError::internal())?
        }
    };
    let submit = submit
        .with_goal_node(authority.agent_authority.attribution)
        .with_agent_authority(authority.agent_authority.clone())
        .with_approval_id(forge_domain::ApprovalRequestId::from_uuid(
            authority.execution_id.into_uuid(),
        ));
    let submission = approval.submit_execution(submit).map_err(|error| {
        if matches!(
            error,
            forge_control::ForgeApprovalCoordinatorError::QueueFull
        ) {
            ForgeError::capacity_exceeded("approval coordinator queue")
        } else {
            ForgeError::internal()
        }
    })?;
    let status = match submission.status() {
        forge_control::ApprovalSubmissionStatus::Pending => "pending",
        forge_control::ApprovalSubmissionStatus::Started => "started",
        forge_control::ApprovalSubmissionStatus::Existing => "existing",
        forge_control::ApprovalSubmissionStatus::Denied => "denied",
    };
    Ok(json!({
        "execution_id": submission.execution_id().into_uuid(),
        "approval_id": submission.approval_id().into_uuid(),
        "status": status,
    }))
}
