//! Issuer/operator observation. This never issues execution or agent authority.

use base64::Engine as _;
use forge_control::{ForgeControlClient, ResolvedWorkspaceScope};
use forge_domain::ExecutionObservationSelection;
use forge_domain::{
    ExecutionId, ExecutionListLimit, ExecutionOutputCursor, GoalAttribution, GoalId,
    VerificationOutputIntegrity, VerificationRunDisposition, VerificationRunState,
};
use forge_persistence::ExecutionEvidenceRecord;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{ScopeDto, decode_scope, parse_body};
use crate::error::ForgeError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoalDto {
    goal_id: Uuid,
    expected_revision: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryBody {
    scope: ScopeDto,
    activity_id: Uuid,
    goal: Option<GoalDto>,
    limit: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserveBody {
    scope: ScopeDto,
    activity_id: Uuid,
    goal: Option<GoalDto>,
    execution_id: Uuid,
    after_sequence: u64,
    max_bytes: u64,
    max_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryCommand {
    scope: ResolvedWorkspaceScope,
    selection: ExecutionObservationSelection,
    limit: ExecutionListLimit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveCommand {
    scope: ResolvedWorkspaceScope,
    selection: ExecutionObservationSelection,
    execution_id: ExecutionId,
    cursor: ExecutionOutputCursor,
    max_bytes: u64,
    max_events: usize,
}

fn selection(
    activity_id: Uuid,
    goal: Option<GoalDto>,
) -> Result<ExecutionObservationSelection, ForgeError> {
    if activity_id.is_nil() || goal.as_ref().is_some_and(|value| value.goal_id.is_nil()) {
        return Err(ForgeError::invalid_input(
            "execution observation identity must be non-nil",
        ));
    }
    let goal = goal
        .map(|goal| {
            super::decode_goal_revision(goal.expected_revision)
                .map(|revision| GoalAttribution::new(GoalId::from_uuid(goal.goal_id), revision))
        })
        .transpose()?;
    Ok(ExecutionObservationSelection::new(
        forge_domain::ActivityId::from_uuid(activity_id),
        goal,
    ))
}

pub(super) fn parse_inventory(value: &Value) -> Result<InventoryCommand, ForgeError> {
    let body: InventoryBody = parse_body(value, "execution.inventory payload is invalid")?;
    Ok(InventoryCommand {
        scope: decode_scope(&body.scope)?,
        selection: selection(body.activity_id, body.goal)?,
        limit: ExecutionListLimit::new(body.limit)
            .map_err(|_| ForgeError::invalid_input("execution inventory limit is invalid"))?,
    })
}

pub(super) fn parse_observe(value: &Value) -> Result<ObserveCommand, ForgeError> {
    let body: ObserveBody = parse_body(value, "execution.observe payload is invalid")?;
    if body.execution_id.is_nil()
        || !(forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES
            ..=forge_domain::MAX_EXECUTION_OUTPUT_READ_BYTES)
            .contains(&body.max_bytes)
        || body.max_events == 0
        || body.max_events > forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS
    {
        return Err(ForgeError::invalid_input(
            "execution observation cursor or output bound is invalid",
        ));
    }
    let id = ExecutionId::from_uuid(body.execution_id);
    let cursor = if body.after_sequence == 0 {
        ExecutionOutputCursor::initial(id)
    } else {
        ExecutionOutputCursor::from_sequence(id, super::decode_sequence(body.after_sequence)?)
    };
    Ok(ObserveCommand {
        scope: decode_scope(&body.scope)?,
        selection: selection(body.activity_id, body.goal)?,
        execution_id: id,
        cursor,
        max_bytes: body.max_bytes,
        max_events: body.max_events,
    })
}

fn selection_json(selection: ExecutionObservationSelection) -> Value {
    json!({"activity_id":selection.activity_id().into_uuid(), "goal":selection.goal().map(|goal|
        json!({"goal_id":goal.goal_id().into_uuid(),"expected_revision":goal.expected_revision().get()}))})
}

pub(super) fn execute_inventory(
    client: &ForgeControlClient,
    command: &InventoryCommand,
) -> Result<Value, ForgeError> {
    let inventory = client
        .execution_evidence_inventory(command.scope.clone(), command.selection, command.limit)
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(
        json!({"scope":super::source::scope_json(&command.scope)?,"selection":selection_json(inventory.selection()),
        "entries":inventory.entries().iter().map(record_json).collect::<Vec<_>>(),
        "entry_count":inventory.entries().len(),"has_more":inventory.has_more()}),
    )
}

pub(super) fn execute_observe(
    client: &ForgeControlClient,
    command: &ObserveCommand,
) -> Result<Value, ForgeError> {
    let read = client
        .execution_evidence_read(
            command.scope.clone(),
            command.selection,
            command.execution_id,
            command.cursor,
            command.max_bytes,
            command.max_events,
        )
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(
        json!({"scope":super::source::scope_json(&command.scope)?,"selection":selection_json(read.selection()),
        "record":record_json(read.record()),"output":{"execution_id":command.execution_id.into_uuid(),
            "next_sequence":read.output().next_cursor().after_sequence(), "truncated":read.output().truncated(),
            "event_count":read.output().events().len(),
            "events":read.output().events().iter().map(super::execution::output_event_json).collect::<Vec<_>>()}}),
    )
}

fn record_json(record: &ExecutionEvidenceRecord) -> Value {
    let header = record.header();
    json!({"execution_id":header.id().into_uuid(),"workspace_id":header.workspace_id().into_uuid(),
        "activity_id":header.activity_id().into_uuid(),"mode":match header.mode() {
            forge_domain::ExecutionMode::Shell=>"shell", forge_domain::ExecutionMode::Structured=>"structured"},
        "request_digest":crate::events::hex_encode(header.request_digest().as_bytes()),
        "cwd_base64":header.cwd().map(|path|base64::engine::general_purpose::STANDARD.encode(path.as_path().as_os_str().as_encoded_bytes())),
        "timeout_ms":header.limits().timeout().get(),"output_limit":header.limits().output().get(),
        "permissions":{"workspace_read":header.permissions().workspace_read(),"workspace_write":header.permissions().workspace_write(),
            "network":header.permissions().network()},
        "state":super::execution_evidence::execution_state_name(header.state()),"revision":header.revision().get(),
        "created_at_ms":header.timestamps().created_at().get(),"updated_at_ms":header.timestamps().updated_at().get(),
        "terminal":header.state().is_terminal(),"failure_code":header.failure_code().map(super::execution_evidence::execution_failure_name),
        "outcome":header.terminal().map(terminal_json),"provenance":header.provenance().map(provenance_json),
        "verification":record.verification().map(verification_json)})
}

fn terminal_json(value: forge_domain::ExecutionTerminalSummary) -> Value {
    json!({"status":match value.termination().status() { forge_domain::ExecutionCompletionStatus::Exited=>"exited",
        forge_domain::ExecutionCompletionStatus::TimedOut=>"timed_out",forge_domain::ExecutionCompletionStatus::Cancelled=>"cancelled"},
        "exit_code":value.termination().exit_code(),"signal":value.termination().signal(),"duration_ms":value.duration_millis(),
        "stdout":output_summary_json(value.stdout()),"stderr":output_summary_json(value.stderr())})
}

fn output_summary_json(value: forge_domain::ExecutionOutputSummary) -> Value {
    json!({"retained_bytes":value.retained_bytes(),"total_bytes":value.total_bytes(),"truncated":value.truncated()})
}

fn provenance_json(value: &forge_domain::ExecutionAgentProvenance) -> Value {
    let attribution = value.attribution();
    json!({"session_id":value.session_id().map(forge_domain::AgentSessionId::into_uuid),"agent_id":value.agent_id().into_uuid(),
        "agent_revision":value.agent_revision().get(),"principal":super::goals::principal_json(value.principal()),
        "goal_id":attribution.goal_id().into_uuid(),"goal_revision":attribution.expected_goal_revision().get(),
        "dag_revision":attribution.dag_revision().get(),"node_id":attribution.node_id().into_uuid(),
        "node_revision":attribution.expected_node_revision().get(),"command_id":value.command_id().as_str(),
        "project_command":value.project_command().map(|command| json!({"class":match command.class() {
            forge_domain::ProjectCommandClass::Verify=>"verify",
            forge_domain::ProjectCommandClass::GeneratedPackage=>"generated_package"},
            "catalog_fingerprint":command.catalog_fingerprint().hash().to_string()}))})
}

fn verification_json(value: &forge_domain::VerificationEvidenceSnapshot) -> Value {
    let run = value.run();
    let input = run.input();
    let terminal = match run.state() {
        VerificationRunState::Starting => None,
        VerificationRunState::Terminal(status) => Some(status),
    };
    json!({"execution_id":run.execution_id().into_uuid(),"workspace_id":run.workspace_id().into_uuid(),"revision":value.revision(),
        "created_at_ms":value.created_at().get(),"updated_at_ms":value.updated_at().get(),
        "state":if terminal.is_some(){"terminal"}else{"starting"},
        "disposition":terminal.map(|status|match status.disposition(){VerificationRunDisposition::Accepted=>"accepted",
            VerificationRunDisposition::Rejected=>"rejected",VerificationRunDisposition::Incomplete=>"incomplete",
            VerificationRunDisposition::RecoveryRequired=>"recovery_required"}),
        "output_integrity":terminal.and_then(forge_domain::VerificationRunTerminalStatus::output_integrity).map(|integrity|match integrity {
            VerificationOutputIntegrity::Complete=>"complete",VerificationOutputIntegrity::Gapped=>"gapped",
            VerificationOutputIntegrity::Truncated=>"truncated",VerificationOutputIntegrity::GappedAndTruncated=>"gapped_and_truncated"}),
        "output_fingerprint":terminal.and_then(forge_domain::VerificationRunTerminalStatus::output_fingerprint).map(|hash|hash.to_string()),
        "catalog_fingerprint":run.catalog_fingerprint().map(|catalog|catalog.hash().to_string()),
        "input":{"input_id":input.input_id().into_uuid(),"fingerprint":input.fingerprint().to_string(),
            "policy":input.policy().version(),"file_count":input.file_count(),"total_bytes":input.total_bytes().get()},
        "requirements":value.requirements().iter().map(|link|json!({"execution_id":link.execution_id().into_uuid(),
            "goal_id":link.goal_id().into_uuid(),"goal_revision":link.goal_revision().get(),
            "requirement_index":link.requirement_index()})).collect::<Vec<_>>()})
}
