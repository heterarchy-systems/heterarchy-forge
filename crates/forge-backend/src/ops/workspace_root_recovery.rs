//! Typed HTTP adapter for owner-confirmed Workspace root-binding recovery.
//!
//! This module only decodes bounded wire values, forwards them through the
//! single-owner control worker, and projects the durable probe/receipt.  It
//! does not inspect SQLite, infer a remount, or authorize an operation from a
//! bearer token alone; the control owner performs the explicit confirmation,
//! Location fencing, physical transition check, and receipt CAS.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use forge_control::{
    ForgeControlClient, WorkspaceLocator, WorkspaceRootRecoveryCommitOutcome,
    WorkspaceRootRecoveryCommitRequest, WorkspaceRootRecoveryPrepareRequest,
    WorkspaceRootRecoveryProbe, WorkspaceRootRecoveryProbeRequest,
    WorkspaceRootRecoveryReadbackRequest,
};
use forge_domain::{
    LocationId, LocationRevision, RegisteredWorkspace, WorkspaceId, WorkspaceRevision,
    WorkspaceRoot, WorkspaceRootFingerprint, WorkspaceRootRecoveryAuthorityMode,
    WorkspaceRootRecoveryDelegatedAuthority, WorkspaceRootRecoveryDelegationFence,
    WorkspaceRootRecoveryFreezeFence, WorkspaceRootRecoveryFreezeState,
    WorkspaceRootRecoveryObservation, WorkspaceRootRecoveryRequest, WorkspaceRootRecoveryWitness,
};
use forge_persistence::RootRecoveryReceipt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{Command, ParseResult, decode_timestamp, parse_body};
use crate::error::{ForgeError, ReadbackHint};

const ROOT_FINGERPRINT_BYTES: usize = 16;
const RECOVERY_WITNESS_BYTES: usize = 32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeBody {
    locator: String,
    #[serde(default)]
    expected_workspace_id: Option<Uuid>,
    #[serde(default)]
    authority_mode: WorkspaceRootRecoveryAuthorityModeWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareBody {
    locator: String,
    expected_workspace: WorkspaceWire,
    observed: ObservationWire,
    operator_confirmed: bool,
    #[serde(default)]
    authority_mode: WorkspaceRootRecoveryAuthorityModeWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitBody {
    locator: String,
    request_id: Uuid,
    location_revision: i64,
    expected_workspace: WorkspaceWire,
    observed: ObservationWire,
    observed_at_ms: i64,
    operator_confirmed: bool,
    #[serde(default)]
    authority_mode: WorkspaceRootRecoveryAuthorityModeWire,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadbackBody {
    locator: String,
    request_id: Uuid,
    intent: Option<IntentWire>,
    #[serde(default)]
    authority_mode: WorkspaceRootRecoveryAuthorityModeWire,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentWire {
    request_id: Uuid,
    location_revision: i64,
    expected_workspace: WorkspaceWire,
    observed: ObservationWire,
    observed_at_ms: i64,
    #[serde(default)]
    authority_mode: WorkspaceRootRecoveryAuthorityModeWire,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkspaceRootRecoveryAuthorityModeWire {
    #[default]
    Quiescent,
    PreserveDelegatedFreeze {
        version: u8,
        freeze: Box<WorkspaceRootRecoveryFreezeFenceWire>,
        delegation: WorkspaceRootRecoveryDelegationFenceWire,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authority_digest: Option<String>,
    },
}

impl WorkspaceRootRecoveryAuthorityModeWire {
    fn is_quiescent(&self) -> bool {
        matches!(self, Self::Quiescent)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootRecoveryFreezeFenceWire {
    pub migration_id: Uuid,
    pub workspace_id: Uuid,
    pub destination_id: Uuid,
    pub state: String,
    pub revision: u64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootRecoveryDelegationFenceWire {
    pub migration_id: Uuid,
    pub workspace_id: Uuid,
    pub destination_id: Uuid,
    pub freeze_revision: u64,
    pub manifest_digest: String,
    pub delegated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootRecoveryObservationWire {
    pub root_path_base64: String,
    pub root_fingerprint: String,
    pub witness: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_version: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootRecoveryWorkspaceWire {
    pub workspace_id: Uuid,
    pub location_id: Uuid,
    pub root_path_base64: String,
    pub root_fingerprint: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub workspace_revision: i64,
}

type ObservationWire = WorkspaceRootRecoveryObservationWire;
type WorkspaceWire = WorkspaceRootRecoveryWorkspaceWire;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootRecoveryProbeWire {
    pub status: WorkspaceRootRecoveryProbeStatus,
    pub locator: String,
    pub location_revision: i64,
    pub schema_version: i64,
    pub requires_schema_upgrade: bool,
    pub workspace: WorkspaceRootRecoveryWorkspaceWire,
    pub observation: WorkspaceRootRecoveryObservationWire,
    #[serde(
        default,
        skip_serializing_if = "WorkspaceRootRecoveryAuthorityModeWire::is_quiescent"
    )]
    pub authority_mode: WorkspaceRootRecoveryAuthorityModeWire,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRootRecoveryProbeStatus {
    Observed,
    Prepared,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootRecoveryReceiptWire {
    pub request_id: Uuid,
    pub location_revision: i64,
    pub expected_workspace_revision: i64,
    pub workspace: WorkspaceRootRecoveryWorkspaceWire,
    pub old_root_fingerprint: String,
    pub request_digest: String,
    pub witness_digest: String,
    pub receipt_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_receipt: Option<WorkspaceRootRecoveryDelegationReceiptWire>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootRecoveryDelegationReceiptWire {
    pub version: u8,
    pub kind: String,
    pub freeze: WorkspaceRootRecoveryFreezeFenceWire,
    pub delegation: WorkspaceRootRecoveryDelegationFenceWire,
    pub authority_digest: String,
    pub normal_request_intent_digest: String,
    pub witness_v2_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootRecoveryCommitWire {
    pub status: WorkspaceRootRecoveryCommitStatus,
    pub confirmed: bool,
    pub receipt: WorkspaceRootRecoveryReceiptWire,
    pub recovery_action: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRootRecoveryCommitStatus {
    Committed,
    Replayed,
    CommittedButUnconfirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRootRecoveryReadbackWire {
    pub found: bool,
    pub status: WorkspaceRootRecoveryReadbackStatus,
    #[serde(default)]
    pub receipt: Option<WorkspaceRootRecoveryReceiptWire>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRootRecoveryReadbackStatus {
    HistoricalReceipt,
}

pub(super) fn parse_probe(request_id: Uuid, payload: &Value) -> ParseResult {
    let body: ProbeBody = parse_body(payload, "workspace.root_recovery.probe payload is invalid")?;
    let authority = decode_authority_mode(&body.authority_mode)?;
    let locator = decode_locator(&body.locator)?;
    let expected = body.expected_workspace_id.map(WorkspaceId::from_uuid);
    Ok(Command::WorkspaceRootRecoveryProbe {
        request_id,
        request: Box::new(match authority {
            WorkspaceRootRecoveryAuthorityMode::Quiescent => {
                WorkspaceRootRecoveryProbeRequest::new(locator, expected)
            }
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) => {
                WorkspaceRootRecoveryProbeRequest::new_preserving_delegated_freeze(
                    locator, expected, authority,
                )
            }
        }),
    })
}

pub(super) fn parse_prepare(request_id: Uuid, payload: &Value) -> ParseResult {
    let body: PrepareBody = parse_body(
        payload,
        "workspace.root_recovery.prepare payload is invalid",
    )?;
    let authority = decode_authority_mode(&body.authority_mode)?;
    let locator = decode_locator(&body.locator)?;
    let workspace = decode_workspace(&body.expected_workspace)?;
    let observation = decode_observation(&body.observed, authority)?;
    Ok(Command::WorkspaceRootRecoveryPrepare {
        request_id,
        request: Box::new(match authority {
            WorkspaceRootRecoveryAuthorityMode::Quiescent => {
                WorkspaceRootRecoveryPrepareRequest::new(
                    locator,
                    workspace,
                    observation,
                    body.operator_confirmed,
                )
            }
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) => {
                WorkspaceRootRecoveryPrepareRequest::new_preserving_delegated_freeze(
                    locator,
                    workspace,
                    observation,
                    body.operator_confirmed,
                    authority,
                )
            }
        }),
    })
}

pub(super) fn parse_commit(request_id: Uuid, payload: &Value) -> ParseResult {
    let body: CommitBody =
        parse_body(payload, "workspace.root_recovery.commit payload is invalid")?;
    if body.request_id != request_id {
        return Err(ForgeError::invalid_input(
            "root recovery request_id must match the transport request identity",
        ));
    }
    let authority = decode_authority_mode(&body.authority_mode)?;
    let intent = decode_request(
        body.request_id,
        body.location_revision,
        &body.expected_workspace,
        &body.observed,
        body.observed_at_ms,
        authority,
    )?;
    Ok(Command::WorkspaceRootRecoveryCommit {
        request_id,
        request: Box::new(WorkspaceRootRecoveryCommitRequest::new(
            decode_locator(&body.locator)?,
            intent,
            body.operator_confirmed,
        )),
    })
}

pub(super) fn parse_readback(request_id: Uuid, payload: &Value) -> ParseResult {
    require_nullable_field(payload, "intent", "workspace.root_recovery.readback")?;
    let body: ReadbackBody = parse_body(
        payload,
        "workspace.root_recovery.readback payload is invalid",
    )?;
    if body.request_id != request_id {
        return Err(ForgeError::invalid_input(
            "root recovery request_id must match the transport request identity",
        ));
    }
    let intent = body
        .intent
        .as_ref()
        .map(decode_intent)
        .transpose()?
        .map(|intent| {
            if intent.request_id() == body.request_id {
                Ok(intent)
            } else {
                Err(ForgeError::invalid_input(
                    "root recovery intent request_id must match the readback identity",
                ))
            }
        })
        .transpose()?;
    let authority = decode_authority_mode(&body.authority_mode)?;
    if intent
        .as_ref()
        .is_some_and(|intent| intent.authority_mode() != authority)
    {
        return Err(ForgeError::invalid_input(
            "root recovery readback authority mode does not match intent",
        ));
    }
    let locator = decode_locator(&body.locator)?;
    Ok(Command::WorkspaceRootRecoveryReadback {
        request_id,
        request: Box::new(match authority {
            WorkspaceRootRecoveryAuthorityMode::Quiescent => {
                WorkspaceRootRecoveryReadbackRequest::new(locator, body.request_id, intent)
            }
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) => {
                WorkspaceRootRecoveryReadbackRequest::new_preserving_delegated_freeze(
                    locator,
                    body.request_id,
                    intent,
                    authority,
                )
            }
        }),
    })
}

pub(super) fn execute_probe(
    client: &ForgeControlClient,
    request: &WorkspaceRootRecoveryProbeRequest,
) -> Result<Value, ForgeError> {
    let probe = client
        .probe_workspace_root_recovery(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(probe_json(
        WorkspaceRootRecoveryProbeStatus::Observed,
        &probe,
    ))
}

pub(super) fn execute_prepare(
    client: &ForgeControlClient,
    request: &WorkspaceRootRecoveryPrepareRequest,
) -> Result<Value, ForgeError> {
    let probe = client
        .prepare_workspace_root_recovery(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(probe_json(
        WorkspaceRootRecoveryProbeStatus::Prepared,
        &probe,
    ))
}

pub(super) fn execute_commit(
    client: &ForgeControlClient,
    request: &WorkspaceRootRecoveryCommitRequest,
) -> Result<Value, ForgeError> {
    let outcome = client
        .commit_workspace_root_recovery(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(match outcome {
        WorkspaceRootRecoveryCommitOutcome::Committed { receipt } => receipt_json(
            WorkspaceRootRecoveryCommitStatus::Committed,
            true,
            &receipt,
            None,
        ),
        WorkspaceRootRecoveryCommitOutcome::Replayed { receipt } => receipt_json(
            WorkspaceRootRecoveryCommitStatus::Replayed,
            true,
            &receipt,
            None,
        ),
        WorkspaceRootRecoveryCommitOutcome::CommittedButUnconfirmed { receipt, reason } => {
            receipt_json(
                WorkspaceRootRecoveryCommitStatus::CommittedButUnconfirmed,
                false,
                &receipt,
                Some(revalidation_reason(reason)),
            )
        }
    })
}

pub(super) fn execute_readback(
    client: &ForgeControlClient,
    request: &WorkspaceRootRecoveryReadbackRequest,
) -> Result<Value, ForgeError> {
    let receipt = client
        .readback_workspace_root_recovery(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    Ok(match receipt {
        Some(receipt) => json!({
            "found": true,
            "status": WorkspaceRootRecoveryReadbackStatus::HistoricalReceipt,
            "receipt": receipt_wire(&receipt),
        }),
        None => json!({
            "found": false,
            "status": WorkspaceRootRecoveryReadbackStatus::HistoricalReceipt,
        }),
    })
}

pub(super) fn readback_hint(request: &WorkspaceRootRecoveryCommitRequest) -> ReadbackHint {
    let intent = request.intent();
    ReadbackHint::WorkspaceRootRecovery {
        locator: request.locator().encode(),
        request_id: intent.request_id(),
        location_revision: intent.location_revision().get(),
        expected_workspace_id: intent.expected().id().into_uuid(),
        expected_workspace_revision: intent.expected().revision().get(),
        expected_root_path_base64: encode_path(intent.expected().root().as_path()),
        expected_root_fingerprint: super::encode_hex(
            intent.expected().root_fingerprint().as_bytes(),
        ),
        expected_created_at_ms: intent.expected().created_at().get(),
        expected_updated_at_ms: intent.expected().updated_at().get(),
        observed_root_path_base64: encode_path(intent.observed().root().as_path()),
        observed_root_fingerprint: super::encode_hex(intent.observed().fingerprint().as_bytes()),
        observed_witness: super::encode_hex(intent.observed().witness().as_bytes()),
        observed_at_ms: intent.observed_at().get(),
        authority_mode: authority_mode_json(intent.authority_mode(), true),
    }
}

fn decode_intent(value: &IntentWire) -> Result<WorkspaceRootRecoveryRequest, ForgeError> {
    decode_request(
        value.request_id,
        value.location_revision,
        &value.expected_workspace,
        &value.observed,
        value.observed_at_ms,
        decode_authority_mode(&value.authority_mode)?,
    )
}

fn decode_request(
    request_id: Uuid,
    location_revision: i64,
    workspace: &WorkspaceWire,
    observation: &ObservationWire,
    observed_at_ms: i64,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
) -> Result<WorkspaceRootRecoveryRequest, ForgeError> {
    let location_revision = decode_location_revision(location_revision)?;
    let workspace = decode_workspace(workspace)?;
    let observation = decode_observation(observation, authority_mode)?;
    let observed_at = decode_timestamp(observed_at_ms)?;
    match authority_mode {
        WorkspaceRootRecoveryAuthorityMode::Quiescent => WorkspaceRootRecoveryRequest::new(
            request_id,
            location_revision,
            workspace,
            observation,
            observed_at,
        ),
        WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) => {
            WorkspaceRootRecoveryRequest::new_preserving_delegated_freeze(
                request_id,
                location_revision,
                workspace,
                observation,
                observed_at,
                authority,
            )
        }
    }
    .map_err(|_| ForgeError::invalid_input("root recovery intent is invalid"))
}

fn decode_authority_mode(
    value: &WorkspaceRootRecoveryAuthorityModeWire,
) -> Result<WorkspaceRootRecoveryAuthorityMode, ForgeError> {
    let WorkspaceRootRecoveryAuthorityModeWire::PreserveDelegatedFreeze {
        version,
        freeze,
        delegation,
        authority_digest,
    } = value
    else {
        return Ok(WorkspaceRootRecoveryAuthorityMode::Quiescent);
    };
    if *version != 2 || freeze.state != "frozen" {
        return Err(ForgeError::invalid_input(
            "preserved delegation authority version or state is invalid",
        ));
    }
    let authority = WorkspaceRootRecoveryDelegatedAuthority::new(
        WorkspaceRootRecoveryFreezeFence {
            migration_id: freeze.migration_id,
            workspace_id: WorkspaceId::from_uuid(freeze.workspace_id),
            destination_id: freeze.destination_id,
            state: WorkspaceRootRecoveryFreezeState::Frozen,
            revision: freeze.revision,
            created_at: decode_timestamp(freeze.created_at_ms)?,
            updated_at: decode_timestamp(freeze.updated_at_ms)?,
        },
        WorkspaceRootRecoveryDelegationFence {
            migration_id: delegation.migration_id,
            workspace_id: WorkspaceId::from_uuid(delegation.workspace_id),
            destination_id: delegation.destination_id,
            freeze_revision: delegation.freeze_revision,
            manifest_digest: decode_digest(&delegation.manifest_digest)?,
            delegated_at: decode_timestamp(delegation.delegated_at_ms)?,
        },
    )
    .map_err(|_| ForgeError::invalid_input("preserved delegation authority is invalid"))?;
    if authority_digest.as_ref().is_some_and(|digest| {
        decode_digest(digest).map_or(true, |digest| {
            digest != forge_persistence::delegated_authority_digest(authority)
        })
    }) {
        return Err(ForgeError::invalid_input(
            "preserved delegation authority digest is invalid",
        ));
    }
    Ok(WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(
        authority,
    ))
}

fn decode_digest(value: &str) -> Result<[u8; 32], ForgeError> {
    let bytes = super::decode_hex(value)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| ForgeError::invalid_input("digest is invalid"))
}

fn decode_locator(value: &str) -> Result<WorkspaceLocator, ForgeError> {
    WorkspaceLocator::decode(value)
        .map_err(|_| ForgeError::invalid_input("encoded Workspace locator is invalid"))
}

fn decode_location_revision(value: i64) -> Result<LocationRevision, ForgeError> {
    LocationRevision::new(value)
        .map_err(|_| ForgeError::invalid_input("Location revision is invalid"))
}

fn decode_workspace(value: &WorkspaceWire) -> Result<RegisteredWorkspace, ForgeError> {
    Ok(RegisteredWorkspace::from_parts_with_revision(
        WorkspaceId::from_uuid(value.workspace_id),
        LocationId::from_uuid(value.location_id),
        decode_root(&value.root_path_base64)?,
        decode_fingerprint(&value.root_fingerprint)?,
        decode_timestamp(value.created_at_ms)?,
        decode_timestamp(value.updated_at_ms)?,
        WorkspaceRevision::new(value.workspace_revision)
            .map_err(|_| ForgeError::invalid_input("Workspace revision is invalid"))?,
    ))
}

fn decode_observation(
    value: &ObservationWire,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
) -> Result<WorkspaceRootRecoveryObservation, ForgeError> {
    match authority_mode {
        WorkspaceRootRecoveryAuthorityMode::Quiescent if value.witness_version.is_some() => {
            return Err(ForgeError::invalid_input(
                "quiescent root recovery must omit witness_version",
            ));
        }
        WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_)
            if value.witness_version != Some(2) =>
        {
            return Err(ForgeError::invalid_input(
                "preserved root recovery requires witness_version 2",
            ));
        }
        _ => {}
    }
    Ok(WorkspaceRootRecoveryObservation::new(
        decode_root(&value.root_path_base64)?,
        decode_fingerprint(&value.root_fingerprint)?,
        decode_witness(&value.witness)?,
    ))
}

fn decode_root(value: &str) -> Result<WorkspaceRoot, ForgeError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| ForgeError::invalid_input("root path base64 is invalid"))?;
    WorkspaceRoot::from_canonical(PathBuf::from(OsString::from_vec(bytes)))
        .map_err(|_| ForgeError::invalid_input("root path is invalid"))
}

fn decode_fingerprint(value: &str) -> Result<WorkspaceRootFingerprint, ForgeError> {
    let bytes = super::decode_hex(value)?;
    let bytes = <[u8; ROOT_FINGERPRINT_BYTES]>::try_from(bytes.as_slice())
        .map_err(|_| ForgeError::invalid_input("root fingerprint is invalid"))?;
    Ok(WorkspaceRootFingerprint::from_bytes(bytes))
}

fn decode_witness(value: &str) -> Result<WorkspaceRootRecoveryWitness, ForgeError> {
    let bytes = super::decode_hex(value)?;
    let bytes = <[u8; RECOVERY_WITNESS_BYTES]>::try_from(bytes.as_slice())
        .map_err(|_| ForgeError::invalid_input("root recovery witness is invalid"))?;
    Ok(WorkspaceRootRecoveryWitness::from_bytes(bytes))
}

fn require_nullable_field(
    payload: &Value,
    field: &'static str,
    operation: &'static str,
) -> Result<(), ForgeError> {
    if payload
        .as_object()
        .is_some_and(|object| object.contains_key(field))
    {
        Ok(())
    } else {
        Err(ForgeError::invalid_input(format!(
            "{operation} {field} is required; use null when no exact intent is supplied"
        )))
    }
}

pub(crate) fn probe_json(
    status: WorkspaceRootRecoveryProbeStatus,
    probe: &WorkspaceRootRecoveryProbe,
) -> Value {
    let mut value = json!({
        "status": status,
        "locator": probe.locator().encode(),
        "location_revision": probe.location_revision().get(),
        "schema_version": probe.schema_version(),
        "requires_schema_upgrade": probe.requires_schema_upgrade(),
        "workspace": workspace_json(probe.workspace()),
        "observation": observation_json_for_mode(probe.observation(), probe.authority_mode()),
    });
    if let Some(authority) = authority_mode_json(probe.authority_mode(), true) {
        value["authority_mode"] = authority;
    }
    value
}

fn receipt_json(
    status: WorkspaceRootRecoveryCommitStatus,
    confirmed: bool,
    receipt: &RootRecoveryReceipt,
    reason: Option<&'static str>,
) -> Value {
    let mut value = json!({
        "status": status,
        "confirmed": confirmed,
        "receipt": receipt_wire(receipt),
        "recovery_action": if confirmed { Value::Null } else { json!("read_back") },
    });
    if let Some(reason) = reason {
        value["reason"] = json!(reason);
    }
    value
}

fn receipt_wire(receipt: &RootRecoveryReceipt) -> Value {
    let mut value = json!({
        "request_id": receipt.request_id(),
        "location_revision": receipt.expected_location_revision().get(),
        "expected_workspace_revision": receipt.expected_workspace_revision().get(),
        "workspace": workspace_json(receipt.workspace()),
        "old_root_fingerprint": super::encode_hex(receipt.old_root_fingerprint().as_bytes()),
        "request_digest": super::encode_hex(receipt.request_digest()),
        "witness_digest": super::encode_hex(receipt.witness_digest()),
        "receipt_digest": super::encode_hex(receipt.receipt_digest()),
    });
    if let WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) =
        receipt.authority_mode()
    {
        value["delegation_receipt"] = json!({
            "version": 2,
            "kind": "preserve_delegated_freeze",
            "freeze": freeze_json(authority.freeze()),
            "delegation": delegation_json(authority.delegation()),
            "authority_digest": super::encode_hex(&forge_persistence::delegated_authority_digest(authority)),
            "normal_request_intent_digest": super::encode_hex(receipt.request_digest()),
            "witness_v2_digest": super::encode_hex(receipt.witness_digest()),
        });
    }
    value
}

pub(crate) fn workspace_json(workspace: &RegisteredWorkspace) -> Value {
    json!({
        "workspace_id": workspace.id().into_uuid(),
        "location_id": workspace.location_id().into_uuid(),
        "root_path_base64": encode_path(workspace.root().as_path()),
        "root_fingerprint": super::encode_hex(workspace.root_fingerprint().as_bytes()),
        "created_at_ms": workspace.created_at().get(),
        "updated_at_ms": workspace.updated_at().get(),
        "workspace_revision": workspace.revision().get(),
    })
}

pub(crate) fn observation_json(observation: &WorkspaceRootRecoveryObservation) -> Value {
    json!({
        "root_path_base64": encode_path(observation.root().as_path()),
        "root_fingerprint": super::encode_hex(observation.fingerprint().as_bytes()),
        "witness": super::encode_hex(observation.witness().as_bytes()),
    })
}

pub(crate) fn observation_json_for_mode(
    observation: &WorkspaceRootRecoveryObservation,
    mode: WorkspaceRootRecoveryAuthorityMode,
) -> Value {
    let mut value = observation_json(observation);
    if matches!(
        mode,
        WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_)
    ) {
        value["witness_version"] = json!(2);
    }
    value
}

pub(crate) fn authority_mode_json(
    mode: WorkspaceRootRecoveryAuthorityMode,
    include_digest: bool,
) -> Option<Value> {
    let WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) = mode else {
        return None;
    };
    let mut value = json!({
        "kind": "preserve_delegated_freeze",
        "version": 2,
        "freeze": freeze_json(authority.freeze()),
        "delegation": delegation_json(authority.delegation()),
    });
    if include_digest {
        value["authority_digest"] =
            super::encode_hex(&forge_persistence::delegated_authority_digest(authority)).into();
    }
    Some(value)
}

fn freeze_json(freeze: WorkspaceRootRecoveryFreezeFence) -> Value {
    json!({
        "migration_id": freeze.migration_id,
        "workspace_id": freeze.workspace_id.into_uuid(),
        "destination_id": freeze.destination_id,
        "state": "frozen",
        "revision": freeze.revision,
        "created_at_ms": freeze.created_at.get(),
        "updated_at_ms": freeze.updated_at.get(),
    })
}

fn delegation_json(delegation: WorkspaceRootRecoveryDelegationFence) -> Value {
    json!({
        "migration_id": delegation.migration_id,
        "workspace_id": delegation.workspace_id.into_uuid(),
        "destination_id": delegation.destination_id,
        "freeze_revision": delegation.freeze_revision,
        "manifest_digest": super::encode_hex(&delegation.manifest_digest),
        "delegated_at_ms": delegation.delegated_at.get(),
    })
}

pub(crate) fn encode_path(path: &std::path::Path) -> String {
    URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes())
}

pub(crate) fn intent_json(request: &WorkspaceRootRecoveryRequest) -> Value {
    let mut value = json!({
        "request_id": request.request_id(),
        "location_revision": request.location_revision().get(),
        "expected_workspace": workspace_json(request.expected()),
        "observed": observation_json_for_mode(request.observed(), request.authority_mode()),
        "observed_at_ms": request.observed_at().get(),
    });
    if let Some(authority) = authority_mode_json(request.authority_mode(), true) {
        value["authority_mode"] = authority;
    }
    value
}

fn revalidation_reason(
    reason: forge_control::WorkspaceRootRecoveryRevalidationReason,
) -> &'static str {
    use forge_control::WorkspaceRootRecoveryRevalidationReason as Reason;
    match reason {
        Reason::LocationRevisionChanged => "location_revision_changed",
        Reason::CandidateRootChanged => "candidate_root_changed",
        Reason::CandidateFingerprintChanged => "candidate_fingerprint_changed",
        Reason::WorkspaceIdentityChanged => "workspace_identity_changed",
        Reason::InventoryUnavailable => "inventory_unavailable",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::CommandOp;
    use forge_domain::{LocationRevision, WorkspaceId};
    use serde_json::json;

    #[test]
    fn required_nullable_intent_rejects_omission_and_accepts_null() {
        let missing = json!({});
        assert!(require_nullable_field(&missing, "intent", "test").is_err());
        let explicit_null = json!({ "intent": null });
        assert!(require_nullable_field(&explicit_null, "intent", "test").is_ok());
    }

    #[test]
    fn native_path_encoding_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let original = PathBuf::from("/tmp/forge-root");
        let encoded = encode_path(&original);
        let decoded = decode_root(&encoded)?;
        assert_eq!(decoded.as_path(), original);
        Ok(())
    }

    #[test]
    fn probe_decodes_to_the_closed_control_request() -> Result<(), Box<dyn std::error::Error>> {
        let locator = WorkspaceLocator::new(
            LocationId::from_uuid(Uuid::from_u128(1)),
            LocationRevision::new(2)?,
            std::path::Path::new("workspace"),
        )?;
        let command = parse_probe(
            Uuid::from_u128(3),
            &json!({
                "locator": locator.encode(),
                "expected_workspace_id": Uuid::from_u128(4),
            }),
        )
        .map_err(|_| "valid probe payload was rejected")?;
        assert_eq!(command.op(), CommandOp::WorkspaceRootRecoveryProbe);
        assert_eq!(command.request_id(), Uuid::from_u128(3));
        let Command::WorkspaceRootRecoveryProbe { request, .. } = command else {
            return Err("wrong command variant".into());
        };
        assert_eq!(
            request.expected_workspace_id(),
            Some(WorkspaceId::from_uuid(Uuid::from_u128(4)))
        );
        Ok(())
    }

    #[test]
    fn preserve_delegated_freeze_wire_is_versioned_and_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let locator = WorkspaceLocator::new(
            LocationId::from_uuid(Uuid::from_u128(1)),
            LocationRevision::new(2)?,
            std::path::Path::new("workspace"),
        )?;
        let migration = Uuid::from_u128(5);
        let workspace = Uuid::from_u128(6);
        let destination = Uuid::from_u128(7);
        let command = parse_probe(
            Uuid::from_u128(3),
            &json!({
                "locator": locator.encode(),
                "expected_workspace_id": workspace,
                "authority_mode": {
                    "kind": "preserve_delegated_freeze",
                    "version": 2,
                    "freeze": {
                        "migration_id": migration,
                        "workspace_id": workspace,
                        "destination_id": destination,
                        "state": "frozen",
                        "revision": 1,
                        "created_at_ms": 10,
                        "updated_at_ms": 10
                    },
                    "delegation": {
                        "migration_id": migration,
                        "workspace_id": workspace,
                        "destination_id": destination,
                        "freeze_revision": 1,
                        "manifest_digest": "ab".repeat(32),
                        "delegated_at_ms": 11
                    }
                }
            }),
        )
        .map_err(|_| "valid preserved-delegation probe was rejected")?;
        let Command::WorkspaceRootRecoveryProbe { request, .. } = command else {
            return Err("wrong command variant".into());
        };
        assert!(matches!(
            request.authority_mode(),
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_)
        ));
        Ok(())
    }

    #[test]
    fn commit_rejects_a_transport_identity_that_differs_from_the_intent()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = encode_path(std::path::Path::new("/tmp/recovery"));
        let workspace = json!({
            "workspace_id": Uuid::from_u128(4),
            "location_id": Uuid::from_u128(1),
            "root_path_base64": root,
            "root_fingerprint": "01".repeat(16),
            "created_at_ms": 1,
            "updated_at_ms": 1,
            "workspace_revision": 1,
        });
        let observed = json!({
            "root_path_base64": encode_path(std::path::Path::new("/tmp/recovery")),
            "root_fingerprint": "02".repeat(8) + &"01".repeat(8),
            "witness": "00".repeat(32),
        });
        let payload = json!({
            "locator": WorkspaceLocator::new(
                LocationId::from_uuid(Uuid::from_u128(1)),
                LocationRevision::new(2)?,
                std::path::Path::new("workspace"),
            )?.encode(),
            "request_id": Uuid::from_u128(9),
            "location_revision": 2,
            "expected_workspace": workspace,
            "observed": observed,
            "observed_at_ms": 2,
            "operator_confirmed": true,
        });
        assert!(parse_commit(Uuid::from_u128(8), &payload).is_err());
        Ok(())
    }
}
