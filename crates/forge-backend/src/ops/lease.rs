//! Typed Writer Lease HTTP adapter inputs and projections.
//!
//! The adapter decodes bounded transport values into the existing typed
//! `forge-control` requests. The worker owns the authoritative observation
//! timestamp after queue admission; the initial timestamp here only satisfies
//! the deterministic domain constructor.

use std::time::{SystemTime, UNIX_EPOCH};

use forge_control::{
    ForgeControlClient, ResolvedWorkspaceScope, WriterLeaseAcquireRequest, WriterLeaseGetRequest,
    WriterLeaseListRequest, WriterLeaseRecoveryReleaseRequest, WriterLeaseReleaseRequest,
    WriterLeaseRenewRequest,
};
use forge_domain::{
    AcquireWriterLease, AgentInstanceId, AgentSessionId, AuthenticatedPrincipal,
    ReleaseWriterLease, RenewWriterLease, TimestampMillis, WriterLease, WriterLeaseDurationMillis,
    WriterLeaseId, WriterLeaseRevision, WriterLeaseScope, WriterLeaseScopeEntry,
    WriterLeaseScopeKind, WriterLeaseState, WriterLeaseStatus,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{PrincipalDto, ScopeDto, decode_principal, decode_scope, decode_timestamp};
use crate::error::ForgeError;

const MAX_SCOPE_OFFSET: usize = forge_domain::MAX_WRITER_LEASE_SCOPE_ENTRIES;
const MAX_SCOPE_PAGE: usize = 4;
const DEFAULT_LIST_LIMIT: usize = 4;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseActorDto {
    session_id: Uuid,
    principal: PrincipalDto,
    agent_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum LeaseScopeKindDto {
    ExactPath,
    DirectorySubtree,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseScopeEntryDto {
    kind: LeaseScopeKindDto,
    path_base64: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseAcquireDto {
    scope: ScopeDto,
    activity_id: Uuid,
    actor: LeaseActorDto,
    writer_lease_id: Uuid,
    duration_ms: i64,
    scopes: Vec<LeaseScopeEntryDto>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseRenewDto {
    scope: ScopeDto,
    activity_id: Uuid,
    actor: LeaseActorDto,
    writer_lease_id: Uuid,
    expected_revision: i64,
    duration_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseReleaseDto {
    scope: ScopeDto,
    activity_id: Uuid,
    actor: LeaseActorDto,
    writer_lease_id: Uuid,
    expected_revision: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseGetDto {
    scope: ScopeDto,
    writer_lease_id: Uuid,
    expected_revision: Option<i64>,
    scope_offset: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseListDto {
    scope: ScopeDto,
    cursor: Option<Uuid>,
    limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGetCommand {
    pub(super) request: WriterLeaseGetRequest,
    pub(super) scope_offset: usize,
}

pub(super) fn parse_acquire(value: &Value) -> Result<WriterLeaseAcquireRequest, ForgeError> {
    let body: LeaseAcquireDto =
        super::parse_body(value, "writer_lease.acquire payload is invalid")?;
    let scope = decode_lease_scope(&body.scope)?;
    let activity_id = forge_domain::ActivityId::from_uuid(require_id(
        body.activity_id,
        "writer lease activity id",
    )?);
    let actor = decode_actor(&body.actor)?;
    let lease_id = WriterLeaseId::from_uuid(require_id(body.writer_lease_id, "writer lease id")?);
    let lease_scope = decode_lease_entries(body.scopes)?;
    let duration = WriterLeaseDurationMillis::new(body.duration_ms)
        .map_err(|_| ForgeError::invalid_input("writer lease duration is invalid"))?;
    let command = AcquireWriterLease::new(
        lease_id,
        scope.workspace_id(),
        activity_id,
        actor.agent_id,
        lease_scope,
        duration,
        current_timestamp_millis()?,
        actor.session_id,
        actor.principal,
    )
    .map_err(|_| ForgeError::invalid_input("writer lease acquire command is invalid"))?;
    Ok(WriterLeaseAcquireRequest {
        scope,
        activity_id,
        agent_id: actor.agent_id,
        principal: actor.principal,
        command,
    })
}

pub(super) fn parse_renew(value: &Value) -> Result<WriterLeaseRenewRequest, ForgeError> {
    let body: LeaseRenewDto = super::parse_body(value, "writer_lease.renew payload is invalid")?;
    let scope = decode_lease_scope(&body.scope)?;
    let activity_id = forge_domain::ActivityId::from_uuid(require_id(
        body.activity_id,
        "writer lease activity id",
    )?);
    let actor = decode_actor(&body.actor)?;
    let lease_id = WriterLeaseId::from_uuid(require_id(body.writer_lease_id, "writer lease id")?);
    let expected_revision = WriterLeaseRevision::new(body.expected_revision)
        .map_err(|_| ForgeError::invalid_input("writer lease revision is invalid"))?;
    let duration = WriterLeaseDurationMillis::new(body.duration_ms)
        .map_err(|_| ForgeError::invalid_input("writer lease duration is invalid"))?;
    let command = RenewWriterLease::new(
        lease_id,
        actor.agent_id,
        expected_revision,
        duration,
        current_timestamp_millis()?,
        actor.session_id,
        actor.principal,
    )
    .map_err(|_| ForgeError::invalid_input("writer lease renew command is invalid"))?;
    Ok(WriterLeaseRenewRequest {
        scope,
        activity_id,
        principal: actor.principal,
        command,
    })
}

pub(super) fn parse_release(value: &Value) -> Result<WriterLeaseReleaseRequest, ForgeError> {
    let body: LeaseReleaseDto =
        super::parse_body(value, "writer_lease.release payload is invalid")?;
    let scope = decode_lease_scope(&body.scope)?;
    let activity_id = forge_domain::ActivityId::from_uuid(require_id(
        body.activity_id,
        "writer lease activity id",
    )?);
    let actor = decode_actor(&body.actor)?;
    let lease_id = WriterLeaseId::from_uuid(require_id(body.writer_lease_id, "writer lease id")?);
    let expected_revision = WriterLeaseRevision::new(body.expected_revision)
        .map_err(|_| ForgeError::invalid_input("writer lease revision is invalid"))?;
    let command = ReleaseWriterLease::new(
        lease_id,
        actor.agent_id,
        expected_revision,
        current_timestamp_millis()?,
        actor.session_id,
        actor.principal,
    );
    Ok(WriterLeaseReleaseRequest {
        scope,
        activity_id,
        principal: actor.principal,
        command,
    })
}

pub(super) fn parse_get(value: &Value) -> Result<LeaseGetCommand, ForgeError> {
    let body: LeaseGetDto = super::parse_body(value, "writer_lease.get payload is invalid")?;
    let scope_offset = parse_scope_offset(body.scope_offset)?;
    let scope = decode_lease_scope(&body.scope)?;
    let lease_id = WriterLeaseId::from_uuid(require_id(body.writer_lease_id, "writer lease id")?);
    let expected_revision = body
        .expected_revision
        .map(WriterLeaseRevision::new)
        .transpose()
        .map_err(|_| ForgeError::invalid_input("writer lease revision is invalid"))?;
    Ok(LeaseGetCommand {
        request: WriterLeaseGetRequest {
            scope,
            lease_id,
            expected_revision,
        },
        scope_offset,
    })
}

pub(super) fn parse_list(value: &Value) -> Result<WriterLeaseListRequest, ForgeError> {
    let body: LeaseListDto = super::parse_body(value, "writer_lease.list payload is invalid")?;
    let scope = decode_lease_scope(&body.scope)?;
    let cursor = body
        .cursor
        .map(|cursor| require_id(cursor, "writer lease cursor"))
        .transpose()?
        .map(WriterLeaseId::from_uuid);
    let limit = body
        .limit
        .map(|limit| usize::try_from(limit).map_err(|_| ()))
        .transpose()
        .map_err(|()| ForgeError::invalid_input("writer lease list limit is invalid"))?
        .unwrap_or(DEFAULT_LIST_LIMIT);
    if !(1..=DEFAULT_LIST_LIMIT).contains(&limit) {
        return Err(ForgeError::invalid_input(
            "writer lease list limit is invalid",
        ));
    }
    Ok(WriterLeaseListRequest {
        scope,
        cursor,
        limit,
    })
}

pub(super) fn execute_acquire(
    client: &ForgeControlClient,
    request: &WriterLeaseAcquireRequest,
) -> Result<Value, ForgeError> {
    let scope = &request.scope;
    let session_id = request.command.session_id();
    let lease = client
        .writer_lease_acquire(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    lease_json(&lease, Some(session_id), scope, 0)
}

pub(super) fn execute_renew(
    client: &ForgeControlClient,
    request: &WriterLeaseRenewRequest,
) -> Result<Value, ForgeError> {
    let scope = &request.scope;
    let session_id = request.command.session_id();
    let lease = client
        .writer_lease_renew(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    lease_json(&lease, Some(session_id), scope, 0)
}

pub(super) fn execute_release(
    client: &ForgeControlClient,
    request: &WriterLeaseReleaseRequest,
) -> Result<Value, ForgeError> {
    let scope = &request.scope;
    let session_id = request.command.session_id();
    let lease = client
        .writer_lease_release(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    lease_json(&lease, Some(session_id), scope, 0)
}

pub(super) fn execute_get(
    client: &ForgeControlClient,
    command: &LeaseGetCommand,
) -> Result<Value, ForgeError> {
    let scope = &command.request.scope;
    let result = client
        .writer_lease_get(command.request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    let Some((lease, session_id)) = result else {
        return Ok(json!({ "found": false }));
    };
    let mut output = lease_json(&lease, session_id, scope, command.scope_offset)?;
    if let Value::Object(object) = &mut output {
        object.insert("found".to_owned(), Value::Bool(true));
    }
    Ok(output)
}

pub(super) fn execute_list(
    client: &ForgeControlClient,
    request: &WriterLeaseListRequest,
) -> Result<Value, ForgeError> {
    let scope = &request.scope;
    let (leases, next_cursor) = client
        .writer_lease_list(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    let leases = leases
        .iter()
        .map(|(lease, session_id)| lease_json(lease, *session_id, scope, 0))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "leases": leases,
        "next_cursor": next_cursor.map(|cursor| cursor.to_string()),
    }))
}

#[derive(Clone, Copy)]
struct LeaseActor {
    session_id: AgentSessionId,
    principal: AuthenticatedPrincipal,
    agent_id: AgentInstanceId,
}

fn decode_actor(actor: &LeaseActorDto) -> Result<LeaseActor, ForgeError> {
    Ok(LeaseActor {
        session_id: AgentSessionId::from_uuid(require_id(
            actor.session_id,
            "writer lease session id",
        )?),
        principal: decode_principal(&actor.principal)?,
        agent_id: AgentInstanceId::from_uuid(require_id(actor.agent_id, "writer lease agent id")?),
    })
}

fn decode_lease_scope(scope: &ScopeDto) -> Result<ResolvedWorkspaceScope, ForgeError> {
    require_id(scope.workspace_id, "writer lease workspace id")?;
    require_id(scope.locator.location_id, "writer lease location id")?;
    decode_scope(scope)
}

fn decode_lease_entries(entries: Vec<LeaseScopeEntryDto>) -> Result<WriterLeaseScope, ForgeError> {
    let entries = entries
        .into_iter()
        .map(|entry| {
            let kind = match entry.kind {
                LeaseScopeKindDto::ExactPath => WriterLeaseScopeKind::ExactPath,
                LeaseScopeKindDto::DirectorySubtree => WriterLeaseScopeKind::DirectorySubtree,
            };
            Ok(WriterLeaseScopeEntry::new(
                kind,
                super::source::decode_relative_path(&entry.path_base64)?,
            ))
        })
        .collect::<Result<Vec<_>, ForgeError>>()?;
    WriterLeaseScope::new(entries)
        .map_err(|_| ForgeError::invalid_input("writer lease scopes are invalid"))
}

fn parse_scope_offset(value: Option<u64>) -> Result<usize, ForgeError> {
    let offset = value.unwrap_or(0);
    let offset = usize::try_from(offset)
        .map_err(|_| ForgeError::invalid_input("writer lease scope offset is invalid"))?;
    if offset > MAX_SCOPE_OFFSET {
        return Err(ForgeError::invalid_input(
            "writer lease scope offset is invalid",
        ));
    }
    Ok(offset)
}

fn require_id(value: Uuid, label: &str) -> Result<Uuid, ForgeError> {
    if value.is_nil() {
        return Err(ForgeError::invalid_input(format!(
            "{label} must be non-nil"
        )));
    }
    Ok(value)
}

fn current_timestamp_millis() -> Result<TimestampMillis, ForgeError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ForgeError::internal())?;
    let millis = i64::try_from(duration.as_millis()).map_err(|_| ForgeError::internal())?;
    TimestampMillis::new(millis).map_err(|_| ForgeError::internal())
}

fn lease_json(
    lease: &WriterLease,
    session_id: Option<AgentSessionId>,
    scope: &ResolvedWorkspaceScope,
    scope_offset: usize,
) -> Result<Value, ForgeError> {
    // The worker-side observation clock for the derived status projection.
    // It stays an explicit effect at this transport boundary, matching the
    // native handlers that derive the same status from their own clock.
    let observed_at = current_timestamp_millis()?;
    let status = lease.status(observed_at);
    let entries = lease.scope().entries();
    let total_scope_count = entries.len();
    let scope_offset = scope_offset.min(total_scope_count);
    let scopes = entries
        .iter()
        .skip(scope_offset)
        .take(MAX_SCOPE_PAGE)
        .map(|entry| {
            json!({
                "kind": match entry.kind() {
                    WriterLeaseScopeKind::ExactPath => "exact_path",
                    WriterLeaseScopeKind::DirectorySubtree => "directory_subtree",
                },
                "path_base64": super::source::encode_relative_path(entry.path()),
            })
        })
        .collect::<Vec<_>>();
    let next_scope_offset =
        (scope_offset + scopes.len() < total_scope_count).then_some(scope_offset + scopes.len());
    let mut object = Map::new();
    object.insert("scope".to_owned(), super::source::scope_json(scope)?);
    object.insert("writer_lease_id".to_owned(), json!(lease.id().to_string()));
    object.insert(
        "workspace_id".to_owned(),
        json!(lease.workspace_id().into_uuid()),
    );
    object.insert(
        "activity_id".to_owned(),
        json!(lease.activity_id().into_uuid()),
    );
    object.insert(
        "owner_activity_id".to_owned(),
        json!(lease.activity_id().into_uuid()),
    );
    object.insert("agent_id".to_owned(), json!(lease.agent_id().into_uuid()));
    object.insert(
        "session_id".to_owned(),
        session_id.map_or(Value::Null, |id| json!(id.into_uuid())),
    );
    object.insert(
        "owner_session_id".to_owned(),
        session_id.map_or(Value::Null, |id| json!(id.into_uuid())),
    );
    object.insert("revision".to_owned(), json!(lease.revision().get()));
    object.insert(
        "state".to_owned(),
        json!(match lease.state() {
            WriterLeaseState::Active => "active",
            WriterLeaseState::Released => "released",
        }),
    );
    object.insert("observed_at_ms".to_owned(), json!(observed_at.get()));
    object.insert("status".to_owned(), json!(writer_lease_status_json(status)));
    object.insert(
        "blocking_reason".to_owned(),
        json!(match status {
            WriterLeaseStatus::ExpiredRecoveryRequired => Some("expired_writer_lease"),
            WriterLeaseStatus::Active | WriterLeaseStatus::Released => None,
        }),
    );
    object.insert(
        "recovery_action".to_owned(),
        json!(match status {
            WriterLeaseStatus::ExpiredRecoveryRequired => "writer_lease_recovery_release",
            WriterLeaseStatus::Active | WriterLeaseStatus::Released => "none",
        }),
    );
    object.insert(
        "acquired_at_ms".to_owned(),
        json!(lease.acquired_at().get()),
    );
    object.insert("updated_at_ms".to_owned(), json!(lease.updated_at().get()));
    object.insert(
        "lease_until_ms".to_owned(),
        json!(lease.lease_until().get()),
    );
    object.insert("scopes".to_owned(), Value::Array(scopes));
    object.insert("total_scope_count".to_owned(), json!(total_scope_count));
    object.insert("scope_offset".to_owned(), json!(scope_offset));
    object.insert("next_scope_offset".to_owned(), json!(next_scope_offset));
    object.insert("scope_page_limit".to_owned(), json!(MAX_SCOPE_PAGE));
    Ok(Value::Object(object))
}

/// Canonical derived-status vocabulary shared with the native Writer Lease
/// projection: an active lease past its expiry is an explicit recovery case,
/// never a silent release.
const fn writer_lease_status_json(value: WriterLeaseStatus) -> &'static str {
    match value {
        WriterLeaseStatus::Active => "active",
        WriterLeaseStatus::ExpiredRecoveryRequired => "expired_recovery_required",
        WriterLeaseStatus::Released => "released",
    }
}

/// Expired-or-orphaned recovery release. Unlike the ordinary release, the
/// caller does not hold the lease: forge-control enforces the
/// recovery-required state and the optimistic revision CAS, and the lease
/// owner identity is deliberately absent.
pub(super) fn parse_recovery_release(
    payload: &Value,
) -> Result<WriterLeaseRecoveryReleaseRequest, ForgeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        scope: ScopeDto,
        writer_lease_id: Uuid,
        expected_revision: i64,
        observed_at_ms: i64,
    }
    let body: Body =
        super::parse_body(payload, "writer_lease.recovery_release payload is invalid")?;
    let scope = decode_scope(&body.scope)?;
    let lease_id = WriterLeaseId::from_uuid(require_id(body.writer_lease_id, "writer lease id")?);
    let expected_revision = WriterLeaseRevision::new(body.expected_revision)
        .map_err(|_| ForgeError::invalid_input("writer lease revision is invalid"))?;
    Ok(WriterLeaseRecoveryReleaseRequest {
        scope,
        lease_id,
        expected_revision,
        observed_at: decode_timestamp(body.observed_at_ms)?,
    })
}

pub(super) fn execute_recovery_release(
    client: &ForgeControlClient,
    request: &WriterLeaseRecoveryReleaseRequest,
) -> Result<Value, ForgeError> {
    let lease = client
        .writer_lease_release_for_recovery(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    lease_json(&lease, None, &request.scope, 0)
}
