//! Exact, verifiable Agent provenance for one Approval row.
//!
//! The payload is a private canonical encoding of every field in
//! `ExecutionAgentProvenance` except execution/workspace/activity identity,
//! which is read from and checked against the parent Approval row. Historical
//! digest-only Approvals intentionally remain without a companion row.

use forge_domain::{
    AgentInstanceId, AgentInstanceRevision, AgentSessionId, ApprovalAgentBindingDigest,
    AuthenticatedPrincipal, DagNodeId, DagNodeRevision, DagRevisionNumber, DirectTokenId,
    ExecutionAgentProvenance, ExecutionCommandId, ExecutionId, FileContentHash, GoalId,
    GoalNodeAttribution, GoalRevision, OAuthGrantId, ProjectCommandCatalogFingerprint,
    ProjectCommandClass, ProjectCommandEvidence, RegisteredApprovalRequest,
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::ApprovalStoreError;

pub(crate) mod schema;

const PAYLOAD_MAGIC: &[u8; 4] = b"FAPV";
const PAYLOAD_VERSION: u8 = 1;
const CHECKSUM_BYTES: usize = 32;
const COMMAND_ID_MAX_BYTES: usize = 128;
type ProvenanceRow = (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);
type ApprovalParentRow = (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);

/// Store the checked preimage for a freshly inserted parent Approval row.
///
/// Callers must invoke this in the same owner transaction and only after that
/// transaction inserted the parent row. Exact replays are handled by the
/// owning Approval insertion helper and never attach metadata to old rows.
pub(crate) fn record_in_transaction(
    connection: &Connection,
    approval: &RegisteredApprovalRequest,
    provenance: Option<&ExecutionAgentProvenance>,
) -> Result<(), ApprovalStoreError> {
    let Some(provenance) = provenance else {
        return Ok(());
    };
    validate_provenance_for_approval(approval, provenance)?;
    validate_parent(connection, approval)?;
    if let Some(existing) = get_in_transaction(connection, approval)? {
        return if existing == *provenance {
            Ok(())
        } else {
            Err(ApprovalStoreError::IdentityConflict)
        };
    }

    let payload = encode_payload(provenance)?;
    let checksum = payload_checksum(&payload);
    connection.execute(
        "INSERT INTO approval_agent_provenance (
            approval_id, agent_id, session_id, payload, payload_checksum
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            approval.id().into_uuid().as_bytes(),
            provenance.agent_id().into_uuid().as_bytes(),
            provenance
                .session_id()
                .map(|session_id| session_id.into_uuid().as_bytes().to_vec()),
            payload,
            checksum.as_slice(),
        ],
    )?;
    Ok(())
}

/// Load exact provenance, preserving `None` for a historical digest-only row.
/// Every returned value has a valid checksum and reproduces the parent digest.
pub(crate) fn get_in_transaction(
    connection: &Connection,
    approval: &RegisteredApprovalRequest,
) -> Result<Option<ExecutionAgentProvenance>, ApprovalStoreError> {
    validate_parent(connection, approval)?;
    let stored: Option<ProvenanceRow> = connection
        .query_row(
            "SELECT substr(payload,1,301), substr(payload_checksum,1,33), substr(agent_id,1,17), substr(session_id,1,17)
             FROM approval_agent_provenance WHERE approval_id = ?1",
            params![approval.id().into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((payload, checksum, indexed_agent_id, indexed_session_id)) = stored else {
        return Ok(None);
    };

    if payload.is_empty()
        || payload.len() > schema::MAX_PAYLOAD_BYTES
        || checksum.len() != CHECKSUM_BYTES
        || indexed_agent_id.len() != 16
        || indexed_session_id
            .as_ref()
            .is_some_and(|session_id| session_id.len() != 16)
    {
        return Err(ApprovalStoreError::CorruptRecord(
            "approval agent provenance shape",
        ));
    }
    let actual_checksum = payload_checksum(&payload);
    if checksum.as_slice() != actual_checksum.as_slice() {
        return Err(ApprovalStoreError::CorruptRecord(
            "approval agent provenance checksum",
        ));
    }
    let provenance = decode_payload(approval.request().execution_id(), &payload)?;
    let expected_session_id = provenance
        .session_id()
        .map(|session_id| session_id.into_uuid().as_bytes().to_vec());
    if encode_payload(&provenance)?.as_slice() != payload.as_slice()
        || indexed_agent_id.as_slice() != &provenance.agent_id().into_uuid().as_bytes()[..]
        || indexed_session_id != expected_session_id
    {
        return Err(ApprovalStoreError::CorruptRecord(
            "approval agent provenance canonical payload",
        ));
    }
    validate_provenance_for_approval(approval, &provenance)
        .map_err(|_| ApprovalStoreError::CorruptRecord("approval agent provenance binding"))?;
    Ok(Some(provenance))
}

pub(crate) fn validate_provenance_for_approval(
    approval: &RegisteredApprovalRequest,
    provenance: &ExecutionAgentProvenance,
) -> Result<(), ApprovalStoreError> {
    let expected_binding = approval
        .agent_binding()
        .ok_or(ApprovalStoreError::IdentityConflict)?;
    if provenance.execution_id() != approval.request().execution_id()
        || ApprovalAgentBindingDigest::from_provenance(provenance) != expected_binding
    {
        return Err(ApprovalStoreError::IdentityConflict);
    }
    Ok(())
}

fn validate_parent(
    connection: &Connection,
    approval: &RegisteredApprovalRequest,
) -> Result<(), ApprovalStoreError> {
    let parent: Option<ApprovalParentRow> = connection
        .query_row(
            "SELECT substr(workspace_id,1,17), substr(activity_id,1,17), substr(execution_id,1,17), substr(agent_binding_digest,1,33)
             FROM approval_requests WHERE approval_id = ?1",
            params![approval.id().into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((workspace_id, activity_id, execution_id, binding_digest)) = parent else {
        return Err(ApprovalStoreError::ApprovalMissing);
    };
    let request = approval.request();
    let expected_binding_digest = approval
        .agent_binding()
        .map(|binding| binding.as_bytes().to_vec());
    if workspace_id.as_slice() != request.workspace_id().into_uuid().as_bytes()
        || activity_id.as_slice() != request.activity_id().into_uuid().as_bytes()
        || execution_id.as_slice() != request.execution_id().into_uuid().as_bytes()
        || binding_digest != expected_binding_digest
    {
        return Err(ApprovalStoreError::CorruptRecord(
            "approval agent provenance parent identity",
        ));
    }
    Ok(())
}

fn payload_checksum(payload: &[u8]) -> [u8; 32] {
    let mut checksum = Sha256::new();
    checksum.update(b"heterarchy.forge.approval-agent-provenance.v1\0");
    checksum.update(payload);
    checksum.finalize().into()
}

fn encode_payload(provenance: &ExecutionAgentProvenance) -> Result<Vec<u8>, ApprovalStoreError> {
    let command = provenance.command_id().as_str().as_bytes();
    if command.is_empty() || command.len() > COMMAND_ID_MAX_BYTES {
        return Err(ApprovalStoreError::IdentityConflict);
    }
    let mut payload = Vec::with_capacity(schema::MAX_PAYLOAD_BYTES);
    payload.extend_from_slice(PAYLOAD_MAGIC);
    payload.push(PAYLOAD_VERSION);
    payload.extend_from_slice(provenance.agent_id().into_uuid().as_bytes());
    payload.extend_from_slice(&provenance.agent_revision().get().to_le_bytes());
    match provenance.principal() {
        AuthenticatedPrincipal::TrustedStdio => payload.push(0),
        AuthenticatedPrincipal::DirectToken(id) => {
            payload.push(1);
            payload.extend_from_slice(id.into_uuid().as_bytes());
        }
        AuthenticatedPrincipal::OAuthGrant(id) => {
            payload.push(2);
            payload.extend_from_slice(id.into_uuid().as_bytes());
        }
    }
    let attribution = provenance.attribution();
    payload.extend_from_slice(attribution.goal_id().into_uuid().as_bytes());
    payload.extend_from_slice(&attribution.expected_goal_revision().get().to_le_bytes());
    payload.extend_from_slice(&attribution.dag_revision().get().to_le_bytes());
    payload.extend_from_slice(attribution.node_id().into_uuid().as_bytes());
    payload.extend_from_slice(&attribution.expected_node_revision().get().to_le_bytes());
    let command_length =
        u16::try_from(command.len()).map_err(|_| ApprovalStoreError::IdentityConflict)?;
    payload.extend_from_slice(&command_length.to_le_bytes());
    payload.extend_from_slice(command);
    match provenance.session_id() {
        Some(session_id) => {
            payload.push(1);
            payload.extend_from_slice(session_id.into_uuid().as_bytes());
        }
        None => payload.push(0),
    }
    match provenance.project_command() {
        Some(evidence) => {
            payload.push(1);
            payload.push(encode_project_command_class(evidence.class()));
            payload.extend_from_slice(evidence.catalog_fingerprint().hash().as_bytes());
        }
        None => payload.push(0),
    }
    if payload.len() > schema::MAX_PAYLOAD_BYTES {
        return Err(ApprovalStoreError::IdentityConflict);
    }
    Ok(payload)
}

fn decode_payload(
    execution_id: ExecutionId,
    bytes: &[u8],
) -> Result<ExecutionAgentProvenance, ApprovalStoreError> {
    if bytes.len() > schema::MAX_PAYLOAD_BYTES {
        return Err(payload_corrupt());
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.take(PAYLOAD_MAGIC.len())? != PAYLOAD_MAGIC || decoder.u8()? != PAYLOAD_VERSION {
        return Err(payload_corrupt());
    }
    let agent_id = AgentInstanceId::from_uuid(decoder.uuid()?);
    let agent_revision =
        AgentInstanceRevision::new(decoder.i64()?).map_err(|_| payload_corrupt())?;
    let principal = match decoder.u8()? {
        0 => AuthenticatedPrincipal::TrustedStdio,
        1 => AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(decoder.uuid()?)),
        2 => AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(decoder.uuid()?)),
        _ => return Err(payload_corrupt()),
    };
    let goal_id = GoalId::from_uuid(decoder.uuid()?);
    let goal_revision = GoalRevision::new(decoder.i64()?).map_err(|_| payload_corrupt())?;
    let dag_revision = DagRevisionNumber::new(decoder.i64()?).map_err(|_| payload_corrupt())?;
    let node_id = DagNodeId::from_uuid(decoder.uuid()?);
    let node_revision = DagNodeRevision::new(decoder.i64()?).map_err(|_| payload_corrupt())?;
    let command_length = usize::from(decoder.u16()?);
    if command_length == 0 || command_length > COMMAND_ID_MAX_BYTES {
        return Err(payload_corrupt());
    }
    let command = std::str::from_utf8(decoder.take(command_length)?)
        .map_err(|_| payload_corrupt())?
        .to_owned();
    let command_id = ExecutionCommandId::new(command).map_err(|_| payload_corrupt())?;
    let session_id = match decoder.u8()? {
        0 => None,
        1 => Some(AgentSessionId::from_uuid(decoder.uuid()?)),
        _ => return Err(payload_corrupt()),
    };
    let project_command = match decoder.u8()? {
        0 => None,
        1 => {
            let class = decode_project_command_class(decoder.u8()?)?;
            let fingerprint = FileContentHash::from_bytes(decoder.array32()?);
            Some(ProjectCommandEvidence::new(
                class,
                ProjectCommandCatalogFingerprint::from_hash(fingerprint),
            ))
        }
        _ => return Err(payload_corrupt()),
    };
    if !decoder.is_finished() {
        return Err(payload_corrupt());
    }
    let attribution =
        GoalNodeAttribution::new(goal_id, goal_revision, dag_revision, node_id, node_revision);
    let provenance = ExecutionAgentProvenance::from_parts(
        execution_id,
        agent_id,
        agent_revision,
        principal,
        attribution,
        command_id,
        session_id,
    );
    Ok(match project_command {
        Some(evidence) => provenance.with_project_command(evidence),
        None => provenance,
    })
}

fn encode_project_command_class(class: ProjectCommandClass) -> u8 {
    match class {
        ProjectCommandClass::Verify => 0,
        ProjectCommandClass::GeneratedPackage => 1,
    }
}

fn decode_project_command_class(value: u8) -> Result<ProjectCommandClass, ApprovalStoreError> {
    match value {
        0 => Ok(ProjectCommandClass::Verify),
        1 => Ok(ProjectCommandClass::GeneratedPackage),
        _ => Err(payload_corrupt()),
    }
}

fn payload_corrupt() -> ApprovalStoreError {
    ApprovalStoreError::CorruptRecord("approval agent provenance payload")
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ApprovalStoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(payload_corrupt)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(payload_corrupt)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ApprovalStoreError> {
        self.take(1)?.first().copied().ok_or_else(payload_corrupt)
    }

    fn u16(&mut self) -> Result<u16, ApprovalStoreError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| payload_corrupt())?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn i64(&mut self) -> Result<i64, ApprovalStoreError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| payload_corrupt())?;
        Ok(i64::from_le_bytes(bytes))
    }

    fn uuid(&mut self) -> Result<Uuid, ApprovalStoreError> {
        Uuid::from_slice(self.take(16)?).map_err(|_| payload_corrupt())
    }

    fn array32(&mut self) -> Result<[u8; 32], ApprovalStoreError> {
        self.take(32)?.try_into().map_err(|_| payload_corrupt())
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        ActivityId, ApprovalRequestId, ApprovalRequestState, ApprovalRevision,
        ExecutionActionClass, ExecutionAuthorizationRequest, ExecutionPermissions,
        ExecutionRequestDigest, PolicyRevision, RequestedExecutionPermissions, TimestampMillis,
        WorkspaceId,
    };
    use rusqlite::{Connection, TransactionBehavior, params};

    use super::*;

    struct Fixture {
        connection: Connection,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
        approval: RegisteredApprovalRequest,
        provenance: ExecutionAgentProvenance,
    }

    impl Fixture {
        fn in_memory() -> Result<Self, Box<dyn std::error::Error>> {
            let connection = Connection::open_in_memory()?;
            connection.execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
                 CREATE TABLE activities(
                    activity_id BLOB PRIMARY KEY,
                    workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id)
                 );",
            )?;
            crate::workspace_approvals::create_schema(&connection)?;
            schema::create_schema(&connection)?;
            let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(1));
            let activity_id = ActivityId::from_uuid(Uuid::from_u128(2));
            connection.execute(
                "INSERT INTO workspace(workspace_id) VALUES (?1)",
                params![workspace_id.into_uuid().as_bytes()],
            )?;
            connection.execute(
                "INSERT INTO activities(activity_id, workspace_id) VALUES (?1, ?2)",
                params![
                    activity_id.into_uuid().as_bytes(),
                    workspace_id.into_uuid().as_bytes()
                ],
            )?;
            let execution_id = ExecutionId::from_uuid(Uuid::from_u128(3));
            let attribution = GoalNodeAttribution::new(
                GoalId::from_uuid(Uuid::from_u128(4)),
                GoalRevision::new(5)?,
                DagRevisionNumber::new(6)?,
                DagNodeId::from_uuid(Uuid::from_u128(7)),
                DagNodeRevision::new(8)?,
            );
            let provenance = ExecutionAgentProvenance::new(
                execution_id,
                AgentInstanceId::from_uuid(Uuid::from_u128(9)),
                AgentInstanceRevision::new(10)?,
                AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_u128(11))),
                attribution,
                ExecutionCommandId::new("make:ci".to_owned())?,
                AgentSessionId::from_uuid(Uuid::from_u128(12)),
            )
            .with_project_command(ProjectCommandEvidence::new(
                ProjectCommandClass::Verify,
                ProjectCommandCatalogFingerprint::from_hash(FileContentHash::from_bytes([13; 32])),
            ));
            let request = ExecutionAuthorizationRequest::new(
                execution_id,
                workspace_id,
                activity_id,
                ExecutionRequestDigest::from_bytes([14; 32]),
                ExecutionActionClass::AnalyzedShell,
                RequestedExecutionPermissions::new(ExecutionPermissions::new(true, false, false)),
            );
            let approval = RegisteredApprovalRequest::from_parts(
                ApprovalRequestId::from_uuid(Uuid::from_u128(15)),
                request,
                PolicyRevision::new(1)?,
                ApprovalRequestState::AutoApproved,
                TimestampMillis::new(20)?,
                TimestampMillis::new(30)?,
                Some(TimestampMillis::new(21)?),
                ApprovalRevision::INITIAL,
            )?
            .with_agent_binding(ApprovalAgentBindingDigest::from_provenance(&provenance));
            Ok(Self {
                connection,
                workspace_id,
                activity_id,
                approval,
                provenance,
            })
        }
    }

    struct TempDb(PathBuf);

    impl TempDb {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!(
                "forge-approval-agent-provenance-{}-{nonce}.sqlite3",
                std::process::id(),
            ));
            Ok(Self(path))
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_file(self.0.with_extension("sqlite3-shm"));
            let _ = std::fs::remove_file(self.0.with_extension("sqlite3-wal"));
        }
    }

    #[test]
    fn canonical_payload_round_trips_after_reopen() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::in_memory()?;
        let database = TempDb::new()?;
        let mut connection = Connection::open(&database.0)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(workspace_id BLOB PRIMARY KEY);
             CREATE TABLE activities(activity_id BLOB PRIMARY KEY, workspace_id BLOB NOT NULL);
             CREATE TABLE approval_requests(
                approval_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL,
                activity_id BLOB NOT NULL,
                execution_id BLOB NOT NULL,
                agent_binding_digest BLOB
             );",
        )?;
        schema::create_schema(&connection)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO approval_requests(approval_id, workspace_id, activity_id, execution_id, agent_binding_digest)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                fixture.approval.id().into_uuid().as_bytes(),
                fixture.workspace_id.into_uuid().as_bytes(),
                fixture.activity_id.into_uuid().as_bytes(),
                fixture.approval.request().execution_id().into_uuid().as_bytes(),
                fixture.approval.agent_binding().map(|binding| binding.as_bytes().to_vec()),
            ],
        )?;
        record_in_transaction(&transaction, &fixture.approval, Some(&fixture.provenance))?;
        transaction.commit()?;
        drop(connection);

        let reopened = Connection::open(&database.0)?;
        let observed = get_in_transaction(&reopened, &fixture.approval)?;
        assert_eq!(observed, Some(fixture.provenance));
        Ok(())
    }

    #[test]
    fn changed_binding_fields_do_not_match_the_parent_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::in_memory()?;
        let wrong_session = ExecutionAgentProvenance::from_parts(
            fixture.provenance.execution_id(),
            fixture.provenance.agent_id(),
            fixture.provenance.agent_revision(),
            fixture.provenance.principal(),
            fixture.provenance.attribution(),
            fixture.provenance.command_id().clone(),
            Some(AgentSessionId::from_uuid(Uuid::from_u128(16))),
        )
        .with_project_command(
            fixture
                .provenance
                .project_command()
                .ok_or("project evidence missing")?,
        );
        let wrong_principal = ExecutionAgentProvenance::from_parts(
            fixture.provenance.execution_id(),
            fixture.provenance.agent_id(),
            fixture.provenance.agent_revision(),
            AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(Uuid::from_u128(17))),
            fixture.provenance.attribution(),
            fixture.provenance.command_id().clone(),
            fixture.provenance.session_id(),
        )
        .with_project_command(
            fixture
                .provenance
                .project_command()
                .ok_or("project evidence missing")?,
        );
        let old_attribution = fixture.provenance.attribution();
        let wrong_node = ExecutionAgentProvenance::from_parts(
            fixture.provenance.execution_id(),
            fixture.provenance.agent_id(),
            fixture.provenance.agent_revision(),
            fixture.provenance.principal(),
            GoalNodeAttribution::new(
                old_attribution.goal_id(),
                old_attribution.expected_goal_revision(),
                old_attribution.dag_revision(),
                DagNodeId::from_uuid(Uuid::from_u128(18)),
                old_attribution.expected_node_revision(),
            ),
            fixture.provenance.command_id().clone(),
            fixture.provenance.session_id(),
        )
        .with_project_command(
            fixture
                .provenance
                .project_command()
                .ok_or("project evidence missing")?,
        );
        for changed in [wrong_session, wrong_principal, wrong_node] {
            assert!(matches!(
                validate_provenance_for_approval(&fixture.approval, &changed),
                Err(ApprovalStoreError::IdentityConflict)
            ));
        }
        Ok(())
    }

    #[test]
    fn unresolved_legacy_session_round_trips_as_explicit_none()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::in_memory()?;
        let provenance = ExecutionAgentProvenance::from_parts(
            fixture.provenance.execution_id(),
            fixture.provenance.agent_id(),
            fixture.provenance.agent_revision(),
            fixture.provenance.principal(),
            fixture.provenance.attribution(),
            fixture.provenance.command_id().clone(),
            None,
        )
        .with_project_command(
            fixture
                .provenance
                .project_command()
                .ok_or("project evidence missing")?,
        );
        let payload = encode_payload(&provenance)?;
        assert_eq!(
            decode_payload(provenance.execution_id(), &payload)?,
            provenance
        );
        Ok(())
    }

    #[test]
    fn missing_legacy_payload_stays_unknown_and_exact_replay_does_not_attach_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = Fixture::in_memory()?;
        let transaction = fixture
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::workspace_approvals::insert_approval_tx(&transaction, &fixture.approval)?;
        transaction.commit()?;
        assert_eq!(
            get_in_transaction(&fixture.connection, &fixture.approval)?,
            None
        );
        // record_in_transaction is reserved for known-fresh rows; the audit
        // insertion helper owns replay detection and must not call it here.
        let replay = fixture
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let observed =
            crate::workspace_approvals::insert_approval_audit_with_provenance_in_transaction(
                &replay,
                &fixture.approval,
                Some(&fixture.provenance),
            )?;
        assert_eq!(observed, fixture.approval);
        assert_eq!(get_in_transaction(&replay, &observed)?, None);
        replay.commit()?;
        Ok(())
    }

    #[test]
    fn corrupt_checksum_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = Fixture::in_memory()?;
        let transaction = fixture
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::workspace_approvals::insert_approval_tx(&transaction, &fixture.approval)?;
        record_in_transaction(&transaction, &fixture.approval, Some(&fixture.provenance))?;
        transaction.commit()?;
        fixture
            .connection
            .execute_batch("DROP TRIGGER approval_agent_provenance_no_update;")?;
        fixture.connection.execute(
            "UPDATE approval_agent_provenance SET payload_checksum = zeroblob(32)",
            [],
        )?;
        assert!(matches!(
            get_in_transaction(&fixture.connection, &fixture.approval),
            Err(ApprovalStoreError::CorruptRecord(
                "approval agent provenance checksum"
            ))
        ));
        Ok(())
    }

    #[test]
    fn provenance_is_immutable_but_follows_parent_cleanup() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut fixture = Fixture::in_memory()?;
        let transaction = fixture
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::workspace_approvals::insert_approval_tx(&transaction, &fixture.approval)?;
        record_in_transaction(&transaction, &fixture.approval, Some(&fixture.provenance))?;
        transaction.commit()?;

        assert!(
            fixture
                .connection
                .execute(
                    "DELETE FROM approval_agent_provenance WHERE approval_id = ?1",
                    params![fixture.approval.id().into_uuid().as_bytes()],
                )
                .is_err()
        );
        fixture.connection.execute(
            "DELETE FROM approval_requests WHERE approval_id = ?1",
            params![fixture.approval.id().into_uuid().as_bytes()],
        )?;
        let provenance_count: i64 = fixture.connection.query_row(
            "SELECT count(*) FROM approval_agent_provenance WHERE approval_id = ?1",
            params![fixture.approval.id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!(provenance_count, 0);
        Ok(())
    }

    #[test]
    fn parent_and_provenance_roll_back_together() -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = Fixture::in_memory()?;
        let transaction = fixture
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::workspace_approvals::insert_approval_tx(&transaction, &fixture.approval)?;
        record_in_transaction(&transaction, &fixture.approval, Some(&fixture.provenance))?;
        transaction.rollback()?;
        let parent_count: i64 = fixture.connection.query_row(
            "SELECT count(*) FROM approval_requests WHERE approval_id = ?1",
            params![fixture.approval.id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        let provenance_count: i64 = fixture.connection.query_row(
            "SELECT count(*) FROM approval_agent_provenance WHERE approval_id = ?1",
            params![fixture.approval.id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        assert_eq!((parent_count, provenance_count), (0, 0));
        Ok(())
    }
}
