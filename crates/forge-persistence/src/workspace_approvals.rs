use forge_domain::{
    ActivityId, ApprovalDecision, ApprovalRequestId, ApprovalRequestState, ApprovalRevision,
    AuthorizationSource, AutoApprovalScope, AutoApprovalScopeId, AutoApprovalScopeRevision,
    AutoApprovalScopeState, AutoApprovalUseLimit, BeginExecution, EffectiveExecutionPermissions,
    ExecutionActionClass, ExecutionAuthorizationDecision, ExecutionAuthorizationRequest,
    ExecutionGrant, ExecutionGrantId, ExecutionGrantRevision, ExecutionGrantState,
    ExecutionListLimit, ExecutionPermissions, ExecutionPolicyRule, ExecutionRequestDigest,
    GoalEvidenceRef, GoalWorkAttribution, PolicyRevision, RegisteredApprovalRequest,
    RequestedExecutionPermissions, TimestampMillis, WorkspaceId, WorkspacePolicy,
    evaluate_execution_authorization,
};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace_dags::{self, DagStoreError};
use crate::workspace_executions::{
    self, BeginExecutionRecord, BeginExecutionStatus, ExecutionStoreError,
};
use crate::workspace_goals::{self, GoalStoreError};

pub(crate) const EXPECTED_WORKSPACE_POLICY_TABLE_SQL: &str = "CREATE TABLE workspace_policy (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), workspace_id BLOB NOT NULL UNIQUE REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), direct_structured_rule INTEGER NOT NULL CHECK(direct_structured_rule IN (0, 1, 2)), discovered_command_rule INTEGER NOT NULL CHECK(discovered_command_rule IN (0, 1, 2)), shell_escape_rule INTEGER NOT NULL CHECK(shell_escape_rule IN (0, 1, 2)), workspace_read_rule INTEGER NOT NULL CHECK(workspace_read_rule IN (0, 1, 2)), workspace_write_rule INTEGER NOT NULL CHECK(workspace_write_rule IN (0, 1, 2)), network_rule INTEGER NOT NULL CHECK(network_rule IN (0, 1, 2)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1))";
pub(crate) const EXPECTED_APPROVAL_REQUESTS_TABLE_SQL: &str = "CREATE TABLE approval_requests (approval_id BLOB PRIMARY KEY NOT NULL CHECK(length(approval_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), execution_id BLOB NOT NULL CHECK(length(execution_id) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), action_class INTEGER NOT NULL CHECK(action_class IN (0, 1, 2)), workspace_read INTEGER NOT NULL CHECK(workspace_read IN (0, 1)), workspace_write INTEGER NOT NULL CHECK(workspace_write IN (0, 1)), network INTEGER NOT NULL CHECK(network IN (0, 1)), policy_revision INTEGER NOT NULL CHECK(policy_revision >= 1), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5, 6, 7)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > created_at_ms), decided_at_ms INTEGER CHECK(decided_at_ms IS NULL OR decided_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((state = 0 AND decided_at_ms IS NULL) OR (state IN (1, 2, 3, 4, 5, 6, 7) AND decided_at_ms IS NOT NULL)))";
pub(crate) const EXPECTED_APPROVAL_PENDING_INDEX_SQL: &str = "CREATE INDEX approval_requests_pending_idx ON approval_requests(workspace_id, state, expires_at_ms, approval_id)";
pub(crate) const EXPECTED_APPROVAL_EXECUTION_INDEX_SQL: &str = "CREATE UNIQUE INDEX approval_requests_execution_idx ON approval_requests(workspace_id, activity_id, execution_id)";
pub(crate) const EXPECTED_AUTO_SCOPES_TABLE_SQL: &str = "CREATE TABLE auto_approval_scopes (scope_id BLOB PRIMARY KEY NOT NULL CHECK(length(scope_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB REFERENCES activities(activity_id) CHECK(activity_id IS NULL OR length(activity_id) = 16), action_class INTEGER NOT NULL CHECK(action_class IN (0, 1, 2)), workspace_read INTEGER NOT NULL CHECK(workspace_read IN (0, 1)), workspace_write INTEGER NOT NULL CHECK(workspace_write IN (0, 1)), network INTEGER NOT NULL CHECK(network IN (0, 1)), policy_revision INTEGER NOT NULL CHECK(policy_revision >= 1), expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0), max_uses INTEGER NOT NULL CHECK(max_uses BETWEEN 1 AND 1000), used_count INTEGER NOT NULL CHECK(used_count BETWEEN 0 AND max_uses), state INTEGER NOT NULL CHECK(state IN (0, 1, 2)), created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0), updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms), revision INTEGER NOT NULL CHECK(revision >= 1))";
pub(crate) const EXPECTED_AUTO_SCOPES_ACTIVE_INDEX_SQL: &str = "CREATE INDEX auto_approval_scopes_active_idx ON auto_approval_scopes(workspace_id, state, expires_at_ms, scope_id)";
pub(crate) const EXPECTED_EXECUTION_GRANTS_TABLE_SQL: &str = "CREATE TABLE execution_grants (grant_id BLOB PRIMARY KEY NOT NULL CHECK(length(grant_id) = 16), approval_id BLOB NOT NULL UNIQUE REFERENCES approval_requests(approval_id) CHECK(length(approval_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16), execution_id BLOB NOT NULL UNIQUE CHECK(length(execution_id) = 16), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), action_class INTEGER NOT NULL CHECK(action_class IN (0, 1, 2)), workspace_read INTEGER NOT NULL CHECK(workspace_read IN (0, 1)), workspace_write INTEGER NOT NULL CHECK(workspace_write IN (0, 1)), network INTEGER NOT NULL CHECK(network IN (0, 1)), effective_workspace_read INTEGER NOT NULL CHECK(effective_workspace_read IN (0, 1)), effective_workspace_write INTEGER NOT NULL CHECK(effective_workspace_write IN (0, 1)), effective_network INTEGER NOT NULL CHECK(effective_network IN (0, 1)), policy_revision INTEGER NOT NULL CHECK(policy_revision >= 1), source INTEGER NOT NULL CHECK(source IN (0, 1)), auto_scope_id BLOB REFERENCES auto_approval_scopes(scope_id) CHECK(auto_scope_id IS NULL OR length(auto_scope_id) = 16), state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3)), expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0), consumed_at_ms INTEGER CHECK(consumed_at_ms IS NULL OR consumed_at_ms >= 0), revision INTEGER NOT NULL CHECK(revision >= 1), CHECK((source = 0 AND auto_scope_id IS NULL) OR (source = 1 AND auto_scope_id IS NOT NULL)), CHECK((state = 1 AND consumed_at_ms IS NOT NULL) OR (state IN (0, 2, 3) AND consumed_at_ms IS NULL)), CHECK(workspace_read = effective_workspace_read AND workspace_write = effective_workspace_write AND network = effective_network))";
pub(crate) const EXPECTED_EXECUTION_GRANTS_STATE_INDEX_SQL: &str = "CREATE INDEX execution_grants_state_idx ON execution_grants(workspace_id, state, expires_at_ms, grant_id)";

const POLICY_QUERY: &str = "SELECT length(CAST(workspace_id AS BLOB)), workspace_id,
        direct_structured_rule, discovered_command_rule, shell_escape_rule,
        workspace_read_rule, workspace_write_rule, network_rule, revision
    FROM workspace_policy WHERE singleton = 1";
const APPROVAL_QUERY: &str = "SELECT
        length(CAST(approval_id AS BLOB)), length(CAST(workspace_id AS BLOB)),
        length(CAST(activity_id AS BLOB)), length(CAST(execution_id AS BLOB)),
        length(CAST(request_digest AS BLOB)), approval_id, workspace_id, activity_id,
        execution_id, request_digest, action_class, workspace_read, workspace_write,
        network, policy_revision, state, created_at_ms, expires_at_ms, decided_at_ms,
        revision FROM approval_requests";
const GRANT_QUERY: &str = "SELECT
        length(CAST(grant_id AS BLOB)), length(CAST(approval_id AS BLOB)),
        length(CAST(workspace_id AS BLOB)), length(CAST(activity_id AS BLOB)),
        length(CAST(execution_id AS BLOB)), length(CAST(request_digest AS BLOB)),
        length(CAST(auto_scope_id AS BLOB)), grant_id, approval_id, workspace_id,
        activity_id, execution_id, request_digest, action_class, workspace_read,
        workspace_write, network, effective_workspace_read, effective_workspace_write,
        effective_network, policy_revision, source, auto_scope_id, state,
        expires_at_ms, consumed_at_ms, revision FROM execution_grants";
const AUTO_SCOPE_QUERY: &str = "SELECT
        length(CAST(scope_id AS BLOB)), length(CAST(workspace_id AS BLOB)),
        length(CAST(activity_id AS BLOB)), scope_id, workspace_id, activity_id,
        action_class, workspace_read, workspace_write, network, policy_revision,
        expires_at_ms, max_uses, used_count, state, revision
    FROM auto_approval_scopes";

pub(crate) fn create_schema(connection: &Connection) -> Result<(), ApprovalStoreError> {
    connection.execute_batch(
        "CREATE TABLE workspace_policy (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            workspace_id BLOB NOT NULL UNIQUE REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16),
            direct_structured_rule INTEGER NOT NULL CHECK(direct_structured_rule IN (0, 1, 2)),
            discovered_command_rule INTEGER NOT NULL CHECK(discovered_command_rule IN (0, 1, 2)),
            shell_escape_rule INTEGER NOT NULL CHECK(shell_escape_rule IN (0, 1, 2)),
            workspace_read_rule INTEGER NOT NULL CHECK(workspace_read_rule IN (0, 1, 2)),
            workspace_write_rule INTEGER NOT NULL CHECK(workspace_write_rule IN (0, 1, 2)),
            network_rule INTEGER NOT NULL CHECK(network_rule IN (0, 1, 2)),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= 0),
            revision INTEGER NOT NULL CHECK(revision >= 1)
         );
         CREATE TABLE approval_requests (
            approval_id BLOB PRIMARY KEY NOT NULL CHECK(length(approval_id) = 16),
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16),
            activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16),
            execution_id BLOB NOT NULL CHECK(length(execution_id) = 16),
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            action_class INTEGER NOT NULL CHECK(action_class IN (0, 1, 2)),
            workspace_read INTEGER NOT NULL CHECK(workspace_read IN (0, 1)),
            workspace_write INTEGER NOT NULL CHECK(workspace_write IN (0, 1)),
            network INTEGER NOT NULL CHECK(network IN (0, 1)),
            policy_revision INTEGER NOT NULL CHECK(policy_revision >= 1),
            state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3, 4, 5, 6, 7)),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms > created_at_ms),
            decided_at_ms INTEGER CHECK(decided_at_ms IS NULL OR decided_at_ms >= created_at_ms),
            revision INTEGER NOT NULL CHECK(revision >= 1),
            CHECK((state = 0 AND decided_at_ms IS NULL) OR (state IN (1, 2, 3, 4, 5, 6, 7) AND decided_at_ms IS NOT NULL))
         );
         CREATE INDEX approval_requests_pending_idx
            ON approval_requests(workspace_id, state, expires_at_ms, approval_id);
         CREATE UNIQUE INDEX approval_requests_execution_idx
            ON approval_requests(workspace_id, activity_id, execution_id);
         CREATE TABLE auto_approval_scopes (
            scope_id BLOB PRIMARY KEY NOT NULL CHECK(length(scope_id) = 16),
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16),
            activity_id BLOB REFERENCES activities(activity_id) CHECK(activity_id IS NULL OR length(activity_id) = 16),
            action_class INTEGER NOT NULL CHECK(action_class IN (0, 1, 2)),
            workspace_read INTEGER NOT NULL CHECK(workspace_read IN (0, 1)),
            workspace_write INTEGER NOT NULL CHECK(workspace_write IN (0, 1)),
            network INTEGER NOT NULL CHECK(network IN (0, 1)),
            policy_revision INTEGER NOT NULL CHECK(policy_revision >= 1),
            expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
            max_uses INTEGER NOT NULL CHECK(max_uses BETWEEN 1 AND 1000),
            used_count INTEGER NOT NULL CHECK(used_count BETWEEN 0 AND max_uses),
            state INTEGER NOT NULL CHECK(state IN (0, 1, 2)),
            created_at_ms INTEGER NOT NULL CHECK(created_at_ms >= 0),
            updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms >= created_at_ms),
            revision INTEGER NOT NULL CHECK(revision >= 1)
         );
         CREATE INDEX auto_approval_scopes_active_idx
            ON auto_approval_scopes(workspace_id, state, expires_at_ms, scope_id);
         CREATE TABLE execution_grants (
            grant_id BLOB PRIMARY KEY NOT NULL CHECK(length(grant_id) = 16),
            approval_id BLOB NOT NULL UNIQUE REFERENCES approval_requests(approval_id) CHECK(length(approval_id) = 16),
            workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16),
            activity_id BLOB NOT NULL REFERENCES activities(activity_id) CHECK(length(activity_id) = 16),
            execution_id BLOB NOT NULL UNIQUE CHECK(length(execution_id) = 16),
            request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
            action_class INTEGER NOT NULL CHECK(action_class IN (0, 1, 2)),
            workspace_read INTEGER NOT NULL CHECK(workspace_read IN (0, 1)),
            workspace_write INTEGER NOT NULL CHECK(workspace_write IN (0, 1)),
            network INTEGER NOT NULL CHECK(network IN (0, 1)),
            effective_workspace_read INTEGER NOT NULL CHECK(effective_workspace_read IN (0, 1)),
            effective_workspace_write INTEGER NOT NULL CHECK(effective_workspace_write IN (0, 1)),
            effective_network INTEGER NOT NULL CHECK(effective_network IN (0, 1)),
            policy_revision INTEGER NOT NULL CHECK(policy_revision >= 1),
            source INTEGER NOT NULL CHECK(source IN (0, 1)),
            auto_scope_id BLOB REFERENCES auto_approval_scopes(scope_id) CHECK(auto_scope_id IS NULL OR length(auto_scope_id) = 16),
            state INTEGER NOT NULL CHECK(state IN (0, 1, 2, 3)),
            expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms >= 0),
            consumed_at_ms INTEGER CHECK(consumed_at_ms IS NULL OR consumed_at_ms >= 0),
            revision INTEGER NOT NULL CHECK(revision >= 1),
            CHECK((source = 0 AND auto_scope_id IS NULL) OR (source = 1 AND auto_scope_id IS NOT NULL)),
            CHECK((state = 1 AND consumed_at_ms IS NOT NULL) OR (state IN (0, 2, 3) AND consumed_at_ms IS NULL)),
            CHECK(workspace_read = effective_workspace_read AND workspace_write = effective_workspace_write AND network = effective_network)
         );
         CREATE INDEX execution_grants_state_idx
            ON execution_grants(workspace_id, state, expires_at_ms, grant_id);",
    )?;
    Ok(())
}

pub(crate) fn migrate_v6_to_v7(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), ApprovalStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "UPDATE executions SET state = 6, revision = revision + 1
         WHERE state IN (0, 1) AND revision < 9223372036854775807",
        [],
    )?;
    let active_remaining: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM executions WHERE state IN (0, 1))",
        [],
        |row| row.get(0),
    )?;
    if active_remaining {
        return Err(ApprovalStoreError::RevisionOverflow);
    }
    create_schema(&transaction)?;
    transaction.pragma_update(None, "user_version", next_schema_version)?;
    transaction.commit()?;
    Ok(())
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 8] {
    [
        ("table", "workspace_policy"),
        ("table", "approval_requests"),
        ("index", "approval_requests_pending_idx"),
        ("index", "approval_requests_execution_idx"),
        ("table", "auto_approval_scopes"),
        ("index", "auto_approval_scopes_active_idx"),
        ("table", "execution_grants"),
        ("index", "execution_grants_state_idx"),
    ]
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), ApprovalStoreError> {
    for (kind, name, expected) in [
        (
            "table",
            "workspace_policy",
            EXPECTED_WORKSPACE_POLICY_TABLE_SQL,
        ),
        (
            "table",
            "approval_requests",
            EXPECTED_APPROVAL_REQUESTS_TABLE_SQL,
        ),
        (
            "index",
            "approval_requests_pending_idx",
            EXPECTED_APPROVAL_PENDING_INDEX_SQL,
        ),
        (
            "index",
            "approval_requests_execution_idx",
            EXPECTED_APPROVAL_EXECUTION_INDEX_SQL,
        ),
        (
            "table",
            "auto_approval_scopes",
            EXPECTED_AUTO_SCOPES_TABLE_SQL,
        ),
        (
            "index",
            "auto_approval_scopes_active_idx",
            EXPECTED_AUTO_SCOPES_ACTIVE_INDEX_SQL,
        ),
        (
            "table",
            "execution_grants",
            EXPECTED_EXECUTION_GRANTS_TABLE_SQL,
        ),
        (
            "index",
            "execution_grants_state_idx",
            EXPECTED_EXECUTION_GRANTS_STATE_INDEX_SQL,
        ),
    ] {
        validate_schema_sql(connection, kind, name, expected)?;
    }
    validate_index_columns(
        connection,
        "approval_requests_pending_idx",
        &["workspace_id", "state", "expires_at_ms", "approval_id"],
    )?;
    validate_index_columns(
        connection,
        "approval_requests_execution_idx",
        &["workspace_id", "activity_id", "execution_id"],
    )?;
    validate_index_columns(
        connection,
        "auto_approval_scopes_active_idx",
        &["workspace_id", "state", "expires_at_ms", "scope_id"],
    )?;
    validate_index_columns(
        connection,
        "execution_grants_state_idx",
        &["workspace_id", "state", "expires_at_ms", "grant_id"],
    )?;
    validate_foreign_keys(connection, "workspace_policy", 1)?;
    validate_foreign_keys(connection, "approval_requests", 2)?;
    validate_foreign_keys(connection, "auto_approval_scopes", 2)?;
    validate_foreign_keys(connection, "execution_grants", 4)
}

pub(crate) fn ensure_policy(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    observed_at: TimestampMillis,
) -> Result<WorkspacePolicy, ApprovalStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO workspace_policy (
            singleton, workspace_id, direct_structured_rule, discovered_command_rule,
            shell_escape_rule, workspace_read_rule, workspace_write_rule, network_rule,
            created_at_ms, updated_at_ms, revision
         ) VALUES (1, ?1, 1, 2, 1, 2, 1, 1, ?2, ?2, 1)
         ON CONFLICT(singleton) DO NOTHING",
        params![workspace_id.into_uuid().as_bytes(), observed_at.get()],
    )?;
    let policy = get_policy_tx(&transaction)?.ok_or(ApprovalStoreError::PolicyMissing)?;
    if policy.workspace_id() != workspace_id {
        return Err(ApprovalStoreError::WorkspaceMismatch);
    }
    transaction.commit()?;
    Ok(policy)
}

pub(crate) fn get_policy(
    connection: &Connection,
) -> Result<Option<WorkspacePolicy>, ApprovalStoreError> {
    connection
        .query_row(POLICY_QUERY, [], decode_policy)
        .optional()
        .map_err(ApprovalStoreError::from)
}

pub(crate) fn replace_policy(
    connection: &mut Connection,
    policy: &WorkspacePolicy,
    expected_revision: PolicyRevision,
    observed_at: TimestampMillis,
) -> Result<WorkspacePolicy, ApprovalStoreError> {
    let next = expected_revision
        .checked_next()
        .map_err(|_| ApprovalStoreError::RevisionOverflow)?;
    if policy.revision() != next {
        return Err(ApprovalStoreError::RevisionConflict);
    }
    let updated = connection.execute(
        "UPDATE workspace_policy SET
            direct_structured_rule = ?1, discovered_command_rule = ?2,
            shell_escape_rule = ?3, workspace_read_rule = ?4,
            workspace_write_rule = ?5, network_rule = ?6,
            updated_at_ms = ?7, revision = ?8
         WHERE singleton = 1 AND workspace_id = ?9 AND revision = ?10",
        params![
            encode_rule(policy.direct_structured_rule()),
            encode_rule(policy.discovered_command_rule()),
            encode_rule(policy.shell_escape_rule()),
            encode_rule(policy.workspace_read_rule()),
            encode_rule(policy.workspace_write_rule()),
            encode_rule(policy.network_rule()),
            observed_at.get(),
            policy.revision().get(),
            policy.workspace_id().into_uuid().as_bytes(),
            expected_revision.get(),
        ],
    )?;
    if updated != 1 {
        return Err(ApprovalStoreError::RevisionConflict);
    }
    get_policy(connection)?.ok_or(ApprovalStoreError::PolicyMissing)
}

#[cfg(test)]
fn insert_pending(
    connection: &mut Connection,
    request: &RegisteredApprovalRequest,
) -> Result<RegisteredApprovalRequest, ApprovalStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = insert_pending_in_transaction(&transaction, request)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn insert_pending_in_transaction(
    transaction: &Transaction<'_>,
    request: &RegisteredApprovalRequest,
) -> Result<RegisteredApprovalRequest, ApprovalStoreError> {
    if request.state() != ApprovalRequestState::Pending {
        return Err(ApprovalStoreError::InvalidTransition);
    }
    let auth = request.request();
    let permissions = auth.requested().get();
    let inserted = transaction.execute(
        "INSERT INTO approval_requests (
            approval_id, workspace_id, activity_id, execution_id, request_digest,
            action_class, workspace_read, workspace_write, network, policy_revision,
            state, created_at_ms, expires_at_ms, decided_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0, ?11, ?12, NULL, ?13)
         ON CONFLICT(workspace_id, activity_id, execution_id) DO NOTHING",
        params![
            request.id().into_uuid().as_bytes(),
            auth.workspace_id().into_uuid().as_bytes(),
            auth.activity_id().into_uuid().as_bytes(),
            auth.execution_id().into_uuid().as_bytes(),
            auth.request_digest().as_bytes(),
            encode_action(auth.action()),
            encode_bool(permissions.workspace_read()),
            encode_bool(permissions.workspace_write()),
            encode_bool(permissions.network()),
            request.policy_revision().get(),
            request.created_at().get(),
            request.expires_at().get(),
            request.revision().get(),
        ],
    )?;
    let persisted = get_approval_by_execution_tx(
        transaction,
        auth.workspace_id(),
        auth.activity_id(),
        auth.execution_id(),
    )?
    .ok_or(ApprovalStoreError::ApprovalMissing)?;
    if inserted == 0 && persisted != *request {
        return Err(ApprovalStoreError::IdentityConflict);
    }
    Ok(persisted)
}

pub(crate) fn insert_approval_audit_in_transaction(
    transaction: &Transaction<'_>,
    request: &RegisteredApprovalRequest,
) -> Result<RegisteredApprovalRequest, ApprovalStoreError> {
    if request.state() == ApprovalRequestState::Pending {
        return Err(ApprovalStoreError::InvalidTransition);
    }
    let auth = request.request();
    if let Some(existing) = get_approval_by_execution_tx(
        transaction,
        auth.workspace_id(),
        auth.activity_id(),
        auth.execution_id(),
    )? {
        return if existing == *request {
            Ok(existing)
        } else {
            Err(ApprovalStoreError::IdentityConflict)
        };
    }
    insert_approval_tx(transaction, request)?;
    Ok(request.clone())
}

pub(crate) fn get_approval(
    connection: &Connection,
    id: ApprovalRequestId,
) -> Result<Option<RegisteredApprovalRequest>, ApprovalStoreError> {
    connection
        .query_row(
            &format!("{APPROVAL_QUERY} WHERE approval_id = ?1"),
            params![id.into_uuid().as_bytes()],
            decode_approval,
        )
        .optional()
        .map_err(ApprovalStoreError::from)
}

pub(crate) fn list_pending(
    connection: &Connection,
    workspace_id: WorkspaceId,
    limit: ExecutionListLimit,
) -> Result<Vec<RegisteredApprovalRequest>, ApprovalStoreError> {
    let mut statement = connection.prepare(&format!(
        "{APPROVAL_QUERY} WHERE workspace_id = ?1 AND state = 0
         ORDER BY expires_at_ms ASC, approval_id ASC LIMIT ?2"
    ))?;
    let rows = statement.query_map(
        params![workspace_id.into_uuid().as_bytes(), i64::from(limit.get())],
        decode_approval,
    )?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(ApprovalStoreError::from)
}

pub(crate) fn approve_once(
    connection: &mut Connection,
    approval_id: ApprovalRequestId,
    expected_revision: ApprovalRevision,
    grant_id: ExecutionGrantId,
    observed_at: TimestampMillis,
    grant_expires_at: TimestampMillis,
) -> Result<(RegisteredApprovalRequest, ExecutionGrant), ApprovalStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current =
        get_approval_tx(&transaction, approval_id)?.ok_or(ApprovalStoreError::ApprovalMissing)?;
    let policy = get_policy_tx(&transaction)?.ok_or(ApprovalStoreError::PolicyMissing)?;
    if current.policy_revision() != policy.revision() {
        return Err(ApprovalStoreError::PolicyRevisionConflict);
    }
    if grant_expires_at.get() > current.expires_at().get()
        || grant_expires_at.get() <= observed_at.get()
    {
        return Err(ApprovalStoreError::InvalidExpiry);
    }
    let approved = current
        .decide(ApprovalDecision::Approve, expected_revision, observed_at)
        .map_err(|_| ApprovalStoreError::InvalidTransition)?;
    let grant = ExecutionGrant::active(
        grant_id,
        approval_id,
        current.request(),
        EffectiveExecutionPermissions::from_grant(current.request().requested().get()),
        policy.revision(),
        AuthorizationSource::ExplicitGrant,
        grant_expires_at,
        ExecutionGrantRevision::INITIAL,
    )
    .map_err(|_| ApprovalStoreError::InvalidTransition)?;
    update_approval_tx(&transaction, &approved, expected_revision)?;
    insert_grant_tx(&transaction, &grant, None)?;
    transaction.commit()?;
    Ok((approved, grant))
}

pub(crate) fn decide_pending(
    connection: &mut Connection,
    approval_id: ApprovalRequestId,
    decision: ApprovalDecision,
    expected_revision: ApprovalRevision,
    observed_at: TimestampMillis,
) -> Result<RegisteredApprovalRequest, ApprovalStoreError> {
    if decision == ApprovalDecision::Approve {
        return Err(ApprovalStoreError::InvalidTransition);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current =
        get_approval_tx(&transaction, approval_id)?.ok_or(ApprovalStoreError::ApprovalMissing)?;
    let decided = current
        .decide(decision, expected_revision, observed_at)
        .map_err(|_| ApprovalStoreError::InvalidTransition)?;
    update_approval_tx(&transaction, &decided, expected_revision)?;
    transaction.commit()?;
    Ok(decided)
}

pub(crate) fn create_auto_scope(
    connection: &mut Connection,
    scope: &AutoApprovalScope,
    created_at: TimestampMillis,
) -> Result<AutoApprovalScope, ApprovalStoreError> {
    let permissions = scope.permission_ceiling();
    let inserted = connection.execute(
        "INSERT INTO auto_approval_scopes (
            scope_id, workspace_id, activity_id, action_class, workspace_read,
            workspace_write, network, policy_revision, expires_at_ms, max_uses,
            used_count, state, created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?13, ?14)
         ON CONFLICT(scope_id) DO NOTHING",
        params![
            scope.id().into_uuid().as_bytes(),
            scope.workspace_id().into_uuid().as_bytes(),
            scope
                .activity_id()
                .map(|id| id.into_uuid().into_bytes().to_vec()),
            encode_action(scope.action()),
            encode_bool(permissions.workspace_read()),
            encode_bool(permissions.workspace_write()),
            encode_bool(permissions.network()),
            scope.policy_revision().get(),
            scope.expires_at().get(),
            i64::from(scope.max_uses().get()),
            i64::from(scope.used_count()),
            encode_auto_state(scope.state()),
            created_at.get(),
            scope.revision().get(),
        ],
    )?;
    let persisted =
        get_auto_scope(connection, scope.id())?.ok_or(ApprovalStoreError::AutoScopeMissing)?;
    if inserted == 0 && persisted != *scope {
        return Err(ApprovalStoreError::IdentityConflict);
    }
    Ok(persisted)
}

pub(crate) fn get_auto_scope(
    connection: &Connection,
    id: AutoApprovalScopeId,
) -> Result<Option<AutoApprovalScope>, ApprovalStoreError> {
    connection
        .query_row(
            &format!("{AUTO_SCOPE_QUERY} WHERE scope_id = ?1"),
            params![id.into_uuid().as_bytes()],
            decode_auto_scope,
        )
        .optional()
        .map_err(ApprovalStoreError::from)
}

pub(crate) fn revoke_auto_scope(
    connection: &mut Connection,
    id: AutoApprovalScopeId,
    expected_revision: AutoApprovalScopeRevision,
    observed_at: TimestampMillis,
) -> Result<AutoApprovalScope, ApprovalStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let scope = get_auto_scope_tx(&transaction, id)?.ok_or(ApprovalStoreError::AutoScopeMissing)?;
    let revoked = scope
        .revoke(expected_revision)
        .map_err(|_| ApprovalStoreError::RevisionConflict)?;
    update_auto_scope_tx(&transaction, &revoked, expected_revision, observed_at)?;
    transaction.commit()?;
    Ok(revoked)
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoApprovalExecutionRecord {
    scope: AutoApprovalScope,
    approval: RegisteredApprovalRequest,
    grant: ExecutionGrant,
    begin: BeginExecutionRecord,
}

impl AutoApprovalExecutionRecord {
    pub const fn scope(&self) -> &AutoApprovalScope {
        &self.scope
    }

    pub const fn approval(&self) -> &RegisteredApprovalRequest {
        &self.approval
    }

    pub const fn grant(&self) -> &ExecutionGrant {
        &self.grant
    }

    pub const fn begin(&self) -> &BeginExecutionRecord {
        &self.begin
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn consume_auto_scope_and_begin_execution(
    connection: &mut Connection,
    scope_id: AutoApprovalScopeId,
    expected_scope_revision: AutoApprovalScopeRevision,
    approval_id: ApprovalRequestId,
    grant_id: ExecutionGrantId,
    request: ExecutionAuthorizationRequest,
    begin: &BeginExecution,
    observed_at: TimestampMillis,
    goal: Option<GoalWorkAttribution>,
) -> Result<AutoApprovalExecutionRecord, ApprovalStoreError> {
    if begin.id() != request.execution_id()
        || begin.workspace_id() != request.workspace_id()
        || begin.activity_id() != request.activity_id()
        || begin.request_digest() != request.request_digest()
        || begin.permissions() != request.requested().get()
    {
        return Err(ApprovalStoreError::GrantMismatch);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let scope =
        get_auto_scope_tx(&transaction, scope_id)?.ok_or(ApprovalStoreError::AutoScopeMissing)?;
    let policy = get_policy_tx(&transaction)?.ok_or(ApprovalStoreError::PolicyMissing)?;
    if !matches!(
        evaluate_execution_authorization(&policy, request, None, Some(&scope), observed_at,),
        ExecutionAuthorizationDecision::Authorized(_)
    ) {
        return Err(ApprovalStoreError::AutoScopeMismatch);
    }
    let consumed_scope = scope
        .consume(
            request,
            policy.revision(),
            expected_scope_revision,
            observed_at,
        )
        .map_err(|_| ApprovalStoreError::AutoScopeMismatch)?;
    let approval = RegisteredApprovalRequest::from_parts(
        approval_id,
        request,
        policy.revision(),
        ApprovalRequestState::AutoApproved,
        observed_at,
        scope.expires_at(),
        Some(observed_at),
        ApprovalRevision::INITIAL,
    )
    .map_err(|_| ApprovalStoreError::InvalidTransition)?;
    let grant = ExecutionGrant::from_parts(
        grant_id,
        approval_id,
        request,
        EffectiveExecutionPermissions::from_grant(request.requested().get()),
        policy.revision(),
        AuthorizationSource::AutoApprovalScope,
        scope.expires_at(),
        ExecutionGrantState::Consumed,
        Some(observed_at),
        ExecutionGrantRevision::INITIAL,
    )
    .map_err(|_| ApprovalStoreError::InvalidTransition)?;
    insert_approval_tx(&transaction, &approval)?;
    insert_grant_tx(&transaction, &grant, Some(scope_id))?;
    update_auto_scope_tx(
        &transaction,
        &consumed_scope,
        expected_scope_revision,
        observed_at,
    )?;
    let begin_record = workspace_executions::begin_execution_in_transaction(&transaction, begin)?;
    if begin_record.status() != BeginExecutionStatus::Created {
        return Err(ApprovalStoreError::GrantReplay);
    }
    associate_authorized_evidence(
        &transaction,
        goal,
        GoalEvidenceRef::Approval(approval.id()),
        observed_at,
    )?;
    associate_authorized_evidence(
        &transaction,
        goal,
        GoalEvidenceRef::Execution(begin.id()),
        observed_at,
    )?;
    transaction.commit()?;
    Ok(AutoApprovalExecutionRecord {
        scope: consumed_scope,
        approval,
        grant,
        begin: begin_record,
    })
}

pub(crate) fn consume_grant_and_begin_execution(
    connection: &mut Connection,
    grant_id: ExecutionGrantId,
    expected_revision: ExecutionGrantRevision,
    request: ExecutionAuthorizationRequest,
    begin: &BeginExecution,
    observed_at: TimestampMillis,
    goal: Option<GoalWorkAttribution>,
) -> Result<(ExecutionGrant, BeginExecutionRecord), ApprovalStoreError> {
    if begin.id() != request.execution_id()
        || begin.workspace_id() != request.workspace_id()
        || begin.activity_id() != request.activity_id()
        || begin.request_digest() != request.request_digest()
        || begin.permissions() != request.requested().get()
    {
        return Err(ApprovalStoreError::GrantMismatch);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let grant = get_grant_tx(&transaction, grant_id)?.ok_or(ApprovalStoreError::GrantMissing)?;
    let policy = get_policy_tx(&transaction)?.ok_or(ApprovalStoreError::PolicyMissing)?;
    if !matches!(
        evaluate_execution_authorization(&policy, request, Some(&grant), None, observed_at,),
        ExecutionAuthorizationDecision::Authorized(_)
    ) {
        return Err(ApprovalStoreError::GrantMismatch);
    }
    let consumed = grant
        .consume(request, expected_revision, observed_at)
        .map_err(|_| ApprovalStoreError::GrantMismatch)?;
    let begin_record = workspace_executions::begin_execution_in_transaction(&transaction, begin)?;
    if begin_record.status() != BeginExecutionStatus::Created {
        return Err(ApprovalStoreError::GrantReplay);
    }
    update_grant_tx(&transaction, &consumed, expected_revision)?;
    associate_authorized_evidence(
        &transaction,
        goal,
        GoalEvidenceRef::Approval(consumed.approval_id()),
        observed_at,
    )?;
    associate_authorized_evidence(
        &transaction,
        goal,
        GoalEvidenceRef::Execution(begin.id()),
        observed_at,
    )?;
    transaction.commit()?;
    Ok((consumed, begin_record))
}

fn associate_authorized_evidence(
    transaction: &Transaction<'_>,
    attribution: Option<GoalWorkAttribution>,
    evidence: GoalEvidenceRef,
    observed_at: TimestampMillis,
) -> Result<(), ApprovalStoreError> {
    workspace_goals::associate_optional_evidence_in_transaction(
        transaction,
        attribution,
        evidence,
        observed_at,
    )?;
    workspace_dags::associate_node_evidence_in_transaction(
        transaction,
        attribution.and_then(GoalWorkAttribution::node),
        evidence,
        observed_at,
    )?;
    Ok(())
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalAuthorityCleanupReport {
    approvals: usize,
    grants: usize,
    auto_scopes: usize,
}

impl ApprovalAuthorityCleanupReport {
    pub const fn approvals(self) -> usize {
        self.approvals
    }

    pub const fn grants(self) -> usize {
        self.grants
    }

    pub const fn auto_scopes(self) -> usize {
        self.auto_scopes
    }

    pub const fn total(self) -> usize {
        self.approvals + self.grants + self.auto_scopes
    }
}

pub(crate) fn reconcile_expired_authority(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
) -> Result<ApprovalAuthorityCleanupReport, ApprovalStoreError> {
    cleanup_authority(
        connection,
        workspace_id,
        None,
        observed_at,
        limit,
        CleanupMode::Expired,
    )
}

pub(crate) fn cancel_activity_authority(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
) -> Result<ApprovalAuthorityCleanupReport, ApprovalStoreError> {
    cleanup_authority(
        connection,
        workspace_id,
        Some(activity_id),
        observed_at,
        limit,
        CleanupMode::Cancelled,
    )
}

pub(crate) fn cancel_workspace_authority(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
) -> Result<ApprovalAuthorityCleanupReport, ApprovalStoreError> {
    cleanup_authority(
        connection,
        workspace_id,
        None,
        observed_at,
        limit,
        CleanupMode::Cancelled,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupMode {
    Expired,
    Cancelled,
}

fn cleanup_authority(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    activity_id: Option<ActivityId>,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
    mode: CleanupMode,
) -> Result<ApprovalAuthorityCleanupReport, ApprovalStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let activity_bytes = activity_id.map(|id| id.into_uuid().into_bytes().to_vec());
    let expired_only = i64::from(mode == CleanupMode::Expired);
    ensure_cleanup_revisions_available(
        &transaction,
        workspace_id,
        observed_at,
        activity_bytes.as_deref(),
        expired_only,
    )?;
    let limit = i64::from(limit.get());
    let approvals = transaction.execute(
        "UPDATE approval_requests SET state = ?5, decided_at_ms = ?2, revision = revision + 1
         WHERE approval_id IN (
            SELECT approval_id FROM approval_requests
            WHERE workspace_id = ?1 AND state = 0
              AND (?3 IS NULL OR activity_id = ?3)
              AND (?6 = 0 OR expires_at_ms <= ?2)
            ORDER BY expires_at_ms ASC, approval_id ASC LIMIT ?4
         )",
        params![
            workspace_id.into_uuid().as_bytes(),
            observed_at.get(),
            activity_bytes,
            limit,
            if mode == CleanupMode::Expired { 6 } else { 5 },
            expired_only,
        ],
    )?;
    let grants = transaction.execute(
        "UPDATE execution_grants SET state = ?5, revision = revision + 1
         WHERE grant_id IN (
            SELECT grant_id FROM execution_grants
            WHERE workspace_id = ?1 AND state = 0
              AND (?3 IS NULL OR activity_id = ?3)
              AND (?6 = 0 OR expires_at_ms <= ?2)
            ORDER BY expires_at_ms ASC, grant_id ASC LIMIT ?4
         )",
        params![
            workspace_id.into_uuid().as_bytes(),
            observed_at.get(),
            activity_bytes,
            limit,
            if mode == CleanupMode::Expired { 3 } else { 2 },
            expired_only,
        ],
    )?;
    let auto_scopes = transaction.execute(
        "UPDATE auto_approval_scopes SET state = ?5, updated_at_ms = ?2, revision = revision + 1
         WHERE scope_id IN (
            SELECT scope_id FROM auto_approval_scopes
            WHERE workspace_id = ?1 AND state = 0
              AND (?3 IS NULL OR activity_id = ?3)
              AND (?6 = 0 OR expires_at_ms <= ?2)
            ORDER BY expires_at_ms ASC, scope_id ASC LIMIT ?4
         )",
        params![
            workspace_id.into_uuid().as_bytes(),
            observed_at.get(),
            activity_bytes,
            limit,
            if mode == CleanupMode::Expired { 2 } else { 1 },
            expired_only,
        ],
    )?;
    transaction.commit()?;
    Ok(ApprovalAuthorityCleanupReport {
        approvals,
        grants,
        auto_scopes,
    })
}

fn ensure_cleanup_revisions_available(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    observed_at: TimestampMillis,
    activity_id: Option<&[u8]>,
    expired_only: i64,
) -> Result<(), ApprovalStoreError> {
    for table in [
        "approval_requests",
        "execution_grants",
        "auto_approval_scopes",
    ] {
        let overflow: bool = transaction.query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM {table}
                 WHERE workspace_id = ?1 AND state = 0 AND revision = 9223372036854775807
                   AND (?3 IS NULL OR activity_id = ?3)
                   AND (?4 = 0 OR expires_at_ms <= ?2))"
            ),
            params![
                workspace_id.into_uuid().as_bytes(),
                observed_at.get(),
                activity_id,
                expired_only,
            ],
            |row| row.get(0),
        )?;
        if overflow {
            return Err(ApprovalStoreError::RevisionOverflow);
        }
    }
    Ok(())
}

fn get_policy_tx(
    transaction: &Transaction<'_>,
) -> Result<Option<WorkspacePolicy>, ApprovalStoreError> {
    transaction
        .query_row(POLICY_QUERY, [], decode_policy)
        .optional()
        .map_err(ApprovalStoreError::from)
}

fn get_approval_tx(
    transaction: &Transaction<'_>,
    id: ApprovalRequestId,
) -> Result<Option<RegisteredApprovalRequest>, ApprovalStoreError> {
    transaction
        .query_row(
            &format!("{APPROVAL_QUERY} WHERE approval_id = ?1"),
            params![id.into_uuid().as_bytes()],
            decode_approval,
        )
        .optional()
        .map_err(ApprovalStoreError::from)
}

fn get_approval_by_execution_tx(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
    execution_id: forge_domain::ExecutionId,
) -> Result<Option<RegisteredApprovalRequest>, ApprovalStoreError> {
    transaction
        .query_row(
            &format!(
                "{APPROVAL_QUERY} WHERE workspace_id = ?1 AND activity_id = ?2 AND execution_id = ?3"
            ),
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.into_uuid().as_bytes(),
                execution_id.into_uuid().as_bytes(),
            ],
            decode_approval,
        )
        .optional()
        .map_err(ApprovalStoreError::from)
}

fn get_grant_tx(
    transaction: &Transaction<'_>,
    id: ExecutionGrantId,
) -> Result<Option<ExecutionGrant>, ApprovalStoreError> {
    transaction
        .query_row(
            &format!("{GRANT_QUERY} WHERE grant_id = ?1"),
            params![id.into_uuid().as_bytes()],
            decode_grant,
        )
        .optional()
        .map_err(ApprovalStoreError::from)
}

fn get_auto_scope_tx(
    transaction: &Transaction<'_>,
    id: AutoApprovalScopeId,
) -> Result<Option<AutoApprovalScope>, ApprovalStoreError> {
    transaction
        .query_row(
            &format!("{AUTO_SCOPE_QUERY} WHERE scope_id = ?1"),
            params![id.into_uuid().as_bytes()],
            decode_auto_scope,
        )
        .optional()
        .map_err(ApprovalStoreError::from)
}

fn insert_approval_tx(
    transaction: &Transaction<'_>,
    approval: &RegisteredApprovalRequest,
) -> Result<(), ApprovalStoreError> {
    let request = approval.request();
    let permissions = request.requested().get();
    transaction.execute(
        "INSERT INTO approval_requests (
            approval_id, workspace_id, activity_id, execution_id, request_digest,
            action_class, workspace_read, workspace_write, network, policy_revision,
            state, created_at_ms, expires_at_ms, decided_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            approval.id().into_uuid().as_bytes(),
            request.workspace_id().into_uuid().as_bytes(),
            request.activity_id().into_uuid().as_bytes(),
            request.execution_id().into_uuid().as_bytes(),
            request.request_digest().as_bytes(),
            encode_action(request.action()),
            encode_bool(permissions.workspace_read()),
            encode_bool(permissions.workspace_write()),
            encode_bool(permissions.network()),
            approval.policy_revision().get(),
            encode_approval_state(approval.state()),
            approval.created_at().get(),
            approval.expires_at().get(),
            approval.decided_at().map(TimestampMillis::get),
            approval.revision().get(),
        ],
    )?;
    Ok(())
}

fn update_approval_tx(
    transaction: &Transaction<'_>,
    approval: &RegisteredApprovalRequest,
    expected_revision: ApprovalRevision,
) -> Result<(), ApprovalStoreError> {
    let updated = transaction.execute(
        "UPDATE approval_requests SET state = ?1, decided_at_ms = ?2, revision = ?3
         WHERE approval_id = ?4 AND state = 0 AND revision = ?5",
        params![
            encode_approval_state(approval.state()),
            approval.decided_at().map(TimestampMillis::get),
            approval.revision().get(),
            approval.id().into_uuid().as_bytes(),
            expected_revision.get(),
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ApprovalStoreError::RevisionConflict)
    }
}

fn insert_grant_tx(
    transaction: &Transaction<'_>,
    grant: &ExecutionGrant,
    auto_scope_id: Option<AutoApprovalScopeId>,
) -> Result<(), ApprovalStoreError> {
    let request = grant.request();
    let requested = request.requested().get();
    let effective = grant.effective().get();
    transaction.execute(
        "INSERT INTO execution_grants (
            grant_id, approval_id, workspace_id, activity_id, execution_id,
            request_digest, action_class, workspace_read, workspace_write, network,
            effective_workspace_read, effective_workspace_write, effective_network,
            policy_revision, source, auto_scope_id, state, expires_at_ms,
            consumed_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                   ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
        params![
            grant.id().into_uuid().as_bytes(),
            grant.approval_id().into_uuid().as_bytes(),
            request.workspace_id().into_uuid().as_bytes(),
            request.activity_id().into_uuid().as_bytes(),
            request.execution_id().into_uuid().as_bytes(),
            request.request_digest().as_bytes(),
            encode_action(request.action()),
            encode_bool(requested.workspace_read()),
            encode_bool(requested.workspace_write()),
            encode_bool(requested.network()),
            encode_bool(effective.workspace_read()),
            encode_bool(effective.workspace_write()),
            encode_bool(effective.network()),
            grant.policy_revision().get(),
            encode_source(grant.source()),
            auto_scope_id.map(|id| id.into_uuid().into_bytes().to_vec()),
            encode_grant_state(grant.state()),
            grant.expires_at().get(),
            grant.consumed_at().map(TimestampMillis::get),
            grant.revision().get(),
        ],
    )?;
    Ok(())
}

fn update_grant_tx(
    transaction: &Transaction<'_>,
    grant: &ExecutionGrant,
    expected_revision: ExecutionGrantRevision,
) -> Result<(), ApprovalStoreError> {
    let updated = transaction.execute(
        "UPDATE execution_grants SET state = ?1, consumed_at_ms = ?2, revision = ?3
         WHERE grant_id = ?4 AND state = 0 AND revision = ?5",
        params![
            encode_grant_state(grant.state()),
            grant.consumed_at().map(TimestampMillis::get),
            grant.revision().get(),
            grant.id().into_uuid().as_bytes(),
            expected_revision.get(),
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ApprovalStoreError::RevisionConflict)
    }
}

fn update_auto_scope_tx(
    transaction: &Transaction<'_>,
    scope: &AutoApprovalScope,
    expected_revision: AutoApprovalScopeRevision,
    observed_at: TimestampMillis,
) -> Result<(), ApprovalStoreError> {
    let updated = transaction.execute(
        "UPDATE auto_approval_scopes SET used_count = ?1, state = ?2,
            updated_at_ms = ?3, revision = ?4
         WHERE scope_id = ?5 AND state = 0 AND revision = ?6",
        params![
            i64::from(scope.used_count()),
            encode_auto_state(scope.state()),
            observed_at.get(),
            scope.revision().get(),
            scope.id().into_uuid().as_bytes(),
            expected_revision.get(),
        ],
    )?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ApprovalStoreError::RevisionConflict)
    }
}

fn decode_policy(row: &Row<'_>) -> rusqlite::Result<WorkspacePolicy> {
    decode_policy_inner(row).map_err(conversion_error)
}

fn decode_policy_inner(row: &Row<'_>) -> Result<WorkspacePolicy, ApprovalStoreError> {
    validate_length("policy.workspace_id", row.get(0)?, 16)?;
    Ok(WorkspacePolicy::new(
        decode_workspace_id(&row.get::<_, Vec<u8>>(1)?)?,
        PolicyRevision::new(row.get(8)?)
            .map_err(|_| ApprovalStoreError::CorruptRecord("policy.revision"))?,
        decode_rule(row.get(2)?)?,
        decode_rule(row.get(3)?)?,
        decode_rule(row.get(4)?)?,
        decode_rule(row.get(5)?)?,
        decode_rule(row.get(6)?)?,
        decode_rule(row.get(7)?)?,
    ))
}

fn decode_approval(row: &Row<'_>) -> rusqlite::Result<RegisteredApprovalRequest> {
    decode_approval_inner(row).map_err(conversion_error)
}

fn decode_approval_inner(row: &Row<'_>) -> Result<RegisteredApprovalRequest, ApprovalStoreError> {
    validate_length("approval.id", row.get(0)?, 16)?;
    validate_length("approval.workspace_id", row.get(1)?, 16)?;
    validate_length("approval.activity_id", row.get(2)?, 16)?;
    validate_length("approval.execution_id", row.get(3)?, 16)?;
    validate_length("approval.request_digest", row.get(4)?, 32)?;
    let request = ExecutionAuthorizationRequest::new(
        forge_domain::ExecutionId::from_uuid(decode_uuid(
            "approval.execution_id",
            &row.get::<_, Vec<u8>>(8)?,
        )?),
        decode_workspace_id(&row.get::<_, Vec<u8>>(6)?)?,
        ActivityId::from_uuid(decode_uuid(
            "approval.activity_id",
            &row.get::<_, Vec<u8>>(7)?,
        )?),
        decode_digest(&row.get::<_, Vec<u8>>(9)?)?,
        decode_action(row.get(10)?)?,
        RequestedExecutionPermissions::new(ExecutionPermissions::new(
            decode_bool("approval.workspace_read", row.get(11)?)?,
            decode_bool("approval.workspace_write", row.get(12)?)?,
            decode_bool("approval.network", row.get(13)?)?,
        )),
    );
    RegisteredApprovalRequest::from_parts(
        ApprovalRequestId::from_uuid(decode_uuid("approval.id", &row.get::<_, Vec<u8>>(5)?)?),
        request,
        PolicyRevision::new(row.get(14)?)
            .map_err(|_| ApprovalStoreError::CorruptRecord("approval.policy_revision"))?,
        decode_approval_state(row.get(15)?)?,
        decode_timestamp("approval.created_at", row.get(16)?)?,
        decode_timestamp("approval.expires_at", row.get(17)?)?,
        row.get::<_, Option<i64>>(18)?
            .map(|value| decode_timestamp("approval.decided_at", value))
            .transpose()?,
        ApprovalRevision::new(row.get(19)?)
            .map_err(|_| ApprovalStoreError::CorruptRecord("approval.revision"))?,
    )
    .map_err(|_| ApprovalStoreError::CorruptRecord("approval.evidence"))
}

fn decode_grant(row: &Row<'_>) -> rusqlite::Result<ExecutionGrant> {
    decode_grant_inner(row).map_err(conversion_error)
}

fn decode_grant_inner(row: &Row<'_>) -> Result<ExecutionGrant, ApprovalStoreError> {
    for (field, index, expected) in [
        ("grant.id", 0, 16),
        ("grant.approval_id", 1, 16),
        ("grant.workspace_id", 2, 16),
        ("grant.activity_id", 3, 16),
        ("grant.execution_id", 4, 16),
        ("grant.request_digest", 5, 32),
    ] {
        validate_length(field, row.get(index)?, expected)?;
    }
    validate_optional_length("grant.auto_scope_id", row.get(6)?, 16)?;
    let requested = ExecutionPermissions::new(
        decode_bool("grant.workspace_read", row.get(14)?)?,
        decode_bool("grant.workspace_write", row.get(15)?)?,
        decode_bool("grant.network", row.get(16)?)?,
    );
    let effective = ExecutionPermissions::new(
        decode_bool("grant.effective_workspace_read", row.get(17)?)?,
        decode_bool("grant.effective_workspace_write", row.get(18)?)?,
        decode_bool("grant.effective_network", row.get(19)?)?,
    );
    let request = ExecutionAuthorizationRequest::new(
        forge_domain::ExecutionId::from_uuid(decode_uuid(
            "grant.execution_id",
            &row.get::<_, Vec<u8>>(11)?,
        )?),
        decode_workspace_id(&row.get::<_, Vec<u8>>(9)?)?,
        ActivityId::from_uuid(decode_uuid(
            "grant.activity_id",
            &row.get::<_, Vec<u8>>(10)?,
        )?),
        decode_digest(&row.get::<_, Vec<u8>>(12)?)?,
        decode_action(row.get(13)?)?,
        RequestedExecutionPermissions::new(requested),
    );
    ExecutionGrant::from_parts(
        ExecutionGrantId::from_uuid(decode_uuid("grant.id", &row.get::<_, Vec<u8>>(7)?)?),
        ApprovalRequestId::from_uuid(decode_uuid(
            "grant.approval_id",
            &row.get::<_, Vec<u8>>(8)?,
        )?),
        request,
        EffectiveExecutionPermissions::from_grant(effective),
        PolicyRevision::new(row.get(20)?)
            .map_err(|_| ApprovalStoreError::CorruptRecord("grant.policy_revision"))?,
        decode_source(row.get(21)?)?,
        decode_timestamp("grant.expires_at", row.get(24)?)?,
        decode_grant_state(row.get(23)?)?,
        row.get::<_, Option<i64>>(25)?
            .map(|value| decode_timestamp("grant.consumed_at", value))
            .transpose()?,
        ExecutionGrantRevision::new(row.get(26)?)
            .map_err(|_| ApprovalStoreError::CorruptRecord("grant.revision"))?,
    )
    .map_err(|_| ApprovalStoreError::CorruptRecord("grant.evidence"))
}

fn decode_auto_scope(row: &Row<'_>) -> rusqlite::Result<AutoApprovalScope> {
    decode_auto_scope_inner(row).map_err(conversion_error)
}

fn decode_auto_scope_inner(row: &Row<'_>) -> Result<AutoApprovalScope, ApprovalStoreError> {
    validate_length("auto_scope.id", row.get(0)?, 16)?;
    validate_length("auto_scope.workspace_id", row.get(1)?, 16)?;
    validate_optional_length("auto_scope.activity_id", row.get(2)?, 16)?;
    AutoApprovalScope::from_parts(
        AutoApprovalScopeId::from_uuid(decode_uuid("auto_scope.id", &row.get::<_, Vec<u8>>(3)?)?),
        decode_workspace_id(&row.get::<_, Vec<u8>>(4)?)?,
        row.get::<_, Option<Vec<u8>>>(5)?
            .map(|value| decode_uuid("auto_scope.activity_id", &value).map(ActivityId::from_uuid))
            .transpose()?,
        decode_action(row.get(6)?)?,
        ExecutionPermissions::new(
            decode_bool("auto_scope.workspace_read", row.get(7)?)?,
            decode_bool("auto_scope.workspace_write", row.get(8)?)?,
            decode_bool("auto_scope.network", row.get(9)?)?,
        ),
        PolicyRevision::new(row.get(10)?)
            .map_err(|_| ApprovalStoreError::CorruptRecord("auto_scope.policy_revision"))?,
        decode_timestamp("auto_scope.expires_at", row.get(11)?)?,
        AutoApprovalUseLimit::new(
            u16::try_from(row.get::<_, i64>(12)?)
                .map_err(|_| ApprovalStoreError::CorruptRecord("auto_scope.max_uses"))?,
        )
        .map_err(|_| ApprovalStoreError::CorruptRecord("auto_scope.max_uses"))?,
        u16::try_from(row.get::<_, i64>(13)?)
            .map_err(|_| ApprovalStoreError::CorruptRecord("auto_scope.used_count"))?,
        decode_auto_state(row.get(14)?)?,
        AutoApprovalScopeRevision::new(row.get(15)?)
            .map_err(|_| ApprovalStoreError::CorruptRecord("auto_scope.revision"))?,
    )
    .map_err(|_| ApprovalStoreError::CorruptRecord("auto_scope.evidence"))
}

fn conversion_error(error: ApprovalStoreError) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(error))
}

fn decode_workspace_id(value: &[u8]) -> Result<WorkspaceId, ApprovalStoreError> {
    decode_uuid("workspace_id", value).map(WorkspaceId::from_uuid)
}

fn decode_uuid(field: &'static str, value: &[u8]) -> Result<Uuid, ApprovalStoreError> {
    Uuid::from_slice(value).map_err(|_| ApprovalStoreError::CorruptRecord(field))
}

fn decode_digest(value: &[u8]) -> Result<ExecutionRequestDigest, ApprovalStoreError> {
    <[u8; ExecutionRequestDigest::BYTE_LEN]>::try_from(value)
        .map(ExecutionRequestDigest::from_bytes)
        .map_err(|_| ApprovalStoreError::CorruptRecord("request_digest"))
}

fn decode_timestamp(
    field: &'static str,
    value: i64,
) -> Result<TimestampMillis, ApprovalStoreError> {
    TimestampMillis::new(value).map_err(|_| ApprovalStoreError::CorruptRecord(field))
}

const fn encode_bool(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn decode_bool(field: &'static str, value: i64) -> Result<bool, ApprovalStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ApprovalStoreError::CorruptRecord(field)),
    }
}

const fn encode_rule(value: ExecutionPolicyRule) -> i64 {
    match value {
        ExecutionPolicyRule::Deny => 0,
        ExecutionPolicyRule::Ask => 1,
        ExecutionPolicyRule::AutoEligible => 2,
    }
}

fn decode_rule(value: i64) -> Result<ExecutionPolicyRule, ApprovalStoreError> {
    match value {
        0 => Ok(ExecutionPolicyRule::Deny),
        1 => Ok(ExecutionPolicyRule::Ask),
        2 => Ok(ExecutionPolicyRule::AutoEligible),
        _ => Err(ApprovalStoreError::CorruptRecord("policy.rule")),
    }
}

const fn encode_action(value: ExecutionActionClass) -> i64 {
    match value {
        ExecutionActionClass::DirectStructured => 0,
        ExecutionActionClass::DiscoveredProjectCommand => 1,
        ExecutionActionClass::ShellEscape => 2,
    }
}

fn decode_action(value: i64) -> Result<ExecutionActionClass, ApprovalStoreError> {
    match value {
        0 => Ok(ExecutionActionClass::DirectStructured),
        1 => Ok(ExecutionActionClass::DiscoveredProjectCommand),
        2 => Ok(ExecutionActionClass::ShellEscape),
        _ => Err(ApprovalStoreError::CorruptRecord("action_class")),
    }
}

const fn encode_approval_state(value: ApprovalRequestState) -> i64 {
    match value {
        ApprovalRequestState::Pending => 0,
        ApprovalRequestState::Approved => 1,
        ApprovalRequestState::Rejected => 2,
        ApprovalRequestState::AutoApproved => 3,
        ApprovalRequestState::Denied => 4,
        ApprovalRequestState::Cancelled => 5,
        ApprovalRequestState::Expired => 6,
        ApprovalRequestState::Superseded => 7,
    }
}

fn decode_approval_state(value: i64) -> Result<ApprovalRequestState, ApprovalStoreError> {
    match value {
        0 => Ok(ApprovalRequestState::Pending),
        1 => Ok(ApprovalRequestState::Approved),
        2 => Ok(ApprovalRequestState::Rejected),
        3 => Ok(ApprovalRequestState::AutoApproved),
        4 => Ok(ApprovalRequestState::Denied),
        5 => Ok(ApprovalRequestState::Cancelled),
        6 => Ok(ApprovalRequestState::Expired),
        7 => Ok(ApprovalRequestState::Superseded),
        _ => Err(ApprovalStoreError::CorruptRecord("approval.state")),
    }
}

const fn encode_grant_state(value: ExecutionGrantState) -> i64 {
    match value {
        ExecutionGrantState::Active => 0,
        ExecutionGrantState::Consumed => 1,
        ExecutionGrantState::Revoked => 2,
        ExecutionGrantState::Expired => 3,
    }
}

fn decode_grant_state(value: i64) -> Result<ExecutionGrantState, ApprovalStoreError> {
    match value {
        0 => Ok(ExecutionGrantState::Active),
        1 => Ok(ExecutionGrantState::Consumed),
        2 => Ok(ExecutionGrantState::Revoked),
        3 => Ok(ExecutionGrantState::Expired),
        _ => Err(ApprovalStoreError::CorruptRecord("grant.state")),
    }
}

const fn encode_auto_state(value: AutoApprovalScopeState) -> i64 {
    match value {
        AutoApprovalScopeState::Active => 0,
        AutoApprovalScopeState::Revoked => 1,
        AutoApprovalScopeState::Expired => 2,
    }
}

fn decode_auto_state(value: i64) -> Result<AutoApprovalScopeState, ApprovalStoreError> {
    match value {
        0 => Ok(AutoApprovalScopeState::Active),
        1 => Ok(AutoApprovalScopeState::Revoked),
        2 => Ok(AutoApprovalScopeState::Expired),
        _ => Err(ApprovalStoreError::CorruptRecord("auto_scope.state")),
    }
}

const fn encode_source(value: AuthorizationSource) -> i64 {
    match value {
        AuthorizationSource::ExplicitGrant => 0,
        AuthorizationSource::AutoApprovalScope => 1,
        AuthorizationSource::LegacyPlan06 => 2,
    }
}

fn decode_source(value: i64) -> Result<AuthorizationSource, ApprovalStoreError> {
    match value {
        0 => Ok(AuthorizationSource::ExplicitGrant),
        1 => Ok(AuthorizationSource::AutoApprovalScope),
        _ => Err(ApprovalStoreError::CorruptRecord("grant.source")),
    }
}

fn validate_length(
    field: &'static str,
    actual: i64,
    expected: usize,
) -> Result<(), ApprovalStoreError> {
    if usize::try_from(actual).ok() == Some(expected) {
        Ok(())
    } else {
        Err(ApprovalStoreError::CorruptRecord(field))
    }
}

fn validate_optional_length(
    field: &'static str,
    actual: Option<i64>,
    expected: usize,
) -> Result<(), ApprovalStoreError> {
    actual.map_or(Ok(()), |actual| validate_length(field, actual, expected))
}

fn validate_schema_sql(
    connection: &Connection,
    object_type: &'static str,
    name: &'static str,
    expected: &'static str,
) -> Result<(), ApprovalStoreError> {
    let sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
            params![object_type, name],
            |row| row.get(0),
        )
        .optional()?;
    let sql = sql.ok_or(ApprovalStoreError::CorruptRecord(name))?;
    if normalized_sql(&sql) == normalized_sql(expected) {
        Ok(())
    } else {
        Err(ApprovalStoreError::CorruptRecord(name))
    }
}

fn normalized_sql(value: &str) -> String {
    value
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect()
}

fn validate_index_columns(
    connection: &Connection,
    index: &'static str,
    expected: &[&str],
) -> Result<(), ApprovalStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA index_info({index})"))?;
    let actual = statement
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    if actual
        .iter()
        .map(String::as_str)
        .eq(expected.iter().copied())
    {
        Ok(())
    } else {
        Err(ApprovalStoreError::CorruptRecord(index))
    }
}

fn validate_foreign_keys(
    connection: &Connection,
    table: &'static str,
    expected: usize,
) -> Result<(), ApprovalStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
    if statement.query_map([], |_| Ok(()))?.count() == expected {
        Ok(())
    } else {
        Err(ApprovalStoreError::CorruptRecord(table))
    }
}

#[derive(Debug, Error)]
pub enum ApprovalStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Execution(#[from] ExecutionStoreError),
    #[error(transparent)]
    Goal(#[from] GoalStoreError),
    #[error(transparent)]
    Dag(#[from] DagStoreError),
    #[error("Workspace policy is missing")]
    PolicyMissing,
    #[error("approval request is missing")]
    ApprovalMissing,
    #[error("execution grant is missing")]
    GrantMissing,
    #[error("auto approval scope is missing")]
    AutoScopeMissing,
    #[error("approval identity conflicts with durable state")]
    IdentityConflict,
    #[error("approval Workspace does not match")]
    WorkspaceMismatch,
    #[error("approval policy revision is stale")]
    PolicyRevisionConflict,
    #[error("approval or grant revision is stale")]
    RevisionConflict,
    #[error("approval or grant revision overflowed")]
    RevisionOverflow,
    #[error("approval expiry is invalid")]
    InvalidExpiry,
    #[error("approval transition is invalid")]
    InvalidTransition,
    #[error("execution grant does not match")]
    GrantMismatch,
    #[error("execution grant was replayed")]
    GrantReplay,
    #[error("auto approval scope does not match")]
    AutoScopeMismatch,
    #[error("corrupt approval field {0}")]
    CorruptRecord(&'static str),
}

#[cfg(test)]
mod tests {
    use forge_domain::{
        ExecutionAttribution, ExecutionKind, ExecutionLimits, ExecutionOutputLimit,
        ExecutionProgram, ExecutionRequest, ExecutionTimeoutMillis,
    };

    use super::*;

    fn fixture() -> Result<(Connection, WorkspaceId, ActivityId), Box<dyn std::error::Error>> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE workspace(workspace_id BLOB UNIQUE);
             CREATE TABLE activities(
                activity_id BLOB PRIMARY KEY,
                workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id),
                state INTEGER NOT NULL
             );
             CREATE TABLE executions(
                execution_id BLOB PRIMARY KEY,
                workspace_id BLOB,
                activity_id BLOB,
                state INTEGER,
                mode INTEGER,
                request_digest BLOB,
                cwd BLOB,
                timeout_ms INTEGER,
                output_limit INTEGER,
                workspace_read INTEGER,
                workspace_write INTEGER,
                network INTEGER,
                exit_code INTEGER,
                signal INTEGER,
                duration_ms INTEGER,
                stdout BLOB,
                stdout_total_bytes INTEGER,
                stdout_truncated INTEGER,
                stderr BLOB,
                stderr_total_bytes INTEGER,
                stderr_truncated INTEGER,
                failure_code INTEGER,
                created_at_ms INTEGER,
                updated_at_ms INTEGER,
                revision INTEGER
             );
             CREATE TABLE goal_evidence_refs(
                goal_id BLOB NOT NULL,
                evidence_kind INTEGER NOT NULL,
                evidence_id BLOB NOT NULL,
                associated_at_ms INTEGER NOT NULL,
                UNIQUE(evidence_kind, evidence_id)
             );",
        )?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(1));
        let activity_id = ActivityId::from_uuid(Uuid::from_u128(2));
        connection.execute(
            "INSERT INTO workspace(workspace_id) VALUES (?1)",
            params![workspace_id.into_uuid().as_bytes()],
        )?;
        connection.execute(
            "INSERT INTO activities(activity_id, workspace_id, state) VALUES (?1, ?2, 1)",
            params![
                activity_id.into_uuid().as_bytes(),
                workspace_id.into_uuid().as_bytes()
            ],
        )?;
        create_schema(&connection)?;
        Ok((connection, workspace_id, activity_id))
    }

    fn auth_request(
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    ) -> ExecutionAuthorizationRequest {
        ExecutionAuthorizationRequest::new(
            forge_domain::ExecutionId::from_uuid(Uuid::from_u128(3)),
            workspace_id,
            activity_id,
            ExecutionRequestDigest::from_bytes([4; 32]),
            ExecutionActionClass::DirectStructured,
            RequestedExecutionPermissions::new(ExecutionPermissions::new(true, false, false)),
        )
    }

    #[test]
    fn schema_policy_pending_approve_and_grant_consumption_are_atomic()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        let policy = ensure_policy(&mut connection, workspace_id, TimestampMillis::new(1)?)?;
        assert_eq!(policy, WorkspacePolicy::conservative_default(workspace_id));
        let auth = auth_request(workspace_id, activity_id);
        let pending = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(Uuid::from_u128(5)),
            auth,
            policy.revision(),
            TimestampMillis::new(2)?,
            TimestampMillis::new(100)?,
        )?;
        assert_eq!(insert_pending(&mut connection, &pending)?, pending);
        assert_eq!(insert_pending(&mut connection, &pending)?, pending);
        let (approved, grant) = approve_once(
            &mut connection,
            pending.id(),
            pending.revision(),
            ExecutionGrantId::from_uuid(Uuid::from_u128(6)),
            TimestampMillis::new(3)?,
            TimestampMillis::new(90)?,
        )?;
        assert_eq!(approved.state(), ApprovalRequestState::Approved);
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(auth.execution_id(), workspace_id, activity_id),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(std::path::PathBuf::from("/usr/bin/true"))?,
                arguments: Vec::new(),
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::new(1_024)?,
            ),
            auth.requested().get(),
        )?;
        let begin =
            BeginExecution::from_request(&request, auth.request_digest(), TimestampMillis::new(4)?);
        let (consumed, started) = consume_grant_and_begin_execution(
            &mut connection,
            grant.id(),
            grant.revision(),
            auth,
            &begin,
            TimestampMillis::new(4)?,
            None,
        )?;
        assert_eq!(consumed.state(), ExecutionGrantState::Consumed);
        assert_eq!(started.status(), BeginExecutionStatus::Created);
        assert!(matches!(
            consume_grant_and_begin_execution(
                &mut connection,
                grant.id(),
                grant.revision(),
                auth,
                &begin,
                TimestampMillis::new(5)?,
                None,
            ),
            Err(ApprovalStoreError::GrantMismatch | ApprovalStoreError::GrantReplay)
        ));

        Ok(())
    }

    #[test]
    fn auto_scope_consumption_writes_audit_grant_and_execution_atomically()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        let policy = ensure_policy(&mut connection, workspace_id, TimestampMillis::new(1)?)?;
        let auto_request = ExecutionAuthorizationRequest::new(
            forge_domain::ExecutionId::from_uuid(Uuid::from_u128(20)),
            workspace_id,
            activity_id,
            ExecutionRequestDigest::from_bytes([21; 32]),
            ExecutionActionClass::DiscoveredProjectCommand,
            RequestedExecutionPermissions::new(ExecutionPermissions::new(true, false, false)),
        );
        let scope = AutoApprovalScope::active(
            AutoApprovalScopeId::from_uuid(Uuid::from_u128(22)),
            workspace_id,
            Some(activity_id),
            ExecutionActionClass::DiscoveredProjectCommand,
            ExecutionPermissions::new(true, false, false),
            policy.revision(),
            TimestampMillis::new(100)?,
            AutoApprovalUseLimit::new(1)?,
            AutoApprovalScopeRevision::INITIAL,
        )?;
        let persisted_scope = create_auto_scope(&mut connection, &scope, TimestampMillis::new(2)?)?;
        assert_eq!(persisted_scope, scope);
        let execution_request = ExecutionRequest::new(
            ExecutionAttribution::new(auto_request.execution_id(), workspace_id, activity_id),
            ExecutionKind::Structured {
                program: ExecutionProgram::new(std::path::PathBuf::from("/usr/bin/true"))?,
                arguments: Vec::new(),
            },
            None,
            ExecutionLimits::new(
                ExecutionTimeoutMillis::new(1_000)?,
                ExecutionOutputLimit::new(1_024)?,
            ),
            auto_request.requested().get(),
        )?;
        let auto_begin = BeginExecution::from_request(
            &execution_request,
            auto_request.request_digest(),
            TimestampMillis::new(5)?,
        );
        let result = consume_auto_scope_and_begin_execution(
            &mut connection,
            scope.id(),
            scope.revision(),
            ApprovalRequestId::from_uuid(Uuid::from_u128(23)),
            ExecutionGrantId::from_uuid(Uuid::from_u128(24)),
            auto_request,
            &auto_begin,
            TimestampMillis::new(5)?,
            None,
        )?;
        assert_eq!(result.scope().used_count(), 1);
        assert_eq!(
            result.approval().state(),
            ApprovalRequestState::AutoApproved
        );
        assert_eq!(result.grant().state(), ExecutionGrantState::Consumed);
        assert_eq!(result.begin().status(), BeginExecutionStatus::Created);
        Ok(())
    }

    #[test]
    fn expiry_and_activity_cancel_cleanup_are_bounded_and_scope_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut connection, workspace_id, activity_id) = fixture()?;
        let policy = ensure_policy(&mut connection, workspace_id, TimestampMillis::new(1)?)?;
        let make_request = |execution: u128, digest: u8, action| {
            ExecutionAuthorizationRequest::new(
                forge_domain::ExecutionId::from_uuid(Uuid::from_u128(execution)),
                workspace_id,
                activity_id,
                ExecutionRequestDigest::from_bytes([digest; 32]),
                action,
                RequestedExecutionPermissions::new(ExecutionPermissions::new(true, false, false)),
            )
        };
        let pending = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(Uuid::from_u128(30)),
            make_request(31, 32, ExecutionActionClass::DirectStructured),
            policy.revision(),
            TimestampMillis::new(2)?,
            TimestampMillis::new(10)?,
        )?;
        let persisted = insert_pending(&mut connection, &pending)?;
        assert_eq!(persisted, pending);

        let grant_pending = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(Uuid::from_u128(33)),
            make_request(34, 35, ExecutionActionClass::DirectStructured),
            policy.revision(),
            TimestampMillis::new(2)?,
            TimestampMillis::new(10)?,
        )?;
        let _grant_pending = insert_pending(&mut connection, &grant_pending)?;
        let (_approved, _grant) = approve_once(
            &mut connection,
            grant_pending.id(),
            grant_pending.revision(),
            ExecutionGrantId::from_uuid(Uuid::from_u128(36)),
            TimestampMillis::new(3)?,
            TimestampMillis::new(9)?,
        )?;
        let scope = AutoApprovalScope::active(
            AutoApprovalScopeId::from_uuid(Uuid::from_u128(37)),
            workspace_id,
            Some(activity_id),
            ExecutionActionClass::DiscoveredProjectCommand,
            ExecutionPermissions::new(true, false, false),
            policy.revision(),
            TimestampMillis::new(9)?,
            AutoApprovalUseLimit::new(2)?,
            AutoApprovalScopeRevision::INITIAL,
        )?;
        let _scope = create_auto_scope(&mut connection, &scope, TimestampMillis::new(2)?)?;
        let expired = reconcile_expired_authority(
            &mut connection,
            workspace_id,
            TimestampMillis::new(11)?,
            ExecutionListLimit::new(10)?,
        )?;
        assert_eq!(expired.approvals(), 1);
        assert_eq!(expired.grants(), 1);
        assert_eq!(expired.auto_scopes(), 1);

        let cancel_pending = RegisteredApprovalRequest::pending(
            ApprovalRequestId::from_uuid(Uuid::from_u128(38)),
            make_request(39, 40, ExecutionActionClass::ShellEscape),
            policy.revision(),
            TimestampMillis::new(12)?,
            TimestampMillis::new(100)?,
        )?;
        let _cancel_pending = insert_pending(&mut connection, &cancel_pending)?;
        let cancelled = cancel_activity_authority(
            &mut connection,
            workspace_id,
            activity_id,
            TimestampMillis::new(13)?,
            ExecutionListLimit::new(10)?,
        )?;
        assert_eq!(cancelled.approvals(), 1);
        assert_eq!(cancelled.total(), 1);
        Ok(())
    }
}
