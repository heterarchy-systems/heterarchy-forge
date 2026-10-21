use std::fmt;

use forge_domain::{
    ActivityId, ApprovalDecision, AutoApprovalScope, AutoApprovalScopeId, ExecutionGrant,
    ExecutionListLimit, TimestampMillis, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use uuid::Uuid;

use super::{
    APPROVAL_QUERY, AUTO_SCOPE_QUERY, ApprovalAuthorityCleanupReport, ApprovalStoreError,
    GRANT_QUERY, decode_auto_scope, decode_timestamp,
};

pub(crate) mod stop_receipts;

const MAX_CLEANUP_PAGE_ROWS: usize = 256;
const MAX_CLEANUP_TOTAL_ROWS: usize = 768;

#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalCleanupSelector {
    Workspace,
    Activity(ActivityId),
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalCleanupMode {
    AuthorityCancellation,
    ExpiredOnly,
}

#[must_use]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApprovalCleanupAttemptId(Uuid);

impl ApprovalCleanupAttemptId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }
}

impl fmt::Debug for ApprovalCleanupAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalCleanupAttemptId")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ApprovalCleanupSelector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalCleanupSelector")
            .field(
                "kind",
                &match self {
                    Self::Workspace => "workspace",
                    Self::Activity(_) => "activity",
                },
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AutoScopeSnapshot {
    scope: AutoApprovalScope,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrantSnapshot {
    grant: ExecutionGrant,
    auto_scope_id: Option<AutoApprovalScopeId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApprovalCleanupPlanData {
    approvals: Vec<forge_domain::RegisteredApprovalRequest>,
    grants: Vec<GrantSnapshot>,
    auto_scopes: Vec<AutoScopeSnapshot>,
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalCleanupPlan {
    workspace_id: WorkspaceId,
    selector: ApprovalCleanupSelector,
    mode: ApprovalCleanupMode,
    observed_at: TimestampMillis,
    data: ApprovalCleanupPlanData,
    after: ApprovalCleanupPlanData,
    has_more: bool,
}

#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalCleanupRejection {
    plan: ApprovalCleanupPlan,
    attempt: ApprovalCleanupAttemptId,
}

impl ApprovalCleanupRejection {
    pub fn matches(&self, plan: &ApprovalCleanupPlan, attempt: ApprovalCleanupAttemptId) -> bool {
        self.attempt == attempt && self.plan == *plan
    }
}

impl fmt::Debug for ApprovalCleanupRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalCleanupRejection")
            .field("plan", &self.plan)
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalCleanupApplyOutcome {
    Applied(ApprovalAuthorityCleanupReport),
    RejectedBeforeWrite(ApprovalCleanupRejection),
}

impl fmt::Debug for ApprovalCleanupPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalCleanupPlan")
            .field("workspace_id", &self.workspace_id)
            .field("selector", &self.selector)
            .field("mode", &self.mode)
            .field("observed_at", &self.observed_at)
            .field("approval_count", &self.data.approvals.len())
            .field("grant_count", &self.data.grants.len())
            .field("auto_scope_count", &self.data.auto_scopes.len())
            .field("has_more", &self.has_more)
            .finish_non_exhaustive()
    }
}

impl ApprovalCleanupPlan {
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn selector(&self) -> ApprovalCleanupSelector {
        self.selector
    }

    pub const fn mode(&self) -> ApprovalCleanupMode {
        self.mode
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }

    pub fn is_empty(&self) -> bool {
        self.data.approvals.is_empty()
            && self.data.grants.is_empty()
            && self.data.auto_scopes.is_empty()
    }

    pub fn report(&self) -> ApprovalAuthorityCleanupReport {
        ApprovalAuthorityCleanupReport::from_counts(
            self.data.approvals.len(),
            self.data.grants.len(),
            self.data.auto_scopes.len(),
        )
    }
}

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalCleanupReadback {
    Absent,
    SettledTargetState,
    Mismatch,
}

pub(crate) fn prepare_cleanup_plan(
    connection: &Connection,
    workspace_id: WorkspaceId,
    selector: ApprovalCleanupSelector,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
    mode: ApprovalCleanupMode,
) -> Result<ApprovalCleanupPlan, ApprovalStoreError> {
    let transaction = connection.unchecked_transaction()?;
    prepare_cleanup_plan_in_transaction(
        &transaction,
        workspace_id,
        selector,
        observed_at,
        limit,
        mode,
    )
}

pub(crate) fn prepare_cleanup_plan_in_transaction(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    selector: ApprovalCleanupSelector,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
    mode: ApprovalCleanupMode,
) -> Result<ApprovalCleanupPlan, ApprovalStoreError> {
    validate_limit(limit)?;
    validate_selector(transaction, workspace_id, selector)?;
    if mode == ApprovalCleanupMode::ExpiredOnly {
        ensure_expiry_revisions_available(transaction, workspace_id, selector, observed_at)?;
    }
    let (approvals, approvals_more) = query_approval_page(
        transaction,
        workspace_id,
        selector,
        observed_at,
        limit,
        mode,
    )?;
    let (grants, grants_more) = query_grant_page(
        transaction,
        workspace_id,
        selector,
        observed_at,
        limit,
        mode,
    )?;
    let (auto_scopes, auto_scopes_more) = query_auto_scope_page(
        transaction,
        workspace_id,
        selector,
        observed_at,
        limit,
        mode,
    )?;
    let data = ApprovalCleanupPlanData {
        approvals,
        grants,
        auto_scopes,
    };
    validate_cleanup_bounds(&data, observed_at)?;
    let after = expected_after_data(&data, observed_at, mode)?;
    Ok(ApprovalCleanupPlan {
        workspace_id,
        selector,
        mode,
        observed_at,
        data,
        after,
        has_more: approvals_more || grants_more || auto_scopes_more,
    })
}

pub(crate) fn apply_cleanup_plan(
    connection: &mut Connection,
    workspace_id: WorkspaceId,
    plan: &ApprovalCleanupPlan,
    attempt: ApprovalCleanupAttemptId,
) -> Result<ApprovalCleanupApplyOutcome, ApprovalStoreError> {
    validate_plan_workspace(workspace_id, plan)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Err(error) = validate_before_images(&transaction, plan) {
        let is_rejection = matches!(&error, ApprovalStoreError::CleanupPlanMismatch);
        return match transaction.rollback() {
            Ok(()) if is_rejection => Ok(ApprovalCleanupApplyOutcome::RejectedBeforeWrite(
                ApprovalCleanupRejection {
                    plan: plan.clone(),
                    attempt,
                },
            )),
            Ok(()) => Err(error),
            Err(source) => Err(ApprovalStoreError::CleanupRollbackUnconfirmed {
                source: Box::new(source),
            }),
        };
    }
    if let Err(error) = apply_after_images(&transaction, plan) {
        return match transaction.rollback() {
            Ok(()) => Err(error),
            Err(source) => Err(ApprovalStoreError::CleanupRollbackUnconfirmed {
                source: Box::new(source),
            }),
        };
    }
    transaction
        .commit()
        .map_err(|source| ApprovalStoreError::CleanupCommittedUnconfirmed {
            source: Box::new(source),
        })?;
    Ok(ApprovalCleanupApplyOutcome::Applied(plan.report()))
}

pub(crate) fn observe_cleanup_plan(
    connection: &Connection,
    workspace_id: WorkspaceId,
    plan: &ApprovalCleanupPlan,
) -> Result<ApprovalCleanupReadback, ApprovalStoreError> {
    validate_plan_workspace(workspace_id, plan)?;
    let transaction = connection
        .unchecked_transaction()
        .map_err(readback_sql_error)?;
    let expected = plan.after.clone();
    let mut before_count = 0;
    let mut after_count = 0;
    let total = plan.report().total();

    for before in &plan.data.approvals {
        let current = get_approval_by_id(&transaction, before.id()).map_err(readback_error)?;
        let Some(current) = current else {
            return Ok(ApprovalCleanupReadback::Mismatch);
        };
        if current == *before {
            before_count += 1;
        } else if expected
            .approvals
            .iter()
            .any(|after| after.id() == before.id() && *after == current)
        {
            after_count += 1;
        } else {
            return Ok(ApprovalCleanupReadback::Mismatch);
        }
    }

    for before in &plan.data.grants {
        let current = get_grant_by_id(&transaction, before.grant.id()).map_err(readback_error)?;
        let Some(current) = current else {
            return Ok(ApprovalCleanupReadback::Mismatch);
        };
        if current == *before {
            before_count += 1;
        } else if expected
            .grants
            .iter()
            .any(|after| after.grant.id() == before.grant.id() && *after == current)
        {
            after_count += 1;
        } else {
            return Ok(ApprovalCleanupReadback::Mismatch);
        }
    }

    for before in &plan.data.auto_scopes {
        let current =
            get_auto_scope_by_id(&transaction, before.scope.id()).map_err(readback_error)?;
        let Some(current) = current else {
            return Ok(ApprovalCleanupReadback::Mismatch);
        };
        if current == *before {
            before_count += 1;
        } else if expected
            .auto_scopes
            .iter()
            .any(|after| after.scope.id() == before.scope.id() && *after == current)
        {
            after_count += 1;
        } else {
            return Ok(ApprovalCleanupReadback::Mismatch);
        }
    }

    if total == 0 || before_count == total {
        Ok(ApprovalCleanupReadback::Absent)
    } else if after_count == total {
        Ok(ApprovalCleanupReadback::SettledTargetState)
    } else {
        Ok(ApprovalCleanupReadback::Mismatch)
    }
}

fn validate_limit(limit: ExecutionListLimit) -> Result<(), ApprovalStoreError> {
    if usize::from(limit.get()) > MAX_CLEANUP_PAGE_ROWS {
        Err(ApprovalStoreError::CleanupLimitExceeded)
    } else {
        Ok(())
    }
}

fn validate_plan_workspace(
    workspace_id: WorkspaceId,
    plan: &ApprovalCleanupPlan,
) -> Result<(), ApprovalStoreError> {
    if plan.workspace_id == workspace_id {
        Ok(())
    } else {
        Err(ApprovalStoreError::WorkspaceMismatch)
    }
}

fn validate_selector(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    selector: ApprovalCleanupSelector,
) -> Result<(), ApprovalStoreError> {
    let ApprovalCleanupSelector::Activity(activity_id) = selector else {
        return Ok(());
    };
    let actual = transaction
        .query_row(
            "SELECT workspace_id FROM activities WHERE activity_id = ?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    let Some(actual) = actual else {
        return Err(ApprovalStoreError::WorkspaceMismatch);
    };
    let actual = super::decode_workspace_id(&actual)?;
    if actual == workspace_id {
        Ok(())
    } else {
        Err(ApprovalStoreError::WorkspaceMismatch)
    }
}

fn ensure_expiry_revisions_available(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    selector: ApprovalCleanupSelector,
    observed_at: TimestampMillis,
) -> Result<(), ApprovalStoreError> {
    let activity_id = selector_activity(selector);
    for table in [
        "approval_requests",
        "execution_grants",
        "auto_approval_scopes",
    ] {
        let sql = format!(
            "SELECT EXISTS(SELECT 1 FROM {table}
             WHERE workspace_id = ?1 AND state = 0
               AND (?2 IS NULL OR activity_id = ?2)
               AND expires_at_ms <= ?3 AND revision = 9223372036854775807)"
        );
        let overflow: bool = transaction.query_row(
            &sql,
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id.clone(),
                observed_at.get(),
            ],
            |row| row.get(0),
        )?;
        if overflow {
            return Err(ApprovalStoreError::RevisionOverflow);
        }
    }
    Ok(())
}

fn query_approval_page(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    selector: ApprovalCleanupSelector,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
    mode: ApprovalCleanupMode,
) -> Result<(Vec<forge_domain::RegisteredApprovalRequest>, bool), ApprovalStoreError> {
    let activity_id = selector_activity(selector);
    let sql = format!(
        "{APPROVAL_QUERY} WHERE workspace_id = ?1 AND state = 0
         AND (?2 IS NULL OR activity_id = ?2)
         AND (?3 = 0 OR expires_at_ms <= ?4)
         ORDER BY expires_at_ms ASC, approval_id ASC LIMIT ?5"
    );
    let mut statement = transaction.prepare(&sql)?;
    let rows = statement
        .query_map(
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id,
                mode_flag(mode),
                observed_at.get(),
                page_limit(limit),
            ],
            super::decode_approval,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(truncate_page(rows, limit))
}

fn query_grant_page(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    selector: ApprovalCleanupSelector,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
    mode: ApprovalCleanupMode,
) -> Result<(Vec<GrantSnapshot>, bool), ApprovalStoreError> {
    let activity_id = selector_activity(selector);
    let sql = format!(
        "{GRANT_QUERY} WHERE workspace_id = ?1 AND state = 0
         AND (?2 IS NULL OR activity_id = ?2)
         AND (?3 = 0 OR expires_at_ms <= ?4)
         ORDER BY expires_at_ms ASC, grant_id ASC LIMIT ?5"
    );
    let mut statement = transaction.prepare(&sql)?;
    let rows = statement
        .query_map(
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id,
                mode_flag(mode),
                observed_at.get(),
                page_limit(limit),
            ],
            |row| {
                let grant = super::decode_grant(row)?;
                let auto_scope_id = row
                    .get::<_, Option<Vec<u8>>>(6)?
                    .map(|bytes| {
                        super::decode_uuid("grant.auto_scope_id", &bytes)
                            .map(AutoApprovalScopeId::from_uuid)
                    })
                    .transpose()
                    .map_err(super::conversion_error)?;
                Ok::<GrantSnapshot, rusqlite::Error>(GrantSnapshot {
                    grant,
                    auto_scope_id,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(truncate_page(rows, limit))
}

fn query_auto_scope_page(
    transaction: &Transaction<'_>,
    workspace_id: WorkspaceId,
    selector: ApprovalCleanupSelector,
    observed_at: TimestampMillis,
    limit: ExecutionListLimit,
    mode: ApprovalCleanupMode,
) -> Result<(Vec<AutoScopeSnapshot>, bool), ApprovalStoreError> {
    let activity_id = selector_activity(selector);
    let sql = format!(
        "{} WHERE workspace_id = ?1 AND state = 0
         AND (?2 IS NULL OR activity_id = ?2)
         AND (?3 = 0 OR expires_at_ms <= ?4)
         ORDER BY expires_at_ms ASC, scope_id ASC LIMIT ?5",
        auto_scope_query_with_timestamps()
    );
    let mut statement = transaction.prepare(&sql)?;
    let rows = statement
        .query_map(
            params![
                workspace_id.into_uuid().as_bytes(),
                activity_id,
                mode_flag(mode),
                observed_at.get(),
                page_limit(limit),
            ],
            |row| {
                Ok(AutoScopeSnapshot {
                    scope: decode_auto_scope(row)?,
                    created_at: decode_timestamp("auto_scope.created_at", row.get(16)?)
                        .map_err(super::conversion_error)?,
                    updated_at: decode_timestamp("auto_scope.updated_at", row.get(17)?)
                        .map_err(super::conversion_error)?,
                })
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(truncate_page(rows, limit))
}

fn selector_activity(selector: ApprovalCleanupSelector) -> Option<Vec<u8>> {
    match selector {
        ApprovalCleanupSelector::Workspace => None,
        ApprovalCleanupSelector::Activity(activity_id) => {
            Some(activity_id.into_uuid().into_bytes().to_vec())
        }
    }
}

fn auto_scope_query_with_timestamps() -> String {
    AUTO_SCOPE_QUERY.replacen(
        "\n    FROM auto_approval_scopes",
        ", created_at_ms, updated_at_ms\n    FROM auto_approval_scopes",
        1,
    )
}

fn page_limit(limit: ExecutionListLimit) -> i64 {
    i64::from(limit.get()) + 1
}

const fn mode_flag(mode: ApprovalCleanupMode) -> i64 {
    match mode {
        ApprovalCleanupMode::AuthorityCancellation => 0,
        ApprovalCleanupMode::ExpiredOnly => 1,
    }
}

fn truncate_page<T>(mut rows: Vec<T>, limit: ExecutionListLimit) -> (Vec<T>, bool) {
    let has_more = rows.len() > usize::from(limit.get());
    if has_more {
        rows.pop();
    }
    (rows, has_more)
}

fn validate_cleanup_bounds(
    data: &ApprovalCleanupPlanData,
    observed_at: TimestampMillis,
) -> Result<(), ApprovalStoreError> {
    for scope in &data.auto_scopes {
        if observed_at.get() < scope.created_at.get() {
            return Err(ApprovalStoreError::InvalidTransition);
        }
    }
    if data.approvals.len() + data.grants.len() + data.auto_scopes.len() > MAX_CLEANUP_TOTAL_ROWS {
        return Err(ApprovalStoreError::CleanupLimitExceeded);
    }
    Ok(())
}

fn expected_after_data(
    data: &ApprovalCleanupPlanData,
    observed_at: TimestampMillis,
    mode: ApprovalCleanupMode,
) -> Result<ApprovalCleanupPlanData, ApprovalStoreError> {
    Ok(ApprovalCleanupPlanData {
        approvals: data
            .approvals
            .iter()
            .map(
                |approval| -> Result<forge_domain::RegisteredApprovalRequest, ApprovalStoreError> {
                    expected_approval_after(approval, observed_at, mode)
                },
            )
            .collect::<Result<Vec<_>, _>>()?,
        grants: data
            .grants
            .iter()
            .map(|grant| -> Result<GrantSnapshot, ApprovalStoreError> {
                Ok(GrantSnapshot {
                    grant: expected_grant_after(&grant.grant, observed_at, mode)?,
                    auto_scope_id: grant.auto_scope_id,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        auto_scopes: data
            .auto_scopes
            .iter()
            .map(|scope| -> Result<AutoScopeSnapshot, ApprovalStoreError> {
                Ok(AutoScopeSnapshot {
                    scope: expected_auto_scope_after(&scope.scope, observed_at, mode)?,
                    created_at: scope.created_at,
                    updated_at: observed_at,
                })
            })
            .collect::<Result<Vec<_>, ApprovalStoreError>>()?,
    })
}

fn expected_approval_after(
    approval: &forge_domain::RegisteredApprovalRequest,
    observed_at: TimestampMillis,
    mode: ApprovalCleanupMode,
) -> Result<forge_domain::RegisteredApprovalRequest, ApprovalStoreError> {
    let decision = match mode {
        ApprovalCleanupMode::AuthorityCancellation
            if observed_at.get() < approval.expires_at().get() =>
        {
            ApprovalDecision::Cancel
        }
        ApprovalCleanupMode::AuthorityCancellation | ApprovalCleanupMode::ExpiredOnly => {
            ApprovalDecision::Expire
        }
    };
    approval
        .decide(decision, approval.revision(), observed_at)
        .map_err(map_transition_error)
}

fn expected_grant_after(
    grant: &ExecutionGrant,
    observed_at: TimestampMillis,
    mode: ApprovalCleanupMode,
) -> Result<ExecutionGrant, ApprovalStoreError> {
    match mode {
        ApprovalCleanupMode::AuthorityCancellation
            if observed_at.get() < grant.expires_at().get() =>
        {
            grant.revoke(grant.revision()).map_err(map_transition_error)
        }
        ApprovalCleanupMode::AuthorityCancellation | ApprovalCleanupMode::ExpiredOnly => grant
            .expire(grant.revision(), observed_at)
            .map_err(map_transition_error),
    }
}

fn expected_auto_scope_after(
    scope: &AutoApprovalScope,
    observed_at: TimestampMillis,
    mode: ApprovalCleanupMode,
) -> Result<AutoApprovalScope, ApprovalStoreError> {
    match mode {
        ApprovalCleanupMode::AuthorityCancellation
            if observed_at.get() < scope.expires_at().get() =>
        {
            scope.revoke(scope.revision()).map_err(map_transition_error)
        }
        ApprovalCleanupMode::AuthorityCancellation | ApprovalCleanupMode::ExpiredOnly => scope
            .expire(scope.revision(), observed_at)
            .map_err(map_transition_error),
    }
}

fn map_transition_error(error: forge_domain::ApprovalDomainError) -> ApprovalStoreError {
    match error {
        forge_domain::ApprovalDomainError::RevisionOverflow => ApprovalStoreError::RevisionOverflow,
        forge_domain::ApprovalDomainError::TimestampOrder
        | forge_domain::ApprovalDomainError::NotExpired
        | forge_domain::ApprovalDomainError::ApprovalTerminal
        | forge_domain::ApprovalDomainError::Expired
        | forge_domain::ApprovalDomainError::GrantUnavailable
        | forge_domain::ApprovalDomainError::GrantMismatch
        | forge_domain::ApprovalDomainError::RevisionConflict
        | forge_domain::ApprovalDomainError::AutoScopeMismatch
        | forge_domain::ApprovalDomainError::InvalidExpiry
        | forge_domain::ApprovalDomainError::InvalidApprovalEvidence
        | forge_domain::ApprovalDomainError::InvalidGrantEvidence
        | forge_domain::ApprovalDomainError::PartialPermissionGrant
        | forge_domain::ApprovalDomainError::UseCountOverflow
        | forge_domain::ApprovalDomainError::InvalidUseLimit { .. } => {
            ApprovalStoreError::InvalidTransition
        }
    }
}

fn validate_before_images(
    transaction: &Transaction<'_>,
    plan: &ApprovalCleanupPlan,
) -> Result<(), ApprovalStoreError> {
    for before in &plan.data.approvals {
        let current = get_approval_by_id(transaction, before.id())?
            .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
        if current != *before || !matches_selector(plan, Some(current.request().activity_id())) {
            return Err(ApprovalStoreError::CleanupPlanMismatch);
        }
    }
    for before in &plan.data.grants {
        let current = get_grant_by_id(transaction, before.grant.id())?
            .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
        if current != *before
            || !matches_selector(plan, Some(current.grant.request().activity_id()))
        {
            return Err(ApprovalStoreError::CleanupPlanMismatch);
        }
    }
    for before in &plan.data.auto_scopes {
        let current = get_auto_scope_by_id(transaction, before.scope.id())?
            .ok_or(ApprovalStoreError::CleanupPlanMismatch)?;
        if current != *before || !matches_selector(plan, current.scope.activity_id()) {
            return Err(ApprovalStoreError::CleanupPlanMismatch);
        }
    }
    Ok(())
}

fn matches_selector(plan: &ApprovalCleanupPlan, activity_id: Option<ActivityId>) -> bool {
    match plan.selector {
        ApprovalCleanupSelector::Workspace => true,
        ApprovalCleanupSelector::Activity(expected) => activity_id == Some(expected),
    }
}

fn apply_after_images(
    transaction: &Transaction<'_>,
    plan: &ApprovalCleanupPlan,
) -> Result<(), ApprovalStoreError> {
    let expected = plan.after.clone();
    for (before, after) in plan.data.approvals.iter().zip(expected.approvals) {
        let changed = transaction.execute(
            "UPDATE approval_requests SET state = ?1, decided_at_ms = ?2, revision = ?3
             WHERE approval_id = ?4 AND workspace_id = ?5 AND activity_id = ?6
               AND state = 0 AND revision = ?7",
            params![
                super::encode_approval_state(after.state()),
                after.decided_at().map(TimestampMillis::get),
                after.revision().get(),
                before.id().into_uuid().as_bytes(),
                plan.workspace_id.into_uuid().as_bytes(),
                before.request().activity_id().into_uuid().as_bytes(),
                before.revision().get(),
            ],
        )?;
        if changed != 1 {
            return Err(ApprovalStoreError::RevisionConflict);
        }
    }
    for (before, after) in plan.data.grants.iter().zip(expected.grants) {
        let changed = transaction.execute(
            "UPDATE execution_grants SET state = ?1, revision = ?2
             WHERE grant_id = ?3 AND approval_id = ?4 AND workspace_id = ?5
               AND activity_id = ?6 AND execution_id = ?7
               AND ((?8 IS NULL AND auto_scope_id IS NULL) OR auto_scope_id = ?8)
               AND state = 0 AND revision = ?9",
            params![
                super::encode_grant_state(after.grant.state()),
                after.grant.revision().get(),
                before.grant.id().into_uuid().as_bytes(),
                before.grant.approval_id().into_uuid().as_bytes(),
                plan.workspace_id.into_uuid().as_bytes(),
                before.grant.request().activity_id().into_uuid().as_bytes(),
                before.grant.request().execution_id().into_uuid().as_bytes(),
                before
                    .auto_scope_id
                    .map(|id| id.into_uuid().into_bytes().to_vec()),
                before.grant.revision().get(),
            ],
        )?;
        if changed != 1 {
            return Err(ApprovalStoreError::RevisionConflict);
        }
    }
    for (before, after) in plan.data.auto_scopes.iter().zip(expected.auto_scopes) {
        let activity_id = before
            .scope
            .activity_id()
            .map(|value| value.into_uuid().into_bytes().to_vec());
        let changed = transaction.execute(
            "UPDATE auto_approval_scopes SET state = ?1, updated_at_ms = ?2, revision = ?3
             WHERE scope_id = ?4 AND workspace_id = ?5
               AND ((?6 IS NULL AND activity_id IS NULL) OR activity_id = ?6)
               AND state = 0 AND revision = ?7",
            params![
                super::encode_auto_state(after.scope.state()),
                plan.observed_at.get(),
                after.scope.revision().get(),
                before.scope.id().into_uuid().as_bytes(),
                plan.workspace_id.into_uuid().as_bytes(),
                activity_id,
                before.scope.revision().get(),
            ],
        )?;
        if changed != 1 {
            return Err(ApprovalStoreError::RevisionConflict);
        }
    }
    Ok(())
}

fn get_approval_by_id(
    transaction: &Connection,
    id: forge_domain::ApprovalRequestId,
) -> Result<Option<forge_domain::RegisteredApprovalRequest>, ApprovalStoreError> {
    transaction
        .query_row(
            &format!("{APPROVAL_QUERY} WHERE approval_id = ?1"),
            params![id.into_uuid().as_bytes()],
            super::decode_approval,
        )
        .optional()
        .map_err(ApprovalStoreError::from)
}

fn get_grant_by_id(
    transaction: &Connection,
    id: forge_domain::ExecutionGrantId,
) -> Result<Option<GrantSnapshot>, ApprovalStoreError> {
    transaction
        .query_row(
            &format!("{GRANT_QUERY} WHERE grant_id = ?1"),
            params![id.into_uuid().as_bytes()],
            |row| {
                let grant = super::decode_grant(row)?;
                let auto_scope_id = row
                    .get::<_, Option<Vec<u8>>>(6)?
                    .map(|bytes| {
                        super::decode_uuid("grant.auto_scope_id", &bytes)
                            .map(AutoApprovalScopeId::from_uuid)
                    })
                    .transpose()
                    .map_err(super::conversion_error)?;
                Ok::<GrantSnapshot, rusqlite::Error>(GrantSnapshot {
                    grant,
                    auto_scope_id,
                })
            },
        )
        .optional()
        .map_err(ApprovalStoreError::from)
}

fn get_auto_scope_by_id(
    transaction: &Connection,
    id: forge_domain::AutoApprovalScopeId,
) -> Result<Option<AutoScopeSnapshot>, ApprovalStoreError> {
    let sql = format!("{} WHERE scope_id = ?1", auto_scope_query_with_timestamps());
    transaction
        .query_row(&sql, params![id.into_uuid().as_bytes()], |row| {
            Ok(AutoScopeSnapshot {
                scope: decode_auto_scope(row)?,
                created_at: decode_timestamp("auto_scope.created_at", row.get(16)?)
                    .map_err(super::conversion_error)?,
                updated_at: decode_timestamp("auto_scope.updated_at", row.get(17)?)
                    .map_err(super::conversion_error)?,
            })
        })
        .optional()
        .map_err(ApprovalStoreError::from)
}

fn readback_error(error: ApprovalStoreError) -> ApprovalStoreError {
    match error {
        ApprovalStoreError::Sqlite(source) => ApprovalStoreError::CleanupReadbackUnavailable {
            source: Box::new(source),
        },
        other => other,
    }
}

fn readback_sql_error(source: rusqlite::Error) -> ApprovalStoreError {
    ApprovalStoreError::CleanupReadbackUnavailable {
        source: Box::new(source),
    }
}

#[cfg(test)]
mod tests;
