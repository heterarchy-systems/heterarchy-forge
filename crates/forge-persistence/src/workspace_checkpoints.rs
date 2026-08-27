//! Workspace-local Git checkpoint and compare-and-set restore journals.
//!
//! Checkpoints retain only bounded metadata and Git object identifiers.  The
//! Git object store and the filesystem remain external effect authorities; no
//! raw file content is admitted to `SQLite`.  A checkpoint/restore transition is
//! persisted in a short `SQLite` transaction after the corresponding pure
//! domain projection has been calculated by its caller.

mod codec;
mod schema;

use codec::{
    EncodedCheckpoint, decode_change_set_id, decode_checkpoint_id, decode_checkpoint_row,
    decode_hash, decode_restore_row, decode_size, encode_checkpoint, encode_restore,
    validate_exact_length, validate_optional_exact_length, validate_path_length_from_sql,
};

use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;

use forge_domain::{
    ChangeSetId, CheckpointFileMode, CheckpointId, CheckpointObservedPathState,
    CheckpointPathState, CheckpointRestoreId, CheckpointRestoreRevision, CheckpointRestoreState,
    CheckpointRevision, CheckpointState, FileContentHash, GitBlobId, GitCommitId,
    RegisteredCheckpoint, RegisteredCheckpointRestore, WorkspaceId,
};
use rusqlite::{
    Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params, params_from_iter,
    types::Value,
};
use thiserror::Error;
use uuid::Uuid;

const ID_BYTES: usize = 16;
const ID_BYTES_I64: i64 = 16;
const SHA1_BYTES: usize = 20;
const SHA1_BYTES_I64: i64 = 20;
const HASH_BYTES: usize = FileContentHash::BYTE_LEN;
const HASH_BYTES_I64: i64 = 32;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_LIST_ROWS: u32 = 1_000;

/// Maximum durable checkpoint rows admitted to one read-only Doctor projection.
pub const CHECKPOINT_DOCTOR_MAX_REFERENCES: usize = 256;
const CHECKPOINT_DOCTOR_PROBE_REFERENCES: u32 = 257;

/// Bounded, metadata-only checkpoint reference projection for owned-store
/// Doctor composition.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointDoctorReport {
    references: Vec<CheckpointDoctorReference>,
    truncated: bool,
}

impl CheckpointDoctorReport {
    const fn new(references: Vec<CheckpointDoctorReference>, truncated: bool) -> Self {
        Self {
            references,
            truncated,
        }
    }

    pub fn references(&self) -> &[CheckpointDoctorReference] {
        &self.references
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

/// One durable checkpoint and its expected Forge-owned PRE/POST objects.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointDoctorReference {
    checkpoint_id: CheckpointId,
    state: CheckpointState,
    pre: CheckpointDoctorSnapshotReference,
    post: Option<CheckpointDoctorSnapshotReference>,
}

impl CheckpointDoctorReference {
    pub const fn checkpoint_id(self) -> CheckpointId {
        self.checkpoint_id
    }

    pub const fn state(self) -> CheckpointState {
        self.state
    }

    pub const fn pre(self) -> CheckpointDoctorSnapshotReference {
        self.pre
    }

    pub const fn post(self) -> Option<CheckpointDoctorSnapshotReference> {
        self.post
    }
}

/// Expected commit and optional regular-file blob for one checkpoint side.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointDoctorSnapshotReference {
    commit: GitCommitId,
    blob: Option<GitBlobId>,
}

impl CheckpointDoctorSnapshotReference {
    const fn from_state(commit: GitCommitId, state: &CheckpointPathState) -> Self {
        let blob = match state {
            CheckpointPathState::Absent => None,
            CheckpointPathState::Regular { blob, .. } => Some(*blob),
        };
        Self { commit, blob }
    }

    pub const fn commit(self) -> GitCommitId {
        self.commit
    }

    pub const fn blob(self) -> Option<GitBlobId> {
        self.blob
    }
}

const CHECKPOINT_QUERY: &str = "SELECT
        length(CAST(checkpoint_id AS BLOB)), length(CAST(changeset_id AS BLOB)),
        length(CAST(workspace_id AS BLOB)), length(CAST(activity_id AS BLOB)),
        length(CAST(relative_path AS BLOB)), length(CAST(pre_blob AS BLOB)),
        length(CAST(pre_hash AS BLOB)), length(CAST(pre_commit AS BLOB)),
        length(CAST(post_blob AS BLOB)), length(CAST(post_hash AS BLOB)),
        length(CAST(post_commit AS BLOB)), checkpoint_id, changeset_id, workspace_id,
        activity_id, workspace_revision, relative_path, object_format, state,
        pre_state, pre_blob, pre_hash, pre_size, pre_mode, pre_commit, post_state,
        post_blob, post_hash, post_size, post_mode, post_commit, created_at_ms,
        updated_at_ms, revision FROM checkpoints";

const RESTORE_QUERY: &str = "SELECT
        length(CAST(restore_id AS BLOB)), length(CAST(checkpoint_id AS BLOB)),
        length(CAST(workspace_id AS BLOB)), length(CAST(expected_post_hash AS BLOB)),
        length(CAST(inverse_blob AS BLOB)), length(CAST(inverse_hash AS BLOB)),
        restore_id, checkpoint_id, workspace_id, expected_checkpoint_revision,
        expected_post_state, expected_post_hash, expected_post_size, expected_post_mode,
        inverse_kind, inverse_blob, inverse_hash, inverse_size, inverse_mode, state,
        failure_code, created_at_ms, updated_at_ms, revision,
        length(CAST(initiator_runtime_instance_id AS BLOB)),
        length(CAST(activity_id AS BLOB)),
        length(CAST(approval_request_id AS BLOB)),
        length(CAST(maintenance_owner AS BLOB)),
        initiator_runtime_instance_id, activity_id, approval_request_id,
        maintenance_owner, maintenance_lease_epoch FROM checkpoint_restores";

pub(crate) fn create_schema(connection: &Connection) -> Result<(), CheckpointStoreError> {
    schema::create_schema(connection)
}

pub(crate) fn migrate_v11_to_v12(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), CheckpointStoreError> {
    schema::migrate_v11_to_v12(connection, next_schema_version)
}

pub(crate) fn migrate_v7_to_v8(
    connection: &mut Connection,
    next_schema_version: i64,
) -> Result<(), CheckpointStoreError> {
    schema::migrate_v7_to_v8(connection, next_schema_version)
}

pub(crate) fn schema_objects() -> [(&'static str, &'static str); 6] {
    schema::objects()
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), CheckpointStoreError> {
    schema::validate_current(connection)
}

pub(crate) fn validate_schema_without_restore_provenance(
    connection: &Connection,
) -> Result<(), CheckpointStoreError> {
    schema::validate_v11(connection)
}

/// Insert a Starting checkpoint.  Retries with the same complete projection
/// are idempotent; a different Checkpoint for the same `ChangeSet` is rejected.
pub(crate) fn insert_checkpoint_in_transaction(
    transaction: &Transaction<'_>,
    checkpoint: &RegisteredCheckpoint,
) -> Result<RegisteredCheckpoint, CheckpointStoreError> {
    if checkpoint.state() != CheckpointState::Starting {
        return Err(CheckpointStoreError::InvalidTransition);
    }
    let encoded = encode_checkpoint(checkpoint)?;
    validate_checkpoint_change_set(transaction, checkpoint, true)?;
    let existing_by_id = get_checkpoint_tx(transaction, checkpoint.id())?;
    if let Some(existing) = existing_by_id {
        if existing == *checkpoint {
            return Ok(existing);
        }
        return Err(CheckpointStoreError::IdentityConflict);
    }
    if query_checkpoint_id_by_change_set(transaction, checkpoint.change_set_id())?.is_some() {
        return Err(CheckpointStoreError::IdentityConflict);
    }
    transaction.execute(
        "INSERT INTO checkpoints (
            checkpoint_id, changeset_id, workspace_id, activity_id, workspace_revision,
            relative_path, object_format, state, pre_state, pre_blob, pre_hash, pre_size,
            pre_mode, pre_commit, post_state, post_blob, post_hash, post_size, post_mode,
            post_commit, created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                   NULL, NULL, NULL, NULL, NULL, NULL, ?15, ?15, ?16)",
        params![
            encoded.id,
            encoded.change_set_id,
            encoded.workspace_id,
            encoded.activity_id,
            encoded.workspace_revision,
            encoded.path,
            encoded.object_format,
            encoded.state,
            encoded.pre.state,
            encoded.pre.blob,
            encoded.pre.hash,
            encoded.pre.size,
            encoded.pre.mode,
            encoded.pre_commit,
            encoded.created_at,
            encoded.revision,
        ],
    )?;
    let result = get_checkpoint_tx(transaction, checkpoint.id())?
        .ok_or(CheckpointStoreError::RecordMissing)?;
    Ok(result)
}

#[cfg(test)]
fn insert_checkpoint(
    connection: &mut Connection,
    checkpoint: &RegisteredCheckpoint,
) -> Result<RegisteredCheckpoint, CheckpointStoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = insert_checkpoint_in_transaction(&transaction, checkpoint)?;
    transaction.commit()?;
    Ok(result)
}

/// Compare-and-set a Starting checkpoint to a Ready domain projection.
pub(crate) fn complete_checkpoint(
    connection: &mut Connection,
    checkpoint: &RegisteredCheckpoint,
    expected_revision: CheckpointRevision,
) -> Result<RegisteredCheckpoint, CheckpointStoreError> {
    if checkpoint.state() != CheckpointState::Ready {
        return Err(CheckpointStoreError::InvalidTransition);
    }
    let encoded = encode_checkpoint(checkpoint)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = get_checkpoint_tx(&transaction, checkpoint.id())?
        .ok_or(CheckpointStoreError::RecordMissing)?;
    if current.state() != CheckpointState::Starting {
        let expected_next = expected_revision
            .checked_next()
            .map_err(|_| CheckpointStoreError::RevisionOverflow)?;
        if current.revision() != expected_next {
            return Err(CheckpointStoreError::RevisionConflict);
        }
        if current == *checkpoint {
            transaction.commit()?;
            return Ok(current);
        }
        return Err(CheckpointStoreError::IdentityConflict);
    }
    if current.revision() != expected_revision {
        return Err(CheckpointStoreError::RevisionConflict);
    }
    validate_checkpoint_immutable(&current, checkpoint)?;
    if checkpoint.revision()
        != expected_revision
            .checked_next()
            .map_err(|_| CheckpointStoreError::RevisionOverflow)?
    {
        return Err(CheckpointStoreError::RevisionConflict);
    }
    if checkpoint.timestamps().created_at() != current.timestamps().created_at()
        || checkpoint.timestamps().updated_at().get() < current.timestamps().created_at().get()
    {
        return Err(CheckpointStoreError::TimestampOrder);
    }
    validate_checkpoint_completion(&transaction, checkpoint)?;
    let EncodedCheckpoint {
        id,
        post,
        post_commit,
        updated_at,
        revision,
        ..
    } = encoded;
    let (post_state, post_blob, post_hash, post_size, post_mode) = post
        .map_or((None, None, None, None, None), |post| {
            (Some(post.state), post.blob, post.hash, post.size, post.mode)
        });
    let changed = transaction.execute(
        "UPDATE checkpoints SET state = 1, post_state = ?1, post_blob = ?2,
             post_hash = ?3, post_size = ?4, post_mode = ?5, post_commit = ?6,
             updated_at_ms = ?7, revision = ?8
         WHERE checkpoint_id = ?9 AND state = 0 AND revision = ?10",
        params![
            post_state,
            post_blob,
            post_hash,
            post_size,
            post_mode,
            post_commit,
            updated_at,
            revision,
            id,
            expected_revision.get(),
        ],
    )?;
    if changed != 1 {
        return Err(CheckpointStoreError::RevisionConflict);
    }
    let result = get_checkpoint_tx(&transaction, checkpoint.id())?
        .ok_or(CheckpointStoreError::RecordMissing)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn get_checkpoint(
    connection: &Connection,
    id: CheckpointId,
) -> Result<Option<RegisteredCheckpoint>, CheckpointStoreError> {
    let mut statement =
        connection.prepare(&format!("{CHECKPOINT_QUERY} WHERE checkpoint_id = ?1"))?;
    let mut rows = statement.query(params![id.into_uuid().as_bytes()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    decode_checkpoint_row(connection, row, None).map(Some)
}

pub(crate) fn list_checkpoints(
    connection: &Connection,
    workspace_id: WorkspaceId,
    limit: u32,
) -> Result<Vec<RegisteredCheckpoint>, CheckpointStoreError> {
    validate_limit(limit)?;
    let transaction = connection.unchecked_transaction()?;
    let bindings = preload_checkpoint_bindings(&transaction, workspace_id, limit)?;
    let mut statement = transaction.prepare(&format!(
        "{CHECKPOINT_QUERY} WHERE workspace_id = ?1
         ORDER BY created_at_ms DESC, checkpoint_id DESC LIMIT ?2"
    ))?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        i64::from(limit)
    ])?;
    let mut records = Vec::with_capacity(limit as usize);
    while let Some(row) = rows.next()? {
        let change_set_bytes: Vec<u8> = row.get(12)?;
        let change_set_id = decode_change_set_id(&change_set_bytes)?;
        let binding = bindings
            .get(&change_set_id)
            .ok_or(CheckpointStoreError::AttributionMismatch)?;
        records.push(decode_checkpoint_row(&transaction, row, Some(binding))?);
    }
    drop(rows);
    drop(statement);
    transaction.commit()?;
    Ok(records)
}

/// Read a deterministic bounded projection of checkpoint rows for owned-store
/// Doctor composition.
///
/// `list_checkpoints` performs one bounded row query plus one bounded binding
/// preload, so this path never issues a per-checkpoint `SQLite` lookup.
pub(crate) fn doctor_references(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<CheckpointDoctorReport, CheckpointStoreError> {
    let mut checkpoints =
        list_checkpoints(connection, workspace_id, CHECKPOINT_DOCTOR_PROBE_REFERENCES)?;
    checkpoints.sort_by_key(RegisteredCheckpoint::id);
    let truncated = checkpoints.len() > CHECKPOINT_DOCTOR_MAX_REFERENCES;
    checkpoints.truncate(CHECKPOINT_DOCTOR_MAX_REFERENCES);
    let references = checkpoints
        .iter()
        .map(doctor_reference_from_checkpoint)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CheckpointDoctorReport::new(references, truncated))
}

fn doctor_reference_from_checkpoint(
    checkpoint: &RegisteredCheckpoint,
) -> Result<CheckpointDoctorReference, CheckpointStoreError> {
    let pre =
        CheckpointDoctorSnapshotReference::from_state(checkpoint.pre_commit(), checkpoint.pre());
    let post = match (
        checkpoint.state(),
        checkpoint.post(),
        checkpoint.post_commit(),
    ) {
        (CheckpointState::Starting, None, None) => None,
        (CheckpointState::Ready, Some(state), Some(commit)) => {
            Some(CheckpointDoctorSnapshotReference::from_state(commit, state))
        }
        _ => return Err(CheckpointStoreError::CorruptRecord("checkpoint.doctor")),
    };
    Ok(CheckpointDoctorReference {
        checkpoint_id: checkpoint.id(),
        state: checkpoint.state(),
        pre,
        post,
    })
}

/// Insert a Starting restore journal after the pure restore plan has passed
/// its exact POST CAS check.
pub(crate) fn insert_checkpoint_restore(
    connection: &mut Connection,
    restore: &RegisteredCheckpointRestore,
) -> Result<RegisteredCheckpointRestore, CheckpointStoreError> {
    if restore.state() != CheckpointRestoreState::Starting {
        return Err(CheckpointStoreError::InvalidTransition);
    }
    let encoded = encode_restore(restore)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    validate_restore_checkpoint(&transaction, restore)?;
    let existing = get_restore_tx(&transaction, restore.id())?;
    if let Some(existing) = existing {
        if existing == *restore {
            transaction.commit()?;
            return Ok(existing);
        }
        return Err(CheckpointStoreError::IdentityConflict);
    }
    transaction.execute(
        "INSERT INTO checkpoint_restores (
            restore_id, checkpoint_id, workspace_id, expected_checkpoint_revision,
            initiator_runtime_instance_id, activity_id, approval_request_id,
            maintenance_owner, maintenance_lease_epoch,
            expected_post_state, expected_post_hash, expected_post_size, expected_post_mode,
            inverse_kind, inverse_blob, inverse_hash, inverse_size, inverse_mode, state,
            failure_code, created_at_ms, updated_at_ms, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                   ?16, ?17, ?18, ?19, NULL, ?20, ?20, ?21)",
        params![
            encoded.id,
            encoded.checkpoint_id,
            encoded.workspace_id,
            encoded.expected_checkpoint_revision,
            encoded.initiator,
            encoded.activity_id,
            encoded.approval_request_id,
            encoded.maintenance_owner,
            encoded.maintenance_lease_epoch,
            encoded.expected_post.state,
            encoded.expected_post.hash,
            encoded.expected_post.size,
            encoded.expected_post.mode,
            encoded.inverse.kind,
            encoded.inverse.blob,
            encoded.inverse.hash,
            encoded.inverse.size,
            encoded.inverse.mode,
            encoded.state,
            encoded.created_at,
            encoded.revision,
        ],
    )?;
    let result =
        get_restore_tx(&transaction, restore.id())?.ok_or(CheckpointStoreError::RecordMissing)?;
    transaction.commit()?;
    Ok(result)
}

/// Compare-and-set a Starting restore journal to a terminal domain
/// projection.  The filesystem/Git effect is deliberately outside this
/// transaction.
pub(crate) fn complete_checkpoint_restore(
    connection: &mut Connection,
    restore: &RegisteredCheckpointRestore,
    expected_revision: CheckpointRestoreRevision,
) -> Result<RegisteredCheckpointRestore, CheckpointStoreError> {
    if restore.state() == CheckpointRestoreState::Starting {
        return Err(CheckpointStoreError::InvalidTransition);
    }
    let encoded = encode_restore(restore)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current =
        get_restore_tx(&transaction, restore.id())?.ok_or(CheckpointStoreError::RecordMissing)?;
    if current.state() != CheckpointRestoreState::Starting {
        let expected_next = expected_revision
            .checked_next()
            .map_err(|_| CheckpointStoreError::RevisionOverflow)?;
        if current.revision() != expected_next {
            return Err(CheckpointStoreError::RevisionConflict);
        }
        if current == *restore {
            transaction.commit()?;
            return Ok(current);
        }
        return Err(CheckpointStoreError::IdentityConflict);
    }
    if current.revision() != expected_revision {
        return Err(CheckpointStoreError::RevisionConflict);
    }
    validate_restore_immutable(&current, restore)?;
    if restore.revision()
        != expected_revision
            .checked_next()
            .map_err(|_| CheckpointStoreError::RevisionOverflow)?
    {
        return Err(CheckpointStoreError::RevisionConflict);
    }
    if restore.timestamps().created_at() != current.timestamps().created_at()
        || restore.timestamps().updated_at().get() < current.timestamps().created_at().get()
    {
        return Err(CheckpointStoreError::TimestampOrder);
    }
    let changed = transaction.execute(
        "UPDATE checkpoint_restores SET state = ?1, failure_code = ?2,
             updated_at_ms = ?3, revision = ?4
         WHERE restore_id = ?5 AND state = 0 AND revision = ?6",
        params![
            encoded.state,
            encoded.failure_code,
            encoded.updated_at,
            encoded.revision,
            encoded.id,
            expected_revision.get(),
        ],
    )?;
    if changed != 1 {
        return Err(CheckpointStoreError::RevisionConflict);
    }
    let result =
        get_restore_tx(&transaction, restore.id())?.ok_or(CheckpointStoreError::RecordMissing)?;
    transaction.commit()?;
    Ok(result)
}

pub(crate) fn get_checkpoint_restore(
    connection: &Connection,
    id: CheckpointRestoreId,
) -> Result<Option<RegisteredCheckpointRestore>, CheckpointStoreError> {
    let mut statement = connection.prepare(&format!("{RESTORE_QUERY} WHERE restore_id = ?1"))?;
    let mut rows = statement.query(params![id.into_uuid().as_bytes()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    decode_restore_row(connection, row, None).map(Some)
}

pub(crate) fn list_checkpoint_restores(
    connection: &Connection,
    workspace_id: WorkspaceId,
    limit: u32,
) -> Result<Vec<RegisteredCheckpointRestore>, CheckpointStoreError> {
    validate_limit(limit)?;
    let transaction = connection.unchecked_transaction()?;
    let checkpoint_ids = list_restore_checkpoint_ids(&transaction, workspace_id, limit)?;
    let checkpoints = preload_checkpoints_by_ids(&transaction, &checkpoint_ids)?;
    let mut statement = transaction.prepare(&format!(
        "{RESTORE_QUERY} WHERE workspace_id = ?1
         ORDER BY created_at_ms DESC, restore_id DESC LIMIT ?2"
    ))?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        i64::from(limit)
    ])?;
    let mut records = Vec::with_capacity(limit as usize);
    while let Some(row) = rows.next()? {
        let checkpoint_id_bytes: Vec<u8> = row.get(7)?;
        let checkpoint_id = decode_checkpoint_id(&checkpoint_id_bytes)?;
        let checkpoint = checkpoints
            .get(&checkpoint_id)
            .ok_or(CheckpointStoreError::AttributionMismatch)?;
        records.push(decode_restore_row(&transaction, row, Some(checkpoint))?);
    }
    drop(rows);
    drop(statement);
    transaction.commit()?;
    Ok(records)
}

// ---- Encoding ----------------------------------------------------------------

fn get_checkpoint_tx(
    connection: &Transaction<'_>,
    id: CheckpointId,
) -> Result<Option<RegisteredCheckpoint>, CheckpointStoreError> {
    let mut statement =
        connection.prepare(&format!("{CHECKPOINT_QUERY} WHERE checkpoint_id = ?1"))?;
    let mut rows = statement.query(params![id.into_uuid().as_bytes()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    decode_checkpoint_row(connection, row, None).map(Some)
}

fn get_restore_tx(
    connection: &Transaction<'_>,
    id: CheckpointRestoreId,
) -> Result<Option<RegisteredCheckpointRestore>, CheckpointStoreError> {
    let mut statement = connection.prepare(&format!("{RESTORE_QUERY} WHERE restore_id = ?1"))?;
    let mut rows = statement.query(params![id.into_uuid().as_bytes()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    decode_restore_row(connection, row, None).map(Some)
}

fn validate_checkpoint_change_set(
    connection: &Connection,
    checkpoint: &RegisteredCheckpoint,
    require_starting_change_set: bool,
) -> Result<(), CheckpointStoreError> {
    let binding = load_file_mutation_binding(connection, checkpoint)?;
    validate_checkpoint_change_set_binding(checkpoint, &binding, require_starting_change_set)
}

fn validate_checkpoint_change_set_binding(
    checkpoint: &RegisteredCheckpoint,
    binding: &FileMutationBinding,
    require_starting_change_set: bool,
) -> Result<(), CheckpointStoreError> {
    if !binding_attribution_matches(checkpoint, binding)
        || (require_starting_change_set && binding.change_set_state != 0)
        || binding.path != checkpoint.path().as_path().as_os_str().as_bytes()
        || !same_file_state(binding.pre, checkpoint.pre().observed())
    {
        return Err(CheckpointStoreError::AttributionMismatch);
    }
    Ok(())
}

fn validate_checkpoint_completion(
    connection: &Connection,
    checkpoint: &RegisteredCheckpoint,
) -> Result<(), CheckpointStoreError> {
    let binding = load_file_mutation_binding(connection, checkpoint)?;
    validate_checkpoint_completion_binding(checkpoint, &binding)
}

fn validate_checkpoint_completion_binding(
    checkpoint: &RegisteredCheckpoint,
    binding: &FileMutationBinding,
) -> Result<(), CheckpointStoreError> {
    let Some(post) = binding.post else {
        return Err(CheckpointStoreError::AttributionMismatch);
    };
    if !binding_attribution_matches(checkpoint, binding)
        || binding.change_set_state != 1
        || binding.path != checkpoint.path().as_path().as_os_str().as_bytes()
        || !same_file_state(binding.pre, checkpoint.pre().observed())
        || checkpoint
            .post()
            .is_none_or(|value| !same_file_state(value.observed(), post))
    {
        return Err(CheckpointStoreError::AttributionMismatch);
    }
    Ok(())
}

fn binding_attribution_matches(
    checkpoint: &RegisteredCheckpoint,
    binding: &FileMutationBinding,
) -> bool {
    binding.workspace_id.as_slice() == checkpoint.workspace_id().into_uuid().as_bytes()
        && binding.activity_id.as_slice() == checkpoint.activity_id().into_uuid().as_bytes()
        && binding.workspace_revision == checkpoint.workspace_revision().get()
}

#[derive(Debug)]
struct FileMutationBinding {
    workspace_id: Vec<u8>,
    activity_id: Vec<u8>,
    workspace_revision: i64,
    path: Vec<u8>,
    pre: CheckpointObservedPathState,
    post: Option<CheckpointObservedPathState>,
    change_set_state: i64,
}

#[derive(Debug)]
struct RawFileMutationBinding {
    path_length: i64,
    pre_hash_length: Option<i64>,
    post_hash_length: Option<i64>,
    workspace_id: Vec<u8>,
    activity_id: Vec<u8>,
    workspace_revision: i64,
    change_set_state: i64,
    path: Vec<u8>,
    pre_state: i64,
    pre_hash: Option<Vec<u8>>,
    pre_size: Option<i64>,
    post_state: Option<i64>,
    post_hash: Option<Vec<u8>>,
    post_size: Option<i64>,
}

fn load_file_mutation_binding(
    connection: &Connection,
    checkpoint: &RegisteredCheckpoint,
) -> Result<FileMutationBinding, CheckpointStoreError> {
    let row: Option<RawFileMutationBinding> = connection
        .query_row(
            "SELECT length(CAST(f.relative_path AS BLOB)),
                    length(CAST(f.pre_hash AS BLOB)),
                    length(CAST(f.post_hash AS BLOB)),
                    c.workspace_id, c.activity_id, c.workspace_revision, c.state,
                    f.relative_path, f.pre_state, f.pre_hash, f.pre_size,
                    f.post_state, f.post_hash, f.post_size
             FROM change_sets AS c
             JOIN file_mutations AS f ON f.changeset_id = c.changeset_id
             WHERE c.changeset_id = ?1",
            params![checkpoint.change_set_id().into_uuid().as_bytes()],
            |row| raw_file_mutation_binding_from_row(row, 0),
        )
        .optional()?;
    let Some(raw) = row else {
        return Err(CheckpointStoreError::AttributionMismatch);
    };
    let binding = decode_raw_file_mutation_binding(raw)?;
    if binding.workspace_id.as_slice() != checkpoint.workspace_id().into_uuid().as_bytes()
        || binding.activity_id.as_slice() != checkpoint.activity_id().into_uuid().as_bytes()
        || binding.workspace_revision != checkpoint.workspace_revision().get()
    {
        return Err(CheckpointStoreError::AttributionMismatch);
    }
    Ok(binding)
}

fn decode_raw_file_mutation_binding(
    raw: RawFileMutationBinding,
) -> Result<FileMutationBinding, CheckpointStoreError> {
    validate_path_length_from_sql("file_mutation.relative_path", raw.path_length)?;
    validate_optional_exact_length(
        "file_mutation.pre_hash",
        raw.pre_hash_length,
        HASH_BYTES_I64,
        HASH_BYTES,
    )?;
    validate_optional_exact_length(
        "file_mutation.post_hash",
        raw.post_hash_length,
        HASH_BYTES_I64,
        HASH_BYTES,
    )?;
    let pre = decode_file_mutation_state(
        "file_mutation.pre",
        raw.pre_state,
        raw.pre_hash,
        raw.pre_size,
    )?;
    let post = raw
        .post_state
        .map(|state| {
            decode_file_mutation_state("file_mutation.post", state, raw.post_hash, raw.post_size)
        })
        .transpose()?;
    Ok(FileMutationBinding {
        workspace_id: raw.workspace_id,
        activity_id: raw.activity_id,
        workspace_revision: raw.workspace_revision,
        path: raw.path,
        pre,
        post,
        change_set_state: raw.change_set_state,
    })
}

fn raw_file_mutation_binding_from_row(
    row: &Row<'_>,
    offset: usize,
) -> rusqlite::Result<RawFileMutationBinding> {
    Ok(RawFileMutationBinding {
        path_length: row.get(offset)?,
        pre_hash_length: row.get(offset + 1)?,
        post_hash_length: row.get(offset + 2)?,
        workspace_id: row.get(offset + 3)?,
        activity_id: row.get(offset + 4)?,
        workspace_revision: row.get(offset + 5)?,
        change_set_state: row.get(offset + 6)?,
        path: row.get(offset + 7)?,
        pre_state: row.get(offset + 8)?,
        pre_hash: row.get(offset + 9)?,
        pre_size: row.get(offset + 10)?,
        post_state: row.get(offset + 11)?,
        post_hash: row.get(offset + 12)?,
        post_size: row.get(offset + 13)?,
    })
}

fn preload_checkpoint_bindings(
    connection: &Connection,
    workspace_id: WorkspaceId,
    limit: u32,
) -> Result<HashMap<ChangeSetId, FileMutationBinding>, CheckpointStoreError> {
    let mut statement = connection.prepare(
        "SELECT length(CAST(c.changeset_id AS BLOB)), c.changeset_id,
                length(CAST(f.relative_path AS BLOB)),
                length(CAST(f.pre_hash AS BLOB)), length(CAST(f.post_hash AS BLOB)),
                c.workspace_id, c.activity_id, c.workspace_revision, c.state,
                f.relative_path, f.pre_state, f.pre_hash, f.pre_size,
                f.post_state, f.post_hash, f.post_size
         FROM checkpoints AS p
         JOIN change_sets AS c ON c.changeset_id = p.changeset_id
         JOIN file_mutations AS f ON f.changeset_id = c.changeset_id
         WHERE p.workspace_id = ?1
         ORDER BY p.created_at_ms DESC, p.checkpoint_id DESC LIMIT ?2",
    )?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        i64::from(limit)
    ])?;
    let mut bindings = HashMap::with_capacity(limit as usize);
    while let Some(row) = rows.next()? {
        validate_exact_length(
            "checkpoint.changeset_id",
            row.get(0)?,
            ID_BYTES_I64,
            ID_BYTES,
        )?;
        let change_set_bytes: Vec<u8> = row.get(1)?;
        let change_set_id = decode_change_set_id(&change_set_bytes)?;
        let raw = raw_file_mutation_binding_from_row(row, 2)?;
        let decoded = decode_raw_file_mutation_binding(raw)?;
        if decoded.workspace_id.as_slice() != workspace_id.into_uuid().as_bytes() {
            return Err(CheckpointStoreError::AttributionMismatch);
        }
        bindings.insert(change_set_id, decoded);
    }
    Ok(bindings)
}

fn list_restore_checkpoint_ids(
    connection: &Connection,
    workspace_id: WorkspaceId,
    limit: u32,
) -> Result<Vec<CheckpointId>, CheckpointStoreError> {
    let mut statement = connection.prepare(
        "SELECT length(CAST(checkpoint_id AS BLOB)), checkpoint_id
         FROM checkpoint_restores
         WHERE workspace_id = ?1
         ORDER BY created_at_ms DESC, restore_id DESC LIMIT ?2",
    )?;
    let mut rows = statement.query(params![
        workspace_id.into_uuid().as_bytes(),
        i64::from(limit)
    ])?;
    let mut ids = Vec::with_capacity(limit as usize);
    while let Some(row) = rows.next()? {
        validate_exact_length("restore.checkpoint_id", row.get(0)?, ID_BYTES_I64, ID_BYTES)?;
        let bytes: Vec<u8> = row.get(1)?;
        ids.push(decode_checkpoint_id(&bytes)?);
    }
    Ok(ids)
}

fn preload_checkpoints_by_ids(
    connection: &Connection,
    ids: &[CheckpointId],
) -> Result<HashMap<CheckpointId, RegisteredCheckpoint>, CheckpointStoreError> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let placeholders = sql_placeholders(ids.len());
    let values = checkpoint_id_values(ids);
    let mut bindings_statement = connection.prepare(&format!(
        "SELECT length(CAST(c.changeset_id AS BLOB)), c.changeset_id,
                length(CAST(f.relative_path AS BLOB)),
                length(CAST(f.pre_hash AS BLOB)), length(CAST(f.post_hash AS BLOB)),
                c.workspace_id, c.activity_id, c.workspace_revision, c.state,
                f.relative_path, f.pre_state, f.pre_hash, f.pre_size,
                f.post_state, f.post_hash, f.post_size
         FROM checkpoints AS p
         JOIN change_sets AS c ON c.changeset_id = p.changeset_id
         JOIN file_mutations AS f ON f.changeset_id = c.changeset_id
         WHERE p.checkpoint_id IN ({placeholders})"
    ))?;
    let mut binding_rows = bindings_statement.query(params_from_iter(values.iter()))?;
    let mut bindings = HashMap::with_capacity(ids.len());
    while let Some(row) = binding_rows.next()? {
        validate_exact_length(
            "checkpoint.changeset_id",
            row.get(0)?,
            ID_BYTES_I64,
            ID_BYTES,
        )?;
        let change_set_bytes: Vec<u8> = row.get(1)?;
        let change_set_id = decode_change_set_id(&change_set_bytes)?;
        let raw = raw_file_mutation_binding_from_row(row, 2)?;
        let decoded = decode_raw_file_mutation_binding(raw)?;
        bindings.insert(change_set_id, decoded);
    }
    drop(binding_rows);
    drop(bindings_statement);

    let mut statement = connection.prepare(&format!(
        "{CHECKPOINT_QUERY} WHERE checkpoint_id IN ({placeholders})"
    ))?;
    let mut rows = statement.query(params_from_iter(values.iter()))?;
    let mut checkpoints = HashMap::with_capacity(ids.len());
    while let Some(row) = rows.next()? {
        let checkpoint_id_bytes: Vec<u8> = row.get(11)?;
        let change_set_bytes: Vec<u8> = row.get(12)?;
        let checkpoint_id = decode_checkpoint_id(&checkpoint_id_bytes)?;
        let change_set_id = decode_change_set_id(&change_set_bytes)?;
        let binding = bindings
            .get(&change_set_id)
            .ok_or(CheckpointStoreError::AttributionMismatch)?;
        let checkpoint = decode_checkpoint_row(connection, row, Some(binding))?;
        if checkpoint.id() != checkpoint_id {
            return Err(CheckpointStoreError::AttributionMismatch);
        }
        checkpoints.insert(checkpoint_id, checkpoint);
    }
    Ok(checkpoints)
}

fn sql_placeholders(count: usize) -> String {
    let mut placeholders = String::with_capacity(count.saturating_mul(2).saturating_sub(1));
    for index in 0..count {
        if index != 0 {
            placeholders.push(',');
        }
        placeholders.push('?');
    }
    placeholders
}

fn checkpoint_id_values(ids: &[CheckpointId]) -> Vec<Value> {
    ids.iter()
        .map(|id| Value::Blob(id.into_uuid().into_bytes().to_vec()))
        .collect()
}

fn decode_file_mutation_state(
    field: &'static str,
    state: i64,
    hash: Option<Vec<u8>>,
    size: Option<i64>,
) -> Result<CheckpointObservedPathState, CheckpointStoreError> {
    match (state, hash, size) {
        (0, None, None) => Ok(CheckpointObservedPathState::Absent),
        (1, Some(hash), Some(size)) => Ok(CheckpointObservedPathState::Regular {
            hash: decode_hash(&hash, field)?,
            size: decode_size(size, field)?,
            mode: CheckpointFileMode::new(0)
                .map_err(|_| CheckpointStoreError::CorruptRecord(field))?,
        }),
        _ => Err(CheckpointStoreError::CorruptRecord(field)),
    }
}

fn same_file_state(
    actual: CheckpointObservedPathState,
    expected: CheckpointObservedPathState,
) -> bool {
    match (actual, expected) {
        (CheckpointObservedPathState::Absent, CheckpointObservedPathState::Absent) => true,
        (
            CheckpointObservedPathState::Regular {
                hash: actual_hash,
                size: actual_size,
                ..
            },
            CheckpointObservedPathState::Regular {
                hash: expected_hash,
                size: expected_size,
                ..
            },
        ) => actual_hash == expected_hash && actual_size == expected_size,
        _ => false,
    }
}

fn validate_restore_checkpoint(
    connection: &Connection,
    restore: &RegisteredCheckpointRestore,
) -> Result<(), CheckpointStoreError> {
    let checkpoint = get_checkpoint(connection, restore.checkpoint_id())?
        .ok_or(CheckpointStoreError::AttributionMismatch)?;
    if checkpoint.workspace_id() != restore.workspace_id()
        || checkpoint.revision() != restore.expected_checkpoint_revision()
    {
        return Err(CheckpointStoreError::AttributionMismatch);
    }
    let activity_matches_workspace: i64 = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM activities WHERE activity_id = ?1 AND workspace_id = ?2)",
        params![
            restore.attribution().activity_id().into_uuid().as_bytes(),
            restore.workspace_id().into_uuid().as_bytes(),
        ],
        |row| row.get(0),
    )?;
    if activity_matches_workspace == 0 {
        return Err(CheckpointStoreError::AttributionMismatch);
    }
    if let Some(approval_id) = restore.attribution().approval_request_id() {
        let approval = crate::workspace_approvals::get_approval(connection, approval_id)?
            .ok_or(CheckpointStoreError::AttributionMismatch)?;
        let approval_request = approval.request();
        if approval_request.workspace_id() != restore.workspace_id()
            || approval_request.activity_id() != restore.attribution().activity_id()
            || !matches!(
                approval.state(),
                forge_domain::ApprovalRequestState::Approved
                    | forge_domain::ApprovalRequestState::AutoApproved
            )
        {
            return Err(CheckpointStoreError::AttributionMismatch);
        }
    }
    Ok(())
}

fn validate_checkpoint_immutable(
    current: &RegisteredCheckpoint,
    next: &RegisteredCheckpoint,
) -> Result<(), CheckpointStoreError> {
    if current.id() != next.id()
        || current.change_set_id() != next.change_set_id()
        || current.workspace_id() != next.workspace_id()
        || current.activity_id() != next.activity_id()
        || current.workspace_revision() != next.workspace_revision()
        || current.path() != next.path()
        || current.pre() != next.pre()
        || current.pre_commit() != next.pre_commit()
    {
        return Err(CheckpointStoreError::IdentityConflict);
    }
    Ok(())
}

fn validate_restore_immutable(
    current: &RegisteredCheckpointRestore,
    next: &RegisteredCheckpointRestore,
) -> Result<(), CheckpointStoreError> {
    if current.attribution() != next.attribution()
        || current.expected_post() != next.expected_post()
        || current.effect() != next.effect()
    {
        return Err(CheckpointStoreError::IdentityConflict);
    }
    Ok(())
}

fn query_checkpoint_id_by_change_set(
    connection: &Connection,
    id: ChangeSetId,
) -> Result<Option<Vec<u8>>, CheckpointStoreError> {
    connection
        .query_row(
            "SELECT checkpoint_id FROM checkpoints WHERE changeset_id = ?1",
            params![id.into_uuid().as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(CheckpointStoreError::from)
}

// ---- Primitive decoders and schema validation --------------------------------

fn validate_limit(limit: u32) -> Result<(), CheckpointStoreError> {
    if limit == 0 || limit > MAX_LIST_ROWS {
        Err(CheckpointStoreError::ListLimitInvalid {
            limit,
            maximum: MAX_LIST_ROWS,
        })
    } else {
        Ok(())
    }
}

fn uuid_bytes(value: Uuid) -> Vec<u8> {
    value.into_bytes().to_vec()
}

#[derive(Debug, Error)]
pub enum CheckpointStoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Approval(#[from] crate::workspace_approvals::ApprovalStoreError),
    #[error("Checkpoint identity conflicts with an existing record")]
    IdentityConflict,
    #[error("Checkpoint record is missing")]
    RecordMissing,
    #[error("Checkpoint or restore projection is terminal")]
    Terminal,
    #[error("Checkpoint or restore revision is stale")]
    RevisionConflict,
    #[error("Checkpoint or restore revision overflowed")]
    RevisionOverflow,
    #[error("Checkpoint or restore timestamp precedes its durable intent")]
    TimestampOrder,
    #[error("Checkpoint attribution does not match its ChangeSet or Workspace")]
    AttributionMismatch,
    #[error("Checkpoint or restore lifecycle transition is invalid")]
    InvalidTransition,
    #[error("v11 checkpoint restore rows lack durable provenance required by schema v12")]
    LegacyRestoreProvenanceUnavailable,
    #[error("Checkpoint byte count exceeds SQLite integer range")]
    SizeOverflow,
    #[error("checkpoint list limit {limit} is outside 1..={maximum}")]
    ListLimitInvalid { limit: u32, maximum: u32 },
    #[error("corrupt checkpoint persistence field {0}")]
    CorruptRecord(&'static str),
    #[error("persisted checkpoint field {field} has {actual} bytes; expected exactly {expected}")]
    PersistedFieldLengthInvalid {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("persisted checkpoint field {field} is {actual} bytes; maximum is {maximum}")]
    PersistedFieldTooLarge {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
}

#[cfg(test)]
mod tests;
