//! Typed `SQLite` row encoding and decoding for checkpoint persistence.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use forge_domain::{
    ActivityId, ChangeSetId, CheckpointAttribution, CheckpointFileMode, CheckpointId,
    CheckpointObservedPathState, CheckpointPathState, CheckpointRestoreAttribution,
    CheckpointRestoreFailureCode, CheckpointRestoreId, CheckpointRestoreRevision,
    CheckpointRestoreState, CheckpointRevision, CheckpointSnapshots, CheckpointState,
    CheckpointTimestamps, FileByteCount, FileContentHash, GitBlobId, GitCommitId,
    RegisteredCheckpoint, RegisteredCheckpointRestore, RestoreEffect, TimestampMillis, WorkspaceId,
    WorkspaceRelativePath, WorkspaceRevision,
};
use rusqlite::{Connection, Row};
use uuid::Uuid;

use super::{
    CheckpointStoreError, FileMutationBinding, HASH_BYTES, HASH_BYTES_I64, ID_BYTES, ID_BYTES_I64,
    MAX_PATH_BYTES, SHA1_BYTES, SHA1_BYTES_I64, get_checkpoint, uuid_bytes,
    validate_checkpoint_change_set, validate_checkpoint_change_set_binding,
    validate_checkpoint_completion, validate_checkpoint_completion_binding,
};

#[derive(Debug, Clone)]
pub(super) struct EncodedPathState {
    pub(super) state: i64,
    pub(super) blob: Option<Vec<u8>>,
    pub(super) hash: Option<Vec<u8>>,
    pub(super) size: Option<i64>,
    pub(super) mode: Option<i64>,
}

#[derive(Debug, Clone)]
pub(super) struct EncodedCheckpoint {
    pub(super) id: Vec<u8>,
    pub(super) change_set_id: Vec<u8>,
    pub(super) workspace_id: Vec<u8>,
    pub(super) activity_id: Vec<u8>,
    pub(super) workspace_revision: i64,
    pub(super) path: Vec<u8>,
    pub(super) object_format: i64,
    pub(super) state: i64,
    pub(super) pre: EncodedPathState,
    pub(super) pre_commit: Vec<u8>,
    pub(super) post: Option<EncodedPathState>,
    pub(super) post_commit: Option<Vec<u8>>,
    pub(super) created_at: i64,
    pub(super) updated_at: i64,
    pub(super) revision: i64,
}

pub(super) fn encode_checkpoint(
    checkpoint: &RegisteredCheckpoint,
) -> Result<EncodedCheckpoint, CheckpointStoreError> {
    let path = checkpoint.path().as_path().as_os_str().as_bytes();
    validate_path_length(path.len())?;
    let pre = encode_path_state(checkpoint.pre())?;
    let post = checkpoint.post().map(encode_path_state).transpose()?;
    let post_commit = checkpoint
        .post_commit()
        .map(|value| value.object_id().as_bytes().to_vec());
    Ok(EncodedCheckpoint {
        id: uuid_bytes(checkpoint.id().into_uuid()),
        change_set_id: uuid_bytes(checkpoint.change_set_id().into_uuid()),
        workspace_id: uuid_bytes(checkpoint.workspace_id().into_uuid()),
        activity_id: uuid_bytes(checkpoint.activity_id().into_uuid()),
        workspace_revision: checkpoint.workspace_revision().get(),
        path: path.to_vec(),
        object_format: encode_object_format(forge_domain::GitObjectFormat::Sha1),
        state: encode_checkpoint_state(checkpoint.state()),
        pre,
        pre_commit: checkpoint.pre_commit().object_id().as_bytes().to_vec(),
        post,
        post_commit,
        created_at: checkpoint.timestamps().created_at().get(),
        updated_at: checkpoint.timestamps().updated_at().get(),
        revision: checkpoint.revision().get(),
    })
}

fn encode_path_state(
    state: &CheckpointPathState,
) -> Result<EncodedPathState, CheckpointStoreError> {
    match state {
        CheckpointPathState::Absent => Ok(EncodedPathState {
            state: 0,
            blob: None,
            hash: None,
            size: None,
            mode: None,
        }),
        CheckpointPathState::Regular {
            blob,
            hash,
            size,
            mode,
        } => Ok(EncodedPathState {
            state: 1,
            blob: Some(blob.object_id().as_bytes().to_vec()),
            hash: Some(hash.as_bytes().to_vec()),
            size: Some(encode_size(*size)?),
            mode: Some(i64::from(mode.get())),
        }),
    }
}

fn encode_observed_state(
    state: CheckpointObservedPathState,
) -> Result<EncodedPathState, CheckpointStoreError> {
    match state {
        CheckpointObservedPathState::Absent => Ok(EncodedPathState {
            state: 0,
            blob: None,
            hash: None,
            size: None,
            mode: None,
        }),
        CheckpointObservedPathState::Regular { hash, size, mode } => Ok(EncodedPathState {
            state: 1,
            blob: None,
            hash: Some(hash.as_bytes().to_vec()),
            size: Some(encode_size(size)?),
            mode: Some(i64::from(mode.get())),
        }),
    }
}

#[derive(Debug, Clone)]
pub(super) struct EncodedRestore {
    pub(super) id: Vec<u8>,
    pub(super) checkpoint_id: Vec<u8>,
    pub(super) workspace_id: Vec<u8>,
    pub(super) expected_checkpoint_revision: i64,
    pub(super) initiator: Vec<u8>,
    pub(super) activity_id: Vec<u8>,
    pub(super) approval_request_id: Option<Vec<u8>>,
    pub(super) maintenance_owner: Option<Vec<u8>>,
    pub(super) maintenance_lease_epoch: Option<i64>,
    pub(super) expected_post: EncodedPathState,
    pub(super) inverse: EncodedInverse,
    pub(super) state: i64,
    pub(super) failure_code: Option<i64>,
    pub(super) created_at: i64,
    pub(super) updated_at: i64,
    pub(super) revision: i64,
}

#[derive(Debug, Clone)]
pub(super) struct EncodedInverse {
    pub(super) kind: i64,
    pub(super) blob: Option<Vec<u8>>,
    pub(super) hash: Option<Vec<u8>>,
    pub(super) size: Option<i64>,
    pub(super) mode: Option<i64>,
}

pub(super) fn encode_restore(
    restore: &RegisteredCheckpointRestore,
) -> Result<EncodedRestore, CheckpointStoreError> {
    let expected_post = encode_observed_state(restore.expected_post())?;
    let inverse = match restore.effect() {
        RestoreEffect::Delete => EncodedInverse {
            kind: 0,
            blob: None,
            hash: None,
            size: None,
            mode: None,
        },
        RestoreEffect::Restore {
            blob,
            hash,
            size,
            mode,
        } => EncodedInverse {
            kind: 1,
            blob: Some(blob.object_id().as_bytes().to_vec()),
            hash: Some(hash.as_bytes().to_vec()),
            size: Some(encode_size(*size)?),
            mode: Some(i64::from(mode.get())),
        },
    };
    let (maintenance_owner, maintenance_lease_epoch) = match restore.attribution().fence() {
        forge_domain::CheckpointRestoreFence::Direct => (None, None),
        forge_domain::CheckpointRestoreFence::Maintenance { owner, lease_epoch } => {
            (Some(uuid_bytes(owner.into_uuid())), Some(lease_epoch.get()))
        }
    };
    Ok(EncodedRestore {
        id: uuid_bytes(restore.id().into_uuid()),
        checkpoint_id: uuid_bytes(restore.checkpoint_id().into_uuid()),
        workspace_id: uuid_bytes(restore.workspace_id().into_uuid()),
        expected_checkpoint_revision: restore.expected_checkpoint_revision().get(),
        initiator: uuid_bytes(restore.attribution().initiator().into_uuid()),
        activity_id: uuid_bytes(restore.attribution().activity_id().into_uuid()),
        approval_request_id: restore
            .attribution()
            .approval_request_id()
            .map(|value| uuid_bytes(value.into_uuid())),
        maintenance_owner,
        maintenance_lease_epoch,
        expected_post,
        inverse,
        state: encode_restore_state(restore.state()),
        failure_code: restore.failure_code().map(encode_failure_code),
        created_at: restore.timestamps().created_at().get(),
        updated_at: restore.timestamps().updated_at().get(),
        revision: restore.revision().get(),
    })
}

fn encode_size(size: FileByteCount) -> Result<i64, CheckpointStoreError> {
    i64::try_from(size.get()).map_err(|_| CheckpointStoreError::SizeOverflow)
}

fn encode_object_format(format: forge_domain::GitObjectFormat) -> i64 {
    match format {
        forge_domain::GitObjectFormat::Sha1 => 0,
    }
}

fn encode_checkpoint_state(state: CheckpointState) -> i64 {
    match state {
        CheckpointState::Starting => 0,
        CheckpointState::Ready => 1,
    }
}

fn encode_restore_state(state: CheckpointRestoreState) -> i64 {
    match state {
        CheckpointRestoreState::Starting => 0,
        CheckpointRestoreState::Restored => 1,
        CheckpointRestoreState::Failed => 2,
        CheckpointRestoreState::RecoveryRequired => 3,
    }
}

fn encode_failure_code(code: CheckpointRestoreFailureCode) -> i64 {
    match code {
        CheckpointRestoreFailureCode::MissingObject => 0,
        CheckpointRestoreFailureCode::ObjectHashMismatch => 1,
        CheckpointRestoreFailureCode::PathConflict => 2,
        CheckpointRestoreFailureCode::IoFailure => 3,
    }
}

// ---- Decoding ----------------------------------------------------------------

#[allow(clippy::too_many_lines)]
pub(super) fn decode_checkpoint_row(
    connection: &Connection,
    row: &Row<'_>,
    binding: Option<&FileMutationBinding>,
) -> Result<RegisteredCheckpoint, CheckpointStoreError> {
    validate_exact_length("checkpoint_id", row.get(0)?, ID_BYTES_I64, ID_BYTES)?;
    validate_exact_length(
        "checkpoint.changeset_id",
        row.get(1)?,
        ID_BYTES_I64,
        ID_BYTES,
    )?;
    validate_exact_length(
        "checkpoint.workspace_id",
        row.get(2)?,
        ID_BYTES_I64,
        ID_BYTES,
    )?;
    validate_exact_length(
        "checkpoint.activity_id",
        row.get(3)?,
        ID_BYTES_I64,
        ID_BYTES,
    )?;
    validate_path_length_from_sql("checkpoint.relative_path", row.get(4)?)?;
    validate_optional_exact_length(
        "checkpoint.pre_blob",
        row.get(5)?,
        SHA1_BYTES_I64,
        SHA1_BYTES,
    )?;
    validate_optional_exact_length(
        "checkpoint.pre_hash",
        row.get(6)?,
        HASH_BYTES_I64,
        HASH_BYTES,
    )?;
    validate_exact_length(
        "checkpoint.pre_commit",
        row.get(7)?,
        SHA1_BYTES_I64,
        SHA1_BYTES,
    )?;
    validate_optional_exact_length(
        "checkpoint.post_blob",
        row.get(8)?,
        SHA1_BYTES_I64,
        SHA1_BYTES,
    )?;
    validate_optional_exact_length(
        "checkpoint.post_hash",
        row.get(9)?,
        HASH_BYTES_I64,
        HASH_BYTES,
    )?;
    validate_optional_exact_length(
        "checkpoint.post_commit",
        row.get(10)?,
        SHA1_BYTES_I64,
        SHA1_BYTES,
    )?;

    let id_bytes: Vec<u8> = row.get(11)?;
    let change_set_bytes: Vec<u8> = row.get(12)?;
    let workspace_bytes: Vec<u8> = row.get(13)?;
    let activity_bytes: Vec<u8> = row.get(14)?;
    let id = decode_checkpoint_id(&id_bytes)?;
    let change_set_id = decode_change_set_id(&change_set_bytes)?;
    let workspace_id = decode_workspace_id(&workspace_bytes)?;
    let activity_id = decode_activity_id(&activity_bytes)?;
    let workspace_revision = decode_workspace_revision(row.get(15)?)?;
    let path = decode_path(row.get(16)?)?;
    let _object_format = decode_object_format(row.get(17)?)?;
    let state = decode_checkpoint_state(row.get(18)?)?;
    let pre_state = decode_path_state(
        "checkpoint.pre",
        row.get(19)?,
        row.get(20)?,
        row.get(21)?,
        row.get(22)?,
        row.get(23)?,
        true,
    )?;
    let pre_commit_bytes: Vec<u8> = row.get(24)?;
    let pre_commit = decode_commit(&pre_commit_bytes, "checkpoint.pre_commit")?;
    let post_state: Option<i64> = row.get(25)?;
    let post = decode_optional_path_state(
        "checkpoint.post",
        post_state,
        row.get(26)?,
        row.get(27)?,
        row.get(28)?,
        row.get(29)?,
    )?;
    let post_commit_bytes: Option<Vec<u8>> = row.get(30)?;
    let post_commit = post_commit_bytes
        .as_deref()
        .map(|value| decode_commit(value, "checkpoint.post_commit"))
        .transpose()?;
    if matches!(state, CheckpointState::Starting) && (post.is_some() || post_commit.is_some()) {
        return Err(CheckpointStoreError::CorruptRecord("checkpoint.post"));
    }
    if matches!(state, CheckpointState::Ready) && (post.is_none() || post_commit.is_none()) {
        return Err(CheckpointStoreError::CorruptRecord("checkpoint.post"));
    }
    let created_at = decode_timestamp(row.get(31)?, "checkpoint.created_at_ms")?;
    let updated_at = decode_timestamp(row.get(32)?, "checkpoint.updated_at_ms")?;
    let revision = decode_checkpoint_revision(row.get(33)?)?;
    match state {
        CheckpointState::Starting
            if revision != CheckpointRevision::INITIAL || updated_at != created_at =>
        {
            return Err(CheckpointStoreError::CorruptRecord("checkpoint.lifecycle"));
        }
        CheckpointState::Ready if revision.get() != 2 => {
            return Err(CheckpointStoreError::CorruptRecord("checkpoint.lifecycle"));
        }
        _ => {}
    }
    let timestamps = CheckpointTimestamps::new(created_at, updated_at)
        .map_err(|_| CheckpointStoreError::TimestampOrder)?;
    let snapshots = match (state, post, post_commit) {
        (CheckpointState::Starting, None, None) => CheckpointSnapshots::Starting {
            pre: pre_state,
            pre_commit,
        },
        (CheckpointState::Ready, Some(post), Some(post_commit)) => CheckpointSnapshots::Ready {
            pre: pre_state,
            pre_commit,
            post,
            post_commit,
        },
        _ => return Err(CheckpointStoreError::CorruptRecord("checkpoint.lifecycle")),
    };
    let checkpoint = RegisteredCheckpoint::from_parts(
        CheckpointAttribution::new(
            id,
            change_set_id,
            workspace_id,
            workspace_revision,
            activity_id,
        ),
        path,
        snapshots,
        timestamps,
        revision,
    )
    .map_err(|_| CheckpointStoreError::CorruptRecord("checkpoint.lifecycle"))?;
    match (checkpoint.state(), binding) {
        (CheckpointState::Starting, Some(binding)) => {
            validate_checkpoint_change_set_binding(&checkpoint, binding, false)?;
        }
        (CheckpointState::Ready, Some(binding)) => {
            validate_checkpoint_completion_binding(&checkpoint, binding)?;
        }
        (CheckpointState::Starting, None) => {
            validate_checkpoint_change_set(connection, &checkpoint, false)?;
        }
        (CheckpointState::Ready, None) => validate_checkpoint_completion(connection, &checkpoint)?,
    }
    Ok(checkpoint)
}

#[allow(clippy::too_many_lines)]
pub(super) fn decode_restore_row(
    connection: &Connection,
    row: &Row<'_>,
    checkpoint_cache: Option<&RegisteredCheckpoint>,
) -> Result<RegisteredCheckpointRestore, CheckpointStoreError> {
    validate_exact_length("restore_id", row.get(0)?, ID_BYTES_I64, ID_BYTES)?;
    validate_exact_length("restore.checkpoint_id", row.get(1)?, ID_BYTES_I64, ID_BYTES)?;
    validate_exact_length("restore.workspace_id", row.get(2)?, ID_BYTES_I64, ID_BYTES)?;
    validate_optional_exact_length(
        "restore.expected_post_hash",
        row.get(3)?,
        HASH_BYTES_I64,
        HASH_BYTES,
    )?;
    validate_optional_exact_length(
        "restore.inverse_blob",
        row.get(4)?,
        SHA1_BYTES_I64,
        SHA1_BYTES,
    )?;
    validate_optional_exact_length(
        "restore.inverse_hash",
        row.get(5)?,
        HASH_BYTES_I64,
        HASH_BYTES,
    )?;

    let restore_id_bytes: Vec<u8> = row.get(6)?;
    let checkpoint_id_bytes: Vec<u8> = row.get(7)?;
    let workspace_id_bytes: Vec<u8> = row.get(8)?;
    let id = decode_restore_id(&restore_id_bytes)?;
    let checkpoint_id = decode_checkpoint_id(&checkpoint_id_bytes)?;
    let workspace_id = decode_workspace_id(&workspace_id_bytes)?;
    let expected_checkpoint_revision = decode_checkpoint_revision(row.get(9)?)?;
    let expected_post = decode_observed_state(
        "restore.expected_post",
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
    )?;
    let inverse = decode_inverse(
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
    )?;
    let state = decode_restore_state(row.get(19)?)?;
    let failure_code = row
        .get::<_, Option<i64>>(20)?
        .map(decode_failure_code)
        .transpose()?;
    if matches!(state, CheckpointRestoreState::Failed) != failure_code.is_some() {
        return Err(CheckpointStoreError::CorruptRecord("restore.failure_code"));
    }
    if !matches!(state, CheckpointRestoreState::Failed) && failure_code.is_some() {
        return Err(CheckpointStoreError::CorruptRecord("restore.failure_code"));
    }
    let created_at = decode_timestamp(row.get(21)?, "restore.created_at_ms")?;
    let updated_at = decode_timestamp(row.get(22)?, "restore.updated_at_ms")?;
    let revision = decode_restore_revision(row.get(23)?)?;
    let initiator = decode_required_uuid_field("restore.initiator", row.get(24)?, row.get(28)?)?;
    let activity_id =
        decode_required_uuid_field("restore.activity_id", row.get(25)?, row.get(29)?)?;
    let approval_length: Option<i64> = row.get(26)?;
    let approval_bytes: Option<Vec<u8>> = row.get(30)?;
    let approval_request_id = decode_optional_uuid_field(
        "restore.approval_request_id",
        approval_length,
        approval_bytes,
    )?;
    let owner_length: Option<i64> = row.get(27)?;
    let owner_bytes: Option<Vec<u8>> = row.get(31)?;
    let maintenance_owner =
        decode_optional_uuid_field("restore.maintenance_owner", owner_length, owner_bytes)?;
    let maintenance_lease_epoch: Option<i64> = row.get(32)?;
    let loaded_checkpoint;
    let checkpoint = if let Some(checkpoint) = checkpoint_cache {
        checkpoint
    } else {
        loaded_checkpoint = get_checkpoint(connection, checkpoint_id)?
            .ok_or(CheckpointStoreError::AttributionMismatch)?;
        &loaded_checkpoint
    };
    if checkpoint.workspace_id() != workspace_id
        || checkpoint.revision() != expected_checkpoint_revision
    {
        return Err(CheckpointStoreError::AttributionMismatch);
    }
    let plan = forge_domain::plan_restore(checkpoint, expected_post)
        .map_err(|_| CheckpointStoreError::AttributionMismatch)?;
    if plan.expected_checkpoint_revision() != expected_checkpoint_revision
        || plan.effect() != &inverse
    {
        return Err(CheckpointStoreError::AttributionMismatch);
    }
    let maintenance_lease_epoch = maintenance_lease_epoch
        .map(forge_domain::RecoveryLeaseEpoch::new)
        .transpose()
        .map_err(|_| CheckpointStoreError::CorruptRecord("restore.maintenance_lease_epoch"))?;
    let fence = match (maintenance_owner, maintenance_lease_epoch) {
        (None, None) => forge_domain::CheckpointRestoreFence::Direct,
        (Some(owner), Some(lease_epoch)) => forge_domain::CheckpointRestoreFence::Maintenance {
            owner: forge_domain::RuntimeInstanceId::from_uuid(owner),
            lease_epoch,
        },
        _ => {
            return Err(CheckpointStoreError::CorruptRecord(
                "restore.maintenance_fence",
            ));
        }
    };
    let attribution = CheckpointRestoreAttribution::new(
        id,
        &plan,
        forge_domain::RuntimeInstanceId::from_uuid(initiator),
        forge_domain::ActivityId::from_uuid(activity_id),
        approval_request_id.map(forge_domain::ApprovalRequestId::from_uuid),
        fence,
    );
    let starting = RegisteredCheckpointRestore::starting(attribution, &plan, created_at);
    match state {
        CheckpointRestoreState::Starting => {
            if revision != starting.revision() || updated_at != created_at || failure_code.is_some()
            {
                return Err(CheckpointStoreError::CorruptRecord("restore.lifecycle"));
            }
            Ok(starting)
        }
        CheckpointRestoreState::Restored => {
            if revision.get() != 2 || failure_code.is_some() {
                return Err(CheckpointStoreError::CorruptRecord("restore.revision"));
            }
            starting
                .restored(starting.revision(), updated_at)
                .map_err(|_| CheckpointStoreError::CorruptRecord("restore.lifecycle"))
        }
        CheckpointRestoreState::Failed => {
            if revision.get() != 2 {
                return Err(CheckpointStoreError::CorruptRecord("restore.revision"));
            }
            let Some(failure_code) = failure_code else {
                return Err(CheckpointStoreError::CorruptRecord("restore.failure_code"));
            };
            starting
                .failed(starting.revision(), failure_code, updated_at)
                .map_err(|_| CheckpointStoreError::CorruptRecord("restore.lifecycle"))
        }
        CheckpointRestoreState::RecoveryRequired => {
            if revision.get() != 2 || failure_code.is_some() {
                return Err(CheckpointStoreError::CorruptRecord("restore.revision"));
            }
            starting
                .recovery_required(starting.revision(), updated_at)
                .map_err(|_| CheckpointStoreError::CorruptRecord("restore.lifecycle"))
        }
    }
}

fn decode_path_state(
    field: &'static str,
    state: i64,
    blob: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
    size: Option<i64>,
    mode: Option<i64>,
    required: bool,
) -> Result<CheckpointPathState, CheckpointStoreError> {
    match state {
        0 if blob.is_none() && hash.is_none() && size.is_none() && mode.is_none() => {
            Ok(CheckpointPathState::Absent)
        }
        1 => {
            let (Some(blob), Some(hash), Some(size), Some(mode)) = (blob, hash, size, mode) else {
                return Err(CheckpointStoreError::CorruptRecord(field));
            };
            Ok(CheckpointPathState::Regular {
                blob: decode_blob(&blob, field)?,
                hash: decode_hash(&hash, field)?,
                size: decode_size(size, field)?,
                mode: decode_mode(mode, field)?,
            })
        }
        _ if !required => Err(CheckpointStoreError::CorruptRecord(field)),
        _ => Err(CheckpointStoreError::CorruptRecord(field)),
    }
}

fn decode_optional_path_state(
    field: &'static str,
    state: Option<i64>,
    blob: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
    size: Option<i64>,
    mode: Option<i64>,
) -> Result<Option<CheckpointPathState>, CheckpointStoreError> {
    let Some(state) = state else {
        if blob.is_none() && hash.is_none() && size.is_none() && mode.is_none() {
            return Ok(None);
        }
        return Err(CheckpointStoreError::CorruptRecord(field));
    };
    decode_path_state(field, state, blob, hash, size, mode, true).map(Some)
}

fn decode_observed_state(
    field: &'static str,
    state: i64,
    hash: Option<Vec<u8>>,
    size: Option<i64>,
    mode: Option<i64>,
) -> Result<CheckpointObservedPathState, CheckpointStoreError> {
    match state {
        0 if hash.is_none() && size.is_none() && mode.is_none() => {
            Ok(CheckpointObservedPathState::Absent)
        }
        1 => {
            let (Some(hash), Some(size), Some(mode)) = (hash, size, mode) else {
                return Err(CheckpointStoreError::CorruptRecord(field));
            };
            Ok(CheckpointObservedPathState::Regular {
                hash: decode_hash(&hash, field)?,
                size: decode_size(size, field)?,
                mode: decode_mode(mode, field)?,
            })
        }
        _ => Err(CheckpointStoreError::CorruptRecord(field)),
    }
}

fn decode_inverse(
    kind: i64,
    blob: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
    size: Option<i64>,
    mode: Option<i64>,
) -> Result<RestoreEffect, CheckpointStoreError> {
    match kind {
        0 if blob.is_none() && hash.is_none() && size.is_none() && mode.is_none() => {
            Ok(RestoreEffect::Delete)
        }
        1 => {
            let (Some(blob), Some(hash), Some(size), Some(mode)) = (blob, hash, size, mode) else {
                return Err(CheckpointStoreError::CorruptRecord("restore.inverse"));
            };
            Ok(RestoreEffect::Restore {
                blob: decode_blob(&blob, "restore.inverse_blob")?,
                hash: decode_hash(&hash, "restore.inverse_hash")?,
                size: decode_size(size, "restore.inverse_size")?,
                mode: decode_mode(mode, "restore.inverse_mode")?,
            })
        }
        _ => Err(CheckpointStoreError::CorruptRecord("restore.inverse_kind")),
    }
}

fn decode_uuid<T, F>(
    bytes: &[u8],
    field: &'static str,
    constructor: F,
) -> Result<T, CheckpointStoreError>
where
    F: FnOnce(Uuid) -> T,
{
    Uuid::from_slice(bytes)
        .map(constructor)
        .map_err(|_| CheckpointStoreError::CorruptRecord(field))
}

pub(super) fn decode_checkpoint_id(bytes: &[u8]) -> Result<CheckpointId, CheckpointStoreError> {
    decode_uuid(bytes, "checkpoint_id", CheckpointId::from_uuid)
}

pub(super) fn decode_change_set_id(bytes: &[u8]) -> Result<ChangeSetId, CheckpointStoreError> {
    decode_uuid(bytes, "checkpoint.changeset_id", ChangeSetId::from_uuid)
}

pub(super) fn decode_workspace_id(bytes: &[u8]) -> Result<WorkspaceId, CheckpointStoreError> {
    decode_uuid(bytes, "checkpoint.workspace_id", WorkspaceId::from_uuid)
}

pub(super) fn decode_activity_id(bytes: &[u8]) -> Result<ActivityId, CheckpointStoreError> {
    decode_uuid(bytes, "checkpoint.activity_id", ActivityId::from_uuid)
}

fn decode_required_uuid_field(
    field: &'static str,
    length: Option<i64>,
    bytes: Vec<u8>,
) -> Result<uuid::Uuid, CheckpointStoreError> {
    let Some(length) = length else {
        return Err(CheckpointStoreError::CorruptRecord(field));
    };
    if length != ID_BYTES_I64 || bytes.len() != ID_BYTES {
        return Err(CheckpointStoreError::CorruptRecord(field));
    }
    let fixed: [u8; ID_BYTES] = bytes
        .try_into()
        .map_err(|_| CheckpointStoreError::CorruptRecord(field))?;
    Ok(uuid::Uuid::from_bytes(fixed))
}

fn decode_optional_uuid_field(
    field: &'static str,
    length: Option<i64>,
    bytes: Option<Vec<u8>>,
) -> Result<Option<uuid::Uuid>, CheckpointStoreError> {
    let Some(bytes) = bytes else {
        if length.is_none() {
            return Ok(None);
        }
        return Err(CheckpointStoreError::CorruptRecord(field));
    };
    let Some(length) = length else {
        return Err(CheckpointStoreError::CorruptRecord(field));
    };
    if length != ID_BYTES_I64 || bytes.len() != ID_BYTES {
        return Err(CheckpointStoreError::CorruptRecord(field));
    }
    let fixed: [u8; ID_BYTES] = bytes
        .try_into()
        .map_err(|_| CheckpointStoreError::CorruptRecord(field))?;
    Ok(Some(uuid::Uuid::from_bytes(fixed)))
}

fn decode_restore_id(bytes: &[u8]) -> Result<CheckpointRestoreId, CheckpointStoreError> {
    decode_uuid(bytes, "restore_id", CheckpointRestoreId::from_uuid)
}

fn decode_path(bytes: Vec<u8>) -> Result<WorkspaceRelativePath, CheckpointStoreError> {
    WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(bytes)))
        .map_err(|_| CheckpointStoreError::CorruptRecord("checkpoint.relative_path"))
}

pub(super) fn decode_workspace_revision(
    value: i64,
) -> Result<WorkspaceRevision, CheckpointStoreError> {
    WorkspaceRevision::new(value)
        .map_err(|_| CheckpointStoreError::CorruptRecord("workspace_revision"))
}

fn decode_checkpoint_revision(value: i64) -> Result<CheckpointRevision, CheckpointStoreError> {
    CheckpointRevision::new(value)
        .map_err(|_| CheckpointStoreError::CorruptRecord("checkpoint.revision"))
}

fn decode_restore_revision(value: i64) -> Result<CheckpointRestoreRevision, CheckpointStoreError> {
    CheckpointRestoreRevision::new(value)
        .map_err(|_| CheckpointStoreError::CorruptRecord("restore.revision"))
}

fn decode_timestamp(
    value: i64,
    field: &'static str,
) -> Result<TimestampMillis, CheckpointStoreError> {
    TimestampMillis::new(value).map_err(|_| CheckpointStoreError::CorruptRecord(field))
}

fn decode_object_format(value: i64) -> Result<forge_domain::GitObjectFormat, CheckpointStoreError> {
    match value {
        0 => Ok(forge_domain::GitObjectFormat::Sha1),
        _ => Err(CheckpointStoreError::CorruptRecord(
            "checkpoint.object_format",
        )),
    }
}

fn decode_checkpoint_state(value: i64) -> Result<CheckpointState, CheckpointStoreError> {
    match value {
        0 => Ok(CheckpointState::Starting),
        1 => Ok(CheckpointState::Ready),
        _ => Err(CheckpointStoreError::CorruptRecord("checkpoint.state")),
    }
}

fn decode_restore_state(value: i64) -> Result<CheckpointRestoreState, CheckpointStoreError> {
    match value {
        0 => Ok(CheckpointRestoreState::Starting),
        1 => Ok(CheckpointRestoreState::Restored),
        2 => Ok(CheckpointRestoreState::Failed),
        3 => Ok(CheckpointRestoreState::RecoveryRequired),
        _ => Err(CheckpointStoreError::CorruptRecord("restore.state")),
    }
}

fn decode_failure_code(value: i64) -> Result<CheckpointRestoreFailureCode, CheckpointStoreError> {
    match value {
        0 => Ok(CheckpointRestoreFailureCode::MissingObject),
        1 => Ok(CheckpointRestoreFailureCode::ObjectHashMismatch),
        2 => Ok(CheckpointRestoreFailureCode::PathConflict),
        3 => Ok(CheckpointRestoreFailureCode::IoFailure),
        _ => Err(CheckpointStoreError::CorruptRecord("restore.failure_code")),
    }
}

pub(super) fn decode_hash(
    bytes: &[u8],
    field: &'static str,
) -> Result<FileContentHash, CheckpointStoreError> {
    let value: [u8; HASH_BYTES] = bytes
        .try_into()
        .map_err(|_| CheckpointStoreError::CorruptRecord(field))?;
    Ok(FileContentHash::from_bytes(value))
}

fn decode_blob(bytes: &[u8], field: &'static str) -> Result<GitBlobId, CheckpointStoreError> {
    let value: [u8; SHA1_BYTES] = bytes
        .try_into()
        .map_err(|_| CheckpointStoreError::CorruptRecord(field))?;
    Ok(GitBlobId::from_sha1_bytes(value))
}

fn decode_commit(bytes: &[u8], field: &'static str) -> Result<GitCommitId, CheckpointStoreError> {
    let value: [u8; SHA1_BYTES] = bytes
        .try_into()
        .map_err(|_| CheckpointStoreError::CorruptRecord(field))?;
    Ok(GitCommitId::from_sha1_bytes(value))
}

pub(super) fn decode_size(
    value: i64,
    field: &'static str,
) -> Result<FileByteCount, CheckpointStoreError> {
    u64::try_from(value)
        .map(FileByteCount::new)
        .map_err(|_| CheckpointStoreError::CorruptRecord(field))
}

fn decode_mode(
    value: i64,
    field: &'static str,
) -> Result<CheckpointFileMode, CheckpointStoreError> {
    let value = u16::try_from(value).map_err(|_| CheckpointStoreError::CorruptRecord(field))?;
    CheckpointFileMode::new(value).map_err(|_| CheckpointStoreError::CorruptRecord(field))
}

fn validate_path_length(length: usize) -> Result<(), CheckpointStoreError> {
    if length == 0 || length > MAX_PATH_BYTES {
        return Err(if length > MAX_PATH_BYTES {
            CheckpointStoreError::PersistedFieldTooLarge {
                field: "checkpoint.relative_path",
                actual: length,
                maximum: MAX_PATH_BYTES,
            }
        } else {
            CheckpointStoreError::CorruptRecord("checkpoint.relative_path")
        });
    }
    Ok(())
}

pub(super) fn validate_path_length_from_sql(
    field: &'static str,
    length: i64,
) -> Result<(), CheckpointStoreError> {
    if length < 0 {
        return Err(CheckpointStoreError::CorruptRecord(field));
    }
    validate_path_length(usize::try_from(length).unwrap_or(usize::MAX))
}

pub(super) fn validate_exact_length(
    field: &'static str,
    length: i64,
    expected_i64: i64,
    expected: usize,
) -> Result<(), CheckpointStoreError> {
    if length == expected_i64 {
        Ok(())
    } else {
        Err(CheckpointStoreError::PersistedFieldLengthInvalid {
            field,
            actual: usize::try_from(length).unwrap_or(usize::MAX),
            expected,
        })
    }
}

pub(super) fn validate_optional_exact_length(
    field: &'static str,
    length: Option<i64>,
    expected_i64: i64,
    expected: usize,
) -> Result<(), CheckpointStoreError> {
    if let Some(length) = length {
        validate_exact_length(field, length, expected_i64, expected)?;
    }
    Ok(())
}
