//! Owner-controlled Workspace root-binding recovery.
//!
//! This module is deliberately separate from normal Workspace open and
//! registration.  A recovery probe may accept the selected Workspace's old
//! root fingerprint while the effect boundary holds the exclusive root gate;
//! ordinary open paths continue to require an exact live binding.

use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use forge_domain::{
    LocationRevision, RegisteredWorkspace, TimestampMillis, WorkspaceId, WorkspaceRoot,
    WorkspaceRootFingerprint, WorkspaceRootRecoveryAuthorityMode,
    WorkspaceRootRecoveryDelegatedAuthority, WorkspaceRootRecoveryDelegationFence,
    WorkspaceRootRecoveryError, WorkspaceRootRecoveryFreezeFence, WorkspaceRootRecoveryFreezeState,
    WorkspaceRootRecoveryObservation, WorkspaceRootRecoveryRequest, WorkspaceRootRecoveryWitness,
    decide_workspace_root_recovery,
};
use forge_workspace::{ExistingWorkspaceStateLayout, WorkspaceStateExclusiveGate};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Row, Transaction, TransactionBehavior, params,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{
    BUSY_TIMEOUT, CURRENT_SCHEMA_VERSION, DatabaseOwnership, DirectoryIdentity,
    DoctorFileObservation, ReadOnlyDoctorDatabase, WorkspaceDoctorIdentity,
    WorkspaceDoctorObservations, WorkspaceDoctorOutcome, WorkspaceDoctorReport,
    WorkspaceDoctorSourceObservation, WorkspaceLiveBinding, WorkspaceSchemaShape,
    WorkspaceStateRemovalBlocker, WorkspaceStore, WorkspaceStoreError, application_id,
    decode_workspace, doctor_foreign_key_check, doctor_quick_check, doctor_stale_count,
    ensure_live_paths, inspect_database, path_to_bytes_bounded, query_workspace_row,
    runtime_policy, schema_version, state_removal_blocker_for_connection,
    state_removal_blocker_rows, validate_runtime_policy, validate_schema_shape_for_version,
};

const TABLE_NAME: &str = "workspace_root_recovery_receipts";
const DELEGATION_TABLE_NAME: &str = "root_recovery_delegation_receipts";
const OPERATOR_KIND_EXPLICIT_OWNER: i64 = 0;
const WITNESS_DIGEST_BYTES: usize = 32;
const FINGERPRINT_BYTES: usize = 16;
const MAX_ROOT_BYTES: usize = 4_096;

// This is the one canonical DDL authority for the additive schema-v62 receipt.
const TABLE_SQL: &str = "CREATE TABLE workspace_root_recovery_receipts (request_id BLOB PRIMARY KEY NOT NULL CHECK(length(request_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), location_id BLOB NOT NULL CHECK(length(location_id) = 16), expected_location_revision INTEGER NOT NULL CHECK(expected_location_revision >= 1), expected_workspace_revision INTEGER NOT NULL CHECK(expected_workspace_revision >= 1), result_workspace_revision INTEGER NOT NULL CHECK(result_workspace_revision = expected_workspace_revision + 1), root_path BLOB NOT NULL CHECK(length(root_path) BETWEEN 1 AND 4096), old_root_fingerprint BLOB NOT NULL CHECK(length(old_root_fingerprint) = 16), new_root_fingerprint BLOB NOT NULL CHECK(length(new_root_fingerprint) = 16 AND new_root_fingerprint != old_root_fingerprint), expected_created_at_ms INTEGER NOT NULL CHECK(expected_created_at_ms >= 0), expected_updated_at_ms INTEGER NOT NULL CHECK(expected_updated_at_ms >= 0), observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms >= expected_updated_at_ms), request_digest BLOB NOT NULL CHECK(length(request_digest) = 32), witness_digest BLOB NOT NULL CHECK(length(witness_digest) = 32), receipt_digest BLOB NOT NULL CHECK(length(receipt_digest) = 32), operator_kind INTEGER NOT NULL CHECK(operator_kind = 0), UNIQUE(workspace_id, expected_workspace_revision))";
const DELEGATION_TABLE_SQL: &str = "CREATE TABLE root_recovery_delegation_receipts (request_id BLOB PRIMARY KEY NOT NULL REFERENCES workspace_root_recovery_receipts(request_id) CHECK(length(request_id) = 16), mode_version INTEGER NOT NULL CHECK(mode_version = 2), mode_kind INTEGER NOT NULL CHECK(mode_kind = 1), migration_id BLOB NOT NULL REFERENCES agent_operations_migrations(migration_id) CHECK(length(migration_id) = 16), workspace_id BLOB NOT NULL REFERENCES workspace(workspace_id) CHECK(length(workspace_id) = 16), destination_id BLOB NOT NULL CHECK(length(destination_id) = 16), freeze_state INTEGER NOT NULL CHECK(freeze_state = 0), freeze_revision INTEGER NOT NULL CHECK(freeze_revision >= 1), freeze_created_at_ms INTEGER NOT NULL CHECK(freeze_created_at_ms >= 0), freeze_updated_at_ms INTEGER NOT NULL CHECK(freeze_updated_at_ms >= freeze_created_at_ms), delegation_freeze_revision INTEGER NOT NULL CHECK(delegation_freeze_revision = freeze_revision), manifest_digest BLOB NOT NULL CHECK(length(manifest_digest) = 32 AND manifest_digest != zeroblob(32)), delegated_at_ms INTEGER NOT NULL CHECK(delegated_at_ms >= freeze_updated_at_ms), authority_digest BLOB NOT NULL CHECK(length(authority_digest) = 32), normal_request_intent_digest BLOB NOT NULL CHECK(length(normal_request_intent_digest) = 32), witness_v2_digest BLOB NOT NULL CHECK(length(witness_v2_digest) = 32))";

const WITNESS_DOMAIN: &[u8] = b"forge.workspace.root-recovery.witness.v1\0";
const WITNESS_V2_DOMAIN: &[u8] = b"forge.workspace.root-recovery.witness.v2\0";
const INTENT_DOMAIN: &[u8] = b"forge.workspace.root-recovery.intent.v1\0";
const INTENT_V2_DOMAIN: &[u8] = b"forge.workspace.root-recovery.intent.v2\0";
const RECEIPT_DOMAIN: &[u8] = b"forge.workspace.root-recovery.receipt.v1\0";
const RECEIPT_V2_DOMAIN: &[u8] = b"forge.workspace.root-recovery.receipt.v2\0";
const AUTHORITY_DOMAIN: &[u8] = b"forge.workspace.root-recovery.delegated-authority.v2\0";

/// One active or nonterminal authority that prevents a root-binding change.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootRecoveryAuthorityBlocker {
    StateRemoval(WorkspaceStateRemovalBlocker),
    AgentOperationsFreeze,
    AgentOperationsDelegation,
    PendingGoalDeletion,
    StartingCheckpoint,
    StartingCheckpointRestore,
    StartingChangeSet,
    PendingDiffEvidence,
    StartingVerification,
    PendingApproval,
    ActiveExecutionGrant,
    ActiveAutoApprovalScope,
    NonterminalAssignment,
    AttachedAgentSession,
    PostDelegationParticipation,
}

/// Exact source observation returned by a read-only owner probe.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRecoveryProbe {
    workspace: RegisteredWorkspace,
    observation: WorkspaceRootRecoveryObservation,
    schema_version: i64,
    doctor: WorkspaceDoctorReport,
    source: WorkspaceDoctorSourceObservation,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
}

/// Bounded read-only identity observation that intentionally tolerates the
/// selected Workspace's old stored root fingerprint.  It performs no
/// authority scan, initialization, migration, or effect admission and is
/// suitable for a control-plane duplicate-identity scan.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRecoveryIdentityObservation {
    workspace: RegisteredWorkspace,
    current_root_fingerprint: WorkspaceRootFingerprint,
    schema_version: i64,
    witness: WorkspaceRootRecoveryWitness,
}

impl RootRecoveryIdentityObservation {
    pub const fn workspace(&self) -> &RegisteredWorkspace {
        &self.workspace
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace.id()
    }

    pub const fn location_id(&self) -> forge_domain::LocationId {
        self.workspace.location_id()
    }

    pub const fn current_root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.current_root_fingerprint
    }

    pub const fn schema_version(&self) -> i64 {
        self.schema_version
    }

    pub const fn witness(&self) -> WorkspaceRootRecoveryWitness {
        self.witness
    }
}

impl RootRecoveryProbe {
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace.id()
    }

    pub const fn location_id(&self) -> forge_domain::LocationId {
        self.workspace.location_id()
    }

    pub const fn workspace(&self) -> &RegisteredWorkspace {
        &self.workspace
    }

    pub const fn observation(&self) -> &WorkspaceRootRecoveryObservation {
        &self.observation
    }

    pub const fn schema_version(&self) -> i64 {
        self.schema_version
    }

    pub const fn requires_schema_upgrade(&self) -> bool {
        self.schema_version < CURRENT_SCHEMA_VERSION
    }

    pub const fn authority_mode(&self) -> WorkspaceRootRecoveryAuthorityMode {
        self.authority_mode
    }

    pub const fn doctor(&self) -> &WorkspaceDoctorReport {
        &self.doctor
    }
}

/// Immutable durable readback of one binding transition.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRecoveryReceipt {
    request_id: Uuid,
    expected_location_revision: LocationRevision,
    expected_workspace_revision: forge_domain::WorkspaceRevision,
    workspace: RegisteredWorkspace,
    old_root_fingerprint: WorkspaceRootFingerprint,
    request_digest: [u8; WITNESS_DIGEST_BYTES],
    witness_digest: [u8; WITNESS_DIGEST_BYTES],
    receipt_digest: [u8; WITNESS_DIGEST_BYTES],
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
}

impl RootRecoveryReceipt {
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub const fn expected_location_revision(&self) -> LocationRevision {
        self.expected_location_revision
    }

    pub const fn expected_workspace_revision(&self) -> forge_domain::WorkspaceRevision {
        self.expected_workspace_revision
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace.id()
    }

    pub const fn workspace(&self) -> &RegisteredWorkspace {
        &self.workspace
    }

    pub const fn old_root_fingerprint(&self) -> WorkspaceRootFingerprint {
        self.old_root_fingerprint
    }

    pub const fn request_digest(&self) -> &[u8; WITNESS_DIGEST_BYTES] {
        &self.request_digest
    }

    pub const fn witness_digest(&self) -> &[u8; WITNESS_DIGEST_BYTES] {
        &self.witness_digest
    }

    pub const fn receipt_digest(&self) -> &[u8; WITNESS_DIGEST_BYTES] {
        &self.receipt_digest
    }

    pub const fn authority_mode(&self) -> WorkspaceRootRecoveryAuthorityMode {
        self.authority_mode
    }
}

/// Result of an owner-controlled transition or an exact request replay.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootRecoveryOperation {
    Committed(RootRecoveryReceipt),
    Replay(RootRecoveryReceipt),
}

#[derive(Debug, Error)]
pub enum RootRecoveryStoreError {
    #[error(transparent)]
    Store(#[from] WorkspaceStoreError),
    #[error(transparent)]
    Intent(#[from] WorkspaceRootRecoveryError),
    #[error("root recovery Workspace projection changed after the probe")]
    WorkspaceChanged,
    #[error("root recovery probe observation changed")]
    ObservationChanged,
    #[error("root recovery requires schema {actual} to be upgraded to {current}")]
    SchemaUpgradeRequired { actual: i64, current: i64 },
    #[error("root recovery schema migration committed but requires durable readback")]
    SchemaMigrationCommittedUnconfirmed {
        #[source]
        source: Box<RootRecoveryStoreError>,
    },
    #[error("root recovery is blocked by active authority {0:?}")]
    ActiveAuthority(RootRecoveryAuthorityBlocker),
    #[error("root recovery Doctor outcome is {0:?}")]
    Doctor(WorkspaceDoctorOutcome),
    #[error("root recovery request conflicts with its durable receipt")]
    RequestConflict,
    #[error("root recovery commit for {request_id} requires durable readback")]
    CommittedUnconfirmed {
        request_id: Uuid,
        #[source]
        source: Box<RootRecoveryStoreError>,
    },
    #[error("root recovery rollback could not be confirmed")]
    RollbackUnconfirmed {
        #[source]
        source: Box<RootRecoveryStoreError>,
        rollback: rusqlite::Error,
    },
    #[error("root recovery receipt {request_id} was not found after commit")]
    ReceiptReadbackMissing { request_id: Uuid },
    #[error("root recovery observation timestamp is not representable")]
    ObservationEncoding,
}

impl From<rusqlite::Error> for RootRecoveryStoreError {
    fn from(source: rusqlite::Error) -> Self {
        Self::Store(WorkspaceStoreError::Sqlite(source))
    }
}

#[derive(Debug, Clone)]
struct ReceiptRecord {
    request_id: Uuid,
    workspace_id: WorkspaceId,
    location_id: forge_domain::LocationId,
    expected_location_revision: i64,
    expected_workspace_revision: i64,
    result_workspace_revision: i64,
    root_path: Vec<u8>,
    old_root_fingerprint: [u8; FINGERPRINT_BYTES],
    new_root_fingerprint: [u8; FINGERPRINT_BYTES],
    expected_created_at_ms: i64,
    expected_updated_at_ms: i64,
    observed_at_ms: i64,
    request_digest: [u8; WITNESS_DIGEST_BYTES],
    witness_digest: [u8; WITNESS_DIGEST_BYTES],
    receipt_digest: [u8; WITNESS_DIGEST_BYTES],
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
}

pub(crate) fn create_schema(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    connection.execute_batch(TABLE_SQL)?;
    connection.execute_batch(DELEGATION_TABLE_SQL)?;
    Ok(())
}

pub(crate) fn create_base_schema(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    connection.execute_batch(TABLE_SQL)?;
    Ok(())
}

pub(crate) fn create_delegation_schema(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    connection.execute_batch(DELEGATION_TABLE_SQL)?;
    Ok(())
}

pub(crate) const fn schema_objects_v62() -> [(&'static str, &'static str); 1] {
    [("table", TABLE_NAME)]
}

pub(crate) const fn delegation_schema_objects() -> [(&'static str, &'static str); 1] {
    [("table", DELEGATION_TABLE_NAME)]
}

pub(crate) fn validate_schema_v62(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    let actual = super::bounded_schema_sql(connection, "table", TABLE_NAME, TABLE_NAME)?;
    if actual.as_deref() != Some(TABLE_SQL)
        && !actual
            .as_deref()
            .is_some_and(|value| super::schema_sql_matches(value, TABLE_SQL))
    {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "root recovery receipt table SQL definition does not match the expected policy"
                .to_owned(),
        });
    }
    let columns = super::table_columns(connection, TABLE_NAME)?;
    let expected = [
        ("request_id", "BLOB", 1, 1),
        ("workspace_id", "BLOB", 1, 0),
        ("location_id", "BLOB", 1, 0),
        ("expected_location_revision", "INTEGER", 1, 0),
        ("expected_workspace_revision", "INTEGER", 1, 0),
        ("result_workspace_revision", "INTEGER", 1, 0),
        ("root_path", "BLOB", 1, 0),
        ("old_root_fingerprint", "BLOB", 1, 0),
        ("new_root_fingerprint", "BLOB", 1, 0),
        ("expected_created_at_ms", "INTEGER", 1, 0),
        ("expected_updated_at_ms", "INTEGER", 1, 0),
        ("observed_at_ms", "INTEGER", 1, 0),
        ("request_digest", "BLOB", 1, 0),
        ("witness_digest", "BLOB", 1, 0),
        ("receipt_digest", "BLOB", 1, 0),
        ("operator_kind", "INTEGER", 1, 0),
    ];
    let columns_match = columns.len() == expected.len()
        && columns.iter().zip(expected).all(
            |((name, data_type, not_null, primary_key), expected)| {
                name == expected.0
                    && data_type == expected.1
                    && *not_null == expected.2
                    && *primary_key == expected.3
            },
        );
    if !columns_match {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "root recovery receipt table columns do not match the expected shape"
                .to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection) -> Result<(), WorkspaceStoreError> {
    validate_schema_v62(connection)?;
    let delegation = super::bounded_schema_sql(
        connection,
        "table",
        DELEGATION_TABLE_NAME,
        DELEGATION_TABLE_NAME,
    )?;
    if delegation.as_deref() != Some(DELEGATION_TABLE_SQL)
        && !delegation
            .as_deref()
            .is_some_and(|value| super::schema_sql_matches(value, DELEGATION_TABLE_SQL))
    {
        return Err(WorkspaceStoreError::DamagedSchema {
            detail: "root recovery delegated receipt table does not match policy".to_owned(),
        });
    }
    Ok(())
}

impl WorkspaceStore {
    /// Probe a selected root while the caller retains the exclusive root gate.
    /// This is the only read path that accepts the durable old fingerprint.
    pub fn probe_root_recovery(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
        expected: &RegisteredWorkspace,
    ) -> Result<RootRecoveryProbe, RootRecoveryStoreError> {
        Self::probe_root_recovery_with_mode(
            layout,
            gate,
            expected,
            WorkspaceRootRecoveryAuthorityMode::Quiescent,
        )
    }

    pub fn probe_root_recovery_preserving_delegated_freeze(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
        expected: &RegisteredWorkspace,
        authority: WorkspaceRootRecoveryDelegatedAuthority,
    ) -> Result<RootRecoveryProbe, RootRecoveryStoreError> {
        Self::probe_root_recovery_with_mode(
            layout,
            gate,
            expected,
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority),
        )
    }

    fn probe_root_recovery_with_mode(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
        expected: &RegisteredWorkspace,
        authority_mode: WorkspaceRootRecoveryAuthorityMode,
    ) -> Result<RootRecoveryProbe, RootRecoveryStoreError> {
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;
        if expected.root().as_path() != layout.workspace_root() {
            return Err(RootRecoveryStoreError::WorkspaceChanged);
        }
        if expected.root_fingerprint() == root_fingerprint {
            return Err(RootRecoveryStoreError::Intent(
                WorkspaceRootRecoveryError::UnchangedFingerprint,
            ));
        }

        let database = ReadOnlyDoctorDatabase::open_under_exclusive(layout, gate)?;
        let ownership = inspect_database(&database.connection)?;
        let shape = recovery_schema_shape(ownership)?;
        validate_schema_shape_for_version(&database.connection, shape)?;
        let stored = query_workspace_row(&database.connection)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        if stored != *expected {
            return Err(RootRecoveryStoreError::WorkspaceChanged);
        }
        let _recovery_lease = crate::workspace_recovery::get(&database.connection, stored.id())
            .map_err(|source| {
                RootRecoveryStoreError::Store(WorkspaceStoreError::Recovery(source))
            })?;

        let doctor = recovery_doctor_report(
            &database.connection,
            &stored,
            schema_version(&database.connection)?,
            application_id(&database.connection)?,
        )?;
        if !doctor.is_healthy() {
            return Err(RootRecoveryStoreError::Doctor(doctor.outcome()));
        }
        validate_authority_mode(&database.connection, stored.id(), authority_mode)?;
        database.ensure_unchanged()?;
        gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;

        let source = database.source_observation();
        let witness = source_witness(
            &stored,
            root_fingerprint,
            &source,
            doctor.schema_version(),
            doctor.application_id(),
            authority_mode,
        )?;
        let observation =
            WorkspaceRootRecoveryObservation::new(stored.root().clone(), root_fingerprint, witness);
        Ok(RootRecoveryProbe {
            workspace: stored,
            observation,
            schema_version: shape.version(),
            doctor,
            source,
            authority_mode,
        })
    }

    /// Observe the stored Workspace identity from a bounded stable snapshot.
    /// The logical root path, schema, recovery row, and source data identities
    /// are validated, but the stored root fingerprint is deliberately allowed
    /// to differ from the current root fingerprint.
    pub fn inspect_existing_root_recovery_identity_read_only(
        layout: &ExistingWorkspaceStateLayout,
    ) -> Result<RootRecoveryIdentityObservation, RootRecoveryStoreError> {
        let current_root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        let database = ReadOnlyDoctorDatabase::open(layout)?;
        let ownership = inspect_database(&database.connection)?;
        let shape = recovery_schema_shape(ownership)?;
        validate_schema_shape_for_version(&database.connection, shape)?;
        let workspace = query_workspace_row(&database.connection)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        if workspace.root().as_path() != layout.workspace_root() {
            return Err(RootRecoveryStoreError::WorkspaceChanged);
        }
        let _recovery_lease = crate::workspace_recovery::get(&database.connection, workspace.id())
            .map_err(|source| {
                RootRecoveryStoreError::Store(WorkspaceStoreError::Recovery(source))
            })?;
        database.ensure_unchanged()?;
        let source = database.source_observation();
        let witness = source_witness(
            &workspace,
            current_root_fingerprint,
            &source,
            schema_version(&database.connection)?,
            application_id(&database.connection)?,
            WorkspaceRootRecoveryAuthorityMode::Quiescent,
        )?;
        Ok(RootRecoveryIdentityObservation {
            workspace,
            current_root_fingerprint,
            schema_version: shape.version(),
            witness,
        })
    }

    /// Upgrade the known schema-v61 receipt shape without changing the
    /// Workspace binding.  The caller must probe again before the CAS because
    /// SQLite metadata and sidecars are allowed to change during migration.
    #[allow(clippy::too_many_lines)]
    pub fn upgrade_root_recovery_schema(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
        probe: &RootRecoveryProbe,
    ) -> Result<(), RootRecoveryStoreError> {
        if probe.schema_version == CURRENT_SCHEMA_VERSION {
            return Ok(());
        }
        if !matches!(
            probe.schema_version,
            super::PREVIOUS_ROOT_RECOVERY_SCHEMA_VERSION
                | super::PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION
                | super::PREVIOUS_EXPIRED_ACTIVITY_RECOVERY_SCHEMA_VERSION
                | super::PREVIOUS_BINDING_REJECTION_SCHEMA_VERSION
                | super::PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION
                | super::PREVIOUS_STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION
                | super::PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION
                | super::PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION
        ) {
            return Err(RootRecoveryStoreError::SchemaUpgradeRequired {
                actual: probe.schema_version,
                current: CURRENT_SCHEMA_VERSION,
            });
        }
        let root_fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        if root_fingerprint != probe.observation.fingerprint() {
            return Err(RootRecoveryStoreError::ObservationChanged);
        }
        gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;
        probe.source.ensure_unchanged(layout)?;

        let mut connection = open_transition_connection(layout, gate, &probe.source)?;
        if !matches!(inspect_database(&connection)?, DatabaseOwnership::Outdated { version } if version == probe.schema_version)
        {
            return Err(RootRecoveryStoreError::ObservationChanged);
        }
        let source_shape = match probe.schema_version {
            super::PREVIOUS_ROOT_RECOVERY_SCHEMA_VERSION => WorkspaceSchemaShape::V61,
            super::PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION => WorkspaceSchemaShape::V62,
            super::PREVIOUS_EXPIRED_ACTIVITY_RECOVERY_SCHEMA_VERSION => WorkspaceSchemaShape::V63,
            super::PREVIOUS_BINDING_REJECTION_SCHEMA_VERSION => WorkspaceSchemaShape::V64,
            super::PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION => {
                WorkspaceSchemaShape::V65
            }
            super::PREVIOUS_STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION => {
                WorkspaceSchemaShape::V66
            }
            super::PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION => WorkspaceSchemaShape::V67,
            super::PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION => {
                WorkspaceSchemaShape::V68
            }
            _ => unreachable!("schema version was checked above"),
        };
        validate_schema_shape_for_version(&connection, source_shape)?;
        let current = query_workspace_row(&connection)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        if current != probe.workspace {
            return Err(RootRecoveryStoreError::WorkspaceChanged);
        }
        validate_authority_mode(&connection, current.id(), probe.authority_mode)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_authority_mode(&transaction, current.id(), probe.authority_mode)?;
        if source_shape == WorkspaceSchemaShape::V61 {
            create_schema(&transaction)?;
            create_delegation_schema(&transaction)?;
            crate::workspace_expired_activity_recovery::create_schema(&transaction).map_err(
                |error| {
                    RootRecoveryStoreError::Store(WorkspaceStoreError::DamagedSchema {
                        detail: error.to_string(),
                    })
                },
            )?;
            crate::workspace_agent_binding_rejections::create_schema(&transaction).map_err(
                |error| {
                    RootRecoveryStoreError::Store(WorkspaceStoreError::DamagedSchema {
                        detail: error.to_string(),
                    })
                },
            )?;
        } else if source_shape == WorkspaceSchemaShape::V62 {
            create_delegation_schema(&transaction)?;
            crate::workspace_expired_activity_recovery::create_schema(&transaction).map_err(
                |error| {
                    RootRecoveryStoreError::Store(WorkspaceStoreError::DamagedSchema {
                        detail: error.to_string(),
                    })
                },
            )?;
            crate::workspace_agent_binding_rejections::create_schema(&transaction).map_err(
                |error| {
                    RootRecoveryStoreError::Store(WorkspaceStoreError::DamagedSchema {
                        detail: error.to_string(),
                    })
                },
            )?;
        } else if source_shape == WorkspaceSchemaShape::V63 {
            crate::workspace_expired_activity_recovery::create_schema(&transaction).map_err(
                |error| {
                    RootRecoveryStoreError::Store(WorkspaceStoreError::DamagedSchema {
                        detail: error.to_string(),
                    })
                },
            )?;
            crate::workspace_agent_binding_rejections::create_schema(&transaction).map_err(
                |error| {
                    RootRecoveryStoreError::Store(WorkspaceStoreError::DamagedSchema {
                        detail: error.to_string(),
                    })
                },
            )?;
        } else if source_shape == WorkspaceSchemaShape::V64 {
            crate::workspace_agent_binding_rejections::create_schema(&transaction).map_err(
                |error| {
                    RootRecoveryStoreError::Store(WorkspaceStoreError::DamagedSchema {
                        detail: error.to_string(),
                    })
                },
            )?;
        } else if !matches!(
            source_shape,
            WorkspaceSchemaShape::V65
                | WorkspaceSchemaShape::V66
                | WorkspaceSchemaShape::V67
                | WorkspaceSchemaShape::V68
        ) {
            return Err(RootRecoveryStoreError::SchemaUpgradeRequired {
                actual: probe.schema_version,
                current: CURRENT_SCHEMA_VERSION,
            });
        }
        if !source_shape.includes_unstarted_activity_continuation() {
            crate::workspace_unstarted_activity_continuation::create_schema(&transaction).map_err(
                |error| {
                    RootRecoveryStoreError::Store(WorkspaceStoreError::DamagedSchema {
                        detail: error.to_string(),
                    })
                },
            )?;
        }
        if !source_shape.includes_started_activity_lease_resume() {
            crate::workspace_started_activity_lease_resumes::create_schema(&transaction).map_err(
                |error| {
                    RootRecoveryStoreError::Store(WorkspaceStoreError::DamagedSchema {
                        detail: error.to_string(),
                    })
                },
            )?;
        }
        if !source_shape.includes_quiescent_activity_lease_resume() {
            crate::workspace_quiescent_activity_lease_resumes::create_schema(&transaction)
                .map_err(|error| {
                    RootRecoveryStoreError::Store(WorkspaceStoreError::DamagedSchema {
                        detail: error.to_string(),
                    })
                })?;
        }
        if probe.schema_version < super::PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION {
            crate::workspace_admission_envelopes::migrate_identity_schema(&transaction)
                .map_err(WorkspaceStoreError::from)?;
        }
        gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;
        ensure_source_identity(&probe.source, layout, root_fingerprint)?;
        transaction
            .pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)
            .map_err(WorkspaceStoreError::from)?;
        validate_schema_shape_for_version(&transaction, WorkspaceSchemaShape::Current)?;
        transaction.commit().map_err(|source| {
            RootRecoveryStoreError::SchemaMigrationCommittedUnconfirmed {
                source: Box::new(RootRecoveryStoreError::Store(WorkspaceStoreError::Sqlite(
                    source,
                ))),
            }
        })?;
        let post_version = schema_version(&connection).map_err(|source| {
            RootRecoveryStoreError::SchemaMigrationCommittedUnconfirmed {
                source: Box::new(RootRecoveryStoreError::Store(source)),
            }
        })?;
        if post_version != CURRENT_SCHEMA_VERSION {
            return Err(
                RootRecoveryStoreError::SchemaMigrationCommittedUnconfirmed {
                    source: Box::new(RootRecoveryStoreError::SchemaUpgradeRequired {
                        actual: post_version,
                        current: CURRENT_SCHEMA_VERSION,
                    }),
                },
            );
        }
        validate_schema(&connection).map_err(|source| {
            RootRecoveryStoreError::SchemaMigrationCommittedUnconfirmed {
                source: Box::new(RootRecoveryStoreError::Store(source)),
            }
        })?;
        gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
            .map_err(
                |source| RootRecoveryStoreError::SchemaMigrationCommittedUnconfirmed {
                    source: Box::new(RootRecoveryStoreError::Store(
                        WorkspaceStoreError::StateGate(source),
                    )),
                },
            )?;
        ensure_source_identity(&probe.source, layout, root_fingerprint).map_err(|source| {
            RootRecoveryStoreError::SchemaMigrationCommittedUnconfirmed {
                source: Box::new(RootRecoveryStoreError::Store(source)),
            }
        })?;
        Ok(())
    }

    /// Prepare a fresh immutable commit intent.  A v61 probe is upgraded in
    /// its own explicit effect and always reprobed before this method returns;
    /// no caller may carry the pre-upgrade witness into the CAS.
    pub fn prepare_root_recovery(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
        probe: &RootRecoveryProbe,
    ) -> Result<RootRecoveryProbe, RootRecoveryStoreError> {
        let expected = probe.workspace.clone();
        if probe.requires_schema_upgrade() {
            Self::upgrade_root_recovery_schema(layout, gate, probe)?;
        }
        Self::probe_root_recovery_with_mode(layout, gate, &expected, probe.authority_mode)
    }

    /// Apply one exact owner-selected root binding change, or replay its
    /// immutable receipt.  The caller owns the gate for the complete call.
    pub fn recover_root_binding(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
        probe: &RootRecoveryProbe,
        request: &WorkspaceRootRecoveryRequest,
    ) -> Result<RootRecoveryOperation, RootRecoveryStoreError> {
        if probe.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(RootRecoveryStoreError::SchemaUpgradeRequired {
                actual: probe.schema_version,
                current: CURRENT_SCHEMA_VERSION,
            });
        }
        if probe.workspace != *request.expected() {
            return Err(RootRecoveryStoreError::WorkspaceChanged);
        }
        if probe.observation != *request.observed() {
            return Err(RootRecoveryStoreError::ObservationChanged);
        }
        let root_fingerprint = request.observed().fingerprint();
        gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;
        if let Some(existing) = load_root_receipt_under_gate(layout, gate, request.request_id())? {
            let intent_digest = request_intent_digest(request);
            if !receipt_matches_request(&existing, request, intent_digest) {
                return Err(RootRecoveryStoreError::RequestConflict);
            }
            return Ok(RootRecoveryOperation::Replay(existing.into_receipt()?));
        }
        probe.source.ensure_unchanged(layout)?;
        let intent_digest = request_intent_digest(request);
        let mut connection = open_transition_connection(layout, gate, &probe.source)?;
        validate_schema_shape_for_version(&connection, WorkspaceSchemaShape::Current)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result =
            recover_in_transaction(&transaction, gate, layout, probe, request, intent_digest);
        let result = match result {
            Ok(result) => result,
            Err(source) => {
                return match transaction.rollback() {
                    Ok(()) => Err(source),
                    Err(rollback) => Err(RootRecoveryStoreError::RollbackUnconfirmed {
                        source: Box::new(source),
                        rollback,
                    }),
                };
            }
        };
        transaction
            .commit()
            .map_err(|source| RootRecoveryStoreError::CommittedUnconfirmed {
                request_id: request.request_id(),
                source: Box::new(RootRecoveryStoreError::Store(WorkspaceStoreError::Sqlite(
                    source,
                ))),
            })?;
        confirm_root_recovery_commit(
            &connection,
            layout,
            gate,
            request,
            intent_digest,
            root_fingerprint,
            &probe.source,
        )
        .map_err(|source| RootRecoveryStoreError::CommittedUnconfirmed {
            request_id: request.request_id(),
            source: Box::new(source),
        })?;
        Ok(result)
    }

    /// Read one immutable root-recovery receipt without opening a write store.
    pub fn root_recovery_receipt(
        layout: &ExistingWorkspaceStateLayout,
        request_id: Uuid,
    ) -> Result<Option<RootRecoveryReceipt>, RootRecoveryStoreError> {
        let database = ReadOnlyDoctorDatabase::open(layout)?;
        let ownership = inspect_database(&database.connection)?;
        if !matches!(ownership, DatabaseOwnership::Current) {
            return Err(RootRecoveryStoreError::SchemaUpgradeRequired {
                actual: schema_version(&database.connection)?,
                current: CURRENT_SCHEMA_VERSION,
            });
        }
        validate_schema_shape_for_version(&database.connection, WorkspaceSchemaShape::Current)?;
        let receipt =
            load_receipt(&database.connection, request_id)?.map(ReceiptRecord::into_receipt);
        database.ensure_unchanged()?;
        receipt.transpose()
    }

    /// Read the original receipt for an exact request intent.  A reused
    /// request identity with changed intent is a durable conflict.
    pub fn root_recovery_receipt_for_request(
        layout: &ExistingWorkspaceStateLayout,
        request: &WorkspaceRootRecoveryRequest,
    ) -> Result<Option<RootRecoveryReceipt>, RootRecoveryStoreError> {
        let Some(receipt) = Self::root_recovery_receipt(layout, request.request_id())? else {
            return Ok(None);
        };
        let intent_digest = request_intent_digest(request);
        if receipt.request_digest != intent_digest
            || receipt.witness_digest != *request.observed().witness().as_bytes()
            || receipt.expected_location_revision != request.location_revision()
            || receipt.expected_workspace_revision != request.expected().revision()
            || receipt.old_root_fingerprint != request.expected().root_fingerprint()
            || receipt.workspace.id() != request.expected().id()
            || receipt.workspace.location_id() != request.expected().location_id()
            || receipt.workspace.root() != request.expected().root()
        {
            return Err(RootRecoveryStoreError::RequestConflict);
        }
        Ok(Some(receipt))
    }

    /// Read and validate an exact request receipt while the caller retains the
    /// current exclusive root gate.  This is the replay path to use before a
    /// new probe when the original Workspace row has already advanced.
    pub fn root_recovery_receipt_for_request_under_gate(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
        request: &WorkspaceRootRecoveryRequest,
    ) -> Result<Option<RootRecoveryReceipt>, RootRecoveryStoreError> {
        let Some(receipt) = load_root_receipt_under_gate(layout, gate, request.request_id())?
        else {
            return Ok(None);
        };
        let intent_digest = request_intent_digest(request);
        if !receipt_matches_request(&receipt, request, intent_digest) {
            return Err(RootRecoveryStoreError::RequestConflict);
        }
        Ok(Some(receipt.into_receipt()?))
    }
}

fn confirm_root_recovery_commit(
    connection: &Connection,
    layout: &ExistingWorkspaceStateLayout,
    gate: &WorkspaceStateExclusiveGate,
    request: &WorkspaceRootRecoveryRequest,
    intent_digest: [u8; WITNESS_DIGEST_BYTES],
    root_fingerprint: WorkspaceRootFingerprint,
    source: &WorkspaceDoctorSourceObservation,
) -> Result<(), RootRecoveryStoreError> {
    gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
        .map_err(WorkspaceStoreError::StateGate)?;
    ensure_source_identity(source, layout, root_fingerprint)?;
    let readback = load_receipt(connection, request.request_id())?.ok_or(
        RootRecoveryStoreError::ReceiptReadbackMissing {
            request_id: request.request_id(),
        },
    )?;
    if !receipt_matches_request(&readback, request, intent_digest) {
        return Err(RootRecoveryStoreError::RequestConflict);
    }
    let readback_workspace = query_workspace_row(connection)?
        .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
        .and_then(decode_workspace)?;
    let readback_receipt = readback.into_receipt()?;
    if readback_workspace != *readback_receipt.workspace() {
        return Err(RootRecoveryStoreError::WorkspaceChanged);
    }
    Ok(())
}

fn load_root_receipt_under_gate(
    layout: &ExistingWorkspaceStateLayout,
    gate: &WorkspaceStateExclusiveGate,
    request_id: Uuid,
) -> Result<Option<ReceiptRecord>, RootRecoveryStoreError> {
    let database = ReadOnlyDoctorDatabase::open_under_exclusive(layout, gate)?;
    let ownership = inspect_database(&database.connection)?;
    if !matches!(ownership, DatabaseOwnership::Current) {
        return Err(RootRecoveryStoreError::SchemaUpgradeRequired {
            actual: schema_version(&database.connection)?,
            current: CURRENT_SCHEMA_VERSION,
        });
    }
    validate_schema_shape_for_version(&database.connection, WorkspaceSchemaShape::Current)?;
    let receipt = load_receipt(&database.connection, request_id)?;
    database.ensure_unchanged()?;
    Ok(receipt)
}

fn recovery_schema_shape(
    ownership: DatabaseOwnership,
) -> Result<WorkspaceSchemaShape, RootRecoveryStoreError> {
    match ownership {
        DatabaseOwnership::Current => Ok(WorkspaceSchemaShape::Current),
        DatabaseOwnership::Outdated { version }
            if version == super::PREVIOUS_DELEGATED_ROOT_RECOVERY_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V62)
        }
        DatabaseOwnership::Outdated { version }
            if version == super::PREVIOUS_ROOT_RECOVERY_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V61)
        }
        DatabaseOwnership::Outdated { version }
            if version == super::PREVIOUS_EXPIRED_ACTIVITY_RECOVERY_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V63)
        }
        DatabaseOwnership::Outdated { version }
            if version == super::PREVIOUS_BINDING_REJECTION_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V64)
        }
        DatabaseOwnership::Outdated { version }
            if version == super::PREVIOUS_UNSTARTED_ACTIVITY_CONTINUATION_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V65)
        }
        DatabaseOwnership::Outdated { version }
            if version == super::PREVIOUS_STARTED_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V66)
        }
        DatabaseOwnership::Outdated { version }
            if version == super::PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V67)
        }
        DatabaseOwnership::Outdated { version }
            if version == super::PREVIOUS_QUIESCENT_ACTIVITY_LEASE_RESUME_SCHEMA_VERSION =>
        {
            Ok(WorkspaceSchemaShape::V68)
        }
        DatabaseOwnership::Outdated { version } => {
            Err(RootRecoveryStoreError::SchemaUpgradeRequired {
                actual: version,
                current: CURRENT_SCHEMA_VERSION,
            })
        }
        DatabaseOwnership::Fresh => Err(RootRecoveryStoreError::Store(
            WorkspaceStoreError::FreshDatabase,
        )),
    }
}

fn recovery_doctor_report(
    connection: &Connection,
    workspace: &RegisteredWorkspace,
    schema_version: i64,
    application_id: i64,
) -> Result<WorkspaceDoctorReport, RootRecoveryStoreError> {
    let quick_check = doctor_quick_check(connection)?;
    let foreign_key_check = doctor_foreign_key_check(connection)?;
    let stale_executions = doctor_stale_count(
        connection,
        "SELECT 1 FROM executions
         WHERE state IN (0, 1)
         ORDER BY updated_at_ms ASC, execution_id ASC
         LIMIT 257",
    )?;
    let stale_checkpoint_restores = doctor_stale_count(
        connection,
        "SELECT 1 FROM checkpoint_restores
         WHERE state = 0
         ORDER BY updated_at_ms ASC, restore_id ASC
         LIMIT 257",
    )?;
    let checkpoint_references =
        crate::workspace_checkpoints::doctor_references(connection, workspace.id()).map_err(
            |source| RootRecoveryStoreError::Store(WorkspaceStoreError::Checkpoint(source)),
        )?;
    let dag_semantics = crate::workspace_dags::doctor_current(connection, workspace.id())
        .map_err(|source| RootRecoveryStoreError::Store(WorkspaceStoreError::Dag(source)))?;
    let diff_references = crate::workspace_diffs::doctor_references(connection)
        .map_err(|source| RootRecoveryStoreError::Store(WorkspaceStoreError::Diff(source)))?;
    Ok(WorkspaceDoctorReport::new(
        WorkspaceDoctorIdentity {
            schema_version,
            application_id,
            location_id: workspace.location_id(),
            workspace_id: workspace.id(),
            workspace_revision: workspace.revision(),
        },
        WorkspaceDoctorObservations {
            quick_check,
            foreign_key_check,
            stale_executions,
            stale_checkpoint_restores,
            checkpoint_references,
            dag_semantics,
            diff_references,
        },
    ))
}

fn ensure_no_active_authority(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), RootRecoveryStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let active_freeze = exists(
        connection,
        "SELECT EXISTS(SELECT 1 FROM agent_operations_migrations WHERE workspace_id = ?1 AND state = 0)",
        &workspace,
    )?;
    if active_freeze {
        return Err(RootRecoveryStoreError::ActiveAuthority(
            RootRecoveryAuthorityBlocker::AgentOperationsFreeze,
        ));
    }
    match crate::workspace_agent_migration::ensure_not_delegated(connection) {
        Ok(()) => {}
        Err(crate::AgentOperationsMigrationError::Delegated { .. }) => {
            return Err(RootRecoveryStoreError::ActiveAuthority(
                RootRecoveryAuthorityBlocker::AgentOperationsDelegation,
            ));
        }
        Err(error) => {
            return Err(RootRecoveryStoreError::Store(
                WorkspaceStoreError::AgentOperationsMigration(error),
            ));
        }
    }
    let blocker = state_removal_blocker_for_connection(connection, workspace_id)?;
    if let Some(blocker) = blocker {
        return Err(RootRecoveryStoreError::ActiveAuthority(
            RootRecoveryAuthorityBlocker::StateRemoval(blocker),
        ));
    }

    ensure_common_authority_absent(connection, workspace_id)
}

fn validate_authority_mode(
    connection: &Connection,
    workspace_id: WorkspaceId,
    mode: WorkspaceRootRecoveryAuthorityMode,
) -> Result<(), RootRecoveryStoreError> {
    match mode {
        WorkspaceRootRecoveryAuthorityMode::Quiescent => {
            ensure_no_active_authority(connection, workspace_id)
        }
        WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(expected) => {
            let actual = current_delegated_authority(connection, workspace_id)?;
            if actual != expected {
                return Err(RootRecoveryStoreError::ActiveAuthority(
                    RootRecoveryAuthorityBlocker::AgentOperationsDelegation,
                ));
            }
            if let Some(blocker) = state_removal_blocker_rows(connection, workspace_id)? {
                return Err(RootRecoveryStoreError::ActiveAuthority(
                    RootRecoveryAuthorityBlocker::StateRemoval(blocker),
                ));
            }
            ensure_common_authority_absent(connection, workspace_id)?;
            ensure_before_participation_census(connection)
        }
    }
}

fn current_delegated_authority(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<WorkspaceRootRecoveryDelegatedAuthority, RootRecoveryStoreError> {
    // A Workspace database is a singleton authority. Historical extra freezes
    // also exclude this deliberately narrow before-first-participation mode.
    for table in [
        "agent_operations_migrations",
        "agent_operations_delegations",
    ] {
        let query = format!("SELECT COUNT(*) FROM (SELECT 1 FROM {table} LIMIT 2)");
        let count: i64 = connection.query_row(&query, [], |row| row.get(0))?;
        if count != 1 {
            return Err(RootRecoveryStoreError::ActiveAuthority(
                RootRecoveryAuthorityBlocker::AgentOperationsDelegation,
            ));
        }
    }
    let delegation = crate::workspace_agent_delegation::get(connection, workspace_id)
        .map_err(|source| {
            RootRecoveryStoreError::Store(WorkspaceStoreError::AgentOperationsDelegation(source))
        })?
        .ok_or(RootRecoveryStoreError::ActiveAuthority(
            RootRecoveryAuthorityBlocker::AgentOperationsDelegation,
        ))?;
    let freeze = delegation.freeze();
    let freeze_fence = WorkspaceRootRecoveryFreezeFence {
        migration_id: freeze.migration_id(),
        workspace_id: freeze.workspace_id(),
        destination_id: freeze.destination_id(),
        state: WorkspaceRootRecoveryFreezeState::Frozen,
        revision: freeze.revision(),
        created_at: freeze.created_at(),
        updated_at: freeze.updated_at(),
    };
    let delegation_fence = WorkspaceRootRecoveryDelegationFence {
        migration_id: delegation.migration_id(),
        workspace_id: delegation.workspace_id(),
        destination_id: delegation.destination_id(),
        freeze_revision: delegation.freeze().revision(),
        manifest_digest: delegation.manifest_digest(),
        delegated_at: delegation.delegated_at(),
    };
    WorkspaceRootRecoveryDelegatedAuthority::new(freeze_fence, delegation_fence)
        .map_err(RootRecoveryStoreError::Intent)
}

fn ensure_common_authority_absent(
    connection: &Connection,
    workspace_id: WorkspaceId,
) -> Result<(), RootRecoveryStoreError> {
    let workspace = workspace_id.into_uuid().into_bytes();
    let checks = [
        (
            RootRecoveryAuthorityBlocker::PendingGoalDeletion,
            "SELECT EXISTS(SELECT 1 FROM goal_deletion_cleanup_journal WHERE workspace_id = ?1)",
        ),
        (
            RootRecoveryAuthorityBlocker::StartingCheckpoint,
            "SELECT EXISTS(SELECT 1 FROM checkpoints WHERE workspace_id = ?1 AND state = 0)",
        ),
        (
            RootRecoveryAuthorityBlocker::StartingCheckpointRestore,
            "SELECT EXISTS(SELECT 1 FROM checkpoint_restores WHERE workspace_id = ?1 AND state = 0)",
        ),
        (
            RootRecoveryAuthorityBlocker::StartingChangeSet,
            "SELECT EXISTS(SELECT 1 FROM change_sets WHERE workspace_id = ?1 AND state = 0)",
        ),
        (
            RootRecoveryAuthorityBlocker::PendingDiffEvidence,
            "SELECT EXISTS(SELECT 1 FROM diff_evidence WHERE workspace_id = ?1 AND state IN (0, 4))",
        ),
        (
            RootRecoveryAuthorityBlocker::StartingVerification,
            "SELECT EXISTS(SELECT 1 FROM verification_runs WHERE workspace_id = ?1 AND state = 0)",
        ),
        (
            RootRecoveryAuthorityBlocker::PendingApproval,
            "SELECT EXISTS(SELECT 1 FROM approval_requests WHERE workspace_id = ?1 AND state = 0)",
        ),
        (
            RootRecoveryAuthorityBlocker::ActiveExecutionGrant,
            "SELECT EXISTS(SELECT 1 FROM execution_grants WHERE workspace_id = ?1 AND state = 0)",
        ),
        (
            RootRecoveryAuthorityBlocker::ActiveAutoApprovalScope,
            "SELECT EXISTS(SELECT 1 FROM auto_approval_scopes WHERE workspace_id = ?1 AND state = 0)",
        ),
        (
            RootRecoveryAuthorityBlocker::NonterminalAssignment,
            "SELECT EXISTS(SELECT 1 FROM agent_assignments WHERE workspace_id = ?1 AND state IN (0, 1, 2))",
        ),
        (
            RootRecoveryAuthorityBlocker::AttachedAgentSession,
            "SELECT EXISTS(SELECT 1 FROM agent_instances WHERE workspace_id = ?1 AND session_id IS NOT NULL AND attachment_state = 0)",
        ),
    ];
    for (blocker, query) in checks {
        if exists(connection, query, &workspace)? {
            return Err(RootRecoveryStoreError::ActiveAuthority(blocker));
        }
    }
    Ok(())
}

fn ensure_before_participation_census(
    connection: &Connection,
) -> Result<(), RootRecoveryStoreError> {
    const TABLES: &[&str] = &[
        "agent_binding_reservations",
        "agent_binding_activations",
        "agent_session_reconciliations",
        "agent_departure_reconciliations",
        "agent_instances",
        "agent_focus_events",
        "agent_work_updates",
        "agent_work_update_evidence_refs",
        "agent_presence",
        "agent_events",
        "agent_inbox",
        "activity_coordinators",
        "agent_dag_plan_ledger",
        "agent_dag_plan_sessions",
        "agent_assignments",
        "agent_assignment_sources",
        "agent_assignment_offer_seals",
        "agent_effect_outbox_entries",
        "effect_fact_outbox_entries",
        "execution_admission_consumptions",
        "leadership_work_cuts",
        "assignment_continuation_batches",
        "assignment_continuation_proposals",
        "assignment_continuation_acknowledgments",
    ];
    for table in TABLES {
        let query = format!("SELECT EXISTS(SELECT 1 FROM {table} LIMIT 1)");
        let present: bool = connection.query_row(&query, [], |row| row.get(0))?;
        if present {
            return Err(RootRecoveryStoreError::ActiveAuthority(
                RootRecoveryAuthorityBlocker::PostDelegationParticipation,
            ));
        }
    }
    Ok(())
}

fn exists(
    connection: &Connection,
    query: &'static str,
    workspace: &[u8],
) -> Result<bool, WorkspaceStoreError> {
    connection
        .query_row(query, params![workspace], |row| row.get(0))
        .map_err(WorkspaceStoreError::from)
}

fn open_transition_connection(
    layout: &ExistingWorkspaceStateLayout,
    gate: &WorkspaceStateExclusiveGate,
    source: &WorkspaceDoctorSourceObservation,
) -> Result<Connection, RootRecoveryStoreError> {
    let root_fingerprint = layout
        .root_fingerprint()
        .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
    gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
        .map_err(WorkspaceStoreError::StateGate)?;
    ensure_source_identity(source, layout, root_fingerprint)?;
    let path = layout.database_path();
    let connection = Connection::open_with_flags(
        &path,
        OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|source| WorkspaceStoreError::Open {
        path: path.clone(),
        source,
    })?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    validate_runtime_policy(&runtime_policy(&connection)?)?;
    ensure_source_identity(source, layout, root_fingerprint)?;
    Ok(connection)
}

fn ensure_source_identity(
    source: &WorkspaceDoctorSourceObservation,
    layout: &ExistingWorkspaceStateLayout,
    root_fingerprint: WorkspaceRootFingerprint,
) -> Result<(), WorkspaceStoreError> {
    if source.root_fingerprint != root_fingerprint {
        return Err(WorkspaceStoreError::WorkspaceRootFingerprintChanged {
            expected: source.root_fingerprint,
            observed: root_fingerprint,
        });
    }
    ensure_live_paths(WorkspaceLiveBinding {
        state_root: layout.state_root(),
        state_root_identity: source.state_root_identity,
        workspace_root: layout.workspace_root(),
        root_fingerprint,
        database_path: &layout.database_path(),
        database_identity: source.database_identity,
        wal_identity: source.wal_identity,
        shm_identity: source.shm_identity,
    })
}

fn source_witness(
    workspace: &RegisteredWorkspace,
    root_fingerprint: WorkspaceRootFingerprint,
    source: &WorkspaceDoctorSourceObservation,
    schema_version: i64,
    application_id: i64,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
) -> Result<WorkspaceRootRecoveryWitness, RootRecoveryStoreError> {
    // Canonical witness encoding: domain tag, then fixed numeric values in
    // little-endian form; every path/blob is length-prefixed with u64; optional
    // WAL/SHM observations carry a one-byte presence tag.  Only bounded
    // metadata and the singleton Workspace row are hashed; database bytes are
    // never read into the digest.
    let mut hasher = Sha256::new();
    hasher.update(match authority_mode {
        WorkspaceRootRecoveryAuthorityMode::Quiescent => WITNESS_DOMAIN,
        WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_) => WITNESS_V2_DOMAIN,
    });
    hash_workspace(&mut hasher, workspace);
    hash_path(&mut hasher, workspace.root().as_path());
    hash_i64(&mut hasher, schema_version);
    hash_i64(&mut hasher, application_id);
    hash_bytes(&mut hasher, root_fingerprint.as_bytes());
    hash_bytes(&mut hasher, source.root_fingerprint.as_bytes());
    hash_directory(&mut hasher, source.state_root_identity);
    hash_file_observation(&mut hasher, source.database_observation)?;
    hash_optional_file_observation(&mut hasher, source.wal_observation)?;
    hash_optional_file_observation(&mut hasher, source.shm_observation)?;
    if let WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) = authority_mode {
        hash_bytes(&mut hasher, &delegated_authority_digest(authority));
    }
    Ok(WorkspaceRootRecoveryWitness::from_bytes(
        hasher.finalize().into(),
    ))
}

fn hash_workspace(hasher: &mut Sha256, workspace: &RegisteredWorkspace) {
    hash_bytes(hasher, workspace.id().into_uuid().as_bytes());
    hash_bytes(hasher, workspace.location_id().into_uuid().as_bytes());
    hash_i64(hasher, workspace.created_at().get());
    hash_i64(hasher, workspace.updated_at().get());
    hash_i64(hasher, workspace.revision().get());
    hash_bytes(hasher, workspace.root_fingerprint().as_bytes());
}

fn hash_directory(hasher: &mut Sha256, identity: DirectoryIdentity) {
    hash_u64(hasher, identity.device);
    hash_u64(hasher, identity.inode);
}

fn hash_file_observation(
    hasher: &mut Sha256,
    observation: DoctorFileObservation,
) -> Result<(), RootRecoveryStoreError> {
    hash_u64(hasher, observation.identity.device);
    hash_u64(hasher, observation.identity.inode);
    hash_u64(hasher, observation.identity.links);
    hash_u64(hasher, observation.size);
    hash_system_time(hasher, observation.modified)
}

fn hash_optional_file_observation(
    hasher: &mut Sha256,
    observation: Option<DoctorFileObservation>,
) -> Result<(), RootRecoveryStoreError> {
    match observation {
        Some(observation) => {
            hasher.update([1]);
            hash_file_observation(hasher, observation)?;
        }
        None => hasher.update([0]),
    }
    Ok(())
}

fn hash_system_time(hasher: &mut Sha256, value: SystemTime) -> Result<(), RootRecoveryStoreError> {
    let elapsed = value
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RootRecoveryStoreError::ObservationEncoding)?;
    hash_u64(hasher, elapsed.as_secs());
    hash_u64(hasher, u64::from(elapsed.subsec_nanos()));
    Ok(())
}

fn hash_path(hasher: &mut Sha256, path: &Path) {
    let bytes = path.as_os_str().as_bytes();
    hash_u64(hasher, u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    hasher.update(bytes);
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hash_u64(hasher, u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    hasher.update(bytes);
}

fn hash_i64(hasher: &mut Sha256, value: i64) {
    hasher.update(value.to_le_bytes());
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn request_intent_digest(request: &WorkspaceRootRecoveryRequest) -> [u8; WITNESS_DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(match request.authority_mode() {
        WorkspaceRootRecoveryAuthorityMode::Quiescent => INTENT_DOMAIN,
        WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_) => INTENT_V2_DOMAIN,
    });
    hasher.update(request.request_id().as_bytes());
    hash_i64(&mut hasher, request.location_revision().get());
    hash_workspace(&mut hasher, request.expected());
    hash_path(&mut hasher, request.observed().root().as_path());
    hash_bytes(&mut hasher, request.observed().fingerprint().as_bytes());
    hash_bytes(&mut hasher, request.observed().witness().as_bytes());
    hash_i64(&mut hasher, request.observed_at().get());
    hash_i64(&mut hasher, OPERATOR_KIND_EXPLICIT_OWNER);
    if let WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) =
        request.authority_mode()
    {
        hash_i64(&mut hasher, 2);
        hash_bytes(&mut hasher, &delegated_authority_digest(authority));
    }
    hasher.finalize().into()
}

pub fn delegated_authority_digest(
    authority: WorkspaceRootRecoveryDelegatedAuthority,
) -> [u8; WITNESS_DIGEST_BYTES] {
    let freeze = authority.freeze();
    let delegation = authority.delegation();
    let mut hasher = Sha256::new();
    hasher.update(AUTHORITY_DOMAIN);
    hash_bytes(&mut hasher, freeze.migration_id.as_bytes());
    hash_bytes(&mut hasher, freeze.workspace_id.into_uuid().as_bytes());
    hash_bytes(&mut hasher, freeze.destination_id.as_bytes());
    hash_i64(&mut hasher, 0);
    hash_u64(&mut hasher, freeze.revision);
    hash_i64(&mut hasher, freeze.created_at.get());
    hash_i64(&mut hasher, freeze.updated_at.get());
    hash_bytes(&mut hasher, delegation.migration_id.as_bytes());
    hash_bytes(&mut hasher, delegation.workspace_id.into_uuid().as_bytes());
    hash_bytes(&mut hasher, delegation.destination_id.as_bytes());
    hash_u64(&mut hasher, delegation.freeze_revision);
    hash_bytes(&mut hasher, &delegation.manifest_digest);
    hash_i64(&mut hasher, delegation.delegated_at.get());
    hasher.finalize().into()
}

fn recover_in_transaction(
    transaction: &Transaction<'_>,
    gate: &WorkspaceStateExclusiveGate,
    layout: &ExistingWorkspaceStateLayout,
    probe: &RootRecoveryProbe,
    request: &WorkspaceRootRecoveryRequest,
    intent_digest: [u8; WITNESS_DIGEST_BYTES],
) -> Result<RootRecoveryOperation, RootRecoveryStoreError> {
    if let Some(existing) = load_receipt(transaction, request.request_id())? {
        if !receipt_matches_request(&existing, request, intent_digest) {
            return Err(RootRecoveryStoreError::RequestConflict);
        }
        return Ok(RootRecoveryOperation::Replay(existing.into_receipt()?));
    }

    let current = query_workspace_row(transaction)?
        .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
        .and_then(decode_workspace)?;
    if current != *request.expected() || current != probe.workspace {
        return Err(RootRecoveryStoreError::WorkspaceChanged);
    }
    validate_authority_mode(transaction, current.id(), request.authority_mode())?;
    let result = decide_workspace_root_recovery(&current, request.observed(), request)?;
    let record = ReceiptRecord::from_request(&current, &result, request, intent_digest)?;
    let changed = transaction.execute(
        "UPDATE workspace
         SET root_fingerprint = ?1, updated_at_ms = ?2, revision = ?3
         WHERE singleton = 1 AND workspace_id = ?4 AND location_id = ?5
           AND root_path = ?6 AND root_fingerprint = ?7 AND updated_at_ms = ?8
           AND revision = ?9",
        params![
            record.new_root_fingerprint.as_slice(),
            record.observed_at_ms,
            record.result_workspace_revision,
            record.workspace_id.into_uuid().as_bytes(),
            record.location_id.into_uuid().as_bytes(),
            record.root_path.as_slice(),
            record.old_root_fingerprint.as_slice(),
            record.expected_updated_at_ms,
            record.expected_workspace_revision,
        ],
    )?;
    if changed != 1 {
        return Err(RootRecoveryStoreError::WorkspaceChanged);
    }
    insert_receipt(transaction, &record)?;
    let root_fingerprint = request.observed().fingerprint();
    gate.ensure_root_binding(layout.workspace_root(), root_fingerprint)
        .map_err(WorkspaceStoreError::StateGate)?;
    ensure_source_identity(&probe.source, layout, root_fingerprint)?;
    Ok(RootRecoveryOperation::Committed(record.into_receipt()?))
}

impl ReceiptRecord {
    fn from_request(
        current: &RegisteredWorkspace,
        result: &RegisteredWorkspace,
        request: &WorkspaceRootRecoveryRequest,
        request_digest: [u8; WITNESS_DIGEST_BYTES],
    ) -> Result<Self, RootRecoveryStoreError> {
        let root_path = path_to_bytes_bounded(current.root().as_path())?;
        let expected_workspace_revision = current.revision().get();
        let result_workspace_revision = result.revision().get();
        let expected_location_revision = request.location_revision().get();
        let witness_digest = *request.observed().witness().as_bytes();
        let mut record = Self {
            request_id: request.request_id(),
            workspace_id: current.id(),
            location_id: current.location_id(),
            expected_location_revision,
            expected_workspace_revision,
            result_workspace_revision,
            root_path,
            old_root_fingerprint: current.root_fingerprint().into_bytes(),
            new_root_fingerprint: result.root_fingerprint().into_bytes(),
            expected_created_at_ms: current.created_at().get(),
            expected_updated_at_ms: current.updated_at().get(),
            observed_at_ms: result.updated_at().get(),
            request_digest,
            witness_digest,
            receipt_digest: [0; WITNESS_DIGEST_BYTES],
            authority_mode: request.authority_mode(),
        };
        record.receipt_digest = record_digest(&record);
        Ok(record)
    }

    fn into_receipt(self) -> Result<RootRecoveryReceipt, RootRecoveryStoreError> {
        let root = WorkspaceRoot::from_canonical(PathBuf::from(std::ffi::OsString::from_vec(
            self.root_path.clone(),
        )))
        .map_err(|source| {
            RootRecoveryStoreError::Store(WorkspaceStoreError::CorruptRecord {
                field: "root_recovery.root_path",
                detail: source.to_string(),
            })
        })?;
        let created_at = TimestampMillis::new(self.expected_created_at_ms).map_err(|source| {
            RootRecoveryStoreError::Store(WorkspaceStoreError::CorruptRecord {
                field: "root_recovery.expected_created_at_ms",
                detail: source.to_string(),
            })
        })?;
        let updated_at = TimestampMillis::new(self.observed_at_ms).map_err(|source| {
            RootRecoveryStoreError::Store(WorkspaceStoreError::CorruptRecord {
                field: "root_recovery.observed_at_ms",
                detail: source.to_string(),
            })
        })?;
        let revision = forge_domain::WorkspaceRevision::new(self.result_workspace_revision)
            .map_err(|source| {
                RootRecoveryStoreError::Store(WorkspaceStoreError::CorruptRecord {
                    field: "root_recovery.result_workspace_revision",
                    detail: source.to_string(),
                })
            })?;
        let expected_revision = forge_domain::WorkspaceRevision::new(
            self.expected_workspace_revision,
        )
        .map_err(|source| {
            RootRecoveryStoreError::Store(WorkspaceStoreError::CorruptRecord {
                field: "root_recovery.expected_workspace_revision",
                detail: source.to_string(),
            })
        })?;
        let location_revision =
            LocationRevision::new(self.expected_location_revision).map_err(|source| {
                RootRecoveryStoreError::Store(WorkspaceStoreError::CorruptRecord {
                    field: "root_recovery.expected_location_revision",
                    detail: source.to_string(),
                })
            })?;
        let workspace = RegisteredWorkspace::from_parts_with_revision(
            self.workspace_id,
            self.location_id,
            root,
            WorkspaceRootFingerprint::from_bytes(self.new_root_fingerprint),
            created_at,
            updated_at,
            revision,
        );
        if expected_revision
            .checked_next()
            .ok()
            .map(forge_domain::WorkspaceRevision::get)
            != Some(revision.get())
            || self.receipt_digest != record_digest(&self)
        {
            return Err(RootRecoveryStoreError::Store(
                WorkspaceStoreError::CorruptRecord {
                    field: "root_recovery.receipt_digest",
                    detail: "receipt digest or revision invariant failed".to_owned(),
                },
            ));
        }
        Ok(RootRecoveryReceipt {
            request_id: self.request_id,
            expected_location_revision: location_revision,
            expected_workspace_revision: expected_revision,
            workspace,
            old_root_fingerprint: WorkspaceRootFingerprint::from_bytes(self.old_root_fingerprint),
            request_digest: self.request_digest,
            witness_digest: self.witness_digest,
            receipt_digest: self.receipt_digest,
            authority_mode: self.authority_mode,
        })
    }
}

fn record_digest(record: &ReceiptRecord) -> [u8; WITNESS_DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(match record.authority_mode {
        WorkspaceRootRecoveryAuthorityMode::Quiescent => RECEIPT_DOMAIN,
        WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(_) => RECEIPT_V2_DOMAIN,
    });
    hasher.update(record.request_id.as_bytes());
    hash_bytes(&mut hasher, record.workspace_id.into_uuid().as_bytes());
    hash_bytes(&mut hasher, record.location_id.into_uuid().as_bytes());
    hash_i64(&mut hasher, record.expected_location_revision);
    hash_i64(&mut hasher, record.expected_workspace_revision);
    hash_i64(&mut hasher, record.result_workspace_revision);
    hash_bytes(&mut hasher, &record.root_path);
    hash_bytes(&mut hasher, &record.old_root_fingerprint);
    hash_bytes(&mut hasher, &record.new_root_fingerprint);
    hash_i64(&mut hasher, record.expected_created_at_ms);
    hash_i64(&mut hasher, record.expected_updated_at_ms);
    hash_i64(&mut hasher, record.observed_at_ms);
    hash_bytes(&mut hasher, &record.request_digest);
    hash_bytes(&mut hasher, &record.witness_digest);
    hash_i64(&mut hasher, OPERATOR_KIND_EXPLICIT_OWNER);
    if let WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) =
        record.authority_mode
    {
        hash_i64(&mut hasher, 2);
        hash_bytes(&mut hasher, &delegated_authority_digest(authority));
    }
    hasher.finalize().into()
}

fn receipt_matches_request(
    record: &ReceiptRecord,
    request: &WorkspaceRootRecoveryRequest,
    request_digest: [u8; WITNESS_DIGEST_BYTES],
) -> bool {
    record.request_id == request.request_id()
        && record.authority_mode == request.authority_mode()
        && record.workspace_id == request.expected().id()
        && record.location_id == request.expected().location_id()
        && record.expected_location_revision == request.location_revision().get()
        && record.expected_workspace_revision == request.expected().revision().get()
        && record.root_path == request.expected().root().as_path().as_os_str().as_bytes()
        && record.old_root_fingerprint == request.expected().root_fingerprint().into_bytes()
        && record.new_root_fingerprint == request.observed().fingerprint().into_bytes()
        && record.expected_created_at_ms == request.expected().created_at().get()
        && record.expected_updated_at_ms == request.expected().updated_at().get()
        && record.observed_at_ms == request.observed_at().get()
        && record.request_digest == request_digest
        && record.witness_digest == *request.observed().witness().as_bytes()
}

fn insert_receipt(
    transaction: &Transaction<'_>,
    record: &ReceiptRecord,
) -> Result<(), RootRecoveryStoreError> {
    transaction.execute(
        "INSERT INTO workspace_root_recovery_receipts (
            request_id, workspace_id, location_id, expected_location_revision,
            expected_workspace_revision, result_workspace_revision, root_path,
            old_root_fingerprint, new_root_fingerprint, expected_created_at_ms,
            expected_updated_at_ms, observed_at_ms, request_digest, witness_digest,
            receipt_digest, operator_kind
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        params![
            record.request_id.as_bytes(),
            record.workspace_id.into_uuid().as_bytes(),
            record.location_id.into_uuid().as_bytes(),
            record.expected_location_revision,
            record.expected_workspace_revision,
            record.result_workspace_revision,
            record.root_path.as_slice(),
            record.old_root_fingerprint.as_slice(),
            record.new_root_fingerprint.as_slice(),
            record.expected_created_at_ms,
            record.expected_updated_at_ms,
            record.observed_at_ms,
            record.request_digest.as_slice(),
            record.witness_digest.as_slice(),
            record.receipt_digest.as_slice(),
            OPERATOR_KIND_EXPLICIT_OWNER,
        ],
    )?;
    if let WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) =
        record.authority_mode
    {
        let freeze = authority.freeze();
        let delegation = authority.delegation();
        transaction.execute(
            "INSERT INTO root_recovery_delegation_receipts (
                request_id, mode_version, mode_kind, migration_id, workspace_id,
                destination_id, freeze_state, freeze_revision, freeze_created_at_ms,
                freeze_updated_at_ms, delegation_freeze_revision, manifest_digest,
                delegated_at_ms, authority_digest, normal_request_intent_digest,
                witness_v2_digest
             ) VALUES (?1,2,1,?2,?3,?4,0,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                record.request_id.as_bytes(),
                freeze.migration_id.as_bytes(),
                freeze.workspace_id.into_uuid().as_bytes(),
                freeze.destination_id.as_bytes(),
                i64::try_from(freeze.revision)
                    .map_err(|_| RootRecoveryStoreError::ObservationEncoding)?,
                freeze.created_at.get(),
                freeze.updated_at.get(),
                i64::try_from(delegation.freeze_revision)
                    .map_err(|_| RootRecoveryStoreError::ObservationEncoding)?,
                delegation.manifest_digest.as_slice(),
                delegation.delegated_at.get(),
                delegated_authority_digest(authority).as_slice(),
                record.request_digest.as_slice(),
                record.witness_digest.as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn load_receipt(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<ReceiptRecord>, RootRecoveryStoreError> {
    let raw = connection
        .query_row(
            "SELECT request_id, workspace_id, location_id,
                    expected_location_revision, expected_workspace_revision,
                    result_workspace_revision, root_path, old_root_fingerprint,
                    new_root_fingerprint, expected_created_at_ms,
                    expected_updated_at_ms, observed_at_ms, request_digest,
                    witness_digest, receipt_digest, operator_kind
             FROM workspace_root_recovery_receipts
             WHERE request_id = ?1",
            params![request_id.as_bytes()],
            decode_raw_receipt,
        )
        .optional()?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let request_id = decode_uuid(&raw.request_id, "root_recovery.request_id")?;
    let companion = load_delegation_receipt(connection, request_id)?;
    let authority_mode = companion
        .as_ref()
        .map_or(WorkspaceRootRecoveryAuthorityMode::Quiescent, |value| {
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(value.authority)
        });
    let record = decode_receipt(raw, authority_mode)?;
    if let Some(companion) = companion
        && (companion.request_digest != record.request_digest
            || companion.witness_digest != record.witness_digest)
    {
        return Err(corrupt("root_recovery.delegation_receipt_digest"));
    }
    Ok(Some(record))
}

struct DelegationReceiptRecord {
    authority: WorkspaceRootRecoveryDelegatedAuthority,
    request_digest: [u8; WITNESS_DIGEST_BYTES],
    witness_digest: [u8; WITNESS_DIGEST_BYTES],
}

fn load_delegation_receipt(
    connection: &Connection,
    request_id: Uuid,
) -> Result<Option<DelegationReceiptRecord>, RootRecoveryStoreError> {
    let raw = connection
        .query_row(
            "SELECT mode_version,mode_kind,migration_id,workspace_id,destination_id,
                    freeze_state,freeze_revision,freeze_created_at_ms,freeze_updated_at_ms,
                    delegation_freeze_revision,manifest_digest,delegated_at_ms,authority_digest,
                    normal_request_intent_digest,witness_v2_digest
             FROM root_recovery_delegation_receipts WHERE request_id=?1",
            params![request_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Vec<u8>>(12)?,
                    row.get::<_, Vec<u8>>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        )
        .optional()?;
    let Some((
        version,
        kind,
        migration,
        workspace,
        destination,
        state,
        revision,
        created,
        updated,
        delegation_revision,
        manifest,
        delegated_at,
        authority_digest,
        request_digest,
        witness_digest,
    )) = raw
    else {
        return Ok(None);
    };
    if version != 2 || kind != 1 || state != 0 {
        return Err(corrupt("root_recovery.delegation_receipt_mode"));
    }
    let migration_id = decode_uuid(&migration, "root_recovery.delegation.migration_id")?;
    let workspace_id = decode_workspace_id(&workspace, "root_recovery.delegation.workspace_id")?;
    let destination_id = decode_uuid(&destination, "root_recovery.delegation.destination_id")?;
    let revision = u64::try_from(revision).map_err(|_| corrupt("root_recovery.freeze_revision"))?;
    let delegation_revision = u64::try_from(delegation_revision)
        .map_err(|_| corrupt("root_recovery.delegation_freeze_revision"))?;
    let authority = WorkspaceRootRecoveryDelegatedAuthority::new(
        WorkspaceRootRecoveryFreezeFence {
            migration_id,
            workspace_id,
            destination_id,
            state: WorkspaceRootRecoveryFreezeState::Frozen,
            revision,
            created_at: TimestampMillis::new(created)
                .map_err(|_| corrupt("root_recovery.freeze_created_at"))?,
            updated_at: TimestampMillis::new(updated)
                .map_err(|_| corrupt("root_recovery.freeze_updated_at"))?,
        },
        WorkspaceRootRecoveryDelegationFence {
            migration_id,
            workspace_id,
            destination_id,
            freeze_revision: delegation_revision,
            manifest_digest: decode_fixed::<32>(manifest, "root_recovery.manifest_digest")?,
            delegated_at: TimestampMillis::new(delegated_at)
                .map_err(|_| corrupt("root_recovery.delegated_at"))?,
        },
    )
    .map_err(RootRecoveryStoreError::Intent)?;
    if decode_fixed::<32>(authority_digest, "root_recovery.authority_digest")?
        != delegated_authority_digest(authority)
    {
        return Err(corrupt("root_recovery.authority_digest"));
    }
    Ok(Some(DelegationReceiptRecord {
        authority,
        request_digest: decode_fixed::<32>(
            request_digest,
            "root_recovery.normal_request_intent_digest",
        )?,
        witness_digest: decode_fixed::<32>(witness_digest, "root_recovery.witness_v2_digest")?,
    }))
}

#[derive(Debug)]
struct RawReceipt {
    request_id: Vec<u8>,
    workspace_id: Vec<u8>,
    location_id: Vec<u8>,
    expected_location_revision: i64,
    expected_workspace_revision: i64,
    result_workspace_revision: i64,
    root_path: Vec<u8>,
    old_root_fingerprint: Vec<u8>,
    new_root_fingerprint: Vec<u8>,
    expected_created_at_ms: i64,
    expected_updated_at_ms: i64,
    observed_at_ms: i64,
    request_digest: Vec<u8>,
    witness_digest: Vec<u8>,
    receipt_digest: Vec<u8>,
    operator_kind: i64,
}

fn decode_raw_receipt(row: &Row<'_>) -> rusqlite::Result<RawReceipt> {
    Ok(RawReceipt {
        request_id: row.get(0)?,
        workspace_id: row.get(1)?,
        location_id: row.get(2)?,
        expected_location_revision: row.get(3)?,
        expected_workspace_revision: row.get(4)?,
        result_workspace_revision: row.get(5)?,
        root_path: row.get(6)?,
        old_root_fingerprint: row.get(7)?,
        new_root_fingerprint: row.get(8)?,
        expected_created_at_ms: row.get(9)?,
        expected_updated_at_ms: row.get(10)?,
        observed_at_ms: row.get(11)?,
        request_digest: row.get(12)?,
        witness_digest: row.get(13)?,
        receipt_digest: row.get(14)?,
        operator_kind: row.get(15)?,
    })
}

fn decode_receipt(
    raw: RawReceipt,
    authority_mode: WorkspaceRootRecoveryAuthorityMode,
) -> Result<ReceiptRecord, RootRecoveryStoreError> {
    let request_id = decode_uuid(&raw.request_id, "root_recovery.request_id")?;
    let workspace_id = decode_workspace_id(&raw.workspace_id, "root_recovery.workspace_id")?;
    let location_id = decode_location_id(&raw.location_id, "root_recovery.location_id")?;
    if raw.operator_kind != OPERATOR_KIND_EXPLICIT_OWNER {
        return Err(corrupt("root_recovery.operator_kind"));
    }
    let old_root_fingerprint = decode_fixed::<FINGERPRINT_BYTES>(
        raw.old_root_fingerprint,
        "root_recovery.old_root_fingerprint",
    )?;
    let new_root_fingerprint = decode_fixed::<FINGERPRINT_BYTES>(
        raw.new_root_fingerprint,
        "root_recovery.new_root_fingerprint",
    )?;
    let request_digest =
        decode_fixed::<WITNESS_DIGEST_BYTES>(raw.request_digest, "root_recovery.request_digest")?;
    let witness_digest =
        decode_fixed::<WITNESS_DIGEST_BYTES>(raw.witness_digest, "root_recovery.witness_digest")?;
    let receipt_digest =
        decode_fixed::<WITNESS_DIGEST_BYTES>(raw.receipt_digest, "root_recovery.receipt_digest")?;
    if raw.root_path.is_empty() || raw.root_path.len() > MAX_ROOT_BYTES {
        return Err(corrupt("root_recovery.root_path"));
    }
    if new_root_fingerprint == old_root_fingerprint
        || raw.expected_workspace_revision < 1
        || raw.result_workspace_revision != raw.expected_workspace_revision.saturating_add(1)
        || raw.expected_location_revision < 1
        || raw.expected_created_at_ms < 0
        || raw.expected_updated_at_ms < 0
        || raw.observed_at_ms < raw.expected_updated_at_ms
    {
        return Err(corrupt("root_recovery.revision_or_timestamp"));
    }
    let record = ReceiptRecord {
        request_id,
        workspace_id,
        location_id,
        expected_location_revision: raw.expected_location_revision,
        expected_workspace_revision: raw.expected_workspace_revision,
        result_workspace_revision: raw.result_workspace_revision,
        root_path: raw.root_path,
        old_root_fingerprint,
        new_root_fingerprint,
        expected_created_at_ms: raw.expected_created_at_ms,
        expected_updated_at_ms: raw.expected_updated_at_ms,
        observed_at_ms: raw.observed_at_ms,
        request_digest,
        witness_digest,
        receipt_digest,
        authority_mode,
    };
    if record.receipt_digest != record_digest(&record) {
        return Err(corrupt("root_recovery.receipt_digest"));
    }
    Ok(record)
}

fn decode_uuid(bytes: &[u8], field: &'static str) -> Result<Uuid, RootRecoveryStoreError> {
    Uuid::from_slice(bytes).map_err(|_| corrupt(field))
}

fn decode_workspace_id(
    bytes: &[u8],
    field: &'static str,
) -> Result<WorkspaceId, RootRecoveryStoreError> {
    decode_uuid(bytes, field).map(WorkspaceId::from_uuid)
}

fn decode_location_id(
    bytes: &[u8],
    field: &'static str,
) -> Result<forge_domain::LocationId, RootRecoveryStoreError> {
    decode_uuid(bytes, field).map(forge_domain::LocationId::from_uuid)
}

fn decode_fixed<const N: usize>(
    bytes: Vec<u8>,
    field: &'static str,
) -> Result<[u8; N], RootRecoveryStoreError> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RootRecoveryStoreError::Store(WorkspaceStoreError::PersistedFieldLengthInvalid {
            field,
            actual: bytes.len(),
            expected: N,
        })
    })
}

fn corrupt(field: &'static str) -> RootRecoveryStoreError {
    RootRecoveryStoreError::Store(WorkspaceStoreError::CorruptRecord {
        field,
        detail: "root recovery receipt is corrupt".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use forge_domain::{
        ActivityId, CreateActivity, EstablishWorkspace, LocationId, LocationRevision,
        TimestampMillis, WorkspaceId, WorkspaceRevision, WorkspaceRoot, WorkspaceRootFingerprint,
        WorkspaceRootRecoveryDelegatedAuthority, WorkspaceRootRecoveryObservation,
        WorkspaceRootRecoveryRequest, WorkspaceRootRecoveryWitness,
    };
    use forge_workspace::WorkspaceStateLayout;
    use rusqlite::Connection;

    use super::*;

    fn workspace() -> Result<RegisteredWorkspace, Box<dyn std::error::Error>> {
        Ok(RegisteredWorkspace::from_parts_with_revision(
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            LocationId::from_uuid(Uuid::from_u128(2)),
            WorkspaceRoot::from_canonical(PathBuf::from("/recovery/selected"))?,
            WorkspaceRootFingerprint::from_bytes([1; 16]),
            TimestampMillis::new(10)?,
            TimestampMillis::new(11)?,
            WorkspaceRevision::new(7)?,
        ))
    }

    fn request() -> Result<WorkspaceRootRecoveryRequest, Box<dyn std::error::Error>> {
        let current = workspace()?;
        Ok(WorkspaceRootRecoveryRequest::new(
            Uuid::from_u128(3),
            LocationRevision::new(4)?,
            current.clone(),
            WorkspaceRootRecoveryObservation::new(
                current.root().clone(),
                WorkspaceRootFingerprint::from_bytes([2; 16]),
                WorkspaceRootRecoveryWitness::from_bytes([3; 32]),
            ),
            TimestampMillis::new(12)?,
        )?)
    }

    fn store_fixture(
        label: &str,
    ) -> Result<
        (PathBuf, WorkspaceStateLayout, WorkspaceStore, WorkspaceId),
        Box<dyn std::error::Error>,
    > {
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-root-recovery-{label}-{}",
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let layout = WorkspaceStateLayout::initialize(&root)?;
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(101));
        let location_id = LocationId::from_uuid(Uuid::from_u128(102));
        let command = EstablishWorkspace::new(
            workspace_id,
            location_id,
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            layout.root_fingerprint()?,
            TimestampMillis::new(1)?,
        );
        let store = WorkspaceStore::open(&layout, &command)?;
        Ok((root, layout, store, workspace_id))
    }

    fn delegated_fixture_authority(
        store: &mut WorkspaceStore,
    ) -> Result<WorkspaceRootRecoveryDelegatedAuthority, Box<dyn std::error::Error>> {
        let freeze = store.freeze_agent_operations(&crate::AgentOperationsFreezeRequest::new(
            Uuid::from_u128(0xD001),
            Uuid::from_u128(0xD002),
            TimestampMillis::new(2)?,
        )?)?;
        let delegation =
            store.delegate_agent_operations(&freeze, [0xAB; 32], TimestampMillis::new(3)?)?;
        let authority = current_delegated_authority(&store.connection, freeze.workspace_id())?;
        assert_eq!(
            authority.delegation().delegated_at,
            delegation.delegated_at()
        );
        Ok(authority)
    }

    #[test]
    fn schema_v63_root_preparation_upgrades_only_explicitly_to_current()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, _workspace_id) = store_fixture("schema-v63-prepare")?;
        let authority = delegated_fixture_authority(&mut store)?;
        let expected = store.workspace()?;
        let actual_fingerprint = layout.root_fingerprint()?;
        let mut old_fingerprint = actual_fingerprint.into_bytes();
        old_fingerprint[0] ^= 1;
        crate::workspace_store::tests::downgrade_admission_identity(&store.connection)?;
        store.connection.execute_batch(
            "DROP TABLE unstarted_activity_continuation_receipts;
             DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
             DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
             DROP TABLE IF EXISTS agent_binding_rejections;
             DROP TABLE expired_activity_recovery_agents;
             DROP INDEX expired_activity_recovery_receipts_successor_uidx;
             DROP TABLE expired_activity_recovery_receipts;
             PRAGMA user_version = 63;",
        )?;
        store.connection.execute(
            "UPDATE workspace SET root_fingerprint=?1",
            params![old_fingerprint.as_slice()],
        )?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let gate = WorkspaceStateExclusiveGate::acquire(&root, actual_fingerprint)?;
        let expected = RegisteredWorkspace::from_parts_with_revision(
            expected.id(),
            expected.location_id(),
            expected.root().clone(),
            WorkspaceRootFingerprint::from_bytes(old_fingerprint),
            expected.created_at(),
            expected.updated_at(),
            expected.revision(),
        );
        let probe = WorkspaceStore::probe_root_recovery_preserving_delegated_freeze(
            &existing, &gate, &expected, authority,
        )?;
        assert_eq!(probe.schema_version(), 63);
        assert!(probe.requires_schema_upgrade());
        let prepared = WorkspaceStore::prepare_root_recovery(&existing, &gate, &probe)?;
        assert_eq!(prepared.schema_version(), CURRENT_SCHEMA_VERSION);
        assert!(!prepared.requires_schema_upgrade());
        let object_count: i64 = Connection::open(existing.database_path())?.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name IN (
                'expired_activity_recovery_receipts',
                'expired_activity_recovery_agents',
                'expired_activity_recovery_receipts_successor_uidx'
            )",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(object_count, 3);
        drop(gate);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn schema_v64_root_preparation_upgrades_only_rejection_schema_to_current()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, _workspace_id) = store_fixture("schema-v64-prepare")?;
        let authority = delegated_fixture_authority(&mut store)?;
        let expected = store.workspace()?;
        let actual_fingerprint = layout.root_fingerprint()?;
        let mut old_fingerprint = actual_fingerprint.into_bytes();
        old_fingerprint[0] ^= 1;
        crate::workspace_store::tests::downgrade_admission_identity(&store.connection)?;
        store.connection.execute_batch(
            "DROP TABLE unstarted_activity_continuation_receipts;
             DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
             DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
             DROP TABLE IF EXISTS agent_binding_rejections;
             PRAGMA user_version = 64;",
        )?;
        store.connection.execute(
            "UPDATE workspace SET root_fingerprint=?1",
            params![old_fingerprint.as_slice()],
        )?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let gate = WorkspaceStateExclusiveGate::acquire(&root, actual_fingerprint)?;
        let expected = RegisteredWorkspace::from_parts_with_revision(
            expected.id(),
            expected.location_id(),
            expected.root().clone(),
            WorkspaceRootFingerprint::from_bytes(old_fingerprint),
            expected.created_at(),
            expected.updated_at(),
            expected.revision(),
        );
        let probe = WorkspaceStore::probe_root_recovery_preserving_delegated_freeze(
            &existing, &gate, &expected, authority,
        )?;
        assert_eq!(probe.schema_version(), 64);
        let prepared = WorkspaceStore::prepare_root_recovery(&existing, &gate, &probe)?;
        assert_eq!(prepared.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(
            Connection::open(existing.database_path())?.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name IN (
                    'agent_binding_rejections',
                    'agent_binding_rejections_block_activation',
                    'agent_binding_activations_block_rejection'
                )",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            3
        );
        drop(gate);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn schema_v65_root_preparation_adds_only_empty_continuation_ledger()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, _workspace_id) = store_fixture("schema-v65-prepare")?;
        let authority = delegated_fixture_authority(&mut store)?;
        let expected = store.workspace()?;
        let actual_fingerprint = layout.root_fingerprint()?;
        let mut old_fingerprint = actual_fingerprint.into_bytes();
        old_fingerprint[0] ^= 1;
        crate::workspace_store::tests::downgrade_admission_identity(&store.connection)?;
        store.connection.execute_batch(
            "DROP TABLE unstarted_activity_continuation_receipts;
             PRAGMA user_version = 65;",
        )?;
        store.connection.execute(
            "UPDATE workspace SET root_fingerprint=?1",
            params![old_fingerprint.as_slice()],
        )?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let gate = WorkspaceStateExclusiveGate::acquire(&root, actual_fingerprint)?;
        let expected = RegisteredWorkspace::from_parts_with_revision(
            expected.id(),
            expected.location_id(),
            expected.root().clone(),
            WorkspaceRootFingerprint::from_bytes(old_fingerprint),
            expected.created_at(),
            expected.updated_at(),
            expected.revision(),
        );
        let probe = WorkspaceStore::probe_root_recovery_preserving_delegated_freeze(
            &existing, &gate, &expected, authority,
        )?;
        assert_eq!(probe.schema_version(), 65);
        let prepared = WorkspaceStore::prepare_root_recovery(&existing, &gate, &probe)?;
        assert_eq!(prepared.schema_version(), CURRENT_SCHEMA_VERSION);
        let count: i64 = Connection::open(existing.database_path())?.query_row(
            "SELECT COUNT(*) FROM unstarted_activity_continuation_receipts",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(count, 0);
        drop(gate);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn schema_v67_root_preparation_preserves_identity_and_upgrades_admission_key()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, _) = store_fixture("admission-v67-prepare")?;
        let authority = delegated_fixture_authority(&mut store)?;
        let expected = store.workspace()?;
        let actual = layout.root_fingerprint()?;
        let mut previous = actual.into_bytes();
        previous[0] ^= 1;
        crate::workspace_store::tests::downgrade_admission_identity(&store.connection)?;
        store.connection.pragma_update(
            None,
            "user_version",
            super::super::PREVIOUS_ADMISSION_IDENTITY_SCHEMA_VERSION,
        )?;
        store.connection.execute(
            "UPDATE workspace SET root_fingerprint=?1",
            params![previous.as_slice()],
        )?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let gate = WorkspaceStateExclusiveGate::acquire(&root, actual)?;
        let expected = RegisteredWorkspace::from_parts_with_revision(
            expected.id(),
            expected.location_id(),
            expected.root().clone(),
            WorkspaceRootFingerprint::from_bytes(previous),
            expected.created_at(),
            expected.updated_at(),
            expected.revision(),
        );
        let probe = WorkspaceStore::probe_root_recovery_preserving_delegated_freeze(
            &existing, &gate, &expected, authority,
        )?;
        assert_eq!(probe.schema_version(), 67);
        let prepared = WorkspaceStore::prepare_root_recovery(&existing, &gate, &probe)?;
        assert_eq!(prepared.schema_version(), CURRENT_SCHEMA_VERSION);
        assert_eq!(prepared.workspace(), &expected);
        crate::workspace_admission_envelopes::validate_schema(&Connection::open(
            existing.database_path(),
        )?)?;
        drop(gate);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn root_preparation_rejects_future_schema_without_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, _workspace_id) = store_fixture("schema-v67-future")?;
        let authority = delegated_fixture_authority(&mut store)?;
        let expected = store.workspace()?;
        store
            .connection
            .pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION + 1)?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let actual_fingerprint = layout.root_fingerprint()?;
        let gate = WorkspaceStateExclusiveGate::acquire(&root, actual_fingerprint)?;
        let result = WorkspaceStore::probe_root_recovery_preserving_delegated_freeze(
            &existing, &gate, &expected, authority,
        );
        assert!(result.is_err(), "future schema must fail closed");
        drop(gate);
        assert_eq!(
            Connection::open(layout.database_path())?.query_row(
                "PRAGMA user_version",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            CURRENT_SCHEMA_VERSION + 1
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn preservation_rejects_extra_history_and_both_post_delegation_outboxes()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, workspace_id) = store_fixture("authority-census")?;
        let authority = delegated_fixture_authority(&mut store)?;
        let mode = WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority);
        validate_authority_mode(&store.connection, workspace_id, mode)?;

        let mut wrong_delegation = authority.delegation();
        wrong_delegation.manifest_digest = [0xCD; 32];
        let wrong =
            WorkspaceRootRecoveryDelegatedAuthority::new(authority.freeze(), wrong_delegation)?;
        assert!(
            validate_authority_mode(
                &store.connection,
                workspace_id,
                WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(wrong),
            )
            .is_err()
        );

        let transaction = store.connection.transaction()?;
        transaction.execute(
            "INSERT INTO agent_operations_migrations(
                migration_id,workspace_id,destination_id,state,revision,created_at_ms,updated_at_ms
             ) VALUES (?1,?2,?3,1,2,1,2)",
            params![
                Uuid::from_u128(0xD099).as_bytes(),
                workspace_id.into_uuid().as_bytes(),
                Uuid::from_u128(0xD098).as_bytes()
            ],
        )?;
        assert!(matches!(
            validate_authority_mode(&transaction, workspace_id, mode),
            Err(RootRecoveryStoreError::ActiveAuthority(
                RootRecoveryAuthorityBlocker::AgentOperationsDelegation
            ))
        ));
        transaction.rollback()?;

        for table in ["agent_effect_outbox_entries", "effect_fact_outbox_entries"] {
            let transaction = store.connection.transaction()?;
            let insert = format!(
                "INSERT INTO {table}(
                sequence,migration_id,destination_id,workspace_id,fact_kind
                ) VALUES (1,?1,?2,?3,0)"
            );
            transaction.execute(
                &insert,
                params![
                    authority.freeze().migration_id.as_bytes(),
                    authority.freeze().destination_id.as_bytes(),
                    workspace_id.into_uuid().as_bytes()
                ],
            )?;
            assert!(matches!(
                validate_authority_mode(&transaction, workspace_id, mode),
                Err(RootRecoveryStoreError::ActiveAuthority(
                    RootRecoveryAuthorityBlocker::PostDelegationParticipation
                ))
            ));
            transaction.rollback()?;
        }
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn intent_digest_is_stable_and_binds_location_and_witness()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let same = request_intent_digest(&request);
        assert_eq!(same, request_intent_digest(&request));
        let changed = WorkspaceRootRecoveryRequest::new(
            request.request_id(),
            LocationRevision::new(5)?,
            request.expected().clone(),
            request.observed().clone(),
            request.observed_at(),
        )?;
        assert_ne!(same, request_intent_digest(&changed));
        Ok(())
    }

    #[test]
    fn historical_v61_identity_is_readable_without_migration_or_receipt_tables()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, store, workspace_id) = store_fixture("identity-v61")?;
        crate::workspace_store::tests::downgrade_admission_identity(&store.connection)?;
        store.connection.execute_batch(
            "DROP TABLE IF EXISTS unstarted_activity_continuation_receipts;
            DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
            DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
            DROP TABLE IF EXISTS agent_binding_rejections;
            DROP TABLE IF EXISTS expired_activity_recovery_agents;
            DROP INDEX IF EXISTS expired_activity_recovery_receipts_successor_uidx;
            DROP TABLE IF EXISTS expired_activity_recovery_receipts;
            DROP TABLE root_recovery_delegation_receipts;
            DROP TABLE workspace_root_recovery_receipts",
        )?;
        store.connection.pragma_update(None, "user_version", 61)?;
        drop(store);
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let before = fs::read(layout.database_path())?;
        assert_eq!(
            WorkspaceStore::inspect_existing_identity_live_read_only(&layout)?.id(),
            workspace_id
        );
        assert_eq!(before, fs::read(layout.database_path())?);
        let connection = Connection::open(layout.database_path())?;
        assert_eq!(
            connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))?,
            61
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM sqlite_schema
            WHERE name IN ('workspace_root_recovery_receipts','root_recovery_delegation_receipts')",
                [],
                |row| row.get::<_, i64>(0)
            )?,
            0
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn receipt_round_trip_preserves_exact_result_and_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = request()?;
        let result =
            decide_workspace_root_recovery(request.expected(), request.observed(), &request)?;
        let digest = request_intent_digest(&request);
        let record = ReceiptRecord::from_request(request.expected(), &result, &request, digest)?;
        let receipt = record.clone().into_receipt()?;
        assert_eq!(receipt.request_id(), request.request_id());
        assert_eq!(receipt.workspace(), &result);
        assert_eq!(
            receipt.expected_location_revision(),
            request.location_revision()
        );
        assert_eq!(receipt.request_digest(), &digest);
        assert_eq!(
            receipt.witness_digest(),
            request.observed().witness().as_bytes()
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn preserve_delegated_freeze_rebinds_only_workspace_metadata_and_dual_receipts()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, mut store, _workspace_id) = store_fixture("preserved-delegation")?;
        let authority = delegated_fixture_authority(&mut store)?;
        let before = store.connection.query_row(
            "SELECT m.migration_id,m.workspace_id,m.destination_id,m.state,m.revision,
                    m.created_at_ms,m.updated_at_ms,d.freeze_revision,d.manifest_digest,d.delegated_at_ms
             FROM agent_operations_migrations m JOIN agent_operations_delegations d USING(migration_id)",
            [],
            |row| Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?,row.get::<_,i64>(5)?,row.get::<_,i64>(6)?,row.get::<_,i64>(7)?,row.get::<_,Vec<u8>>(8)?,row.get::<_,i64>(9)?)),
        )?;
        let expected = store.workspace()?;
        let actual_fingerprint = layout.root_fingerprint()?;
        let mut old = actual_fingerprint.into_bytes();
        old[0] ^= 1;
        crate::workspace_store::tests::downgrade_admission_identity(&store.connection)?;
        store.connection.execute_batch(
            "DROP TABLE IF EXISTS unstarted_activity_continuation_receipts;
             DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
             DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
             DROP TABLE IF EXISTS agent_binding_rejections;
             DROP TABLE IF EXISTS expired_activity_recovery_agents;
             DROP INDEX IF EXISTS expired_activity_recovery_receipts_successor_uidx;
             DROP TABLE IF EXISTS expired_activity_recovery_receipts;
             DROP TABLE root_recovery_delegation_receipts;
             PRAGMA user_version = 62;",
        )?;
        store.connection.execute(
            "UPDATE workspace SET root_fingerprint=?1",
            params![old.as_slice()],
        )?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let gate = WorkspaceStateExclusiveGate::acquire(&root, actual_fingerprint)?;
        let expected = RegisteredWorkspace::from_parts_with_revision(
            expected.id(),
            expected.location_id(),
            expected.root().clone(),
            WorkspaceRootFingerprint::from_bytes(old),
            expected.created_at(),
            expected.updated_at(),
            expected.revision(),
        );
        let probe = WorkspaceStore::probe_root_recovery_preserving_delegated_freeze(
            &existing, &gate, &expected, authority,
        )?;
        assert_eq!(probe.schema_version(), 62);
        assert!(probe.requires_schema_upgrade());
        let probe = WorkspaceStore::prepare_root_recovery(&existing, &gate, &probe)?;
        assert_eq!(probe.schema_version(), CURRENT_SCHEMA_VERSION);
        assert!(!probe.requires_schema_upgrade());
        let request = WorkspaceRootRecoveryRequest::new_preserving_delegated_freeze(
            Uuid::from_u128(0xD003),
            LocationRevision::INITIAL,
            expected.clone(),
            probe.observation().clone(),
            TimestampMillis::new(4)?,
            authority,
        )?;
        let RootRecoveryOperation::Committed(receipt) =
            WorkspaceStore::recover_root_binding(&existing, &gate, &probe, &request)?
        else {
            return Err("expected commit".into());
        };
        assert_eq!(
            receipt.authority_mode(),
            WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority)
        );
        let mut connection = Connection::open(existing.database_path())?;
        let after = connection.query_row(
            "SELECT m.migration_id,m.workspace_id,m.destination_id,m.state,m.revision,
                    m.created_at_ms,m.updated_at_ms,d.freeze_revision,d.manifest_digest,d.delegated_at_ms
             FROM agent_operations_migrations m JOIN agent_operations_delegations d USING(migration_id)",
            [],
            |row| Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?,row.get::<_,i64>(5)?,row.get::<_,i64>(6)?,row.get::<_,i64>(7)?,row.get::<_,Vec<u8>>(8)?,row.get::<_,i64>(9)?)),
        )?;
        assert_eq!(before, after);
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM root_recovery_delegation_receipts WHERE request_id=?1",
                params![request.request_id().as_bytes()],
                |row| row.get::<_, i64>(0)
            )?,
            1
        );

        // Lost reply is settled through the original intent, not a second effect.
        let RootRecoveryOperation::Replay(replayed) =
            WorkspaceStore::recover_root_binding(&existing, &gate, &probe, &request)?
        else {
            return Err("expected exact replay".into());
        };
        assert_eq!(replayed.request_digest(), receipt.request_digest());
        let ordinary = WorkspaceRootRecoveryRequest::new(
            request.request_id(),
            request.location_revision(),
            request.expected().clone(),
            request.observed().clone(),
            request.observed_at(),
        )?;
        assert!(WorkspaceStore::recover_root_binding(&existing, &gate, &probe, &ordinary).is_err());

        verify_damaged_companion_rollback(&mut connection, &request)?;
        verify_sequential_delegation_receipts(&mut connection, &receipt)?;
        drop(gate);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    fn verify_damaged_companion_rollback(
        connection: &mut Connection,
        request: &WorkspaceRootRecoveryRequest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Neither missing nor altered companion evidence may turn a v2 receipt
        // into ordinary v1 evidence. Failed checks do not destroy the receipt.
        let transaction = connection.transaction()?;
        transaction.execute(
            "DELETE FROM root_recovery_delegation_receipts WHERE request_id=?1",
            params![request.request_id().as_bytes()],
        )?;
        assert!(load_receipt(&transaction, request.request_id()).is_err());
        transaction.rollback()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "UPDATE root_recovery_delegation_receipts
            SET witness_v2_digest=zeroblob(32) WHERE request_id=?1",
            params![request.request_id().as_bytes()],
        )?;
        assert!(load_receipt(&transaction, request.request_id()).is_err());
        transaction.rollback()?;
        let transaction = connection.transaction()?;
        transaction.execute_batch("DROP TABLE root_recovery_delegation_receipts")?;
        assert!(validate_schema(&transaction).is_err());
        transaction.rollback()?;
        assert!(load_receipt(connection, request.request_id())?.is_some());

        Ok(())
    }

    fn verify_sequential_delegation_receipts(
        connection: &mut Connection,
        first: &RootRecoveryReceipt,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let WorkspaceRootRecoveryAuthorityMode::PreserveDelegatedFreeze(authority) =
            first.authority_mode()
        else {
            return Err("preserved authority missing".into());
        };
        // Repeated migration identity is valid across sequential revisions.
        // This codec/DDL proof complements the physical transition owner tests.
        let expected_second = first.workspace().clone();
        let mut next_fingerprint = expected_second.root_fingerprint().into_bytes();
        next_fingerprint[0] ^= 2;
        let second = WorkspaceRootRecoveryRequest::new_preserving_delegated_freeze(
            Uuid::from_u128(0xD004),
            first.expected_location_revision(),
            expected_second.clone(),
            WorkspaceRootRecoveryObservation::new(
                expected_second.root().clone(),
                WorkspaceRootFingerprint::from_bytes(next_fingerprint),
                WorkspaceRootRecoveryWitness::from_bytes([0x55; 32]),
            ),
            TimestampMillis::new(5)?,
            authority,
        )?;
        let result_second =
            decide_workspace_root_recovery(&expected_second, second.observed(), &second)?;
        let second_record = ReceiptRecord::from_request(
            &expected_second,
            &result_second,
            &second,
            request_intent_digest(&second),
        )?;
        let transaction = connection.transaction()?;
        insert_receipt(&transaction, &second_record)?;
        transaction.commit()?;
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM root_recovery_delegation_receipts WHERE migration_id=?1",
                params![authority.freeze().migration_id.as_bytes()],
                |row| row.get::<_, i64>(0)
            )?,
            2
        );
        assert_eq!(
            load_receipt(connection, first.request_id())?
                .ok_or("first missing")?
                .into_receipt()?
                .request_digest(),
            first.request_digest()
        );
        assert_eq!(
            load_receipt(connection, second.request_id())?
                .ok_or("second missing")?
                .into_receipt()?
                .workspace(),
            &result_second
        );
        Ok(())
    }

    #[test]
    fn active_activity_rejects_root_recovery_authority() -> Result<(), Box<dyn std::error::Error>> {
        let (root, _layout, mut store, workspace_id) = store_fixture("active-activity")?;
        store.create_activity(&CreateActivity::new(
            ActivityId::from_uuid(Uuid::from_u128(103)),
            workspace_id,
            WorkspaceRevision::INITIAL,
            TimestampMillis::new(2)?,
        ))?;
        assert!(matches!(
            ensure_no_active_authority(&store.connection, workspace_id),
            Err(RootRecoveryStoreError::ActiveAuthority(
                RootRecoveryAuthorityBlocker::StateRemoval(
                    WorkspaceStateRemovalBlocker::OpenActivity,
                )
            ))
        ));
        drop(store);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn recovery_cas_replays_exact_receipt_and_rejects_changed_intent()
    -> Result<(), Box<dyn std::error::Error>> {
        let (root, layout, store, workspace_id) = store_fixture("cas-replay")?;
        let current_fingerprint = layout.root_fingerprint()?;
        let old_fingerprint = WorkspaceRootFingerprint::from_bytes([9; 16]);
        store.connection.execute(
            "UPDATE workspace SET root_fingerprint = ?1",
            params![old_fingerprint.as_bytes().as_slice()],
        )?;
        drop(store);
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
        let expected = RegisteredWorkspace::from_parts_with_revision(
            workspace_id,
            LocationId::from_uuid(Uuid::from_u128(102)),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
            old_fingerprint,
            TimestampMillis::new(1)?,
            TimestampMillis::new(1)?,
            WorkspaceRevision::INITIAL,
        );
        let identity =
            WorkspaceStore::inspect_existing_root_recovery_identity_read_only(&existing)?;
        assert_eq!(identity.workspace(), &expected);
        assert_eq!(identity.current_root_fingerprint(), current_fingerprint);
        let gate =
            WorkspaceStateExclusiveGate::acquire(layout.workspace_root(), current_fingerprint)?;
        let probe = WorkspaceStore::probe_root_recovery(&existing, &gate, &expected)?;
        let prepared = WorkspaceStore::prepare_root_recovery(&existing, &gate, &probe)?;
        let request = WorkspaceRootRecoveryRequest::new(
            Uuid::from_u128(104),
            LocationRevision::new(3)?,
            expected.clone(),
            prepared.observation().clone(),
            TimestampMillis::new(2)?,
        )?;
        let committed =
            WorkspaceStore::recover_root_binding(&existing, &gate, &prepared, &request)?;
        assert!(matches!(committed, RootRecoveryOperation::Committed(_)));
        let sabotage = Connection::open(existing.database_path())?;
        sabotage.execute("UPDATE workspace SET revision = 99", [])?;
        drop(sabotage);
        let postcommit_connection = Connection::open(existing.database_path())?;
        assert!(matches!(
            confirm_root_recovery_commit(
                &postcommit_connection,
                &existing,
                &gate,
                &request,
                request_intent_digest(&request),
                current_fingerprint,
                &prepared.source,
            ),
            Err(RootRecoveryStoreError::WorkspaceChanged)
        ));
        drop(postcommit_connection);
        let replayed = WorkspaceStore::recover_root_binding(&existing, &gate, &prepared, &request)?;
        assert!(matches!(replayed, RootRecoveryOperation::Replay(_)));
        assert!(
            WorkspaceStore::root_recovery_receipt_for_request_under_gate(
                &existing, &gate, &request,
            )?
            .is_some()
        );
        let changed = WorkspaceRootRecoveryRequest::new(
            request.request_id(),
            LocationRevision::new(4)?,
            expected,
            prepared.observation().clone(),
            TimestampMillis::new(2)?,
        )?;
        assert!(matches!(
            WorkspaceStore::root_recovery_receipt_for_request_under_gate(
                &existing, &gate, &changed,
            ),
            Err(RootRecoveryStoreError::RequestConflict)
        ));
        drop(gate);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
