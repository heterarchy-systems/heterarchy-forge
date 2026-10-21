//! Exact same-physical-root rebind while the offline operator owns its gate.
use super::{
    BUSY_TIMEOUT, EstablishWorkspace, ExistingOpenPolicy, ExistingWorkspaceStateLayout,
    ReadOnlyDoctorDatabase, RegisteredWorkspace, TimestampMillis, WorkspaceRoot,
    WorkspaceStateExclusiveGate, WorkspaceStore, WorkspaceStoreError, decode_workspace,
    query_workspace_row, validate_owned_database,
};
use rusqlite::params;

impl WorkspaceStore {
    /// Read the stored identity across a planned same-inode rename without rebinding.
    pub fn inspect_relocation_under_exclusive(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
    ) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        let fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        gate.ensure_root_binding(layout.workspace_root(), fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;
        let database = ReadOnlyDoctorDatabase::open_under_exclusive(layout, gate)?;
        validate_owned_database(&database.connection)?;
        let workspace = query_workspace_row(&database.connection)?
            .ok_or(WorkspaceStoreError::WorkspaceIdentityMissing)
            .and_then(decode_workspace)?;
        if workspace.root_fingerprint() != fingerprint {
            return Err(WorkspaceStoreError::RelocationBlocked(
                "physical identity differs",
            ));
        }
        database.ensure_unchanged()?;
        Ok(workspace)
    }

    /// Rebind an existing current-schema Workspace without altering semantic work.
    /// The caller retains the new-root exclusive gate throughout this operation.
    pub fn relocate_root_under_exclusive(
        layout: &ExistingWorkspaceStateLayout,
        gate: &WorkspaceStateExclusiveGate,
        expected: &RegisteredWorkspace,
        observed_at: TimestampMillis,
    ) -> Result<RegisteredWorkspace, WorkspaceStoreError> {
        let fingerprint = layout
            .root_fingerprint()
            .map_err(|source| WorkspaceStoreError::LayoutFingerprintObservation { source })?;
        gate.ensure_root_binding(layout.workspace_root(), fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;
        if fingerprint != expected.root_fingerprint()
            || layout.workspace_root() == expected.root().as_path()
            || observed_at.get() < expected.updated_at().get()
        {
            return Err(WorkspaceStoreError::RelocationBlocked(
                "root identity or time differs",
            ));
        }
        let mut store = Self::open_existing_with_timeout_and_gate_policy(
            layout,
            BUSY_TIMEOUT,
            None,
            || Ok(()),
            ExistingOpenPolicy::Relocation(expected),
        )?;
        if !store.list_active_writer_leases()?.is_empty() {
            return Err(WorkspaceStoreError::RelocationBlocked(
                "Writer Lease remains",
            ));
        }
        let active: bool = store.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM executions WHERE workspace_id=?1 AND state IN (0,1))",
            params![expected.id().into_uuid().as_bytes()],
            |row| row.get(0),
        )?;
        if active {
            return Err(WorkspaceStoreError::RelocationBlocked(
                "physical execution remains",
            ));
        }
        let command = EstablishWorkspace::new(
            expected.id(),
            expected.location_id(),
            WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())
                .map_err(|_| WorkspaceStoreError::RelocationBlocked("invalid new root"))?,
            fingerprint,
            observed_at,
        );
        let updated = store.establish_or_confirm_expected(&command, Some(expected))?;
        store.ensure_live_binding()?;
        gate.ensure_root_binding(layout.workspace_root(), fingerprint)
            .map_err(WorkspaceStoreError::StateGate)?;
        if updated.id() != expected.id()
            || updated.location_id() != expected.location_id()
            || updated.root_fingerprint() != fingerprint
            || updated.revision().get() != expected.revision().get() + 1
        {
            return Err(WorkspaceStoreError::RelocationBlocked(
                "rebind readback differs",
            ));
        }
        Ok(updated)
    }
}
