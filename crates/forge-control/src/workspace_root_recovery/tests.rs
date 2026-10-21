use super::*;
use forge_domain::{EstablishWorkspace, TimestampMillis, WorkspaceRevision, WorkspaceRoot};
use forge_persistence::GlobalRegistry;
use forge_workspace::LocationService;
use std::fs;

struct RecoveryFixture {
    root: PathBuf,
    control: ForgeControl,
    locator: WorkspaceLocator,
    workspace: RegisteredWorkspace,
}

impl Drop for RecoveryFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fixture() -> Result<RecoveryFixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("forge-control-root-recovery-{}", Uuid::now_v7()));
    let location_root = root.join("location");
    let child = location_root.join("workspace");
    fs::create_dir_all(&child)?;
    let registry_path = root.join("registry.sqlite3");
    let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
    let location = locations.register_selected_path(
        LocationId::from_uuid(Uuid::now_v7()),
        "recovery fixture",
        &location_root,
        TimestampMillis::new(1)?,
    )?;
    let locator = WorkspaceLocator::new(location.id(), location.revision(), "workspace")?;
    let layout = WorkspaceStateLayout::initialize(&child)?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::now_v7());
    let current_fingerprint = layout.root_fingerprint()?;
    let workspace_root = WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
    drop(WorkspaceStore::open(
        &layout,
        EstablishWorkspace::new(
            workspace_id,
            location.id(),
            workspace_root.clone(),
            current_fingerprint,
            TimestampMillis::new(2)?,
        ),
    )?);
    // Seed only this isolated fixture's historical device component. Tests do
    // not remount a volume or use SQL to recover any retained/live Workspace.
    let mut old_bytes = current_fingerprint.into_bytes();
    old_bytes[0] ^= 1;
    let old_fingerprint = WorkspaceRootFingerprint::from_bytes(old_bytes);
    let connection = rusqlite::Connection::open(layout.database_path())?;
    connection.execute(
        "UPDATE workspace SET root_fingerprint = ?1",
        rusqlite::params![old_fingerprint.as_bytes().as_slice()],
    )?;
    drop(connection);
    drop(locations);
    Ok(RecoveryFixture {
        root,
        control: ForgeControl::new(GlobalRegistry::open_existing(&registry_path)?),
        locator,
        workspace: RegisteredWorkspace::from_parts_with_revision(
            workspace_id,
            location.id(),
            workspace_root,
            old_fingerprint,
            TimestampMillis::new(2)?,
            TimestampMillis::new(2)?,
            WorkspaceRevision::INITIAL,
        ),
    })
}

#[test]
fn public_recovery_preserves_identity_requires_confirmation_and_replays_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let probe =
        fixture
            .control
            .probe_workspace_root_recovery(&WorkspaceRootRecoveryProbeRequest::new(
                fixture.locator.clone(),
                Some(fixture.workspace.id()),
            ))?;
    assert_eq!(probe.workspace(), &fixture.workspace);
    assert!(
        fixture
            .control
            .resolve_workspace(
                fixture.locator.location_id(),
                fixture.locator.expected_revision(),
                &fixture.locator,
            )
            .is_err()
    );
    let prepared = fixture.control.prepare_workspace_root_recovery(
        &WorkspaceRootRecoveryPrepareRequest::new(
            fixture.locator.clone(),
            probe.workspace().clone(),
            probe.observation().clone(),
            true,
        ),
    )?;
    assert_eq!(prepared.workspace(), probe.workspace());
    let intent = WorkspaceRootRecoveryRequest::new(
        Uuid::now_v7(),
        fixture.locator.expected_revision(),
        prepared.workspace().clone(),
        prepared.observation().clone(),
        TimestampMillis::new(3)?,
    )?;
    let denied =
        fixture
            .control
            .commit_workspace_root_recovery(&WorkspaceRootRecoveryCommitRequest::new(
                fixture.locator.clone(),
                intent.clone(),
                false,
            ));
    assert!(
        matches!(denied, Err(error) if error.code() == ControlErrorCode::AuthorizationRequired)
    );
    let request =
        WorkspaceRootRecoveryCommitRequest::new(fixture.locator.clone(), intent.clone(), true);
    let WorkspaceRootRecoveryCommitOutcome::Committed { receipt } =
        fixture.control.commit_workspace_root_recovery(&request)?
    else {
        return Err("fresh exact recovery was not confirmed".into());
    };
    assert_eq!(receipt.workspace_id(), fixture.workspace.id());
    assert_eq!(receipt.workspace().revision(), WorkspaceRevision::new(2)?);
    let readback = fixture.control.readback_workspace_root_recovery(
        &WorkspaceRootRecoveryReadbackRequest::new(
            fixture.locator.clone(),
            intent.request_id(),
            Some(intent),
        ),
    )?;
    assert_eq!(readback, Some(receipt.clone()));
    assert!(matches!(
        fixture.control.commit_workspace_root_recovery(&request)?,
        WorkspaceRootRecoveryCommitOutcome::Replayed { receipt: replay } if replay == receipt
    ));
    Ok(())
}

#[test]
fn physical_transition_requires_device_change_with_same_inode_bytes() {
    let old =
        WorkspaceRootFingerprint::from_bytes([1, 0, 0, 0, 0, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2]);
    let new =
        WorkspaceRootFingerprint::from_bytes([2, 0, 0, 0, 0, 0, 0, 0, 9, 8, 7, 6, 5, 4, 3, 2]);
    assert!(validate_physical_transition(old, new).is_ok());
}

fn seed_preserved_delegation(
    fixture: &RecoveryFixture,
) -> Result<WorkspaceRootRecoveryDelegatedAuthority, Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::initialize(fixture.workspace.root().as_path())?;
    let actual = layout.root_fingerprint()?;
    let connection = rusqlite::Connection::open(layout.database_path())?;
    connection.execute(
        "UPDATE workspace SET root_fingerprint=?1",
        rusqlite::params![actual.as_bytes().as_slice()],
    )?;
    let mut store = WorkspaceStore::open(
        &layout,
        EstablishWorkspace::new(
            fixture.workspace.id(),
            fixture.workspace.location_id(),
            fixture.workspace.root().clone(),
            actual,
            fixture.workspace.created_at(),
        ),
    )?;
    let freeze =
        store.freeze_agent_operations(&forge_persistence::AgentOperationsFreezeRequest::new(
            Uuid::from_u128(0xD501),
            Uuid::from_u128(0xD502),
            TimestampMillis::new(3)?,
        )?)?;
    let delegation =
        store.delegate_agent_operations(&freeze, [0xAB; 32], TimestampMillis::new(4)?)?;
    let authority = WorkspaceRootRecoveryDelegatedAuthority::new(
        forge_domain::WorkspaceRootRecoveryFreezeFence {
            migration_id: freeze.migration_id(),
            workspace_id: freeze.workspace_id(),
            destination_id: freeze.destination_id(),
            state: forge_domain::WorkspaceRootRecoveryFreezeState::Frozen,
            revision: freeze.revision(),
            created_at: freeze.created_at(),
            updated_at: freeze.updated_at(),
        },
        forge_domain::WorkspaceRootRecoveryDelegationFence {
            migration_id: delegation.migration_id(),
            workspace_id: delegation.workspace_id(),
            destination_id: delegation.destination_id(),
            freeze_revision: freeze.revision(),
            manifest_digest: delegation.manifest_digest(),
            delegated_at: delegation.delegated_at(),
        },
    )?;
    drop(store);
    let current_admission_sql: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type='table' AND name='execution_admission_consumptions'",
        [], |row| row.get(0),
    )?;
    // Recreate this historical fixture's former key without maintaining a
    // second copy of the canonical table definition in another crate.
    let legacy_admission_sql = current_admission_sql
        .replace(
            "execution_id BLOB NOT NULL REFERENCES",
            "execution_id BLOB NOT NULL UNIQUE REFERENCES",
        )
        .replace(
            "PRIMARY KEY(execution_id)",
            "PRIMARY KEY(issuer, request_digest)",
        );
    assert_ne!(legacy_admission_sql, current_admission_sql);
    connection.execute_batch(
        "ALTER TABLE execution_admission_consumptions RENAME TO fixture_admission_identity_current",
    )?;
    connection.execute_batch(&legacy_admission_sql)?;
    connection.execute_batch("INSERT INTO execution_admission_consumptions SELECT * FROM fixture_admission_identity_current; DROP TABLE fixture_admission_identity_current; CREATE INDEX execution_admission_consumptions_execution_idx ON execution_admission_consumptions(execution_id);")?;
    connection.execute_batch(
        "DROP TABLE IF EXISTS quiescent_activity_lease_resume_receipts;
         DROP TABLE IF EXISTS unstarted_activity_continuation_receipts;
         DROP TRIGGER IF EXISTS agent_binding_activations_block_rejection;
         DROP TRIGGER IF EXISTS agent_binding_rejections_block_activation;
         DROP TABLE IF EXISTS agent_binding_rejections;
         DROP TABLE IF EXISTS expired_activity_recovery_agents;
         DROP INDEX IF EXISTS expired_activity_recovery_receipts_successor_uidx;
         DROP TABLE IF EXISTS expired_activity_recovery_receipts;
         DROP TABLE root_recovery_delegation_receipts",
    )?;
    connection.pragma_update(None, "user_version", 62)?;
    connection.execute(
        "UPDATE workspace SET root_fingerprint=?1",
        rusqlite::params![fixture.workspace.root_fingerprint().as_bytes().as_slice()],
    )?;
    Ok(authority)
}

#[test]
fn preserved_v2_witness_prepares_commits_and_reads_back_without_v1_reinterpretation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let authority = seed_preserved_delegation(&fixture)?;
    let probe = fixture.control.probe_workspace_root_recovery(
        &WorkspaceRootRecoveryProbeRequest::new_preserving_delegated_freeze(
            fixture.locator.clone(),
            Some(fixture.workspace.id()),
            authority,
        ),
    )?;
    assert_eq!(probe.schema_version(), 62);
    let wrong = WorkspaceRootRecoveryObservation::new(
        probe.observation().root().clone(),
        probe.observation().fingerprint(),
        forge_domain::WorkspaceRootRecoveryWitness::from_bytes([1; 32]),
    );
    assert!(
        fixture
            .control
            .prepare_workspace_root_recovery(
                &WorkspaceRootRecoveryPrepareRequest::new_preserving_delegated_freeze(
                    fixture.locator.clone(),
                    probe.workspace().clone(),
                    wrong,
                    true,
                    authority,
                ),
            )
            .is_err()
    );
    let prepared = fixture.control.prepare_workspace_root_recovery(
        &WorkspaceRootRecoveryPrepareRequest::new_preserving_delegated_freeze(
            fixture.locator.clone(),
            probe.workspace().clone(),
            probe.observation().clone(),
            true,
            authority,
        ),
    )?;
    assert_eq!(prepared.schema_version(), 69);
    assert_ne!(
        prepared.observation().witness(),
        probe.observation().witness()
    );
    let intent = WorkspaceRootRecoveryRequest::new_preserving_delegated_freeze(
        Uuid::now_v7(),
        fixture.locator.expected_revision(),
        prepared.workspace().clone(),
        prepared.observation().clone(),
        TimestampMillis::new(5)?,
        authority,
    )?;
    let command =
        WorkspaceRootRecoveryCommitRequest::new(fixture.locator.clone(), intent.clone(), true);
    let WorkspaceRootRecoveryCommitOutcome::Committed { receipt } =
        fixture.control.commit_workspace_root_recovery(&command)?
    else {
        return Err("preserved recovery was not confirmed".into());
    };
    assert_eq!(receipt.workspace_id(), fixture.workspace.id());
    assert_eq!(receipt.workspace().revision(), WorkspaceRevision::new(2)?);
    let readback = fixture.control.readback_workspace_root_recovery(
        &WorkspaceRootRecoveryReadbackRequest::new_preserving_delegated_freeze(
            fixture.locator.clone(),
            intent.request_id(),
            Some(intent),
            authority,
        ),
    )?;
    assert_eq!(readback, Some(receipt.clone()));
    assert!(
        matches!(fixture.control.commit_workspace_root_recovery(&command)?,
        WorkspaceRootRecoveryCommitOutcome::Replayed {receipt: replay} if replay==receipt)
    );
    Ok(())
}

#[test]
fn physical_transition_rejects_inode_changes_and_unchanged_identity() {
    let old = WorkspaceRootFingerprint::from_bytes([1; 16]);
    let changed_inode =
        WorkspaceRootFingerprint::from_bytes([2, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1]);
    assert!(validate_physical_transition(old, changed_inode).is_err());
    assert!(validate_physical_transition(old, old).is_err());
}
