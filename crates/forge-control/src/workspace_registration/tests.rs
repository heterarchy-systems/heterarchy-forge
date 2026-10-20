use super::*;
use forge_domain::{LocationId, LocationRevision, LocationState, SetLocationState};
use forge_persistence::GlobalRegistry;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

struct Fixture {
    root: PathBuf,
    child: PathBuf,
    service: LocationService<GlobalRegistry>,
    request: WorkspaceRegistrationRequest,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("forge-registration-{}", Uuid::now_v7()));
    let location_root = root.join("location");
    let child = location_root.join("child");
    fs::create_dir_all(&child)?;
    let mut service = LocationService::new(GlobalRegistry::open(root.join("registry.sqlite3"))?);
    let location = service.register_selected_path(
        LocationId::from_uuid(Uuid::now_v7()),
        "registration",
        &location_root,
        TimestampMillis::new(1)?,
    )?;
    let locator = WorkspaceLocator::new(location.id(), location.revision(), "child")?;
    let probe = probe_workspace_registration(&service, &locator)?;
    assert!(probe.workspace.is_none());
    assert!(!child.join(".heterarchy-forge").exists());
    let request = WorkspaceRegistrationRequest::new(
        locator,
        WorkspaceId::from_uuid(Uuid::now_v7()),
        probe.root_fingerprint,
        TimestampMillis::new(2)?,
    )?;
    Ok(Fixture {
        root,
        child,
        service,
        request,
    })
}

#[test]
fn post_commit_revision_change_preserves_identity_without_confirming_selection()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let location_id = fixture.request.locator.location_id();
    let changed_at = TimestampMillis::new(3)?;
    let outcome =
        register_workspace_with_hook(&mut fixture.service, &fixture.request, |service| {
            assert!(
                service
                    .set_location_state(&SetLocationState::new(
                        location_id,
                        LocationRevision::INITIAL,
                        LocationState::Disabled,
                        changed_at
                    ))
                    .is_ok()
            );
        })?;
    assert!(
        matches!(outcome, WorkspaceRegistrationOutcome::CommittedButUnconfirmed {
        workspace, reason: WorkspaceRevalidationReason::LocationRevisionChanged,
    } if workspace.id() == fixture.request.proposed_workspace_id)
    );
    let layout =
        WorkspaceStateLayout::inspect_existing(&fixture.child)?.ok_or("committed state missing")?;
    let workspace = WorkspaceStore::inspect_existing_identity_live_read_only(&layout)?;
    assert_eq!(workspace.id(), fixture.request.proposed_workspace_id);
    Ok(())
}

#[test]
fn post_commit_replacement_never_initializes_the_replacement_root()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let moved = fixture.child.with_file_name("moved-child");
    let child = fixture.child.clone();
    let outcome = register_workspace_with_hook(&mut fixture.service, &fixture.request, |_| {
        assert!(fs::rename(&child, &moved).is_ok());
        assert!(fs::create_dir(&child).is_ok());
    })?;
    assert!(
        matches!(outcome, WorkspaceRegistrationOutcome::CommittedButUnconfirmed {
        workspace, reason: WorkspaceRevalidationReason::CandidateFingerprintChanged,
    } if workspace.id() == fixture.request.proposed_workspace_id)
    );
    assert!(moved.join(".heterarchy-forge/state.sqlite3").is_file());
    assert!(!child.join(".heterarchy-forge").exists());
    // Supported explicit reopening preserves the original identity after the
    // original physical directory is moved; no direct database repair.
    let moved_layout = WorkspaceStateLayout::initialize(&moved)?;
    let store = WorkspaceStore::open(
        &moved_layout,
        EstablishWorkspace::new(
            fixture.request.proposed_workspace_id,
            fixture.request.locator.location_id(),
            WorkspaceRoot::from_canonical(moved_layout.workspace_root().to_path_buf())?,
            moved_layout.root_fingerprint()?,
            TimestampMillis::new(4)?,
        ),
    )?;
    let recovered = store.workspace()?;
    assert_eq!(recovered.id(), fixture.request.proposed_workspace_id);
    assert_eq!(recovered.root().as_path(), fs::canonicalize(&moved)?);
    assert_eq!(recovered.revision().get(), 2);
    Ok(())
}

#[test]
fn probe_replay_preserve_existing_identity_and_stale_fingerprint_cannot_initialize()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let first = register_workspace(&mut fixture.service, &fixture.request)?;
    let WorkspaceRegistrationOutcome::Confirmed(first) = first else {
        return Err("first registration not confirmed".into());
    };
    let database = fixture.child.join(".heterarchy-forge/state.sqlite3");
    let before = fs::read(&database)?;
    let probe = probe_workspace_registration(&fixture.service, &fixture.request.locator)?;
    assert_eq!(probe.workspace.as_ref(), Some(&first));
    assert_eq!(fs::read(&database)?, before);
    let another_proposal = WorkspaceRegistrationRequest::new(
        fixture.request.locator.clone(),
        WorkspaceId::from_uuid(Uuid::now_v7()),
        fixture.request.expected_root_fingerprint,
        TimestampMillis::new(4)?,
    )?;
    assert_eq!(
        register_workspace(&mut fixture.service, &another_proposal)?,
        WorkspaceRegistrationOutcome::Confirmed(first)
    );
    let moved = fixture.child.with_file_name("moved-child");
    fs::rename(&fixture.child, moved)?;
    fs::create_dir(&fixture.child)?;
    assert!(matches!(
        register_workspace(&mut fixture.service, &fixture.request),
        Err(WorkspaceRegistrationError::FingerprintConflict)
    ));
    assert!(!fixture.child.join(".heterarchy-forge").exists());
    Ok(())
}

#[test]
fn registration_store_failure_requires_readback_while_probe_failure_remains_read_only()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let layout = WorkspaceStateLayout::initialize(&fixture.child)?;
    fs::write(layout.database_path(), b"invalid sqlite fixture")?;
    let before = fs::read(layout.database_path())?;
    let mut control =
        ForgeControl::new(GlobalRegistry::open(fixture.root.join("registry.sqlite3"))?);
    let probe_error = control
        .probe_workspace_registration(&fixture.request.locator)
        .err()
        .ok_or("corrupt state unexpectedly probed successfully")?;
    assert_eq!(
        probe_error.view().details(),
        crate::ControlErrorDetails::None
    );
    assert_eq!(fs::read(layout.database_path())?, before);
    let registration_error = control
        .register_workspace(&fixture.request)
        .err()
        .ok_or("corrupt state unexpectedly registered successfully")?;
    assert_eq!(
        registration_error.view().details(),
        crate::ControlErrorDetails::WorkspaceRegistrationUnknown
    );
    assert_eq!(
        registration_error.view().recovery_action(),
        crate::ControlRecoveryAction::ReadBack
    );
    assert!(
        !registration_error.is_committed(),
        "failure must not fabricate a commit"
    );
    assert_eq!(fs::read(layout.database_path())?, before);
    Ok(())
}
