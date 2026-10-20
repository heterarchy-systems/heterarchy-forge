use super::*;
use forge_domain::{
    ActivityId, CreateActivity, EstablishWorkspace, LocationName, RegisterLocation, WorkspaceId,
    WorkspaceRevision, WorkspaceRoot,
};
use forge_workspace::LocationRepository;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn fixture() -> Result<(std::path::PathBuf, Plan), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("forge-relocation-{}", Uuid::now_v7()));
    fs::create_dir(&root)?;
    let root = fs::canonicalize(root)?;
    let source = root.join("old");
    fs::create_dir(&source)?;
    fs::write(source.join("report.txt"), "preserved research\n")?;
    let layout = WorkspaceStateLayout::initialize(&source)?;
    let location = Uuid::now_v7();
    let workspace = Uuid::now_v7();
    let fingerprint = layout.root_fingerprint()?;
    let mut store = WorkspaceStore::open(
        &layout,
        EstablishWorkspace::new(
            WorkspaceId::from_uuid(workspace),
            LocationId::from_uuid(location),
            WorkspaceRoot::from_canonical(source.clone())?,
            fingerprint,
            TimestampMillis::new(1)?,
        ),
    )?;
    store.create_activity(&CreateActivity::new(
        ActivityId::from_uuid(Uuid::from_u128(17)),
        WorkspaceId::from_uuid(workspace),
        WorkspaceRevision::INITIAL,
        TimestampMillis::new(2)?,
    ))?;
    drop(store);
    let registry_path = root.join("registry.sqlite3");
    let mut registry = GlobalRegistry::open(&registry_path)?;
    registry.register_location(&RegisterLocation::new(
        LocationId::from_uuid(location),
        LocationName::new("preserved")?,
        LocationRoot::from_canonical(source.clone())?,
        TimestampMillis::new(1)?,
    ))?;
    drop(registry);
    let db_metadata = fs::metadata(source.join(".heterarchy-forge/state.sqlite3"))?;
    let plan = Plan {
        request_id: Uuid::now_v7(),
        registry_path,
        source,
        destination: root.join("new"),
        location_id: location,
        expected_location_revision: 1,
        workspace_id: workspace,
        expected_workspace_revision: 1,
        root_fingerprint: fingerprint.into_bytes(),
        database_device: db_metadata.dev(),
        database_inode: db_metadata.ino(),
        observed_at_ms: 3,
    };
    Ok((root, plan))
}

#[test]
fn relocate_preserves_identity_content_and_replays_after_each_interruption()
-> Result<(), Box<dyn std::error::Error>> {
    for phase in [
        Phase::Prepared,
        Phase::Renamed,
        Phase::WorkspaceRebound,
        Phase::RegistryRebound,
    ] {
        let (root, plan) = fixture()?;
        assert!(relocate(&plan, Some(phase)).is_err());
        assert!(ensure_complete(&plan.registry_path).is_err());
        relocate(&plan, None)?;
        relocate(&plan, None)?;
        ensure_complete(&plan.registry_path)?;
        assert!(!plan.source.exists());
        assert_eq!(
            fs::read_to_string(plan.destination.join("report.txt"))?,
            "preserved research\n"
        );
        let layout = WorkspaceStateLayout::inspect_existing(&plan.destination)?.ok_or("layout")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert_eq!(store.workspace()?.id().into_uuid(), plan.workspace_id);
        assert_eq!(store.workspace()?.revision().get(), 2);
        drop(store);
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn relocate_rejects_busy_host_existing_target_and_changed_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, plan) = fixture()?;
    let fence = ServeFence::acquire(&plan.registry_path)?;
    assert!(relocate(&plan, None).is_err());
    drop(fence);
    fs::create_dir(&plan.destination)?;
    assert!(relocate(&plan, None).is_err());
    fs::remove_dir(&plan.destination)?;
    assert!(relocate(&plan, Some(Phase::Prepared)).is_err());
    let mut changed = plan.clone();
    changed.request_id = Uuid::now_v7();
    assert!(relocate(&changed, None).is_err());
    relocate(&plan, None)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn plans_are_bounded_private_and_reject_overlap() -> Result<(), Box<dyn std::error::Error>> {
    let (root, plan) = fixture()?;
    let file = root.join("plan.json");
    fs::write(&file, serde_json::to_vec(&plan)?)?;
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644))?;
    assert!(paths::read_private(&file).is_err());
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
    assert!(paths::read_private(&file).is_ok());
    let mut changed = plan;
    changed.destination = changed.source.join("inside");
    assert!(paths::validate_plan(&changed).is_err());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn stale_workspace_or_database_identity_never_renames() -> Result<(), Box<dyn std::error::Error>> {
    let (root, plan) = fixture()?;
    let mut stale = plan.clone();
    stale.expected_workspace_revision = 2;
    assert!(relocate(&stale, None).is_err());
    assert!(plan.source.exists());
    assert!(!plan.destination.exists());
    let mut foreign = plan.clone();
    foreign.database_inode += 1;
    assert!(relocate(&foreign, None).is_err());
    assert!(plan.source.exists());
    let mut scope = plan.clone();
    scope.location_id = Uuid::now_v7();
    assert!(relocate(&scope, None).is_err());
    assert!(plan.source.exists());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn nested_workspace_blocks_before_any_rename() -> Result<(), Box<dyn std::error::Error>> {
    let (root, plan) = fixture()?;
    fs::create_dir_all(plan.source.join("child/.heterarchy-forge"))?;
    assert!(relocate(&plan, None).is_err());
    assert!(plan.source.exists());
    assert!(!plan.destination.exists());
    fs::remove_dir_all(root)?;
    Ok(())
}
