use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use forge_domain::{
    EstablishWorkspace, LocationId, LocationRevision, RegisteredWorkspace, TimestampMillis,
    WorkspaceId, WorkspaceRoot,
};
use forge_persistence::{GlobalRegistry, WorkspaceStore};
use forge_workspace::{LocationService, WorkspaceStateLayout};
use rusqlite::Connection;
use uuid::Uuid;

use super::*;
use crate::ForgeControl;

struct Fixture {
    root: PathBuf,
    location_root: PathBuf,
    location_id: LocationId,
    control: ForgeControl,
}

impl Fixture {
    fn cleanup(self) -> Result<(), Box<dyn std::error::Error>> {
        fs::remove_dir_all(self.root)?;
        Ok(())
    }
}

fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    Ok(TimestampMillis::new(value)?)
}

fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-workspace-inventory-{label}-{}",
        Uuid::now_v7()
    ));
    let location_root = root.join("location");
    fs::create_dir_all(&location_root)?;
    let registry_path = root.join("registry.sqlite3");
    let location_id = LocationId::from_uuid(Uuid::now_v7());
    let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
    locations.register_selected_path(
        location_id,
        "Inventory Location",
        &location_root,
        timestamp(1)?,
    )?;
    drop(locations);
    Ok(Fixture {
        root,
        location_root,
        location_id,
        control: ForgeControl::new(GlobalRegistry::open(&registry_path)?),
    })
}

fn establish_workspace(
    fixture: &Fixture,
    relative_root: &str,
    workspace_id: WorkspaceId,
    location_id: LocationId,
) -> Result<RegisteredWorkspace, Box<dyn std::error::Error>> {
    let workspace_root = fixture.location_root.join(relative_root);
    fs::create_dir_all(&workspace_root)?;
    let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
    let root = WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?;
    let command = EstablishWorkspace::new(
        workspace_id,
        location_id,
        root,
        layout.root_fingerprint()?,
        timestamp(2)?,
    );
    let store = WorkspaceStore::open(&layout, &command)?;
    Ok(store.workspace()?)
}

#[test]
fn inventory_returns_registered_child_and_skips_uninitialized_sibling()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("registered-child")?;
    let child = fixture.location_root.join("a-registered");
    let sibling = fixture.location_root.join("b-uninitialized");
    fs::create_dir_all(&child)?;
    fs::create_dir_all(&sibling)?;
    // Give the uninitialized sibling a discovery signal without creating Forge
    // state; inventory must omit it rather than initialize it.
    fs::write(sibling.join("Cargo.toml"), b"[workspace]\n")?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x1001));
    establish_workspace(&fixture, "a-registered", workspace_id, fixture.location_id)?;

    let inventory = fixture
        .control
        .registered_workspace_inventory(fixture.location_id, LocationRevision::INITIAL)?;
    assert_eq!(inventory.location_id(), fixture.location_id);
    assert_eq!(inventory.location_revision(), LocationRevision::INITIAL);
    assert_eq!(inventory.entries().len(), 1);
    let WorkspaceInventoryEntry::Registered {
        scope,
        workspace,
        display_name,
    } = &inventory.entries()[0]
    else {
        return Err("registered child was not returned as Registered".into());
    };
    assert_eq!(scope.workspace_id(), workspace_id);
    assert_eq!(workspace.id(), workspace_id);
    assert_eq!(display_name, "a-registered");
    assert!(!sibling.join(".heterarchy-forge").exists());
    fixture.cleanup()
}

#[test]
fn inventory_resolves_v68_workspace_read_only_before_normal_open_migrates_to_v69()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("v68-before-supervised-host-open")?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x10_6801));
    let workspace_root = fixture.location_root.join("legacy-v68");
    establish_workspace(&fixture, "legacy-v68", workspace_id, fixture.location_id)?;
    let layout = WorkspaceStateLayout::inspect_existing(&workspace_root)?
        .ok_or("initialized Workspace layout missing")?;
    let database_path = layout.database_path().clone();
    let old = Connection::open(&database_path)?;
    old.pragma_update(None, "journal_mode", "DELETE")?;
    old.execute_batch("DROP TABLE quiescent_activity_lease_resume_receipts")?;
    old.pragma_update(None, "user_version", 68_i64)?;
    drop(old);

    let inventory = fixture
        .control
        .registered_workspace_inventory(fixture.location_id, LocationRevision::INITIAL)?;
    let scope = inventory
        .entries()
        .iter()
        .find_map(|entry| match entry {
            WorkspaceInventoryEntry::Registered {
                scope, workspace, ..
            } if workspace.id() == workspace_id => Some(scope.clone()),
            _ => None,
        })
        .ok_or("schema v68 Workspace was not listed as registered")?;
    let resolved = fixture.control.resolve_workspace(
        fixture.location_id,
        LocationRevision::INITIAL,
        scope.locator(),
    )?;
    assert_eq!(resolved, scope);

    let read_only = Connection::open(&database_path)?;
    let version_before_open: i64 =
        read_only.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let q_table_before_open: bool = read_only.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='quiescent_activity_lease_resume_receipts')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version_before_open, 68);
    assert!(
        !q_table_before_open,
        "inventory and resolve must remain read-only"
    );
    drop(read_only);

    let (opened_scope, migrated) = fixture.control.open_resolved_workspace(
        resolved.locator().location_id(),
        resolved.locator().expected_revision(),
        resolved.locator(),
    )?;
    assert_eq!(opened_scope, resolved);
    assert_eq!(migrated.health()?.schema_version(), 69);
    drop(migrated);

    let current = Connection::open(&database_path)?;
    let version_after_open: i64 =
        current.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let q_table_after_open: bool = current.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='quiescent_activity_lease_resume_receipts')",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version_after_open, 69);
    assert!(
        q_table_after_open,
        "normal open owns the v68 to v69 migration"
    );
    drop(current);
    fixture.cleanup()
}

#[test]
fn inventory_orders_location_root_before_direct_child() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("root-child")?;
    let root_workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x2001));
    let child_workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x2002));
    establish_workspace(&fixture, ".", root_workspace_id, fixture.location_id)?;
    establish_workspace(&fixture, "child", child_workspace_id, fixture.location_id)?;

    let inventory = fixture
        .control
        .registered_workspace_inventory(fixture.location_id, LocationRevision::INITIAL)?;
    assert_eq!(inventory.entries().len(), 2);
    let WorkspaceInventoryEntry::Registered {
        scope: root_scope,
        workspace: root_workspace,
        display_name: root_name,
    } = &inventory.entries()[0]
    else {
        return Err("Location root was not the first registered entry".into());
    };
    let WorkspaceInventoryEntry::Registered {
        scope: child_scope,
        workspace: child_workspace,
        display_name: child_name,
    } = &inventory.entries()[1]
    else {
        return Err("direct child was not the second registered entry".into());
    };
    assert_eq!(root_scope.locator().relative_root(), Path::new("."));
    assert_eq!(root_workspace.id(), root_workspace_id);
    assert_eq!(root_name, "Inventory Location");
    assert_eq!(child_scope.locator().relative_root(), Path::new("child"));
    assert_eq!(child_workspace.id(), child_workspace_id);
    assert_eq!(child_name, "child");
    fixture.cleanup()
}

#[test]
fn inventory_classifies_duplicate_workspace_ids_as_identity_conflicts()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("duplicate-id")?;
    let duplicate_id = WorkspaceId::from_uuid(Uuid::from_u128(0x2501));
    establish_workspace(&fixture, "a-first", duplicate_id, fixture.location_id)?;
    establish_workspace(&fixture, "b-second", duplicate_id, fixture.location_id)?;

    let inventory = fixture
        .control
        .registered_workspace_inventory(fixture.location_id, LocationRevision::INITIAL)?;
    assert_eq!(inventory.entries().len(), 2);
    for entry in inventory.entries() {
        assert!(matches!(
            entry,
            WorkspaceInventoryEntry::Unavailable {
                code: ControlErrorCode::WorkspaceIdentityConflict,
                known_workspace_id: Some(id),
                ..
            } if *id == duplicate_id
        ));
        assert!(entry.registered_scope().is_none());
    }
    fixture.cleanup()
}

#[test]
fn inventory_keeps_healthy_siblings_when_foreign_or_corrupt_children_fail()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("diagnostics")?;
    let healthy_id = WorkspaceId::from_uuid(Uuid::from_u128(0x3001));
    let foreign_id = WorkspaceId::from_uuid(Uuid::from_u128(0x3002));
    establish_workspace(&fixture, "a-healthy", healthy_id, fixture.location_id)?;
    establish_workspace(
        &fixture,
        "b-foreign",
        foreign_id,
        LocationId::from_uuid(Uuid::from_u128(0x30ff)),
    )?;
    let corrupt_root = fixture.location_root.join("c-corrupt");
    fs::create_dir_all(&corrupt_root)?;
    let corrupt_layout = WorkspaceStateLayout::initialize(&corrupt_root)?;
    fs::write(corrupt_layout.database_path(), b"not a sqlite database")?;

    let inventory = fixture
        .control
        .registered_workspace_inventory(fixture.location_id, LocationRevision::INITIAL)?;
    assert_eq!(inventory.entries().len(), 3);
    let Some(WorkspaceInventoryEntry::Registered { workspace, .. }) = inventory
        .entries()
        .iter()
        .find(|entry| entry.known_workspace_id() == Some(healthy_id))
    else {
        return Err("healthy sibling disappeared from inventory".into());
    };
    assert_eq!(workspace.id(), healthy_id);

    let foreign = inventory
        .entries()
        .iter()
        .find(|entry| entry.known_workspace_id() == Some(foreign_id))
        .ok_or("foreign diagnostic missing")?;
    assert!(matches!(
        foreign,
        WorkspaceInventoryEntry::Unavailable {
            code: ControlErrorCode::WorkspaceIdentityConflict,
            known_workspace_id: Some(id),
            ..
        } if *id == foreign_id
    ));

    let corrupt = inventory
        .entries()
        .iter()
        .find(|entry| entry.locator().relative_root() == Path::new("c-corrupt"))
        .ok_or("corrupt diagnostic missing")?;
    assert!(matches!(
        corrupt,
        WorkspaceInventoryEntry::Unavailable {
            code: ControlErrorCode::WorkspaceStateUnavailable
                | ControlErrorCode::PersistenceFailure,
            known_workspace_id: None,
            ..
        }
    ));
    fixture.cleanup()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    bytes: Option<Vec<u8>>,
    modified: Option<SystemTime>,
}

fn snapshot(path: &Path) -> Result<FileSnapshot, Box<dyn std::error::Error>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(FileSnapshot {
                bytes: None,
                modified: None,
            });
        }
        Err(error) => return Err(error.into()),
    };
    Ok(FileSnapshot {
        bytes: Some(fs::read(path)?),
        modified: metadata.modified().ok(),
    })
}

#[test]
fn inventory_is_read_only_for_workspace_database_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("read-only")?;
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x4001));
    establish_workspace(&fixture, "workspace", workspace_id, fixture.location_id)?;
    let workspace_root = fixture.location_root.join("workspace");
    let layout =
        WorkspaceStateLayout::inspect_existing(&workspace_root)?.ok_or("layout missing")?;
    let active_store = WorkspaceStore::open_existing(&layout)?;
    let state_database = workspace_root.join(".heterarchy-forge/state.sqlite3");
    let before = [
        snapshot(&state_database)?,
        snapshot(&workspace_root.join(".heterarchy-forge/state.sqlite3-wal"))?,
        snapshot(&workspace_root.join(".heterarchy-forge/state.sqlite3-shm"))?,
    ];
    let inventory = fixture
        .control
        .registered_workspace_inventory(fixture.location_id, LocationRevision::INITIAL)?;
    assert_eq!(inventory.entries().len(), 1);
    let after = [
        snapshot(&state_database)?,
        snapshot(&workspace_root.join(".heterarchy-forge/state.sqlite3-wal"))?,
        snapshot(&workspace_root.join(".heterarchy-forge/state.sqlite3-shm"))?,
    ];
    assert_eq!(before, after, "inventory changed Workspace SQLite bytes");
    drop(active_store);
    fixture.cleanup()
}
