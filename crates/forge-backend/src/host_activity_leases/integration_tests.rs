//! In-process Source integration for lease supervision. No network client or
//! external service participates in this test; the control workers own a
//! temporary local Registry and Workspace.

use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use forge_control::{ForgeControlClient, ResolvedWorkspaceScope, WorkspaceInventoryEntry};
use forge_domain::{
    ActivityId, LocationId, LocationRevision, RegisteredActivity, RuntimeInstanceId,
    TimestampMillis, WorkspaceId,
};
use forge_persistence::GlobalRegistry;
use rusqlite::{Connection, params};
use uuid::Uuid;

use super::*;
use crate::await_shutdown_worker;

mod scenario;

type WorkHistoryRow = (Vec<u8>, i64, String, i64, i64);

fn timestamp_now() -> Result<TimestampMillis, Box<dyn Error>> {
    let millis = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
    Ok(TimestampMillis::new(millis)?)
}

fn set_lease_until(
    database_path: &Path,
    activity_id: ActivityId,
    lease_until_ms: i64,
) -> Result<(), Box<dyn Error>> {
    let connection = Connection::open(database_path)?;
    let changed = connection.execute(
        "UPDATE activities SET lease_until_ms=?1 WHERE activity_id=?2",
        params![
            lease_until_ms,
            activity_id.into_uuid().as_bytes().as_slice()
        ],
    )?;
    if changed != 1 {
        return Err("the test Activity lease row was not updated exactly once".into());
    }
    Ok(())
}

fn receipt_count(database_path: &Path) -> Result<i64, Box<dyn Error>> {
    let connection = Connection::open(database_path)?;
    Ok(connection.query_row(
        "SELECT COUNT(*) FROM quiescent_activity_lease_resume_receipts",
        [],
        |row| row.get(0),
    )?)
}

fn work_history_rows(
    database_path: &Path,
    activity_id: ActivityId,
) -> Result<Vec<WorkHistoryRow>, Box<dyn Error>> {
    let connection = Connection::open(database_path)?;
    let mut statement = connection.prepare(
        "SELECT update_id, update_sequence, summary, evidence_count, observed_at_ms
         FROM agent_work_updates WHERE activity_id=?1
         ORDER BY update_sequence, update_id",
    )?;
    let rows = statement.query_map(
        params![activity_id.into_uuid().as_bytes().as_slice()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn activity_row_count(
    database_path: &Path,
    table: &'static str,
    activity_id: ActivityId,
) -> Result<i64, Box<dyn Error>> {
    let query = match table {
        "agent_assignments" => "SELECT COUNT(*) FROM agent_assignments WHERE activity_id=?1",
        "executions" => "SELECT COUNT(*) FROM executions WHERE activity_id=?1",
        _ => return Err("unsupported integration snapshot table".into()),
    };
    let connection = Connection::open(database_path)?;
    Ok(connection.query_row(
        query,
        params![activity_id.into_uuid().as_bytes().as_slice()],
        |row| row.get(0),
    )?)
}

fn observe_activity(
    leases: &forge_control::ActivityLeaseClient,
    scope: &ResolvedWorkspaceScope,
    activity_id: ActivityId,
) -> Result<RegisteredActivity, Box<dyn Error>> {
    leases
        .observe_activity_leases(scope.clone(), vec![activity_id])?
        .into_iter()
        .next()
        .ok_or_else(|| "the test Activity is missing".into())
}

async fn wait_for_owned_lease(
    leases: forge_control::ActivityLeaseClient,
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    owner: RuntimeInstanceId,
    previous_lease_revision: i64,
    timeout: Duration,
) -> Result<RegisteredActivity, Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let read_leases = leases.clone();
        let read_scope = scope.clone();
        let activity = tokio::task::spawn_blocking(move || {
            read_leases.observe_activity_leases(read_scope, vec![activity_id])
        })
        .await??
        .into_iter()
        .next()
        .ok_or("the test Activity is missing")?;
        if activity.lease_owner_id() == Some(owner)
            && activity.lease_revision().get() > previous_lease_revision
        {
            return Ok(activity);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("host supervisor did not acquire the expected Activity lease".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn stop_supervisor(supervisor: HostActivityLeaseSupervisor) -> Result<(), Box<dyn Error>> {
    let joined = await_shutdown_worker(
        supervisor.stop(),
        "test host Activity lease supervisor",
        Duration::from_secs(3),
    )
    .await?;
    joined?;
    Ok(())
}

fn find_scope(
    control: &ForgeControlClient,
    location_id: LocationId,
    workspace_id: WorkspaceId,
) -> Result<ResolvedWorkspaceScope, Box<dyn Error>> {
    let inventory =
        control.registered_workspace_inventory(location_id, LocationRevision::INITIAL)?;
    inventory
        .entries()
        .iter()
        .find_map(|entry| match entry {
            WorkspaceInventoryEntry::Registered {
                scope, workspace, ..
            } if workspace.id() == workspace_id => Some(scope.clone()),
            WorkspaceInventoryEntry::Unavailable { .. }
            | WorkspaceInventoryEntry::Registered { .. } => None,
        })
        .ok_or_else(|| "registered root Workspace scope is missing".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_quiescent_activity_resumes_renews_and_continues_after_boot_change()
-> Result<(), Box<dyn Error>> {
    scenario::run().await
}

#[cfg(unix)]
mod journal_guard_tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    fn registration(supervision: u128, activity: u128) -> HostActivityLeaseRegistration {
        HostActivityLeaseRegistration {
            supervision_id: Uuid::from_u128(supervision),
            scope: HostActivityLeaseScope {
                location_id: Uuid::from_u128(1),
                location_revision: 1,
                workspace_id: Uuid::from_u128(2),
                workspace_revision: 1,
            },
            activity_id: Uuid::from_u128(activity),
            goal_id: Uuid::from_u128(3),
            goal_created_at_ms: 4,
            initiating_session_id: Uuid::from_u128(5),
            principal: HostPrincipalConfig {
                kind: HostPrincipalKind::TrustedStdio,
                id: None,
            },
            coordinator: HostCoordinatorPin {
                agent_id: Uuid::from_u128(6),
                session_id: Uuid::from_u128(5),
                revision: 1,
            },
        }
    }

    fn config(
        root: &Path,
        supervision: u128,
        activity: u128,
    ) -> HostActivityLeaseSupervisionConfig {
        HostActivityLeaseSupervisionConfig {
            journal_root: root.to_path_buf(),
            lease_duration_ms: default_lease_duration_ms(),
            renew_interval_ms: default_renew_interval_ms(),
            registrations: vec![registration(supervision, activity)],
        }
    }

    fn journal_snapshot(path: &Path) -> Result<(Vec<u8>, u64, SystemTime), Box<dyn Error>> {
        let bytes = fs::read(path)?;
        let metadata = fs::metadata(path)?;
        Ok((bytes, metadata.ino(), metadata.modified()?))
    }

    fn renewal(supervision_id: Uuid, activity_id: Uuid) -> PendingOperation {
        let owner_id = Uuid::from_u128(42);
        let scope = SourceScopeSelector {
            location_id: Uuid::from_u128(40),
            location_revision: 1,
            workspace_id: Uuid::from_u128(41),
            workspace_revision: 1,
        };
        PendingOperation::Renewal(PendingRenewal {
            supervision_id,
            scope,
            activity_id,
            owner_id,
            expected_lease_revision: 1,
            duration_ms: default_lease_duration_ms(),
            observed_at_ms: 100,
            prestate: LeasePrestate {
                activity_state: HostActivityState::Open,
                activity_revision: 1,
                lease_owner_id: owner_id,
                lease_until_ms: 50_000,
                lease_revision: 1,
            },
        })
    }

    #[test]
    fn competing_startup_does_not_rewrite_the_active_owner_journal() -> Result<(), Box<dyn Error>> {
        let root = std::env::temp_dir().join(format!("forge-journal-fence-{}", Uuid::now_v7()));
        fs::create_dir_all(&root)?;
        let registry_path = root.join("registry.sqlite3");
        drop(GlobalRegistry::open(&registry_path)?);
        let journal_root = root.join("private-journal");
        fs::create_dir(&journal_root)?;
        fs::set_permissions(&journal_root, fs::Permissions::from_mode(0o700))?;
        let config = config(&journal_root, 100, 101);
        PreparedHostActivityLeaseSupervisor::validate_config(Some(&config), &registry_path)?;
        let first_journal_owner = JournalStore::open(&journal_root)?;
        let journal_path = journal_root.join("activity-lease-supervision.json");
        let before = journal_snapshot(&journal_path)?;
        let first_owner = forge_backend::ServeFence::acquire(&registry_path)?;

        let second_start = crate::acquire_registry_owner_and_prepare_activity_supervisor(
            &registry_path,
            Some(&config),
        );
        assert!(matches!(
            second_start,
            Err(crate::HostError::ServeFenceBusy)
        ));
        assert_eq!(journal_snapshot(&journal_path)?, before);
        drop(first_journal_owner);
        drop(first_owner);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn distinct_registry_owners_cannot_share_one_live_journal() -> Result<(), Box<dyn Error>> {
        let root = std::env::temp_dir().join(format!("forge-shared-journal-{}", Uuid::now_v7()));
        fs::create_dir_all(&root)?;
        let registry_one = root.join("registry-one.sqlite3");
        let registry_two = root.join("registry-two.sqlite3");
        drop(GlobalRegistry::open(&registry_one)?);
        drop(GlobalRegistry::open(&registry_two)?);
        let journal_root = root.join("private-journal");
        fs::create_dir(&journal_root)?;
        fs::set_permissions(&journal_root, fs::Permissions::from_mode(0o700))?;
        let config = config(&journal_root, 200, 201);
        let registry_one_owner = forge_backend::ServeFence::acquire(&registry_one)?;
        let registry_two_owner = forge_backend::ServeFence::acquire(&registry_two)?;

        let journal_owner =
            PreparedHostActivityLeaseSupervisor::prepare(Some(&config), &registry_one)?
                .ok_or("configured journal owner unexpectedly disabled")?;
        let journal_path = journal_root.join("activity-lease-supervision.json");
        let before = journal_snapshot(&journal_path)?;
        assert!(matches!(
            PreparedHostActivityLeaseSupervisor::prepare(Some(&config), &registry_two),
            Err(SupervisorError::Journal)
        ));
        assert_eq!(journal_snapshot(&journal_path)?, before);

        drop(journal_owner);
        let reopened = PreparedHostActivityLeaseSupervisor::prepare(Some(&config), &registry_two)?
            .ok_or("configured journal did not reopen after owner drop")?;
        assert_eq!(journal_snapshot(&journal_path)?, before);
        drop(reopened);
        drop(registry_two_owner);
        drop(registry_one_owner);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[tokio::test]
    async fn full_pending_journal_rejects_reconfigured_seventeenth_intent_without_rewrite()
    -> Result<(), Box<dyn Error>> {
        let root = std::env::temp_dir().join(format!("forge-journal-bound-{}", Uuid::now_v7()));
        fs::create_dir_all(&root)?;
        let registry_path = root.join("registry.sqlite3");
        drop(GlobalRegistry::open(&registry_path)?);
        let journal_root = root.join("private-journal");
        fs::create_dir(&journal_root)?;
        fs::set_permissions(&journal_root, fs::Permissions::from_mode(0o700))?;
        let mut journal = JournalStore::open(&journal_root)?;
        for index in 0..MAX_REGISTRATIONS {
            let id = Uuid::from_u128(1_000 + index as u128);
            journal
                .file
                .pending
                .insert(id, renewal(id, Uuid::from_u128(2_000 + index as u128)));
        }
        journal.persist()?;
        let journal_path = journal_root.join("activity-lease-supervision.json");
        let before = journal_snapshot(&journal_path)?;

        let new_intent_id = Uuid::from_u128(999);
        assert_eq!(
            journal
                .insert_pending(new_intent_id, renewal(new_intent_id, Uuid::from_u128(998)),)
                .await,
            Err(JournalError::PendingCapacity)
        );
        assert_eq!(journal.file.pending.len(), MAX_REGISTRATIONS);
        assert_eq!(journal_snapshot(&journal_path)?, before);
        drop(journal);

        let reconfigured = config(&journal_root, 999, 998);
        let rejected = crate::acquire_registry_owner_and_prepare_activity_supervisor(
            &registry_path,
            Some(&reconfigured),
        );
        assert!(matches!(
            rejected,
            Err(crate::HostError::ActivityLeaseSupervisorJournal)
        ));
        assert_eq!(journal_snapshot(&journal_path)?, before);

        let readable = JournalStore::open(&journal_root)?;
        assert_eq!(readable.file.pending.len(), MAX_REGISTRATIONS);
        assert_eq!(journal_snapshot(&journal_path)?, before);
        drop(readable);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
