//! Native closure schema migration must never invent historical process proof.

use super::*;
use forge_domain::{
    ExecutionAttribution, ExecutionFailureCode, ExecutionNativeClosureFact,
    ExecutionNativeClosureFactParts, ExecutionOutputCursor, FailExecution, NativeClosureLaunch,
    NativeClosureProcess, NativeClosureRuntime,
};

fn gap_event(
    id: forge_domain::ExecutionId,
    missing: u64,
) -> Result<forge_domain::ExecutionOutputEvent, Box<dyn std::error::Error>> {
    Ok(forge_domain::ExecutionOutputEvent::Gap(
        forge_domain::ExecutionOutputGap::new(
            id,
            forge_domain::ExecutionOutputSequence::new(missing + 1)?,
            forge_domain::ExecutionOutputGapParts::new(
                forge_domain::ExecutionOutputSequence::new(missing)?,
                forge_domain::ExecutionOutputSequence::new(missing)?,
                None,
                1,
                1,
                forge_domain::ExecutionOutputGapCause::Backpressure,
            ),
        )?,
    ))
}

#[test]
fn native_closure_terminal_transaction_rolls_back_bad_output_then_reopens_exact_fact()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, _layout, mut store, event) = journal_execution_fixture("native-closure-atomic")?;
    let before = store
        .get_execution(event.execution_id())?
        .ok_or("execution missing")?;
    store.append_execution_output_events(std::slice::from_ref(&event))?;
    let gap = gap_event(before.id(), 2)?;
    let after_gap =
        forge_domain::ExecutionOutputEvent::Chunk(forge_domain::ExecutionOutputChunk::new(
            before.id(),
            forge_domain::ExecutionOutputSequence::new(4)?,
            forge_domain::ExecutionOutputStream::Stdout,
            b"x",
        )?);
    let final_gap = gap_event(before.id(), 5)?;
    store.append_execution_output_events(&[gap, after_gap, final_gap.clone()])?;
    let command = FailExecution::new(
        before.id(),
        before.revision(),
        timestamp(10)?,
        ExecutionFailureCode::Supervision,
    );
    let parts = ExecutionNativeClosureFactParts {
        attribution: ExecutionAttribution::new(
            before.id(),
            before.workspace_id(),
            before.activity_id(),
        ),
        request_digest: before.request_digest(),
        before_revision: before.revision(),
        after_revision: before.revision().checked_next()?,
        output_cursor: ExecutionOutputCursor::initial(before.id()),
        launch: NativeClosureLaunch::Baseline,
        process: NativeClosureProcess::ProcessGroupReaped,
        runtime: NativeClosureRuntime::NotApplicable,
        observed_at: timestamp(10)?,
    };
    let invalid = ExecutionNativeClosureFact::from_parts(parts)?;
    assert!(
        store
            .fail_execution_with_native_closure(command, Some(invalid))
            .is_err()
    );
    assert_eq!(store.get_execution(before.id())?, Some(before.clone()));
    assert_eq!(
        store
            .execution_native_closure_snapshot(before.id())?
            .ok_or("snapshot missing")?
            .closure(),
        None
    );
    let fact = ExecutionNativeClosureFact::from_parts(ExecutionNativeClosureFactParts {
        output_cursor: ExecutionOutputCursor::from_sequence(before.id(), final_gap.sequence()),
        ..parts
    })?;
    let missing_manifest =
        ExecutionNativeClosureFact::from_parts(ExecutionNativeClosureFactParts {
            output_cursor: fact.output_cursor(),
            launch: NativeClosureLaunch::GeneratedPackage,
            runtime: NativeClosureRuntime::Cleaned,
            ..parts
        })?;
    assert!(matches!(
        store.fail_execution_with_native_closure(command, Some(missing_manifest)),
        Err(WorkspaceStoreError::Execution(
            crate::ExecutionStoreError::NativeClosureArtifactConflict
        ))
    ));
    assert_eq!(store.get_execution(before.id())?, Some(before.clone()));
    let terminal = store.fail_execution_with_native_closure(command, Some(fact))?;
    assert_eq!(terminal.revision(), fact.after_revision());
    drop(store);
    let reopened = WorkspaceStore::open_existing(
        &WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?,
    )?;
    let snapshot = reopened
        .execution_native_closure_snapshot(before.id())?
        .ok_or("reopen snapshot missing")?;
    assert_eq!(snapshot.record(), &terminal);
    assert_eq!(snapshot.closure(), Some(fact));
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_closure_v58_migration_is_empty_and_read_only_does_not_upgrade()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, layout, store, event) = journal_execution_fixture("native-closure-v58")?;
    let before = store
        .get_execution(event.execution_id())?
        .ok_or("execution missing")?;
    drop(store);
    let connection = Connection::open(layout.database_path())?;
    remove_stop_settlement_schema(&connection)?;
    connection.execute_batch("DROP TABLE execution_native_closures")?;
    connection.pragma_update(None, "user_version", 58)?;
    drop(connection);
    let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
    let paths = [
        layout.database_path(),
        super::super::sidecar_path(&layout.database_path(), "-wal"),
        super::super::sidecar_path(&layout.database_path(), "-shm"),
    ];
    let read_bytes = || -> Result<Vec<Option<Vec<u8>>>, std::io::Error> {
        paths
            .iter()
            .map(|path| match fs::read(path) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            })
            .collect()
    };
    let bytes_before = read_bytes()?;
    assert!(matches!(
        WorkspaceStore::inspect_existing_read_only(&existing),
        Err(WorkspaceStoreError::OutdatedSchema {
            actual: 58,
            current: CURRENT_SCHEMA_VERSION
        })
    ));
    assert_eq!(read_bytes()?, bytes_before);
    let connection = Connection::open(layout.database_path())?;
    assert_eq!(super::super::schema_version(&connection)?, 58);
    assert_eq!(
        connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'execution_native_closures'",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        0
    );
    drop(connection);
    let store = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(store.health()?.schema_version(), CURRENT_SCHEMA_VERSION);
    let snapshot = store
        .execution_native_closure_snapshot(event.execution_id())?
        .ok_or("snapshot missing")?;
    assert_eq!(snapshot.record(), &before);
    assert_eq!(snapshot.closure(), None);
    drop(store);
    let reopened = WorkspaceStore::open_existing(&existing)?;
    assert_eq!(
        reopened
            .execution_native_closure_snapshot(event.execution_id())?
            .ok_or("reopen snapshot missing")?
            .closure(),
        None
    );
    drop(reopened);
    fs::remove_dir_all(root)?;
    Ok(())
}
