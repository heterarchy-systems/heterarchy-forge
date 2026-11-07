//! Regression proof for list-only approval observer and disabled-fixture shutdown.

use super::*;

use forge_persistence::WorkspaceStore;
use forge_workspace::WorkspaceStateLayout;

#[test]
fn list_only_observer_cannot_acquire_cleanup_authority() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = prepare_fixture()?;
    let result = list_only_cleanup_flow(&fixture);
    let shutdown = shutdown_disabled_fixture(fixture);
    match (result, shutdown) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(flow), Err(shutdown)) => {
            Err(format!("list-only: {flow}; shutdown: {shutdown}").into())
        }
    }
}

fn list_only_cleanup_flow(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let layout = WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("list-only Workspace layout missing")?;
    let mut store = WorkspaceStore::open_existing(&layout)?;
    let now = timestamp_now()?;
    let policy = store.ensure_workspace_policy(now)?;
    let pending = forge_domain::RegisteredApprovalRequest::pending(
        forge_domain::ApprovalRequestId::from_uuid(Uuid::now_v7()),
        forge_domain::ExecutionAuthorizationRequest::new(
            ExecutionId::from_uuid(Uuid::now_v7()),
            fixture.scope.workspace_id(),
            fixture.activity_id,
            forge_domain::ExecutionRequestDigest::from_bytes([0xC1; 32]),
            forge_domain::ExecutionActionClass::DirectStructured,
            forge_domain::RequestedExecutionPermissions::new(
                forge_domain::ExecutionPermissions::new(false, false, false),
            ),
        ),
        policy.revision(),
        now,
        add_millis(now, 60_000)?,
    )?;
    let _inserted = store.insert_pending_approval(&pending)?;
    drop(store);
    let listed = fixture
        .approval
        .client()
        .list_pending(fixture.scope.clone())?;
    assert_eq!(listed.len(), 1);
    let stopped = fixture.approval.client().stop_owned()?;
    assert_eq!(stopped.pending_cancelled(), 0);
    assert_eq!(stopped.executions_cancelled(), 0);
    let store = WorkspaceStore::open_existing(&layout)?;
    let after = store
        .get_approval_request(pending.id())?
        .ok_or("list-only pending missing")?;
    assert_eq!(after, pending);
    Ok(())
}

pub(super) fn shutdown_disabled_fixture(
    fixture: Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    shutdown_disabled_fixture_owned(fixture)
}

fn shutdown_disabled_fixture_owned(fixture: Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let Fixture {
        root,
        mut worker,
        mut lease_worker,
        mut execution,
        mut approval,
        ..
    } = fixture;
    let approval_result = approval.shutdown();
    let execution_result = execution.shutdown();
    let worker_result = worker.shutdown();
    let lease_result = lease_worker.shutdown();
    let _approval_report = approval_result?;
    let _execution_report = execution_result?;
    worker_result?;
    lease_result?;
    fs::remove_dir_all(root)?;
    Ok(())
}
