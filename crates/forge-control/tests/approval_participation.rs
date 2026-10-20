use std::fs;
use std::path::PathBuf;

use forge_control::{
    ApprovalSubmissionStatus, AutoApprovalScopeCreateRequest, ControlErrorCode,
    ForgeApprovalCoordinator, ForgeControl, ForgeControlWorker, ForgeExecutionCoordinator,
    SemanticEventsPageRequest, SubmitExecutionForApproval, WorkspaceSemanticSnapshotRequest,
};
use forge_domain::{
    ActivityId, AutoApprovalScope, AutoApprovalScopeId, AutoApprovalScopeRevision,
    AutoApprovalScopeState, AutoApprovalUseLimit, EstablishWorkspace, ExecutionActionClass,
    ExecutionAttribution, ExecutionId, ExecutionKind, ExecutionLimits, ExecutionOutputLimit,
    ExecutionPermissions, ExecutionProgram, ExecutionRequest, ExecutionTimeoutMillis, LocationId,
    LocationRevision, PolicyRevision, RuntimeInstanceId, TimestampMillis, WorkspaceId,
    WorkspaceRevision, WorkspaceRoot,
};
use forge_persistence::{GlobalRegistry, WorkspaceStore};
use forge_workspace::{LocationService, WorkspaceStateLayout};
use uuid::Uuid;

struct TempRoot(PathBuf);

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    scope: forge_control::ResolvedWorkspaceScope,
    activity_id: ActivityId,
    runtime_instance_id: RuntimeInstanceId,
    control_client: forge_control::ForgeControlClient,
    control_worker: ForgeControlWorker,
    _root: TempRoot,
}

fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
    Ok(TimestampMillis::new(value)?)
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "heterarchy-forge-approval-participation-{}-{}",
        std::process::id(),
        Uuid::now_v7()
    ));
    fs::create_dir_all(&root)?;
    let location_root = root.join("location");
    let workspace_root = location_root.join("workspace");
    let registry_path = root.join("registry.sqlite3");
    fs::create_dir_all(&workspace_root)?;

    let location_id = LocationId::from_uuid(Uuid::from_u128(0xA101));
    let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0xA102));
    let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
    let location = locations.register_selected_path(
        location_id,
        "Approval participation fixture",
        &location_root,
        timestamp(1)?,
    )?;
    let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
    let establish = EstablishWorkspace::new(
        workspace_id,
        location.id(),
        WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
        layout.root_fingerprint()?,
        timestamp(2)?,
    );
    drop(WorkspaceStore::open(&layout, &establish)?);
    drop(locations);

    let control = ForgeControl::new(GlobalRegistry::open(&registry_path)?);
    let locator = control
        .workspace_discover(location_id, LocationRevision::INITIAL)?
        .into_iter()
        .find(|entry| entry.display_name() == "workspace")
        .ok_or("initialized Workspace was not discovered")?
        .locator()
        .clone();
    let scope = control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
    let (control_client, control_worker) = ForgeControlWorker::start(control)?;
    let activity_id = ActivityId::from_uuid(Uuid::from_u128(0xA103));
    let runtime_instance_id = RuntimeInstanceId::from_uuid(Uuid::from_u128(0xA104));
    let _activity = control_client
        .bootstrap_activity(
            scope.clone(),
            activity_id,
            runtime_instance_id,
            timestamp(3)?,
            timestamp(86_400_003)?,
        )
        .map_err(|error| format!("bootstrap_activity: {error:?}"))?;

    Ok(Fixture {
        _root: TempRoot(root),
        scope,
        activity_id,
        runtime_instance_id,
        control_client,
        control_worker,
    })
}

fn pending_execution_request(
    execution_id: ExecutionId,
    workspace_id: WorkspaceId,
    activity_id: ActivityId,
) -> Result<ExecutionRequest, Box<dyn std::error::Error>> {
    Ok(ExecutionRequest::new(
        ExecutionAttribution::new(execution_id, workspace_id, activity_id),
        ExecutionKind::Structured {
            program: ExecutionProgram::new(PathBuf::from("/usr/bin/true"))?,
            arguments: Vec::new(),
        },
        None,
        ExecutionLimits::new(
            ExecutionTimeoutMillis::new(30_000)?,
            ExecutionOutputLimit::DEFAULT,
        ),
        ExecutionPermissions::new(false, false, false),
    )?)
}

#[test]
fn stop_owned_is_scoped_to_the_coordinator_that_admitted_the_work()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let execution_id = ExecutionId::from_uuid(Uuid::from_u128(0xA105));
    let approval_id = forge_domain::ApprovalRequestId::from_uuid(Uuid::from_u128(0xA106));
    let auto_scope_id = AutoApprovalScopeId::from_uuid(Uuid::from_u128(0xA107));

    let mut execution_a = ForgeExecutionCoordinator::start(fixture.control_client.clone(), 1)?;
    let execution_client_a = execution_a.client();
    let mut approval_a =
        ForgeApprovalCoordinator::start(fixture.control_client.clone(), execution_client_a)?;
    let approval_client_a = approval_a.client();

    let mut execution_b = ForgeExecutionCoordinator::start(fixture.control_client.clone(), 1)?;
    let execution_client_b = execution_b.client();
    let mut approval_b =
        ForgeApprovalCoordinator::start(fixture.control_client.clone(), execution_client_b)?;
    let approval_client_b = approval_b.client();

    let auto_scope = approval_client_a
        .register_auto_scope(AutoApprovalScopeCreateRequest {
            scope: fixture.scope.clone(),
            auto_scope: AutoApprovalScope::active(
                auto_scope_id,
                fixture.scope.workspace_id(),
                None,
                ExecutionActionClass::DiscoveredProjectCommand,
                ExecutionPermissions::new(true, false, false),
                PolicyRevision::INITIAL,
                timestamp(3_600_004)?,
                AutoApprovalUseLimit::new(5)?,
                AutoApprovalScopeRevision::INITIAL,
            )?,
            created_at: timestamp(4)?,
        })
        .map_err(|error| format!("register_auto_scope: {error:?}"))?;
    assert_eq!(auto_scope.id(), auto_scope_id);

    let submitted = approval_client_a
        .submit_execution(
            SubmitExecutionForApproval::direct(
                fixture.scope.clone(),
                fixture.activity_id,
                fixture.runtime_instance_id,
                pending_execution_request(
                    execution_id,
                    fixture.scope.workspace_id(),
                    fixture.activity_id,
                )?,
            )
            .with_approval_id(approval_id),
        )
        .map_err(|error| format!("submit_execution: {error:?}"))?;
    assert_eq!(submitted.status(), ApprovalSubmissionStatus::Pending);
    assert_eq!(submitted.approval_id(), approval_id);

    let pending_before = approval_client_a.list_pending(fixture.scope.clone())?;
    assert_eq!(pending_before.len(), 1);
    assert_eq!(pending_before[0].approval_id(), approval_id);
    assert!(pending_before[0].actionable());
    let auto_scope_before = fixture
        .control_client
        .get_auto_approval_scope(fixture.scope.clone(), auto_scope_id)?
        .ok_or("registered auto scope disappeared")?;
    assert_eq!(auto_scope_before, auto_scope);
    assert_eq!(auto_scope_before.state(), AutoApprovalScopeState::Active);

    let observed_by_b = approval_client_b.list_pending(fixture.scope.clone())?;
    assert_eq!(observed_by_b.len(), 1);
    assert_eq!(observed_by_b[0].approval_id(), approval_id);
    assert!(!observed_by_b[0].actionable());

    let b_stop = approval_client_b.stop_owned()?;
    assert_eq!(b_stop.pending_cancelled(), 0);
    assert_eq!(b_stop.executions_cancelled(), 0);

    let pending_after_b = approval_client_a.list_pending(fixture.scope.clone())?;
    assert_eq!(pending_after_b, pending_before);
    let auto_scope_after_b = fixture
        .control_client
        .get_auto_approval_scope(fixture.scope.clone(), auto_scope_id)?
        .ok_or("B.stop_owned revoked A's auto scope")?;
    assert_eq!(auto_scope_after_b, auto_scope_before);
    assert_eq!(auto_scope_after_b.state(), AutoApprovalScopeState::Active);

    // stop_owned closes only this coordinator's owned state; B remains a
    // usable participant for later reads and responses.
    assert_eq!(
        approval_client_b.list_pending(fixture.scope.clone())?,
        observed_by_b
    );

    let a_stop = approval_client_a.stop_owned()?;
    assert_eq!(a_stop.pending_cancelled(), 1);
    assert_eq!(a_stop.executions_cancelled(), 0);
    assert!(
        approval_client_b
            .list_pending(fixture.scope.clone())?
            .is_empty()
    );
    let auto_scope_after_a = fixture
        .control_client
        .get_auto_approval_scope(fixture.scope.clone(), auto_scope_id)?
        .ok_or("A.stop_owned removed the auto scope row")?;
    assert_eq!(auto_scope_after_a.state(), AutoApprovalScopeState::Revoked);

    let _ = approval_a.shutdown()?;
    let _ = approval_b.shutdown()?;
    let _ = execution_a.shutdown()?;
    let _ = execution_b.shutdown()?;
    fixture.control_worker.shutdown()?;
    Ok(())
}

#[test]
fn semantic_projections_require_exact_requested_workspace_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = fixture()?;
    let correct_page = fixture
        .control_client
        .semantic_events_page(SemanticEventsPageRequest {
            scope: fixture.scope.clone(),
            after: 0,
            limit: 64,
        })?;
    assert_eq!(correct_page.scope(), &fixture.scope);
    let correct_snapshot =
        fixture
            .control_client
            .workspace_semantic_snapshot(WorkspaceSemanticSnapshotRequest {
                scope: fixture.scope.clone(),
            })?;
    assert_eq!(correct_snapshot.scope(), &fixture.scope);

    let wrong_workspace = forge_control::ResolvedWorkspaceScope::from_observation(
        WorkspaceId::from_uuid(Uuid::from_u128(0xB101)),
        fixture.scope.workspace_revision(),
        fixture.scope.locator().clone(),
    );
    let wrong_page = fixture
        .control_client
        .semantic_events_page(SemanticEventsPageRequest {
            scope: wrong_workspace.clone(),
            after: 0,
            limit: 64,
        });
    assert_eq!(
        wrong_page.err().map(|error| error.code()),
        Some(ControlErrorCode::WorkspaceRevisionConflict)
    );
    let wrong_snapshot =
        fixture
            .control_client
            .workspace_semantic_snapshot(WorkspaceSemanticSnapshotRequest {
                scope: wrong_workspace,
            });
    assert_eq!(
        wrong_snapshot.err().map(|error| error.code()),
        Some(ControlErrorCode::WorkspaceRevisionConflict)
    );

    let stale_scope = forge_control::ResolvedWorkspaceScope::from_observation(
        fixture.scope.workspace_id(),
        WorkspaceRevision::new(fixture.scope.workspace_revision().get() + 1)?,
        fixture.scope.locator().clone(),
    );
    let stale_page = fixture
        .control_client
        .semantic_events_page(SemanticEventsPageRequest {
            scope: stale_scope.clone(),
            after: 0,
            limit: 64,
        });
    assert_eq!(
        stale_page.err().map(|error| error.code()),
        Some(ControlErrorCode::WorkspaceRevisionConflict)
    );
    let stale_snapshot = fixture
        .control_client
        .workspace_semantic_snapshot(WorkspaceSemanticSnapshotRequest { scope: stale_scope });
    assert_eq!(
        stale_snapshot.err().map(|error| error.code()),
        Some(ControlErrorCode::WorkspaceRevisionConflict)
    );
    fixture.control_worker.shutdown()?;
    Ok(())
}
