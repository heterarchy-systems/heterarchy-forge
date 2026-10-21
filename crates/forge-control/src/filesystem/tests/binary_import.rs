use super::*;

#[test]
fn binary_import_preserves_bounds_and_source_authority() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("binary-bounds")?;
    let mut request = create_mutation_request(
        &fixture,
        0xB100,
        0xB101,
        "binary.rs",
        &vec![0xFF; forge_workspace::MAX_BINARY_IMPORT_BYTES + 1],
    )?;
    assert_eq!(
        fixture
            .control
            .file_import_binary(&request)
            .err()
            .map(|e| e.code()),
        Some(ControlErrorCode::FileCapacityExceeded)
    );
    request.content = Some(vec![0xFF; 3 * 1024 * 1024]);
    assert_eq!(
        fixture
            .control
            .file_mutate(&request)
            .err()
            .map(|e| e.code()),
        Some(ControlErrorCode::FileCapacityExceeded)
    );
    request.plan = FileMutationPlan::new(
        WorkspaceRelativePath::new(PathBuf::from("outside-lease.bin"))?,
        FileMutationKind::Create,
        forge_domain::FilePrecondition::Absent,
    );
    assert_eq!(
        fixture
            .control
            .file_import_binary(&request)
            .err()
            .map(|e| e.code()),
        Some(ControlErrorCode::WriterLeaseConflict)
    );
    assert!(!workspace_root(&fixture).join("binary.rs").exists());
    assert!(!workspace_root(&fixture).join("outside-lease.bin").exists());
    let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
        .ok_or("workspace layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    assert!(
        store
            .get_diff_for_change_set(request.change_set_id)?
            .is_none()
    );
    assert!(
        store
            .list_goal_evidence(request.write_authority.attribution().goal_id(), 10)?
            .is_empty()
    );
    drop(store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn binary_import_replays_and_restores_complete_checkpoint_after_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture_with_git("binary-restore")?;
    let original = vec![0xFF; forge_workspace::MAX_BINARY_IMPORT_BYTES];
    let create = create_mutation_request(&fixture, 0xB200, 0xB201, "binary.rs", &original)?;
    let applied = fixture.control.file_import_binary(&create)?;
    assert_eq!(applied.status(), FileMutationStatus::Applied);
    assert_eq!(
        applied.record().mutation().intended_content_hash(),
        Some(bounded_binary_content_hash(&original)?)
    );
    let target = workspace_root(&fixture).join("binary.rs");
    assert_eq!(fs::read(&target)?, original);
    let mode = fs::metadata(&target)?.permissions().mode();
    assert_eq!(
        fixture.control.file_import_binary(&create)?.status(),
        FileMutationStatus::AlreadyApplied
    );

    let mut expired_retry = create.clone();
    let expiry_layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
        .ok_or("layout missing")?;
    let expiry_store = WorkspaceStore::open_existing(&expiry_layout)?;
    expired_retry.activity.observed_at = expiry_store
        .get_writer_lease(create.write_authority.writer_lease_id())?
        .ok_or("lease missing")?
        .lease_until();
    drop(expiry_store);
    assert!(
        fixture.control.file_import_binary(&expired_retry).is_err(),
        "durable replay must not bypass current source authority"
    );
    assert_eq!(fs::read(&target)?, original);

    let replacement = vec![0; 3 * 1024 * 1024];
    let replace = FileMutationRequest {
        plan: FileMutationPlan::new(
            create.plan.path().clone(),
            FileMutationKind::Replace,
            forge_domain::FilePrecondition::Matches(bounded_binary_content_hash(&original)?),
        ),
        change_set_id: ChangeSetId::from_uuid(id(0xB202)),
        mutation_id: FileMutationId::from_uuid(id(0xB203)),
        content: Some(replacement.clone()),
        ..create
    };
    assert_eq!(
        fixture.control.file_import_binary(&replace)?.status(),
        FileMutationStatus::Applied
    );
    assert_eq!(fs::read(&target)?, replacement);
    let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
        .ok_or("workspace layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let diff = store
        .get_diff_for_change_set(replace.change_set_id)?
        .ok_or("Diff missing")?;
    assert!(matches!(
        diff.payload(),
        DiffPayloadProjection::SummaryOnly { .. }
    ));
    let checkpoint = checkpoint_for_change_set(&store, fixture.scope.workspace_id(), 0xB202)?;
    assert_eq!(checkpoint.state(), forge_domain::CheckpointState::Ready);
    drop(store);

    // New control/store instances must replay durable evidence and restore all
    // bytes, not the bounded review prefix. No live effect handles are reused.
    let reopened = ForgeControl::from_location_service(
        LocationService::new(GlobalRegistry::open(fixture.root.join("registry.sqlite3"))?),
        fixture.root.join("agent-sessions.sqlite3"),
    );
    assert_eq!(
        reopened.file_import_binary(&replace)?.status(),
        FileMutationStatus::AlreadyApplied
    );
    let restore = direct_restore_request(
        &fixture,
        checkpoint.id(),
        fixture.activity.runtime_instance_id,
        21,
    )?;
    let outcome = reopened.checkpoint_restore(&restore)?;
    assert_eq!(
        outcome.state,
        forge_domain::CheckpointRestoreState::Restored
    );
    assert_eq!(fs::read(&target)?, original);
    assert_eq!(fs::metadata(&target)?.permissions().mode(), mode);
    let store = WorkspaceStore::open_existing(&layout)?;
    let evidence = store
        .get_checkpoint_restore(outcome.restore_id)?
        .ok_or("restore journal missing")?;
    assert_direct_restore_provenance(&fixture, &evidence, checkpoint.id());
    drop(store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}

#[test]
fn binary_import_never_renders_payload_as_text() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture("binary-text")?;
    let request = create_mutation_request(
        &fixture,
        0xB300,
        0xB301,
        "binary.rs",
        b"printable binary metadata",
    )?;
    assert_eq!(
        fixture.control.file_import_binary(&request)?.status(),
        FileMutationStatus::Applied
    );
    let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
        .ok_or("layout missing")?;
    let store = WorkspaceStore::open_existing(&layout)?;
    let diff = store
        .get_diff_for_change_set(request.change_set_id)?
        .ok_or("Diff missing")?;
    assert!(matches!(
        diff.payload(),
        DiffPayloadProjection::SummaryOnly {
            render_kind: DiffRenderKind::Binary,
            ..
        }
    ));
    drop(store);
    fs::remove_dir_all(fixture.root)?;
    Ok(())
}
