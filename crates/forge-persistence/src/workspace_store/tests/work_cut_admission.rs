//! Storage-contract regressions; no process, browser, or provider E2E.

use super::*;
use crate::WriterLeaseStoreError;
use crate::workspace_work_cuts::guards;
use forge_domain::{
    ExecutionAgentProvenance, ExecutionCommandId, ExecutionId, OrchestrationIssuerId, WorkCutGrant,
    WorkCutNodeScope, WorkCutRequest, WorkCutScope, WorkCutSession, WorkCutSide,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct CutFixture {
    file: FileFactFixture,
    goal: GoalWorkAttribution,
    authority: SourceWriteAuthority,
}

impl CutFixture {
    fn new(label: &str) -> TestResult<Self> {
        let mut file = file_fact_fixture(label, 0xFA00)?;
        let workspace = file.store.workspace()?.id();
        let goal =
            insert_file_test_goal_seeded(&mut file.store, workspace, file.activity.id(), 0xFA20)?;
        let path = WorkspaceRelativePath::new(PathBuf::from("src/custody.rs"))?;
        let authority = seed_test_source_write_authority(
            &mut file.store,
            workspace,
            &file.activity,
            goal,
            &path,
            0xFA30,
        )?;
        Ok(Self {
            file,
            goal,
            authority,
        })
    }

    fn command(&self, seed: u128, at: i64, path: &str) -> TestResult<BeginFileMutation> {
        Ok(BeginFileMutation::new(
            FileMutationIdentity::new(
                ChangeSetId::from_uuid(Uuid::from_u128(seed)),
                FileMutationId::from_uuid(Uuid::from_u128(seed + 1)),
            ),
            FileMutationScope::new(
                self.file.store.workspace()?.id(),
                WorkspaceRevision::INITIAL,
                self.file.activity.id(),
                self.file.owner,
                self.file.activity.lease_revision(),
            ),
            FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from(path))?,
                FileMutationKind::Create,
                FilePrecondition::Absent,
            ),
            Some(FileContentHash::from_bytes([7; 32])),
            FilePathState::Absent,
            timestamp(at)?,
        )?)
    }

    fn node_scope(&self) -> TestResult<WorkCutNodeScope> {
        let node = self.authority.attribution();
        let goal = self
            .file
            .store
            .get_goal(node.goal_id())?
            .ok_or("Goal missing")?;
        Ok(WorkCutNodeScope::new(
            goal.activity_id(),
            goal.id(),
            goal.timestamps().created_at(),
            forge_domain::GoalRevision::INITIAL,
            node.dag_revision(),
            node.node_id(),
        )?)
    }

    fn prepare(
        &mut self,
        scope: WorkCutScope,
        other: Option<SourceWriteAuthority>,
    ) -> TestResult<WorkCutRequest> {
        let delegation = install_delegation_seal(&mut self.file.store, 0xFA40, 25)?;
        let agent = self
            .file
            .store
            .get_agent(self.authority.agent_id())?
            .ok_or("writer missing")?;
        let (session, binding) = inventory_endpoint(&agent, WorkCutSide::Incumbent)?;
        let mut sessions = vec![session];
        let mut bindings = vec![binding];
        if let Some(other) = other {
            let agent = self
                .file
                .store
                .get_agent(other.agent_id())?
                .ok_or("other writer missing")?;
            let (session, binding) = inventory_endpoint(&agent, WorkCutSide::Elected)?;
            sessions.push(session);
            bindings.push(binding);
        } else {
            sessions.push(WorkCutSession::new(
                WorkCutSide::Elected,
                AgentSessionId::from_uuid(Uuid::from_u128(0xFA50)),
            )?);
        }
        let request = work_cut_request_for_inventory(
            &self.file.store,
            delegation.destination_id(),
            0xFA60,
            sessions,
            bindings,
            scope,
        )?;
        let issuer = OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xFA70));
        let grant = WorkCutGrant::new(
            issuer,
            request.request_digest(),
            timestamp(30)?,
            timestamp(90)?,
        )?;
        assert!(matches!(
            self.file.store.prepare_leadership_work_cut(
                &request,
                grant,
                issuer,
                request.backend_id(),
                timestamp(40)?,
            )?,
            crate::WorkCutPrepareOutcome::Prepared(_)
        ));
        Ok(request)
    }

    fn cleanup(self) -> TestResult {
        drop(self.file.store);
        fs::remove_dir_all(self.file.root)?;
        Ok(())
    }
}

#[test]
fn held_work_cut_blocks_new_source_intent_but_preserves_exact_recovery() -> TestResult {
    let mut fixture = CutFixture::new("cut-source-admission")?;
    let original = fixture.command(0xFA80, 24, "src/custody.rs")?;
    let original_diff = summary_diff_intent(&original)?;
    let admitted = fixture.file.store.begin_file_mutation_for_goal(
        &original,
        &original_diff,
        Some(fixture.goal),
        fixture.authority,
    )?;
    assert_eq!(admitted.status(), BeginFileMutationStatus::Started);
    let request = fixture.prepare(WorkCutScope::Workspace, None)?;
    let before = fixture
        .file
        .store
        .get_leadership_work_cut(request.cut_id())?
        .ok_or("cut missing")?;
    assert!(
        before
            .effects()
            .iter()
            .any(|effect| effect.id() == original.change_set_id().into_uuid())
    );
    let retry = fixture.file.store.begin_file_mutation_for_goal(
        &original,
        &original_diff,
        Some(fixture.goal),
        fixture.authority,
    )?;
    assert_eq!(retry.status(), BeginFileMutationStatus::RecoveryRequired);
    let fresh = fixture.command(0xFA90, 50, "src/custody.rs")?;
    let result = fixture.file.store.begin_file_mutation_for_goal(
        &fresh,
        &summary_diff_intent(&fresh)?,
        Some(fixture.goal),
        fixture.authority,
    );
    assert!(
        matches!(result, Err(WorkspaceStoreError::WorkCut(_))),
        "fresh source intent crossed custody: {result:?}"
    );
    assert!(
        fixture
            .file
            .store
            .get_file_mutation(fresh.change_set_id())?
            .is_none()
    );
    assert_effect_drain_keeps_unsettled_changeset(&mut fixture, &request, &original)?;
    assert_eq!(
        fixture
            .file
            .store
            .get_leadership_work_cut(request.cut_id())?,
        Some(before)
    );
    fixture.cleanup()
}

fn assert_effect_drain_keeps_unsettled_changeset(
    fixture: &mut CutFixture,
    request: &WorkCutRequest,
    original: &BeginFileMutation,
) -> TestResult {
    let initial = fixture.file.store.observe_leadership_work_cut_drain(
        request.cut_id(),
        1,
        timestamp(55)?,
    )?;
    assert!(!initial.effects_drained());
    assert_eq!(initial.effects().len(), 2);
    let _released = fixture.file.store.release_writer_lease(
        request.workspace_id(),
        fixture.file.activity.id(),
        forge_domain::ReleaseWriterLease::new(
            fixture.authority.writer_lease_id(),
            fixture.authority.agent_id(),
            fixture.authority.expected_writer_lease_revision(),
            timestamp(60)?,
            fixture.authority.session_id(),
            fixture.authority.principal(),
        ),
    )?;
    let lease_only = fixture.file.store.observe_leadership_work_cut_drain(
        request.cut_id(),
        1,
        timestamp(65)?,
    )?;
    assert!(!lease_only.effects_drained());
    assert_eq!(
        lease_only
            .effects()
            .iter()
            .filter(|effect| effect.settlement() == crate::WorkCutEffectSettlement::Pending)
            .count(),
        1
    );
    let (complete, diff) = summary_completion(
        FileMutationIdentity::new(original.change_set_id(), original.mutation_id()),
        FileContentHash::from_bytes([7; 32]),
        70,
    )?;
    let _completed = fixture.file.store.complete_file_mutation(
        &complete,
        &diff,
        ChangeSetProducer::new(fixture.authority.agent_id(), fixture.authority.session_id()),
    )?;
    let finished = fixture.file.store.observe_leadership_work_cut_drain(
        request.cut_id(),
        1,
        timestamp(75)?,
    )?;
    assert!(finished.effects_drained());
    assert_eq!(finished.snapshot_digest(), initial.snapshot_digest());
    assert!(
        fixture
            .file
            .store
            .observe_leadership_work_cut_drain(request.cut_id(), 2, timestamp(75)?,)
            .is_err()
    );
    Ok(())
}

fn execution_provenance(
    authority: SourceWriteAuthority,
    seed: u128,
) -> TestResult<ExecutionAgentProvenance> {
    Ok(ExecutionAgentProvenance::new(
        ExecutionId::from_uuid(Uuid::from_u128(seed)),
        authority.agent_id(),
        authority.expected_agent_revision(),
        authority.principal(),
        authority.attribution(),
        ExecutionCommandId::new("fixture-check".to_owned())?,
        authority.session_id(),
    ))
}

#[test]
fn team_work_cut_keeps_known_unrelated_work_open_in_the_same_activity() -> TestResult {
    let mut fixture = CutFixture::new("cut-team-scope")?;
    let workspace = fixture.file.store.workspace()?.id();
    let other_goal = insert_file_test_goal_seeded(
        &mut fixture.file.store,
        workspace,
        fixture.file.activity.id(),
        0xFB00,
    )?;
    let other = seed_test_source_write_authority(
        &mut fixture.file.store,
        workspace,
        &fixture.file.activity,
        other_goal,
        &WorkspaceRelativePath::new(PathBuf::from("src/unrelated.rs"))?,
        0xFB10,
    )?;
    let unrelated_change = fixture.command(0xFB40, 24, "src/unrelated.rs")?;
    let _unrelated = fixture.file.store.begin_file_mutation_for_goal(
        &unrelated_change,
        &summary_diff_intent(&unrelated_change)?,
        Some(other_goal),
        other,
    )?;
    let request = fixture.prepare(
        WorkCutScope::Team {
            team_id: Uuid::from_u128(0xFB20),
            nodes: vec![fixture.node_scope()?],
        },
        Some(other),
    )?;
    let cut = fixture
        .file
        .store
        .get_leadership_work_cut(request.cut_id())?
        .ok_or("cut missing")?;
    assert!(!cut.effects().iter().any(|effect| effect.id()
        == unrelated_change.change_set_id().into_uuid()
        || effect.id() == other.writer_lease_id().into_uuid()));
    let selected = fresh_team_lease(&fixture, fixture.authority, 0xFB50)?;
    let unrelated_lease = fresh_team_lease(&fixture, other, 0xFB51)?;
    assert!(matches!(
        fixture.file.store.acquire_writer_lease(&selected),
        Err(WorkspaceStoreError::WriterLease(
            WriterLeaseStoreError::WorkCut(error)
        )) if matches!(*error, crate::WorkCutError::Conflict(_))
    ));
    assert!(
        fixture
            .file
            .store
            .get_writer_lease(selected.lease_id())?
            .is_none()
    );
    assert_eq!(
        fixture
            .file
            .store
            .acquire_writer_lease(&unrelated_lease)?
            .id(),
        unrelated_lease.lease_id()
    );
    let unrelated = execution_provenance(other, 0xFB30)?;
    guards::ensure_execution_open(
        &fixture.file.store.connection,
        workspace,
        fixture.file.activity.id(),
        Some(&unrelated),
    )?;
    let captured = execution_provenance(fixture.authority, 0xFB31)?;
    assert!(
        guards::ensure_execution_open(
            &fixture.file.store.connection,
            workspace,
            fixture.file.activity.id(),
            Some(&captured),
        )
        .is_err()
    );
    assert!(
        guards::ensure_execution_open(
            &fixture.file.store.connection,
            workspace,
            fixture.file.activity.id(),
            None,
        )
        .is_err()
    );
    fixture.cleanup()
}

fn fresh_team_lease(
    fixture: &CutFixture,
    authority: SourceWriteAuthority,
    id: u128,
) -> TestResult<forge_domain::AcquireWriterLease> {
    Ok(forge_domain::AcquireWriterLease::new(
        forge_domain::WriterLeaseId::from_uuid(Uuid::from_u128(id)),
        fixture.file.store.workspace()?.id(),
        fixture.file.activity.id(),
        authority.agent_id(),
        forge_domain::WriterLeaseScope::new(vec![forge_domain::WriterLeaseScopeEntry::new(
            forge_domain::WriterLeaseScopeKind::ExactPath,
            WorkspaceRelativePath::new(PathBuf::from("src/new-lease.rs"))?,
        )])?,
        forge_domain::WriterLeaseDurationMillis::new(60_000)?,
        timestamp(50)?,
        authority.session_id(),
        authority.principal(),
    )?)
}
