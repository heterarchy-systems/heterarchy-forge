use super::lease_readback::{post_ok, scope_json};
use super::*;
use forge_control::{AgentOperationsDelegationReadRequest, EffectFactOutboxReadRequest};
use forge_persistence::EffectFact;
use serde_json::{Value, json};

fn delegation(fixture: &Fixture) -> Result<(uuid::Uuid, uuid::Uuid), Box<dyn std::error::Error>> {
    let delegation = fixture
        .client
        .agent_operations_delegation(AgentOperationsDelegationReadRequest {
            scope: fixture.scope.clone(),
        })?
        .ok_or("fixture Agent operations delegation is missing")?;
    Ok((delegation.migration_id(), delegation.destination_id()))
}

fn native_entries(
    fixture: &Fixture,
) -> Result<
    (
        uuid::Uuid,
        uuid::Uuid,
        Vec<forge_persistence::EffectFactOutboxEntry>,
    ),
    Box<dyn std::error::Error>,
> {
    let (migration_id, destination_id) = delegation(fixture)?;
    let entries = fixture
        .client
        .effect_fact_outbox(EffectFactOutboxReadRequest {
            scope: fixture.scope.clone(),
            migration_id,
            destination_id,
            after: 0,
            limit: 64,
        })?;
    Ok((migration_id, destination_id, entries))
}

async fn http_page(
    address: SocketAddr,
    fixture: &Fixture,
    migration_id: uuid::Uuid,
    destination_id: uuid::Uuid,
    after: u64,
    limit: u32,
) -> Result<Value, Box<dyn std::error::Error>> {
    post_ok(
        address,
        "effect_fact.outbox",
        json!({
            "scope": scope_json(fixture),
            "migration_id": migration_id,
            "destination_id": destination_id,
            "after": after,
            "limit": limit,
        }),
    )
    .await
}

pub(super) async fn assert_http_effect_fact_outbox(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let (migration_id, destination_id, native) = native_entries(fixture)?;
    if native.is_empty() {
        return Err("real fixture produced no delegated effect facts".into());
    }
    let source_path = fixture.workspace_root.join("tree-fixture/new.txt");
    let source_before = fs::read(&source_path)?;
    let full = http_page(address, fixture, migration_id, destination_id, 0, 64).await?;
    assert_page_header(&full, migration_id, destination_id, 0);
    let full_entries = full["entries"].as_array().ok_or("effect entries missing")?;
    assert_eq!(full_entries.len(), native.len());
    for (entry, wire) in native.iter().zip(full_entries) {
        assert_entry_projection(entry, wire);
    }
    let request = EffectFactOutboxReadRequest {
        scope: fixture.scope.clone(),
        migration_id,
        destination_id,
        after: 0,
        limit: 64,
    };
    assert_typed_client_projection(address, destination_id, &request, &full).await?;
    assert!(
        full_entries
            .iter()
            .any(|entry| entry["fact"]["kind"] == "execution_terminal")
    );
    assert!(
        full_entries
            .iter()
            .any(|entry| entry["fact"]["kind"] == "change_set_terminal")
    );

    assert_http_pagination(
        address,
        fixture,
        migration_id,
        destination_id,
        &native,
        &full,
    )
    .await?;
    assert_eq!(
        fs::read(&source_path)?,
        source_before,
        "paginated delegated reads must not mutate the source tree"
    );
    assert_rejects_wrong_scope_identity(address, fixture, migration_id, destination_id).await?;
    Ok(())
}

async fn assert_typed_client_projection(
    address: SocketAddr,
    destination_id: uuid::Uuid,
    request: &EffectFactOutboxReadRequest,
    full: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let typed_client = forge_backend::ForgeHttpClient::new(
        address,
        SECRET,
        forge_domain::ForgeBackendId::from_uuid(BACKEND_ID),
        destination_id,
        Duration::from_secs(5),
    )?;
    let typed_page = typed_client.effect_fact_outbox(request).await?;
    assert_eq!(serde_json::to_value(&typed_page)?, full.clone());

    let wrong_backend = forge_backend::ForgeHttpClient::new(
        address,
        SECRET,
        forge_domain::ForgeBackendId::from_uuid(Uuid::now_v7()),
        destination_id,
        Duration::from_secs(5),
    )?;
    assert!(matches!(
        wrong_backend.effect_fact_outbox(request).await,
        Err(forge_backend::ForgeHttpClientError::Protocol)
    ));

    let wrong_destination = forge_backend::ForgeHttpClient::new(
        address,
        SECRET,
        forge_domain::ForgeBackendId::from_uuid(BACKEND_ID),
        Uuid::now_v7(),
        Duration::from_secs(5),
    )?;
    assert!(matches!(
        wrong_destination.effect_fact_outbox(request).await,
        Err(forge_backend::ForgeHttpClientError::DestinationMismatch)
    ));
    Ok(())
}

async fn assert_http_pagination(
    address: SocketAddr,
    fixture: &Fixture,
    migration_id: uuid::Uuid,
    destination_id: uuid::Uuid,
    native: &[forge_persistence::EffectFactOutboxEntry],
    full: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let first = http_page(address, fixture, migration_id, destination_id, 0, 1).await?;
    assert_eq!(first["entries"].as_array().map(Vec::len), Some(1));
    assert_entry_projection(&native[0], &first["entries"][0]);
    let after_first = native[0].sequence();
    let remaining = http_page(
        address,
        fixture,
        migration_id,
        destination_id,
        after_first,
        64,
    )
    .await?;
    assert_page_header(&remaining, migration_id, destination_id, after_first);
    let remaining_entries = remaining["entries"]
        .as_array()
        .ok_or("remaining entries missing")?;
    assert_eq!(remaining_entries.len(), native.len().saturating_sub(1));
    for (entry, wire) in native.iter().skip(1).zip(remaining_entries) {
        assert_entry_projection(entry, wire);
    }

    let last_sequence = native
        .last()
        .ok_or("native effect facts disappeared")?
        .sequence();
    let empty = http_page(
        address,
        fixture,
        migration_id,
        destination_id,
        last_sequence,
        1,
    )
    .await?;
    assert_page_header(&empty, migration_id, destination_id, last_sequence);
    assert_eq!(empty["entries"], json!([]));

    let repeated = http_page(address, fixture, migration_id, destination_id, 0, 64).await?;
    assert_eq!(repeated, full.clone());
    Ok(())
}

fn assert_page_header(
    value: &Value,
    migration_id: uuid::Uuid,
    destination_id: uuid::Uuid,
    after: u64,
) {
    assert_eq!(value["backend_id"], BACKEND_ID.to_string());
    assert_eq!(value["migration_id"], migration_id.to_string());
    assert_eq!(value["destination_id"], destination_id.to_string());
    assert_eq!(value["after"], after);
}

async fn assert_rejects_wrong_scope_identity(
    address: SocketAddr,
    fixture: &Fixture,
    migration_id: uuid::Uuid,
    destination_id: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wrong_destination = json!({
        "scope": scope_json(fixture),
        "migration_id": migration_id,
        "destination_id": destination_id,
        "after": 0,
        "limit": 1,
    });
    wrong_destination["destination_id"] = json!(Uuid::now_v7());
    let (status, rejected) = post_command(address, "effect_fact.outbox", wrong_destination).await?;
    assert_ne!(status, 200);
    assert_eq!(rejected["ok"], false);
    assert_eq!(rejected["error"]["code"], "AUTH_FAILED");

    let mut wrong_migration = json!({
        "scope": scope_json(fixture),
        "migration_id": migration_id,
        "destination_id": destination_id,
        "after": 0,
        "limit": 1,
    });
    wrong_migration["migration_id"] = json!(Uuid::now_v7());
    let (status, rejected) = post_command(address, "effect_fact.outbox", wrong_migration).await?;
    assert_ne!(status, 200);
    assert_eq!(rejected["ok"], false);
    for limit in [0, 65] {
        let (status, rejected) = post_command(
            address,
            "effect_fact.outbox",
            json!({
                "scope": scope_json(fixture),
                "migration_id": migration_id,
                "destination_id": destination_id,
                "after": 0,
                "limit": limit,
            }),
        )
        .await?;
        assert_ne!(status, 200);
        assert_eq!(rejected["ok"], false);
    }
    Ok(())
}

fn assert_entry_projection(native: &forge_persistence::EffectFactOutboxEntry, wire: &Value) {
    assert_eq!(wire["sequence"], native.sequence());
    assert_eq!(wire["migration_id"], native.migration_id().to_string());
    assert_eq!(wire["destination_id"], native.destination_id().to_string());
    assert_eq!(
        wire["workspace_id"],
        native.workspace_id().into_uuid().to_string()
    );
    let source_refs = native.submitted_source_refs().map(|refs| {
        refs.iter()
            .map(|source_ref| {
                json!({
                    "ordinal": source_ref.ordinal(),
                    "evidence": evidence_json(source_ref.evidence()),
                })
            })
            .collect::<Vec<_>>()
    });
    assert_eq!(wire["submitted_source_refs"], json!(source_refs));
    match native.fact() {
        EffectFact::ExecutionTerminal(fact) => assert_execution_projection(fact, wire),
        EffectFact::ChangeSetTerminal(fact) => assert_change_set_projection(fact, wire),
        EffectFact::AssignmentReviewed(fact) => assert_review_projection(fact, wire),
        EffectFact::AssignmentOffered(fact) => assert_offer_projection(fact, wire),
        EffectFact::AssignmentSubmitted(fact) => assert_submission_projection(fact, wire),
    }
}

fn assert_execution_projection(
    fact: &forge_persistence::ExecutionTerminalEffectFact,
    wire: &Value,
) {
    assert_eq!(wire["fact"]["kind"], "execution_terminal");
    assert_eq!(
        wire["fact"]["execution_id"],
        fact.execution_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["activity_id"],
        fact.activity_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["execution_revision"],
        fact.execution_revision().get()
    );
    assert_eq!(wire["fact"]["state"], execution_state_name(fact.state()));
    assert_eq!(wire["fact"]["observed_at_ms"], fact.observed_at().get());
    assert_eq!(
        wire["fact"]["agent_id"],
        fact.agent_id().into_uuid().to_string()
    );
    assert_eq!(wire["fact"]["agent_revision"], fact.agent_revision().get());
    assert_eq!(
        wire["fact"]["session_id"],
        json!(
            fact.session_id()
                .map(forge_domain::AgentSessionId::into_uuid)
        )
    );
    assert_eq!(
        wire["fact"]["goal_id"],
        fact.goal_id().into_uuid().to_string()
    );
    assert_eq!(wire["fact"]["goal_revision"], fact.goal_revision().get());
    assert_eq!(wire["fact"]["dag_revision"], fact.dag_revision().get());
    assert_eq!(
        wire["fact"]["node_id"],
        fact.node_id().into_uuid().to_string()
    );
    assert_eq!(wire["fact"]["node_revision"], fact.node_revision().get());
    assert!(wire["fact"]["verification"].is_null());
}

fn assert_change_set_projection(
    fact: &forge_persistence::ChangeSetTerminalEffectFact,
    wire: &Value,
) {
    assert_eq!(wire["fact"]["kind"], "change_set_terminal");
    assert_eq!(
        wire["fact"]["change_set_id"],
        fact.change_set_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["workspace_id"],
        fact.workspace_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["workspace_revision"],
        fact.workspace_revision().get()
    );
    assert_eq!(
        wire["fact"]["activity_id"],
        fact.activity_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["runtime_instance_id"],
        fact.runtime_instance_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["activity_lease_revision"],
        fact.activity_lease_revision().get()
    );
    assert_eq!(
        wire["fact"]["change_set_revision"],
        fact.change_set_revision().get()
    );
    assert_eq!(wire["fact"]["state"], change_set_state_name(fact.state()));
    assert_eq!(
        wire["fact"]["failure_code"],
        json!(fact.failure_code().map(file_failure_name))
    );
    assert_eq!(
        wire["fact"]["diff_id"],
        fact.diff_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["diff_state"],
        diff_state_name(fact.diff_state())
    );
    assert_eq!(wire["fact"]["diff_revision"], fact.diff_revision().get());
    assert_eq!(wire["fact"]["observed_at_ms"], fact.observed_at().get());
    assert_eq!(
        wire["fact"]["producer_agent_id"],
        json!(
            fact.producer_agent_id()
                .map(forge_domain::AgentInstanceId::into_uuid)
        )
    );
    assert_eq!(
        wire["fact"]["producer_session_id"],
        json!(
            fact.producer_session_id()
                .map(forge_domain::AgentSessionId::into_uuid)
        )
    );
}

fn assert_review_projection(fact: &forge_persistence::AssignmentReviewedEffectFact, wire: &Value) {
    assert_eq!(wire["fact"]["kind"], "assignment_reviewed");
    assert_eq!(
        wire["fact"]["assignment_id"],
        fact.assignment_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["workspace_id"],
        fact.workspace_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["activity_id"],
        fact.activity_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["goal_id"],
        fact.goal_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["node_id"],
        fact.node_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["target_agent_id"],
        fact.target_agent_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["target_session_id"],
        json!(
            fact.target_session_id()
                .map(forge_domain::AgentSessionId::into_uuid)
        )
    );
    assert_eq!(
        wire["fact"]["outcome"],
        assignment_outcome_name(fact.outcome())
    );
    assert_eq!(
        wire["fact"]["credit_budget"],
        json!(fact.credit_budget().map(credit_budget_name))
    );
    assert_eq!(
        wire["fact"]["reviewer_agent_id"],
        fact.reviewer_agent_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["reviewer_session_id"],
        json!(
            fact.reviewer_session_id()
                .map(forge_domain::AgentSessionId::into_uuid)
        )
    );
    assert_eq!(
        wire["fact"]["result_digest"],
        json!(
            fact.result_digest()
                .map(|digest| forge_backend::events::hex_encode(&digest))
        )
    );
    assert_eq!(wire["fact"]["observed_at_ms"], fact.observed_at().get());
}

fn assert_offer_projection(fact: &forge_persistence::AssignmentOfferedEffectFact, wire: &Value) {
    assert_eq!(wire["fact"]["kind"], "assignment_offered");
    assert_eq!(
        wire["fact"]["assignment_id"],
        fact.assignment_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["workspace_id"],
        fact.workspace_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["activity_id"],
        fact.activity_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["goal_id"],
        fact.goal_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["node_id"],
        fact.node_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["target_agent_id"],
        fact.target_agent_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["target_session_id"],
        json!(
            fact.target_session_id()
                .map(forge_domain::AgentSessionId::into_uuid)
        )
    );
    assert_eq!(
        wire["fact"]["credit_budget"],
        json!(fact.credit_budget().map(credit_budget_name))
    );
    assert_eq!(wire["fact"]["offered_at_ms"], fact.offered_at().get());
}

fn assert_submission_projection(
    fact: &forge_persistence::AssignmentSubmittedEffectFact,
    wire: &Value,
) {
    assert_eq!(wire["fact"]["kind"], "assignment_submitted");
    assert_eq!(
        wire["fact"]["assignment_id"],
        fact.assignment_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["workspace_id"],
        fact.workspace_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["activity_id"],
        fact.activity_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["goal_id"],
        fact.goal_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["node_id"],
        fact.node_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["target_agent_id"],
        fact.target_agent_id().into_uuid().to_string()
    );
    assert_eq!(
        wire["fact"]["target_session_id"],
        json!(
            fact.target_session_id()
                .map(forge_domain::AgentSessionId::into_uuid)
        )
    );
    assert_eq!(wire["fact"]["source_count"], fact.source_count());
    assert_eq!(
        wire["fact"]["source_digests"],
        json!(
            fact.source_digests()
                .map(|digest| forge_backend::events::hex_encode(&digest))
        )
    );
    assert_eq!(
        wire["fact"]["source_kinds"],
        json!(fact.source_kinds().map(|values| {
            values
                .iter()
                .map(|value| source_kind_name(*value))
                .collect::<Vec<_>>()
        }))
    );
    assert_eq!(
        wire["fact"]["result_digest"],
        json!(
            fact.result_digest()
                .map(|digest| forge_backend::events::hex_encode(&digest))
        )
    );
    assert_eq!(wire["fact"]["submitted_at_ms"], fact.submitted_at().get());
}

fn execution_state_name(value: forge_domain::ExecutionState) -> &'static str {
    match value {
        forge_domain::ExecutionState::Starting => "starting",
        forge_domain::ExecutionState::Running => "running",
        forge_domain::ExecutionState::Completed => "completed",
        forge_domain::ExecutionState::Failed => "failed",
        forge_domain::ExecutionState::TimedOut => "timed_out",
        forge_domain::ExecutionState::Cancelled => "cancelled",
        forge_domain::ExecutionState::Interrupted => "interrupted",
    }
}

fn change_set_state_name(value: forge_domain::ChangeSetState) -> &'static str {
    match value {
        forge_domain::ChangeSetState::Starting => "starting",
        forge_domain::ChangeSetState::Applied => "applied",
        forge_domain::ChangeSetState::Failed => "failed",
    }
}

fn diff_state_name(value: forge_domain::DiffEvidenceState) -> &'static str {
    match value {
        forge_domain::DiffEvidenceState::Intent => "intent",
        forge_domain::DiffEvidenceState::Ready => "ready",
        forge_domain::DiffEvidenceState::SummaryOnly => "summary_only",
        forge_domain::DiffEvidenceState::Abandoned => "abandoned",
        forge_domain::DiffEvidenceState::PurgePending => "purge_pending",
        forge_domain::DiffEvidenceState::Tombstoned => "tombstoned",
    }
}

fn file_failure_name(value: forge_domain::FileMutationFailureCode) -> &'static str {
    match value {
        forge_domain::FileMutationFailureCode::InvalidPath => "invalid_path",
        forge_domain::FileMutationFailureCode::ProtectedPath => "protected_path",
        forge_domain::FileMutationFailureCode::PathConflict => "path_conflict",
        forge_domain::FileMutationFailureCode::StaleWrite => "stale_write",
        forge_domain::FileMutationFailureCode::CapacityExceeded => "capacity_exceeded",
        forge_domain::FileMutationFailureCode::IoFailure => "io_failure",
    }
}

fn assignment_outcome_name(value: forge_persistence::AssignmentReviewedOutcome) -> &'static str {
    match value {
        forge_persistence::AssignmentReviewedOutcome::Accepted => "accepted",
        forge_persistence::AssignmentReviewedOutcome::Rejected => "rejected",
    }
}

fn credit_budget_name(value: forge_domain::WorkCreditBudget) -> &'static str {
    match value {
        forge_domain::WorkCreditBudget::One => "one",
        forge_domain::WorkCreditBudget::Three => "three",
        forge_domain::WorkCreditBudget::Five => "five",
    }
}

fn source_kind_name(value: u8) -> &'static str {
    match value {
        0 => "url",
        1 => "provenance",
        _ => unreachable!("native source kinds are bounded to 0 or 1"),
    }
}

fn evidence_json(value: forge_domain::GoalEvidenceRef) -> Value {
    let (kind, id) = match value {
        forge_domain::GoalEvidenceRef::ChangeSet(id) => ("change_set", id.into_uuid()),
        forge_domain::GoalEvidenceRef::Execution(id) => ("execution", id.into_uuid()),
        forge_domain::GoalEvidenceRef::Approval(id) => ("approval", id.into_uuid()),
        forge_domain::GoalEvidenceRef::Checkpoint(id) => ("checkpoint", id.into_uuid()),
    };
    json!({"kind": kind, "id": id})
}
