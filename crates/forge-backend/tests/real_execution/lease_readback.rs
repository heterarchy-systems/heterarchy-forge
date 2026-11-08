use super::*;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use forge_domain::FileMutationId;
use serde_json::{Value, json};

pub(super) const MUTATION_PATH: &str = "lease-readback-created.txt";
const LEASE_PATHS: [&str; 5] = [
    MUTATION_PATH,
    "lease-readback-b.txt",
    "lease-readback-c.txt",
    "lease-readback-d.txt",
    "lease-readback-e.txt",
];
const SHORT_LEASE_DURATION_MS: i64 = 2_000;
const ACTIVE_WRITE_LEASE_DURATION_MS: i64 = forge_domain::MAX_WRITER_LEASE_DURATION_MILLIS;
const ACTIVE_WRITE_LEASE_ACQUIRE_DURATION_MS: i64 =
    ACTIVE_WRITE_LEASE_DURATION_MS - SHORT_LEASE_DURATION_MS;

pub(super) fn path_token(path: &str) -> String {
    URL_SAFE_NO_PAD.encode(path.as_bytes())
}

pub(super) fn scope_json(fixture: &Fixture) -> Value {
    let scope = &fixture.scope;
    json!({
        "workspace_id": scope.workspace_id().into_uuid(),
        "workspace_revision": scope.workspace_revision().get(),
        "locator": {
            "location_id": scope.locator().location_id().into_uuid(),
            "expected_revision": scope.locator().expected_revision().get(),
            "relative_root": scope.locator().relative_root().to_string_lossy(),
        }
    })
}

fn lease_actor(fixture: &Fixture) -> Value {
    json!({
        "session_id": fixture.session_id.into_uuid(),
        "principal": { "kind": "trusted_stdio" },
        "agent_id": fixture.agent_id.into_uuid(),
    })
}

fn ok_result<'a>(
    status: u16,
    response: &'a Value,
    operation: &str,
) -> Result<&'a Value, Box<dyn std::error::Error>> {
    if status != 200 {
        return Err(format!("{operation} failed ({status}): {response}").into());
    }
    if response["ok"] != true {
        return Err(format!("{operation} returned a failure: {response}").into());
    }
    Ok(&response["result"])
}

pub(super) async fn post_ok(
    address: SocketAddr,
    operation: &str,
    payload: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (status, response) = post_command(address, operation, payload).await?;
    Ok(ok_result(status, &response, operation)?.clone())
}

pub(super) async fn wait_until_expired(
    lease_until_ms: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if timestamp_now()?.get() >= lease_until_ms {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("short Writer Lease did not expire within its bound".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn acquire_and_read_lease(
    address: SocketAddr,
    fixture: &Fixture,
    duration_ms: i64,
) -> Result<(Uuid, i64), Box<dyn std::error::Error>> {
    let scope = scope_json(fixture);
    let actor = lease_actor(fixture);
    let lease_id = Uuid::now_v7();
    let scope_entries: Vec<Value> = LEASE_PATHS
        .iter()
        .map(|path| json!({ "kind": "exact_path", "path_base64": path_token(path) }))
        .collect();

    let acquired = post_ok(
        address,
        "writer_lease.acquire",
        json!({
            "scope": scope.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": actor.clone(),
            "writer_lease_id": lease_id,
            "duration_ms": duration_ms,
            "scopes": scope_entries,
        }),
    )
    .await?;
    assert_eq!(acquired["scope"], scope);
    assert_eq!(acquired["writer_lease_id"], lease_id.to_string());
    assert_eq!(acquired["total_scope_count"], 5);
    assert_eq!(acquired["scopes"].as_array().map(Vec::len), Some(4));
    assert_eq!(acquired["next_scope_offset"], 4);
    assert_eq!(
        acquired["owner_activity_id"],
        json!(fixture.activity_id.into_uuid())
    );
    assert_eq!(
        acquired["owner_session_id"],
        json!(fixture.session_id.into_uuid())
    );
    assert_eq!(acquired["status"], "active");
    assert!(acquired["blocking_reason"].is_null());
    assert_eq!(acquired["recovery_action"], "none");
    assert_eq!(acquired["scope_page_limit"], 4);
    assert!(acquired["observed_at_ms"].as_i64().is_some());
    let acquired_revision = acquired["revision"]
        .as_i64()
        .ok_or("acquire revision missing")?;

    let listed = post_ok(
        address,
        "writer_lease.list",
        json!({
            "scope": scope.clone(),
            "limit": 1,
        }),
    )
    .await?;
    assert_eq!(listed["leases"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["leases"][0]["scope"], scope);
    assert_eq!(listed["leases"][0]["writer_lease_id"], lease_id.to_string());
    assert_eq!(listed["leases"][0]["status"], "active");
    assert_eq!(listed["leases"][0]["scope_page_limit"], 4);

    let page = post_ok(
        address,
        "writer_lease.get",
        json!({
            "scope": scope.clone(),
            "writer_lease_id": lease_id,
            "expected_revision": acquired_revision,
        }),
    )
    .await?;
    assert_eq!(page["found"], true);
    assert_eq!(page["scope"], scope);
    assert_eq!(page["scopes"].as_array().map(Vec::len), Some(4));
    assert_eq!(page["next_scope_offset"], 4);

    let tail = post_ok(
        address,
        "writer_lease.get",
        json!({
            "scope": scope.clone(),
            "writer_lease_id": lease_id,
            "scope_offset": 4,
        }),
    )
    .await?;
    assert_eq!(tail["found"], true);
    assert_eq!(tail["scopes"].as_array().map(Vec::len), Some(1));
    assert!(tail["next_scope_offset"].is_null());

    Ok((lease_id, acquired_revision))
}

async fn renew_lease(
    address: SocketAddr,
    fixture: &Fixture,
    lease_id: Uuid,
    acquired_revision: i64,
    duration_ms: i64,
) -> Result<(i64, i64), Box<dyn std::error::Error>> {
    let scope = scope_json(fixture);
    let actor = lease_actor(fixture);
    let renewed = post_ok(
        address,
        "writer_lease.renew",
        json!({
            "scope": scope.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": actor.clone(),
            "writer_lease_id": lease_id,
            "expected_revision": acquired_revision,
            "duration_ms": duration_ms,
        }),
    )
    .await?;
    let renewed_revision = renewed["revision"]
        .as_i64()
        .ok_or("renew revision missing")?;
    assert_eq!(renewed_revision, acquired_revision + 1);
    let lease_until_ms = renewed["lease_until_ms"]
        .as_i64()
        .ok_or("renew lease_until_ms missing")?;

    let (status, stale) = post_command(
        address,
        "writer_lease.renew",
        json!({
            "scope": scope.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": actor.clone(),
            "writer_lease_id": lease_id,
            "expected_revision": acquired_revision,
            "duration_ms": duration_ms,
        }),
    )
    .await?;
    assert_ne!(status, 200, "stale lease revision was accepted: {stale}");
    assert_eq!(stale["ok"], false);

    Ok((renewed_revision, lease_until_ms))
}

async fn acquire_historical_readback_lease(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<(Uuid, i64, i64), Box<dyn std::error::Error>> {
    let scope = scope_json(fixture);
    let lease_id = Uuid::now_v7();
    let acquired = post_ok(
        address,
        "writer_lease.acquire",
        json!({
            "scope": scope.clone(),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": lease_actor(fixture),
            "writer_lease_id": lease_id,
            "duration_ms": SHORT_LEASE_DURATION_MS,
            "scopes": [{
                "kind": "exact_path",
                "path_base64": path_token(MUTATION_PATH),
            }],
        }),
    )
    .await?;
    assert_eq!(acquired["scope"], scope);
    assert_eq!(acquired["writer_lease_id"], lease_id.to_string());
    assert_eq!(acquired["status"], "active");
    assert_eq!(acquired["total_scope_count"], 1);
    let revision = acquired["revision"]
        .as_i64()
        .ok_or("historical readback lease revision missing")?;
    let lease_until_ms = acquired["lease_until_ms"]
        .as_i64()
        .ok_or("historical readback lease expiry missing")?;
    assert!(timestamp_now()?.get() < lease_until_ms);
    Ok((lease_id, revision, lease_until_ms))
}

pub(super) async fn assert_http_lease_and_mutation_readback(
    address: SocketAddr,
    fixture: &Fixture,
) -> Result<Uuid, Box<dyn std::error::Error>> {
    let (active_lease_id, acquired_revision) =
        acquire_and_read_lease(address, fixture, ACTIVE_WRITE_LEASE_ACQUIRE_DURATION_MS).await?;
    let (active_lease_revision, active_lease_until_ms) = renew_lease(
        address,
        fixture,
        active_lease_id,
        acquired_revision,
        ACTIVE_WRITE_LEASE_DURATION_MS,
    )
    .await?;
    assert!(timestamp_now()?.get() < active_lease_until_ms);
    let active_release = post_ok(
        address,
        "writer_lease.release",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": lease_actor(fixture),
            "writer_lease_id": active_lease_id,
            "expected_revision": active_lease_revision,
        }),
    )
    .await?;
    assert_eq!(active_release["state"], "released");
    assert_eq!(active_release["status"], "released");
    assert_eq!(active_release["revision"], active_lease_revision + 1);

    let (short_lease_id, short_lease_revision, short_lease_until_ms) =
        acquire_historical_readback_lease(address, fixture).await?;
    let change_set_id = forge_domain::ChangeSetId::from_uuid(Uuid::now_v7());
    let mutation_id = FileMutationId::from_uuid(Uuid::now_v7());
    seed_historical_diff(
        fixture,
        forge_domain::SourceWriteAuthority::new(
            fixture.agent_id,
            fixture.agent_revision,
            forge_domain::AuthenticatedPrincipal::TrustedStdio,
            fixture.attribution,
            forge_domain::WriterLeaseId::from_uuid(short_lease_id),
            forge_domain::WriterLeaseRevision::new(short_lease_revision)?,
            fixture.session_id,
        ),
        change_set_id,
        mutation_id,
    )?;
    let diffs = fixture.client.diff_list(forge_control::DiffListRequest {
        scope: fixture.scope.clone(),
        activity_id: fixture.activity_id,
        limit: forge_domain::DiffListLimit::new(16)?,
    })?;
    let diff_id = diffs
        .diffs()
        .iter()
        .find(|diff| diff.change_set_id() == change_set_id)
        .ok_or("mutation readback diff id missing")?
        .id()
        .into_uuid();
    wait_until_expired(short_lease_until_ms).await?;
    assert!(timestamp_now()?.get() >= short_lease_until_ms);
    let released = post_ok(
        address,
        "writer_lease.release",
        json!({
            "scope": scope_json(fixture),
            "activity_id": fixture.activity_id.into_uuid(),
            "actor": lease_actor(fixture),
            "writer_lease_id": short_lease_id,
            "expected_revision": short_lease_revision,
        }),
    )
    .await?;
    assert_eq!(released["state"], "released");
    assert_eq!(released["status"], "released");
    assert_eq!(released["revision"], short_lease_revision + 1);
    Ok(diff_id)
}

fn stage_historical_diff(
    fixture: &Fixture,
    diff_artifacts: &forge_workspace::DiffArtifactStore,
    relative_path: &forge_domain::WorkspaceRelativePath,
    change_set_id: forge_domain::ChangeSetId,
    mutation_id: FileMutationId,
    content: &[u8],
    observed_at: forge_domain::TimestampMillis,
) -> Result<
    (
        forge_domain::DiffId,
        forge_workspace::StagedDiffArtifact,
        forge_domain::BeginDiffEvidence,
    ),
    Box<dyn std::error::Error>,
> {
    let rendered = forge_workspace::render_diff_evidence(
        relative_path,
        forge_domain::DiffChangeKind::Created,
        &forge_workspace::CapturedDiffSource::Absent,
        &forge_workspace::CapturedDiffSource::Text(String::from_utf8(content.to_vec())?),
    )?;
    let forge_workspace::RenderedDiffEvidence::Text(rendered_text) = rendered else {
        return Err("expected text diff".into());
    };
    let diff_id = forge_domain::DiffId::for_change_set(change_set_id);
    let staged = diff_artifacts.stage(diff_id, &rendered_text)?;
    let file_entry = forge_domain::DiffEntrySummary::new(
        forge_domain::DiffEntrySubject::File,
        relative_path.clone(),
        None,
        forge_domain::DiffChangeKind::Created,
        rendered_text.additions(),
        rendered_text.deletions(),
    )?;
    let begin_diff = forge_domain::BeginDiffEvidence::new(
        forge_domain::DiffAttribution::for_file_mutation(
            diff_id,
            fixture.scope.workspace_id(),
            fixture.activity_id,
            change_set_id,
            mutation_id,
        ),
        vec![file_entry],
        forge_domain::DiffPayloadProjection::IntentText {
            pending_relative_path: staged.pending_relative_path()?,
            final_relative_path: staged.final_relative_path()?,
            compressed_hash: staged.compressed_hash(),
            uncompressed_hash: staged.uncompressed_hash(),
            compressed_size: staged.compressed_size(),
            uncompressed_size: staged.uncompressed_size(),
        },
        observed_at,
        forge_domain::DiffContractVersions::V1,
    )?;
    Ok((diff_id, staged, begin_diff))
}

fn seed_historical_diff(
    fixture: &Fixture,
    write_authority: forge_domain::SourceWriteAuthority,
    change_set_id: forge_domain::ChangeSetId,
    mutation_id: FileMutationId,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed_at = timestamp_now()?;
    let relative_path = forge_domain::WorkspaceRelativePath::new(MUTATION_PATH.into())?;
    let content = b"historical source outcome\r\n";
    let layout = forge_workspace::WorkspaceStateLayout::inspect_existing(&fixture.workspace_root)?
        .ok_or("workspace state layout missing")?;
    let mut store = forge_persistence::WorkspaceStore::open_existing(&layout)?;
    let activity_row = store
        .get_activity(fixture.activity_id)?
        .ok_or("activity missing")?;
    let filesystem = forge_workspace::ConfinedWorkspace::open(&layout)?;
    let diff_artifacts = filesystem.diff_artifact_store()?;
    let (diff_id, staged, begin_diff) = stage_historical_diff(
        fixture,
        &diff_artifacts,
        &relative_path,
        change_set_id,
        mutation_id,
        content,
        observed_at,
    )?;
    std::fs::write(fixture.workspace_root.join(MUTATION_PATH), content)?;
    let post_read = filesystem.read(&relative_path)?;
    let intended_hash = post_read.hash();
    let identity = forge_domain::FileMutationIdentity::new(change_set_id, mutation_id);
    let begin_cmd = forge_domain::BeginFileMutation::new(
        identity,
        forge_domain::FileMutationScope::new(
            fixture.scope.workspace_id(),
            fixture.scope.workspace_revision(),
            activity_row.id(),
            fixture.runtime_instance_id,
            activity_row.lease_revision(),
        ),
        forge_domain::FileMutationPlan::new(
            relative_path,
            forge_domain::FileMutationKind::Create,
            forge_domain::FilePrecondition::Absent,
        ),
        Some(intended_hash),
        forge_domain::FilePathState::Absent,
        observed_at,
    )?;
    let begin =
        store.begin_file_mutation_for_goal(&begin_cmd, &begin_diff, None, write_authority)?;
    let published = diff_artifacts.publish(staged)?;
    let expected = published.expectation();
    let complete_cmd = forge_domain::CompleteFileMutation::new(
        identity,
        begin.record().change_set().revision(),
        begin.record().mutation().revision(),
        post_read.state(),
        observed_at,
    );
    let diff_revision = begin.diff().map_or(
        forge_domain::DiffRevision::INITIAL,
        forge_domain::RegisteredDiffEvidence::revision,
    );
    let complete_diff = forge_domain::CompleteDiffEvidence::new(
        diff_id,
        diff_revision,
        forge_domain::DiffPayloadProjection::Ready {
            relative_path: published.relative_path()?,
            compressed_hash: expected.compressed_hash(),
            uncompressed_hash: expected.uncompressed_hash(),
            compressed_size: expected.compressed_size(),
            uncompressed_size: expected.uncompressed_size(),
        },
        observed_at,
    )?;
    let producer = forge_domain::ChangeSetProducer::new(
        write_authority.agent_id(),
        write_authority.session_id(),
    );
    let _record = store.complete_file_mutation(&complete_cmd, &complete_diff, producer)?;
    Ok(())
}
