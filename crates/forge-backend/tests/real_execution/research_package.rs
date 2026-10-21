//! Ignored cross-process `PackageV1` acceptance proof.
//!
//! This fixture starts the actual `forge-backend` binary, submits the fixed
//! `PackageV` command over HTTP, approves the local Forge grant, and begins one
//! isolated execution with a bounded Orchestration admission envelope.  It is
//! a source-process proof for a disposable fixture, never the user's live
//! research cycle.

use super::*;

use forge_control::{
    AgentExecutionAuthorityRequest, AgentOperationsDelegationReadRequest,
    EffectFactOutboxReadRequest, FileActivityScope, ProjectCommandId, ProjectCommandListRequest,
};
use forge_domain::{
    ExecutionCommandId, ExecutionId, ExecutionListLimit, ExecutionObservationSelection,
    ExecutionOutputCursor, ExecutionOutputEvent, GoalAttribution, ProjectCommandClass,
    VerificationOutputIntegrity, VerificationRunDisposition,
};
use forge_persistence::EffectFact;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

const PACKAGE_COMMAND_ID: &str = "forge:research-package-v1";
const PACKAGE_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const PACKAGE_POLL_INTERVAL: Duration = Duration::from_millis(100);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an actual standalone forge-backend process and FORGE_ORCHESTRATION_BACKEND_BIN"]
async fn real_http_research_package_v1_reaches_accepted_native_terminal()
-> Result<(), Box<dyn std::error::Error>> {
    run_research_package_fixture().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an actual standalone forge-backend process and FORGE_ORCHESTRATION_BACKEND_BIN"]
async fn real_http_research_package_v1_uses_revised_goal_and_current_agent_focus()
-> Result<(), Box<dyn std::error::Error>> {
    run_research_package_fixture_variant(true).await
}

async fn run_research_package_fixture() -> Result<(), Box<dyn std::error::Error>> {
    run_research_package_fixture_variant(false).await
}

async fn run_research_package_fixture_variant(
    revise_goal: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let forge_binary = env::var_os("FORGE_PACKAGE_V_BACKEND_BIN").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_BIN_EXE_forge-backend")),
        std::path::PathBuf::from,
    );
    let orchestration_binary = required_binary("FORGE_ORCHESTRATION_BACKEND_BIN")?;
    let mut fixture = prepare_fixture()?;
    let fixture_root = fixture.root.clone();
    let retain_failure = env::var_os("FORGE_PACKAGE_V_KEEP_FAILURE").is_some();
    if retain_failure {
        eprintln!("PackageV temp_dir={}", std::env::temp_dir().display());
    }
    let result = run_package_flow(
        &mut fixture,
        &forge_binary,
        &orchestration_binary,
        revise_goal,
    )
    .await;
    if retain_failure && result.is_err() {
        if let Err(error) = diagnose_published_inputs(&fixture) {
            eprintln!("PackageV published-input diagnosis failed: {error}");
        }
        let diagnostic_root = std::env::temp_dir().join(format!(
            "forge-package-v-diagnostic-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        if let Err(error) = copy_failure_diagnostics(&fixture_root, &diagnostic_root) {
            eprintln!("PackageV diagnostic copy failed: {error}");
        } else {
            eprintln!(
                "PackageV failure fixture_root={} diagnostic_root={}",
                fixture_root.display(),
                diagnostic_root.display()
            );
        }
    }
    let snapshot_cleanup = restore_fixture_verification_directories(
        &fixture
            .workspace_root
            .join(".heterarchy-forge/artifacts/verification"),
        0,
    );
    let fixture_shutdown = fixture.shutdown();
    result?;
    snapshot_cleanup?;
    fixture_shutdown.map_err(|error| format!("PackageV fixture shutdown failed: {error}"))?;
    Ok(())
}

fn diagnose_published_inputs(fixture: &Fixture) -> Result<(), Box<dyn std::error::Error>> {
    let fixture_root = &fixture.root;
    let workspace_root = fixture_root.join("location/workspace");
    let layout = forge_workspace::WorkspaceStateLayout::inspect_existing(&workspace_root)?
        .ok_or("PackageV diagnostic Workspace layout missing")?;
    let confined = forge_workspace::ConfinedWorkspace::open(&layout)?;
    let verification_root = layout.state_root().join("artifacts/verification");
    for entry in fs::read_dir(&verification_root)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(name) else {
            continue;
        };
        let manifest = fs::read_to_string(entry.path().join("manifest"))?;
        let fingerprint = manifest
            .lines()
            .find_map(|line| line.strip_prefix("fingerprint\t"))
            .ok_or("PackageV diagnostic manifest fingerprint missing")?
            .parse::<forge_domain::VerificationInputFingerprint>()?;
        let input = confined.open_verification_input(
            forge_domain::VerificationInputId::from_uuid(id),
            fingerprint,
        )?;
        input.validate()?;
        let result = forge_execution::validate_published_input(&input)?;
        let result_json: Value = serde_json::from_slice(&result.to_json_bytes()?)?;
        eprintln!(
            "PackageV published input id={} source={} valid={} files={} claims={} citations={}",
            id,
            input.source_root().display(),
            result.valid(),
            result_json["checkedFiles"],
            result_json["checkedClaims"],
            result_json["checkedCitations"],
        );
        let command_id = ProjectCommandId::new(PACKAGE_COMMAND_ID.to_owned())?;
        let snapshot = fixture
            .client
            .project_command_list(ProjectCommandListRequest {
                scope: fixture.scope.clone(),
                activity: FileActivityScope {
                    activity_id: fixture.activity_id,
                    runtime_instance_id: fixture.runtime_instance_id,
                    observed_at: timestamp_now()?,
                },
            })?;
        let resolved = fixture.client.project_command_execution_request_fenced(
            ProjectCommandListRequest {
                scope: fixture.scope.clone(),
                activity: FileActivityScope {
                    activity_id: fixture.activity_id,
                    runtime_instance_id: fixture.runtime_instance_id,
                    observed_at: timestamp_now()?,
                },
            },
            command_id,
            snapshot.fingerprint(),
            forge_domain::ExecutionId::from_uuid(id),
        )?;
        let runner = forge_execution::ExecutionRunner::new(1)?;
        match runner.spawn_package_verification(&layout, resolved.request().clone(), input) {
            Ok(running) => {
                eprintln!("PackageV diagnostic runner accepted native spawn; cancelling probe");
                let _ignored = running.cancel();
                let _ignored = running.wait();
            }
            Err(error) => eprintln!("PackageV diagnostic runner error: {error:?}"),
        }
    }
    let capability = forge_execution::PackageVExecutableCapability::prepare_current()?;
    capability.revalidate()?;
    eprintln!("PackageV executable capability revalidated before diagnostic readback");
    Ok(())
}

fn copy_failure_diagnostics(
    fixture_root: &Path,
    diagnostic_root: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(diagnostic_root)?;
    for entry in fs::read_dir(fixture_root)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !(name.starts_with("research-package-")
            && (name.ends_with(".stdout")
                || name.ends_with(".stderr")
                || path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))))
        {
            continue;
        }
        fs::copy(&path, diagnostic_root.join(name))?;
    }
    Ok(())
}

async fn run_package_flow(
    fixture: &mut Fixture,
    forge_binary: &Path,
    orchestration_binary: &Path,
    revise_goal: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let package = write_package_fixture(fixture)?;
    let runtime = start_package_backend(fixture, forge_binary, orchestration_binary).await?;
    let address = runtime.address();
    let result = async {
        if revise_goal {
            // Retain the first run's coordinator and durable history while
            // revising the Goal before a second distinct execution.
            execute_package_flow(address, fixture, &package, false).await?;
        }
        execute_package_flow(address, fixture, &package, revise_goal).await
    }
    .await;
    let shutdown = runtime.shutdown().await;
    result?;
    shutdown?;
    Ok(())
}

struct PackageFixture {
    manifest_sha256: String,
}

fn write_package_fixture(fixture: &Fixture) -> Result<PackageFixture, Box<dyn std::error::Error>> {
    let report = b"# Research report\nStructural evidence only; no profitability claim.\n";
    let claims = br#"[{"id":"claim-1","claimClass":"qualitative","section":"Conclusion","citationIds":["citation-1"]}]"#;
    let citations = br#"[{"id":"citation-1","url":"https://example.com/source","publisher":"Example","title":"Source","publicationTime":null,"observationTime":null,"retrievalTime":null,"sourceClass":"primary"}]"#;
    fs::write(fixture.workspace_root.join("report.md"), report)?;
    fs::write(fixture.workspace_root.join("claims.json"), claims)?;
    fs::write(fixture.workspace_root.join("citations.json"), citations)?;
    let manifest = format!(
        "{{\"schemaVersion\":1,\"artifactKind\":\"official_report\",\"reportPath\":\"report.md\",\"reportSha256\":\"{}\",\"claimsPath\":\"claims.json\",\"claimsSha256\":\"{}\",\"citationsPath\":\"citations.json\",\"citationsSha256\":\"{}\",\"noTrade\":true,\"simulationState\":\"simulated_only\",\"quantProtocolPath\":null,\"quantProtocolSha256\":null,\"quantResultPath\":null,\"quantResultSha256\":null}}",
        sha256_hex(report),
        sha256_hex(claims),
        sha256_hex(citations),
    );
    let manifest_sha256 = sha256_hex(manifest.as_bytes());
    fs::write(fixture.workspace_root.join("package-v.json"), manifest)?;
    Ok(PackageFixture { manifest_sha256 })
}

#[allow(
    clippy::too_many_lines,
    reason = "The positive cross-process chain is intentionally asserted in order."
)]
async fn execute_package_flow(
    address: std::net::SocketAddr,
    fixture: &mut Fixture,
    package: &PackageFixture,
    revise_goal: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let execution_id = ExecutionId::from_uuid(Uuid::now_v7());
    let command_id = ExecutionCommandId::new(PACKAGE_COMMAND_ID.to_owned())?;
    let command_list_observed_at = timestamp_now()?;
    eprintln!("PackageV phase=command.list");
    let (_, list) = post_command(
        address,
        "command.list",
        json!({
            "scope": scope_json(fixture),
            "activity": {
                "activity_id": fixture.activity_id.into_uuid(),
                "runtime_instance_id": fixture.runtime_instance_id.into_uuid(),
                "observed_at_ms": command_list_observed_at.get(),
            },
        }),
    )
    .await?;
    let (catalog_fingerprint, request_digest) = assert_package_descriptor(&list)?;
    if revise_goal {
        revise_goal_requirement_and_refocus(fixture, &request_digest)?;
    }
    let observed_at = timestamp_now()?;
    let authority = authority_json(fixture, execution_id, &command_id, observed_at);

    eprintln!("PackageV phase=command.submit");
    let (status, submitted) = post_command(
        address,
        "command.submit",
        json!({
            "authority": authority.clone(),
            "expected_catalog_fingerprint": catalog_fingerprint.clone(),
        }),
    )
    .await?;
    assert_eq!(status, 200, "PackageV command.submit: {submitted}");
    assert_eq!(submitted["result"]["status"], "pending");
    assert_eq!(
        submitted["result"]["execution_id"],
        json!(execution_id.into_uuid())
    );
    let approval_id = submitted["result"]["approval_id"]
        .as_str()
        .ok_or("PackageV approval id missing")?;

    eprintln!("PackageV phase=approval.get");
    let (status, pending) = post_command(
        address,
        "approval.get",
        json!({"scope": scope_json(fixture), "approval_id": approval_id}),
    )
    .await?;
    assert_eq!(status, 200, "PackageV pending approval.get: {pending}");
    assert_eq!(pending["result"]["state"], "pending");
    assert_eq!(pending["result"]["execution"], Value::Null);
    assert_eq!(
        pending["result"]["request"]["request_digest"],
        request_digest
    );
    let expected_revision = pending["result"]["revision"]
        .as_i64()
        .ok_or("PackageV approval revision missing")?;

    let grant_id = Uuid::now_v7();
    let issued_at = timestamp_now()?;
    let grant_expires_at = add_millis(issued_at, 60_000)?;
    eprintln!("PackageV phase=approval.approve_once");
    let (status, approved) = post_command(
        address,
        "approval.approve_once",
        json!({
            "scope": scope_json(fixture),
            "approval_id": approval_id,
            "expected_revision": expected_revision,
            "grant_id": grant_id,
            "observed_at_ms": issued_at.get(),
            "grant_expires_at_ms": grant_expires_at.get(),
        }),
    )
    .await?;
    assert_eq!(status, 200, "PackageV approval.approve_once: {approved}");
    assert_eq!(approved["result"]["state"], "approved");
    assert_eq!(approved["result"]["execution"], Value::Null);
    assert_eq!(approved["result"]["grant"]["grant_id"], json!(grant_id));
    assert_eq!(approved["result"]["grant"]["state"], "active");
    assert_eq!(
        approved["result"]["request"]["request_digest"],
        request_digest
    );

    eprintln!("PackageV phase=execution.begin");
    let begin_result = post_command(
        address,
        "execution.begin",
        json!({
            "authority": authority,
            "grant_id": grant_id,
            "expected_grant_revision": 1,
            "mode": {
                "kind": "sealed_project_command",
                "command_id": PACKAGE_COMMAND_ID,
                "expected_catalog_fingerprint": catalog_fingerprint.clone(),
            },
            "admission": {
                "backend_id": BACKEND_ID,
                "issuer": ISSUER_ID,
                "expected_digest": request_digest.clone(),
                "issued_at_ms": issued_at.get(),
                "expires_at_ms": grant_expires_at.get(),
            },
        }),
    )
    .await;
    if let Err(begin_error) = &begin_result {
        eprintln!("PackageV execution.begin uncertainty: {begin_error}");
        let readback_authority =
            authority_json(fixture, execution_id, &command_id, timestamp_now()?);
        let readback = tokio::time::timeout(
            Duration::from_secs(5),
            post_command_unbounded(
                address,
                "execution.get",
                json!({"authority": readback_authority}),
            ),
        )
        .await;
        match readback {
            Ok(Ok((status, response))) => eprintln!(
                "PackageV pure readback status={status} state={} terminal={} error={}",
                response["result"]["state"],
                response["result"]["terminal"],
                response["error"]["code"],
            ),
            Ok(Err(error)) => eprintln!("PackageV pure readback error: {error}"),
            Err(_) => eprintln!("PackageV pure readback timed out"),
        }
    }
    let (status, begin) = begin_result?;
    eprintln!("PackageV execution.begin response status={status} body={begin}");
    assert!(
        status == 200 || status == 202,
        "PackageV execution.begin returned an unexpected status: {status}; {begin}"
    );
    if status == 202 {
        assert_eq!(begin["error"]["code"], "UNKNOWN_OUTCOME");
        assert_eq!(
            begin["error"]["readback"]["execution_id"],
            json!(execution_id.into_uuid())
        );
    }
    if status == 200 {
        assert_eq!(
            begin["result"]["execution_id"],
            json!(execution_id.into_uuid())
        );
    }

    eprintln!("PackageV phase=execution.get");
    wait_package_terminal(address, fixture, execution_id).await?;
    assert_package_execution(
        fixture,
        execution_id,
        &command_id,
        &catalog_fingerprint,
        &request_digest,
        package,
    )?;
    assert_package_effect_fact(fixture, execution_id).await?;
    Ok(())
}

fn assert_package_descriptor(
    result: &Value,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    assert_eq!(result["ok"], true, "PackageV command.list: {result}");
    assert_eq!(result["result"]["command_count"], 1);
    let commands = result["result"]["commands"]
        .as_array()
        .ok_or("PackageV command list missing commands")?;
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0]["id"], PACKAGE_COMMAND_ID);
    assert_eq!(commands[0]["class"], "verify");
    let catalog = result["result"]["catalog_fingerprint"]
        .as_str()
        .ok_or("PackageV catalog fingerprint missing")?
        .to_owned();
    let request = commands[0]["request_digest"]
        .as_str()
        .ok_or("PackageV request digest missing")?
        .to_owned();
    assert_hex_digest(&catalog)?;
    assert_hex_digest(&request)?;
    Ok((catalog, request))
}

async fn wait_package_terminal(
    address: std::net::SocketAddr,
    fixture: &Fixture,
    execution_id: ExecutionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = authority_json(
        fixture,
        execution_id,
        &ExecutionCommandId::new(PACKAGE_COMMAND_ID.to_owned())?,
        timestamp_now()?,
    );
    let deadline = Instant::now() + PACKAGE_WAIT_TIMEOUT;
    loop {
        let (status, response) =
            post_command(address, "execution.get", json!({"authority": authority})).await?;
        if status != 200 {
            return Err(format!("PackageV execution.get failed ({status}): {response}").into());
        }
        if response["result"]["terminal"] == json!(true) {
            if response["result"]["state"] != json!("completed") {
                return Err(
                    format!("PackageV terminal execution was not completed: {response}").into(),
                );
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("PackageV execution did not reach a terminal state".into());
        }
        sleep(PACKAGE_POLL_INTERVAL).await;
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "The durable PackageV acceptance and provenance assertions stay together."
)]
fn assert_package_execution(
    fixture: &Fixture,
    execution_id: ExecutionId,
    command_id: &ExecutionCommandId,
    catalog_fingerprint: &str,
    request_digest: &str,
    package: &PackageFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = AgentExecutionAuthorityRequest {
        session_id: fixture.session_id,
        scope: fixture.scope.clone(),
        activity_id: fixture.activity_id,
        agent_id: fixture.agent_id,
        expected_revision: fixture.agent_revision,
        principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
        attribution: fixture.attribution,
        command_id: command_id.clone(),
    };
    let record = fixture
        .client
        .execution_get_authorized(authority.clone(), execution_id)?;
    assert_eq!(record.state(), forge_domain::ExecutionState::Completed);
    assert_eq!(
        record
            .outcome()
            .and_then(forge_domain::ExecutionOutcome::exit_code),
        Some(0)
    );
    let read = fixture.client.execution_read_authorized(
        authority,
        execution_id,
        ExecutionOutputCursor::initial(execution_id),
        forge_domain::MIN_EXECUTION_OUTPUT_READ_BYTES,
        forge_domain::MAX_EXECUTION_OUTPUT_READ_EVENTS,
    )?;
    let bytes: Vec<u8> = read
        .output()
        .events()
        .iter()
        .filter_map(|event| match event {
            ExecutionOutputEvent::Chunk(chunk) => Some(chunk.bytes()),
            ExecutionOutputEvent::Gap(_) => None,
        })
        .flatten()
        .copied()
        .collect();
    let output: Value = serde_json::from_slice(&bytes)?;
    assert_eq!(output["packageVersion"], 1);
    assert_eq!(output["valid"], true);
    assert_eq!(output["noTrade"], true);
    assert_eq!(output["manifestSha256"], package.manifest_sha256);
    assert_eq!(output["errors"], json!([]));

    let selection = ExecutionObservationSelection::new(
        fixture.activity_id,
        Some(GoalAttribution::new(
            fixture.attribution.goal_id(),
            fixture.attribution.expected_goal_revision(),
        )),
    );
    let inventory = fixture.client.execution_evidence_inventory(
        fixture.scope.clone(),
        selection,
        ExecutionListLimit::DEFAULT,
    )?;
    let evidence = inventory
        .entries()
        .iter()
        .find(|entry| entry.header().id() == execution_id)
        .ok_or("PackageV execution evidence was not persisted")?;
    let header = evidence.header();
    assert_eq!(
        forge_backend::events::hex_encode(header.request_digest().as_bytes()),
        request_digest
    );
    let provenance = header
        .provenance()
        .ok_or("PackageV Agent provenance missing")?;
    assert_eq!(provenance.agent_id(), fixture.agent_id);
    assert_eq!(provenance.agent_revision(), fixture.agent_revision);
    assert_eq!(provenance.session_id(), Some(fixture.session_id));
    assert_eq!(provenance.attribution(), fixture.attribution);
    assert_eq!(provenance.command_id(), command_id);
    let project_command = provenance
        .project_command()
        .ok_or("PackageV project-command evidence missing")?;
    assert_eq!(project_command.class(), ProjectCommandClass::Verify);
    assert_eq!(
        forge_backend::events::hex_encode(project_command.catalog_fingerprint().hash().as_bytes()),
        catalog_fingerprint
    );
    let verification = evidence
        .verification()
        .ok_or("PackageV verification evidence was not persisted")?;
    let run = verification.run();
    assert_eq!(run.execution_id(), execution_id);
    assert_eq!(
        run.input_id(),
        forge_domain::VerificationInputId::from_uuid(execution_id.into_uuid())
    );
    let terminal = run
        .terminal_status()
        .ok_or("PackageV verification run was not terminal")?;
    assert_eq!(terminal.disposition(), VerificationRunDisposition::Accepted);
    assert_eq!(
        terminal.output_integrity(),
        Some(VerificationOutputIntegrity::Complete)
    );
    assert!(terminal.output_fingerprint().is_some());
    Ok(())
}

async fn assert_package_effect_fact(
    fixture: &Fixture,
    execution_id: ExecutionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let delegation = fixture
        .client
        .agent_operations_delegation(AgentOperationsDelegationReadRequest {
            scope: fixture.scope.clone(),
        })?
        .ok_or("PackageV delegation missing for effect fact readback")?;
    let deadline = Instant::now() + PACKAGE_WAIT_TIMEOUT;
    loop {
        let entries = fixture
            .client
            .effect_fact_outbox(EffectFactOutboxReadRequest {
                scope: fixture.scope.clone(),
                migration_id: delegation.migration_id(),
                destination_id: delegation.destination_id(),
                after: 0,
                limit: 64,
            })?;
        if let Some(fact) = entries.iter().find_map(|entry| match entry.fact() {
            EffectFact::ExecutionTerminal(fact) if fact.execution_id() == execution_id => {
                Some(fact.as_ref())
            }
            _ => None,
        }) {
            let verification = fact
                .verification()
                .ok_or("PackageV effect fact omitted verification evidence")?;
            assert_eq!(
                verification.disposition(),
                VerificationRunDisposition::Accepted
            );
            assert_eq!(
                verification.output_integrity(),
                Some(VerificationOutputIntegrity::Complete)
            );
            assert!(verification.output_fingerprint().is_some());
            assert_eq!(fact.agent_id(), fixture.agent_id);
            assert_eq!(fact.session_id(), Some(fixture.session_id));
            assert_eq!(fact.goal_id(), fixture.attribution.goal_id());
            assert_eq!(
                fact.goal_revision(),
                fixture.attribution.expected_goal_revision()
            );
            assert_eq!(fact.dag_revision(), fixture.attribution.dag_revision());
            assert_eq!(fact.node_id(), fixture.attribution.node_id());
            assert_eq!(
                fact.node_revision(),
                fixture.attribution.expected_node_revision()
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("PackageV execution effect fact was not persisted".into());
        }
        sleep(PACKAGE_POLL_INTERVAL).await;
    }
}

fn scope_json(fixture: &Fixture) -> Value {
    let locator = fixture.scope.locator();
    json!({
        "workspace_id": fixture.scope.workspace_id().into_uuid(),
        "workspace_revision": fixture.scope.workspace_revision().get(),
        "locator": {
            "location_id": locator.location_id().into_uuid(),
            "expected_revision": locator.expected_revision().get(),
            "relative_root": locator.relative_root().to_string_lossy(),
        }
    })
}

fn required_binary(name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = env::var_os(name)
        .map(std::path::PathBuf::from)
        .ok_or_else(|| format!("{name} is required for the ignored PackageV test"))?;
    if !path.is_absolute() || !path.is_file() {
        return Err(format!("{name} must name an existing absolute binary").into());
    }
    Ok(path)
}

fn assert_hex_digest(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("invalid lowercase SHA-256 digest: {value}").into());
    }
    Ok(())
}

fn revise_goal_requirement_and_refocus(
    fixture: &mut Fixture,
    request_digest: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let revised_goal = revise_goal_contract_for_package(fixture, request_digest)?;
    refocus_current_agent(fixture, &revised_goal)
}

fn revise_goal_contract_for_package(
    fixture: &Fixture,
    request_digest: &str,
) -> Result<forge_domain::RegisteredGoal, Box<dyn std::error::Error>> {
    let requirement_digest = package_request_digest(request_digest)?;
    let initial_attribution = fixture.attribution;
    assert_eq!(
        initial_attribution.expected_goal_revision(),
        forge_domain::GoalRevision::INITIAL
    );
    assert_eq!(
        initial_attribution.dag_revision(),
        forge_domain::DagRevisionNumber::INITIAL
    );
    assert_eq!(initial_attribution.expected_node_revision().get(), 2);

    let current_goal = fixture
        .client
        .goal_get(
            fixture.scope.clone(),
            fixture.activity_id,
            initial_attribution.goal_id(),
        )?
        .ok_or("PackageV initial Goal readback missing")?;
    assert_eq!(current_goal.revision(), forge_domain::GoalRevision::INITIAL);
    let current_contract = current_goal.contract();
    assert!(current_contract.verification_requirements().is_empty());
    let revised_contract = forge_domain::GoalContract::new(
        current_contract.objective().clone(),
        current_contract.success_criteria().to_vec(),
        current_contract.constraints().to_vec(),
        current_contract.out_of_scope().to_vec(),
        vec![
            forge_domain::GoalVerificationRequirement::ExecutionSucceeded {
                request_digest: requirement_digest,
                description: forge_domain::GoalStatement::new(
                    "The current PackageV execution succeeds".to_owned(),
                )?,
            },
        ],
        current_contract.stop_conditions().to_vec(),
    )?;
    let coordinator = fixture
        .client
        .activity_coordinator_actor(forge_control::CoordinatorActorRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
        })?
        .ok_or("PackageV current coordinator actor readback missing")?;
    let goal_observed_at = TimestampMillis::new(
        timestamp_now()?
            .get()
            .max(current_goal.timestamps().updated_at().get()),
    )?;
    let revised_goal =
        fixture
            .client
            .goal_revise_contract(forge_control::GoalContractRevisionRequest {
                scope: fixture.scope.clone(),
                activity_id: fixture.activity_id,
                actor: coordinator,
                goal_id: current_goal.id(),
                expected_revision: current_goal.revision(),
                contract: revised_contract,
                observed_at: goal_observed_at,
            })?;
    assert_eq!(
        revised_goal.revision(),
        current_goal.revision().checked_next()?
    );
    let persisted_goal = fixture
        .client
        .goal_get(
            fixture.scope.clone(),
            fixture.activity_id,
            current_goal.id(),
        )?
        .ok_or("PackageV revised Goal readback missing")?;
    assert_eq!(persisted_goal, revised_goal);
    assert!(matches!(
        persisted_goal.contract().verification_requirements(),
        [forge_domain::GoalVerificationRequirement::ExecutionSucceeded {
            request_digest: actual,
            ..
        }] if *actual == requirement_digest
    ));
    Ok(persisted_goal)
}

fn package_request_digest(
    value: &str,
) -> Result<forge_domain::ExecutionRequestDigest, Box<dyn std::error::Error>> {
    assert_hex_digest(value)?;
    let mut digest_bytes = [0_u8; forge_domain::ExecutionRequestDigest::BYTE_LEN];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        digest_bytes[index] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(forge_domain::ExecutionRequestDigest::from_bytes(
        digest_bytes,
    ))
}

fn refocus_current_agent(
    fixture: &mut Fixture,
    revised_goal: &forge_domain::RegisteredGoal,
) -> Result<(), Box<dyn std::error::Error>> {
    let initial_attribution = fixture.attribution;
    let agent_projection = fixture
        .client
        .agent_list(forge_control::AgentListRequest {
            scope: fixture.scope.clone(),
            activity_id: Some(fixture.activity_id),
            now: timestamp_now()?,
            limit: forge_domain::AgentListLimit::DEFAULT,
        })?
        .into_iter()
        .find(|projection| projection.agent().id() == fixture.agent_id)
        .ok_or("PackageV current Agent readback missing")?;
    let focus_observed_at = TimestampMillis::new(
        timestamp_now()?
            .get()
            .max(agent_projection.agent().updated_at().get()),
    )?;
    let current_coordinator = fixture
        .client
        .activity_coordinator_actor(forge_control::CoordinatorActorRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            principal: forge_domain::AuthenticatedPrincipal::TrustedStdio,
        })?
        .ok_or("PackageV current coordinator actor readback missing before focus")?;
    let focus = forge_domain::AgentFocus::new(
        Some(forge_domain::GoalAttribution::new(
            revised_goal.id(),
            revised_goal.revision(),
        )),
        Some(initial_attribution.dag_revision()),
        Some(forge_domain::AgentFocusNode::new(
            initial_attribution.node_id(),
            initial_attribution.expected_node_revision(),
        )),
    )?;
    let focused = fixture
        .client
        .agent_set_focus(forge_control::AgentFocusRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity_id,
            actor: current_coordinator,
            agent_id: fixture.agent_id,
            expected_revision: agent_projection.agent().revision(),
            focus,
            observed_at: focus_observed_at,
        })?;
    assert_eq!(focused.focus(), focus);
    let focused_node = focused
        .focus()
        .node()
        .ok_or("PackageV refocused Agent node missing")?;
    fixture.agent_revision = focused.revision();
    fixture.attribution = forge_domain::GoalNodeAttribution::new(
        revised_goal.id(),
        revised_goal.revision(),
        initial_attribution.dag_revision(),
        initial_attribution.node_id(),
        focused_node.expected_revision(),
    );
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(64);
    for byte in digest {
        let _ = write!(result, "{byte:02x}");
    }
    result
}
