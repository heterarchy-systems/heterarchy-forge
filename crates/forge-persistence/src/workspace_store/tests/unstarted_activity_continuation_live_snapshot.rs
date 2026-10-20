//! Opt-in, read-only dry run of the closed census over a disposable copied
//! real Workspace snapshot. It never opens a live database: the caller must
//! point `FORGE_UAC_SNAPSHOT` at a copy, which this test may migrate 65→66.

use std::time::Duration;

use forge_domain::{
    ActivityId, AgentSessionId, AuthenticatedPrincipal, DirectTokenId,
    ExpiredActivityRecoveryProbeScope, ForgeBackendId, LocationRevision, OAuthGrantId,
    OrchestrationIssuerId, RuntimeInstanceId, TimestampMillis,
    UnstartedActivityContinuationServiceIdentity,
};
use rusqlite::{Connection, params};
use uuid::Uuid;

#[test]
#[ignore = "requires FORGE_UAC_SNAPSHOT pointing at a disposable copied state.sqlite3"]
fn copied_live_snapshot_census_dry_run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::var_os("FORGE_UAC_SNAPSHOT").ok_or("FORGE_UAC_SNAPSHOT unset")?;
    let activity_id =
        ActivityId::from_uuid(Uuid::parse_str(&std::env::var("FORGE_UAC_ACTIVITY")?)?);
    let observed_at = TimestampMillis::new(std::env::var("FORGE_UAC_OBSERVED_AT_MS")?.parse()?)?;
    let mut connection = Connection::open(&path)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == 65 {
        crate::workspace_store::migrate_unstarted_activity_continuation_schema(
            &mut connection,
            Duration::from_secs(5),
        )?;
    }
    let workspace = crate::workspace_store::query_workspace_row(&connection)?
        .ok_or("Workspace row missing")
        .map(crate::workspace_store::decode_workspace)??;
    let (coordinator_session, principal_kind, principal_id): (Vec<u8>, i64, Option<Vec<u8>>) =
        connection.query_row(
            "SELECT a.session_id, a.principal_kind, a.principal_id FROM activity_coordinators c
             JOIN agent_instances a ON a.agent_id=c.agent_id AND a.activity_id=c.activity_id
             WHERE c.activity_id=?1",
            params![activity_id.into_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
    let principal = match (principal_kind, principal_id) {
        (0, None) => AuthenticatedPrincipal::TrustedStdio,
        (1, Some(id)) => {
            AuthenticatedPrincipal::DirectToken(DirectTokenId::from_uuid(Uuid::from_slice(&id)?))
        }
        (2, Some(id)) => {
            AuthenticatedPrincipal::OAuthGrant(OAuthGrantId::from_uuid(Uuid::from_slice(&id)?))
        }
        _ => return Err("Coordinator principal shape".into()),
    };
    let scope = ExpiredActivityRecoveryProbeScope::new(
        workspace.id(),
        workspace.revision(),
        workspace.location_id(),
        LocationRevision::INITIAL,
        b".".to_vec(),
        workspace.root_fingerprint(),
        [0x11; 32],
    )?;
    let service = UnstartedActivityContinuationServiceIdentity::new(
        ForgeBackendId::from_uuid(Uuid::from_u128(0xD1)),
        OrchestrationIssuerId::from_uuid(Uuid::from_u128(0xD2)),
        RuntimeInstanceId::from_uuid(Uuid::from_u128(0xD3)),
    )?;
    for (component, outcome) in
        crate::workspace_store::unstarted_activity_continuation::census_components_for_test(
            &connection,
            workspace.id(),
            activity_id,
        )
    {
        eprintln!("component {component}: {outcome}");
    }
    let transaction = connection.unchecked_transaction()?;
    let probe = crate::workspace_store::unstarted_activity_continuation::probe_raw_for_test(
        &transaction,
        &scope,
        activity_id,
        AgentSessionId::from_uuid(Uuid::from_slice(&coordinator_session)?),
        principal,
        service,
        observed_at,
    );
    transaction.rollback()?;
    match &probe {
        Ok(value) => eprintln!(
            "probe blocker={:?} continuable={} agents={} plan_digest={}",
            value.blocker(),
            value.continuable_now(),
            value.expectation().expected_agent_count(),
            hex(&value.expectation().expected_plan_digest())
        ),
        Err(error) => eprintln!("probe error: {error:?}"),
    }
    if std::env::var_os("FORGE_UAC_EXPECT_CONTINUABLE").is_some() {
        let value = probe.map_err(|error| format!("{error:?}"))?;
        assert!(value.continuable_now(), "{:?}", value.blocker());
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut output, byte| {
        let _ = write!(output, "{byte:02x}");
        output
    })
}
