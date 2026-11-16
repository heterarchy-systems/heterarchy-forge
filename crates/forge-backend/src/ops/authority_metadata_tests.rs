use super::CommandOp;

#[test]
fn assignment_read_routes_advertise_current_session_authority() {
    assert!(CommandOp::AgentAssignmentGet.requires_session_authority());
    assert!(CommandOp::AgentAssignmentList.requires_session_authority());
    assert!(CommandOp::AgentAssignmentMutate.requires_session_authority());
    assert!(!CommandOp::ActivityGet.requires_session_authority());
    assert!(!CommandOp::QueueStatus.requires_session_authority());
}

#[test]
fn binding_lifecycle_receipts_require_current_session_authority() {
    for op in [
        CommandOp::AgentBindingReserve,
        CommandOp::AgentBindingReservationGet,
        CommandOp::AgentBindingActivate,
        CommandOp::AgentBindingActivationGet,
        CommandOp::AgentBindingReject,
        CommandOp::AgentBindingRejectionGet,
        CommandOp::AgentSessionReconcile,
        CommandOp::AgentSessionReconciliationGet,
        CommandOp::AgentDepartureReconcile,
        CommandOp::AgentDepartureReconciliationGet,
    ] {
        assert!(op.requires_session_authority(), "{}", op.as_str());
    }
    assert!(!CommandOp::AgentOperationsDelegate.requires_session_authority());
    assert!(!CommandOp::AgentOperationsDelegationGet.requires_session_authority());
    for op in [
        CommandOp::AgentOperationsFreeze,
        CommandOp::AgentOperationsFreezeGet,
        CommandOp::AgentOperationsExport,
        CommandOp::AgentOperationsFreezeRelease,
    ] {
        assert!(!op.requires_session_authority(), "{}", op.as_str());
    }
}

#[test]
fn unstarted_continuation_only_binds_the_authenticated_run() {
    assert!(!CommandOp::ActivityUnstartedContinuationProbe.requires_session_authority());
    assert!(CommandOp::ActivityUnstartedContinuationRun.requires_session_authority());
    assert!(!CommandOp::ActivityUnstartedContinuationGet.requires_session_authority());
}

#[test]
fn dag_settle_and_node_workspace_authority_and_parse_contract() -> Result<(), crate::ForgeError> {
    assert!(CommandOp::DagSettle.requires_session_authority());
    assert!(!CommandOp::NodeWorkspace.requires_session_authority());

    let request_id_1 = uuid::Uuid::from_u128(0x9001);
    let ws_payload = serde_json::json!({
        "scope": {
            "workspace_id": "00000000-0000-0000-0000-000000000020",
            "workspace_revision": 1,
            "locator": {
                "location_id": "00000000-0000-0000-0000-000000000010",
                "expected_revision": 1,
                "relative_root": "."
            }
        },
        "goal_id": "00000000-0000-0000-0000-000000000030",
        "dag_revision": 1,
        "node_id": "00000000-0000-0000-0000-000000000040"
    });
    let ws_cmd = super::parse_command(CommandOp::NodeWorkspace, request_id_1, &ws_payload)?;
    assert_eq!(ws_cmd.op(), CommandOp::NodeWorkspace);

    let request_id_2 = uuid::Uuid::from_u128(0x9002);
    let settle_payload = serde_json::json!({
        "scope": {
            "workspace_id": "00000000-0000-0000-0000-000000000020",
            "workspace_revision": 1,
            "locator": {
                "location_id": "00000000-0000-0000-0000-000000000010",
                "expected_revision": 1,
                "relative_root": "."
            }
        },
        "activity_id": "00000000-0000-0000-0000-000000000050",
        "actor": {
            "workspace_id": "00000000-0000-0000-0000-000000000020",
            "session_id": "00000000-0000-0000-0000-000000000060",
            "principal": { "kind": "trusted_stdio" }
        },
        "goal_id": "00000000-0000-0000-0000-000000000030",
        "expected_goal_revision": 1,
        "expected_dag_revision": 1,
        "settlement_id": "00000000-0000-0000-0000-000000000070",
        "observed_at_ms": 1234
    });
    let settle_cmd = super::parse_command(CommandOp::DagSettle, request_id_2, &settle_payload)?;
    assert_eq!(settle_cmd.op(), CommandOp::DagSettle);
    Ok(())
}

fn swarm_test_payloads() -> Vec<(CommandOp, serde_json::Value)> {
    let scope = serde_json::json!({
        "workspace_id": "00000000-0000-0000-0000-000000000020",
        "workspace_revision": 1,
        "locator": {
            "location_id": "00000000-0000-0000-0000-000000000010",
            "expected_revision": 1,
            "relative_root": "."
        }
    });
    let actor = serde_json::json!({
        "workspace_id": "00000000-0000-0000-0000-000000000020",
        "session_id": "00000000-0000-0000-0000-000000000060",
        "principal": { "kind": "trusted_stdio" }
    });
    let run_id = "00000000-0000-0000-0000-000000000031";
    let member_id = "00000000-0000-0000-0000-000000000032";
    let settlement_id = "00000000-0000-0000-0000-000000000033";
    let oid = "0123456789abcdef0123456789abcdef01234567";
    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    vec![
        (
            CommandOp::SwarmWorkspaceProvision,
            serde_json::json!({
                "scope": scope, "actor": actor, "swarm_run_id": run_id,
                "member_id": member_id, "mode": "share",
                "target": { "kind": "standalone_swarm" },
                "candidate_commit_oid": oid, "observed_at_ms": 100
            }),
        ),
        (
            CommandOp::SwarmWorkspaceGet,
            serde_json::json!({ "scope": scope, "swarm_run_id": run_id, "member_id": member_id }),
        ),
        (
            CommandOp::SwarmMemberCapture,
            serde_json::json!({
                "scope": scope, "actor": actor, "swarm_run_id": run_id,
                "member_id": member_id, "captured_at_ms": 101
            }),
        ),
        (
            CommandOp::SwarmConverge,
            serde_json::json!({
                "scope": scope, "actor": actor, "swarm_run_id": run_id,
                "candidates": [{
                    "member_id": member_id,
                    "expected_output_commit_oid": oid,
                    "expected_diff_digest": digest
                }],
                "observed_at_ms": 102
            }),
        ),
        (
            CommandOp::SwarmSettle,
            serde_json::json!({
                "scope": scope,
                "activity_id": "00000000-0000-0000-0000-000000000050",
                "actor": actor,
                "coordinator_agent_id": "00000000-0000-0000-0000-000000000051",
                "swarm_run_id": run_id, "settlement_id": settlement_id,
                "converged_commit_oid": oid, "expected_diff_digest": digest,
                "settled_at_ms": 103
            }),
        ),
        (
            CommandOp::SwarmMaterializeHybrid,
            serde_json::json!({
                "scope": scope,
                "activity_id": "00000000-0000-0000-0000-000000000050",
                "actor": actor, "swarm_run_id": run_id,
                "settlement_id": settlement_id,
                "goal_id": "00000000-0000-0000-0000-000000000052",
                "expected_goal_revision": 1, "expected_dag_revision": 1,
                "node_id": "00000000-0000-0000-0000-000000000053",
                "converged_commit_oid": oid, "expected_diff_digest": digest,
                "settled_at_ms": 104
            }),
        ),
        (
            CommandOp::SwarmSettlementGet,
            serde_json::json!({ "scope": scope, "swarm_run_id": run_id }),
        ),
        (
            CommandOp::SwarmPurge,
            serde_json::json!({ "scope": scope, "actor": actor, "swarm_run_id": run_id }),
        ),
    ]
}

#[test]
fn swarm_routes_enforce_session_authority_and_strict_payloads() -> Result<(), crate::ForgeError> {
    for op in [
        CommandOp::SwarmWorkspaceProvision,
        CommandOp::SwarmMemberCapture,
        CommandOp::SwarmConverge,
        CommandOp::SwarmSettle,
        CommandOp::SwarmMaterializeHybrid,
        CommandOp::SwarmPurge,
    ] {
        assert!(op.requires_session_authority(), "{}", op.as_str());
        assert!(CommandOp::ALL.contains(&op), "{}", op.as_str());
        assert_eq!(CommandOp::parse(op.as_str()), Some(op));
    }
    for op in [CommandOp::SwarmWorkspaceGet, CommandOp::SwarmSettlementGet] {
        assert!(!op.requires_session_authority(), "{}", op.as_str());
        assert!(CommandOp::ALL.contains(&op), "{}", op.as_str());
        assert_eq!(CommandOp::parse(op.as_str()), Some(op));
    }
    for (idx, (op, payload)) in swarm_test_payloads().into_iter().enumerate() {
        let req_id = uuid::Uuid::from_u128(0x9100 + idx as u128);
        let cmd = super::parse_command(op, req_id, &payload)?;
        assert_eq!(cmd.op(), op);
        assert_eq!(cmd.request_id(), req_id);
        let mut with_unknown = payload;
        if let Some(obj) = with_unknown.as_object_mut() {
            obj.insert("unexpected".to_owned(), serde_json::json!(true));
        }
        assert!(super::parse_command(op, req_id, &with_unknown).is_err());
    }
    let bad_settle = serde_json::json!({
        "scope": {
            "workspace_id": "00000000-0000-0000-0000-000000000020",
            "workspace_revision": 1,
            "locator": {
                "location_id": "00000000-0000-0000-0000-000000000010",
                "expected_revision": 1, "relative_root": "."
            }
        },
        "actor": {
            "workspace_id": "00000000-0000-0000-0000-000000000099",
            "session_id": "00000000-0000-0000-0000-000000000060",
            "principal": { "kind": "trusted_stdio" }
        },
        "coordinator_agent_id": "00000000-0000-0000-0000-000000000051",
        "swarm_run_id": "00000000-0000-0000-0000-000000000031",
        "settlement_id": "00000000-0000-0000-0000-000000000033",
        "converged_commit_oid": "0123456789abcdef0123456789abcdef01234567",
        "settled_at_ms": 103
    });
    assert!(
        super::parse_command(
            CommandOp::SwarmSettle,
            uuid::Uuid::from_u128(0x9200),
            &bad_settle
        )
        .is_err()
    );
    Ok(())
}
