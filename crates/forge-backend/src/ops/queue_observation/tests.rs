use serde_json::{Value, json};
use uuid::Uuid;

use super::{QueueObservationRequest, parse};
use crate::ops::CommandOp;
use forge_control::QueueRuntimeError;

fn scope_payload() -> Value {
    json!({
        "scope": {
            "workspace_id": Uuid::from_u128(1),
            "workspace_revision": 7,
            "locator": {
                "location_id": Uuid::from_u128(2),
                "expected_revision": 3,
                "relative_root": "."
            }
        }
    })
}

#[test]
fn global_status_accepts_only_an_empty_object() {
    assert!(matches!(
        parse(CommandOp::QueueStatus, &json!({})),
        Ok(QueueObservationRequest::GlobalStatus)
    ));
    assert!(parse(CommandOp::QueueStatus, &json!({ "unexpected": true })).is_err());
    assert!(parse(CommandOp::QueueStatus, &scope_payload()).is_err());
}

#[test]
fn scoped_observations_decode_and_echo_the_exact_scope_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let request = parse(CommandOp::WorkspaceQueueStatus, &scope_payload())?;
    let QueueObservationRequest::WorkspaceStatus { scope } = request else {
        return Err("workspace queue status must produce a scoped request".into());
    };
    assert_eq!(scope.workspace_id().into_uuid(), Uuid::from_u128(1));
    assert_eq!(scope.workspace_revision().get(), 7);
    assert_eq!(
        scope.locator().location_id().into_uuid(),
        Uuid::from_u128(2)
    );
    assert_eq!(scope.locator().expected_revision().get(), 3);

    assert!(matches!(
        parse(CommandOp::WorkspaceQueueSettings, &scope_payload()),
        Ok(QueueObservationRequest::WorkspaceSettings { .. })
    ));
    Ok(())
}

#[test]
fn scoped_observations_reject_unknown_fields_nil_ids_and_bad_revisions() {
    let mut unknown = scope_payload();
    unknown["unexpected"] = json!(true);
    assert!(parse(CommandOp::WorkspaceQueueStatus, &unknown).is_err());

    let mut nil_workspace = scope_payload();
    nil_workspace["scope"]["workspace_id"] = json!(Uuid::nil());
    assert!(parse(CommandOp::WorkspaceQueueStatus, &nil_workspace).is_err());

    let mut nil_location = scope_payload();
    nil_location["scope"]["locator"]["location_id"] = json!(Uuid::nil());
    assert!(parse(CommandOp::WorkspaceQueueSettings, &nil_location).is_err());

    let mut negative_revision = scope_payload();
    negative_revision["scope"]["workspace_revision"] = json!(-1);
    assert!(parse(CommandOp::WorkspaceQueueStatus, &negative_revision).is_err());
}

#[test]
fn queue_runtime_errors_preserve_retryability_without_leaking_details() {
    let closed = super::queue_runtime_error(&QueueRuntimeError::Closed);
    assert_eq!(
        closed.code(),
        crate::error::ErrorCode::DependencyUnavailable
    );
    assert!(closed.retryable());

    for error in [
        QueueRuntimeError::PartitionLimit,
        QueueRuntimeError::CounterOverflow,
        QueueRuntimeError::Poisoned,
    ] {
        let mapped = super::queue_runtime_error(&error);
        assert_eq!(mapped.code(), crate::error::ErrorCode::ForgeUnavailable);
        assert!(!mapped.retryable());
    }
}
