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
