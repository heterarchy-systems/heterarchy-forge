//! Bounded local diagnostics; never changes admission or returned errors.

use std::io::Write as _;

use forge_domain::ExecutionId;

use super::ForgeExecutionCoordinatorError;
use crate::{ControlClientError, ControlErrorCode};

#[derive(Debug, Clone, Copy)]
pub(super) enum Stage {
    Authority,
    ResolveCommand,
    ValidateStart,
    LaunchKind,
    Provenance,
    ConsumeAuthorization,
}

impl Stage {
    const fn name(self) -> &'static str {
        match self {
            Self::Authority => "authority",
            Self::ResolveCommand => "resolve_command",
            Self::ValidateStart => "validate_start",
            Self::LaunchKind => "launch_kind",
            Self::Provenance => "provenance",
            Self::ConsumeAuthorization => "consume_authorization",
        }
    }
}

fn line(id: ExecutionId, stage: Stage, code: ControlErrorCode) -> String {
    format!(
        "execution admission error execution_id={} stage={} code={}",
        id.into_uuid(),
        stage.name(),
        code.as_str()
    )
}

pub(super) fn control(id: ExecutionId, stage: Stage, error: &ControlClientError) {
    emit(id, stage, error.code());
}

pub(super) fn coordinator(id: ExecutionId, stage: Stage, error: &ForgeExecutionCoordinatorError) {
    emit(id, stage, error.view().code());
}

fn emit(id: ExecutionId, stage: Stage, code: ControlErrorCode) {
    let _ = writeln!(std::io::stderr().lock(), "{}", line(id, stage, code));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_has_only_closed_stage_code_and_identity() {
        let id = ExecutionId::from_uuid(uuid::Uuid::from_u128(1));
        assert_eq!(
            line(
                id,
                Stage::ConsumeAuthorization,
                ControlErrorCode::ApprovalConflict
            ),
            "execution admission error execution_id=00000000-0000-0000-0000-000000000001 stage=consume_authorization code=CONTROL_APPROVAL_CONFLICT"
        );
    }
}
