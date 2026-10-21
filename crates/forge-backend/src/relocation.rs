//! Offline, same-device relocation with durable phase readback.

mod journal;
mod paths;
#[cfg(test)]
mod tests;

use std::path::Path;

use forge_backend::ServeFence;
use forge_domain::{
    LocationId, LocationRevision, LocationRoot, TimestampMillis, WorkspaceRootFingerprint,
};
use forge_persistence::{GlobalRegistry, WorkspaceStore};
use forge_workspace::{
    LocationRepository, LocationRepositoryError, WorkspaceStateExclusiveGate, WorkspaceStateLayout,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use journal::{Journal, Phase};

#[derive(Debug, thiserror::Error)]
pub(super) enum RelocationError {
    #[error("relocation input, path, identity or phase conflict: {0}")]
    Conflict(&'static str),
    #[error("relocation filesystem operation failed")]
    Io(#[from] std::io::Error),
    #[error("relocation JSON is invalid")]
    Json(#[from] serde_json::Error),
    #[error("relocation persistence operation failed")]
    Registry(#[from] forge_persistence::RegistryError),
    #[error("relocation Location read failed")]
    Location(#[from] LocationRepositoryError),
    #[error("relocation Workspace operation failed")]
    Workspace(#[from] forge_persistence::WorkspaceStoreError),
    #[error("relocation state layout is invalid")]
    Layout(#[from] forge_workspace::StateLayoutError),
    #[error("relocation requires exclusive offline ownership")]
    Fence(#[from] forge_backend::ServeFenceError),
    #[error("relocation Workspace gate is busy or mismatched")]
    Gate(#[from] forge_workspace::WorkspaceStateGateError),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    request_id: Uuid,
    registry_path: std::path::PathBuf,
    source: std::path::PathBuf,
    destination: std::path::PathBuf,
    location_id: Uuid,
    expected_location_revision: i64,
    workspace_id: Uuid,
    expected_workspace_revision: i64,
    root_fingerprint: [u8; 16],
    database_device: u64,
    database_inode: u64,
    observed_at_ms: i64,
}

pub(super) fn ensure_complete(registry: &Path) -> Result<(), RelocationError> {
    if let Some(journal) = journal::read(registry)?
        && journal.phase != Phase::Complete
    {
        return Err(RelocationError::Conflict(
            "unfinished relocation; resume its exact plan",
        ));
    }
    Ok(())
}

pub(super) fn run(path: &Path) -> Result<(), RelocationError> {
    let plan: Plan = serde_json::from_slice(&paths::read_private(path)?)?;
    relocate(&plan, None)?;
    println!(
        "{{\"state\":\"complete\",\"request_id\":\"{}\",\"workspace_id\":\"{}\"}}",
        plan.request_id, plan.workspace_id
    );
    Ok(())
}

fn relocate(plan: &Plan, stop_after: Option<Phase>) -> Result<(), RelocationError> {
    paths::validate_plan(plan)?;
    let _host = ServeFence::acquire(&plan.registry_path)?;
    let existing = journal::read(&plan.registry_path)?;
    if let Some(prior) = &existing
        && prior.plan != *plan
    {
        return Err(RelocationError::Conflict("journal intent differs"));
    }
    let mut registry = GlobalRegistry::open_existing(&plan.registry_path)?;
    let location = registry
        .get_location(LocationId::from_uuid(plan.location_id))?
        .ok_or(RelocationError::Conflict("Location missing"))?;
    let current_root = location.root().as_path();
    let location_before =
        current_root == plan.source && location.revision().get() == plan.expected_location_revision;
    let location_after = current_root == plan.destination
        && location.revision().get() == plan.expected_location_revision + 1;
    if !location_before && !location_after {
        return Err(RelocationError::Conflict("Location fence changed"));
    }
    let old_exists = plan.source.try_exists()?;
    let new_exists = plan.destination.try_exists()?;
    if old_exists == new_exists {
        return Err(RelocationError::Conflict("exactly one root must exist"));
    }
    if existing.is_none() && (!old_exists || !location_before) {
        return Err(RelocationError::Conflict(
            "new intent requires original root",
        ));
    }
    let current = if old_exists {
        &plan.source
    } else {
        &plan.destination
    };
    paths::require_root(current, plan)?;
    paths::require_database(current, plan)?;
    let fingerprint = WorkspaceRootFingerprint::from_bytes(plan.root_fingerprint);
    let layout = WorkspaceStateLayout::inspect_existing(current)?
        .ok_or(RelocationError::Conflict("Workspace state missing"))?;
    let gate = WorkspaceStateExclusiveGate::acquire(current, fingerprint)?;
    let workspace = WorkspaceStore::inspect_relocation_under_exclusive(&layout, &gate)?;
    let gate = Some(gate);
    paths::require_single_workspace(current)?;
    if workspace.id().into_uuid() != plan.workspace_id
        || workspace.location_id().into_uuid() != plan.location_id
        || workspace.root_fingerprint() != fingerprint
    {
        return Err(RelocationError::Conflict("Workspace identity differs"));
    }
    let workspace_before = workspace.root().as_path() == plan.source
        && workspace.revision().get() == plan.expected_workspace_revision;
    let workspace_after = workspace.root().as_path() == plan.destination
        && workspace.revision().get() == plan.expected_workspace_revision + 1;
    if !workspace_before && !workspace_after {
        return Err(RelocationError::Conflict("Workspace fence changed"));
    }
    if existing
        .as_ref()
        .is_some_and(|j| j.phase == Phase::Complete)
    {
        if location_after && workspace_after && new_exists {
            return Ok(());
        }
        return Err(RelocationError::Conflict("complete readback differs"));
    }
    finish(
        plan,
        &mut registry,
        Progress {
            workspace,
            gate,
            old_exists,
            location_before,
            workspace_before,
            existing_phase: existing.as_ref().map(|j| j.phase),
        },
        stop_after,
    )
}

struct Progress {
    workspace: forge_domain::RegisteredWorkspace,
    gate: Option<WorkspaceStateExclusiveGate>,
    old_exists: bool,
    location_before: bool,
    workspace_before: bool,
    existing_phase: Option<Phase>,
}

fn finish(
    plan: &Plan,
    registry: &mut GlobalRegistry,
    progress: Progress,
    stop_after: Option<Phase>,
) -> Result<(), RelocationError> {
    let Progress {
        workspace,
        mut gate,
        old_exists,
        location_before,
        workspace_before,
        existing_phase,
    } = progress;
    let fingerprint = WorkspaceRootFingerprint::from_bytes(plan.root_fingerprint);
    if existing_phase.is_none() {
        journal::write(&Journal {
            plan: plan.clone(),
            phase: Phase::Prepared,
        })?;
    }
    stop(Phase::Prepared, stop_after)?;
    if old_exists {
        if !workspace_before || !location_before {
            return Err(RelocationError::Conflict("old root has changed binding"));
        }
        paths::rename(plan)?;
        drop(gate.take());
        gate = Some(WorkspaceStateExclusiveGate::acquire(
            &plan.destination,
            fingerprint,
        )?);
    }
    paths::require_root(&plan.destination, plan)?;
    paths::require_database(&plan.destination, plan)?;
    journal::write(&Journal {
        plan: plan.clone(),
        phase: Phase::Renamed,
    })?;
    stop(Phase::Renamed, stop_after)?;
    let layout = WorkspaceStateLayout::inspect_existing(&plan.destination)?
        .ok_or(RelocationError::Conflict("moved state missing"))?;
    let current_gate = gate
        .as_ref()
        .ok_or(RelocationError::Conflict("root gate missing"))?;
    if workspace_before {
        WorkspaceStore::relocate_root_under_exclusive(
            &layout,
            current_gate,
            &workspace,
            TimestampMillis::new(plan.observed_at_ms)
                .map_err(|_| RelocationError::Conflict("invalid time"))?,
        )?;
    }
    journal::write(&Journal {
        plan: plan.clone(),
        phase: Phase::WorkspaceRebound,
    })?;
    stop(Phase::WorkspaceRebound, stop_after)?;
    if location_before {
        registry.relocate_location_root(
            LocationId::from_uuid(plan.location_id),
            LocationRevision::new(plan.expected_location_revision)
                .map_err(|_| RelocationError::Conflict("invalid Location revision"))?,
            &LocationRoot::from_canonical(plan.source.clone())
                .map_err(|_| RelocationError::Conflict("invalid old root"))?,
            &LocationRoot::from_canonical(plan.destination.clone())
                .map_err(|_| RelocationError::Conflict("invalid new root"))?,
            TimestampMillis::new(plan.observed_at_ms)
                .map_err(|_| RelocationError::Conflict("invalid time"))?,
        )?;
    }
    journal::write(&Journal {
        plan: plan.clone(),
        phase: Phase::RegistryRebound,
    })?;
    stop(Phase::RegistryRebound, stop_after)?;
    let location = registry
        .get_location(LocationId::from_uuid(plan.location_id))?
        .ok_or(RelocationError::Conflict("Location readback missing"))?;
    if location.root().as_path() != plan.destination
        || location.revision().get() != plan.expected_location_revision + 1
    {
        return Err(RelocationError::Conflict("Location commit unconfirmed"));
    }
    journal::write(&Journal {
        plan: plan.clone(),
        phase: Phase::Complete,
    })?;
    Ok(())
}

fn stop(phase: Phase, requested: Option<Phase>) -> Result<(), RelocationError> {
    if requested == Some(phase) {
        return Err(RelocationError::Conflict("test phase stop"));
    }
    Ok(())
}
