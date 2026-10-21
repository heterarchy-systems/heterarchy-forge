//! Bounded read-only inventory of registered Workspaces at one Location.
//!
//! This projection is deliberately distinct from [`ForgeControl::workspace_list`]:
//! the existing list contract remains root-only, while this operation walks the
//! already bounded root/direct-child discovery candidates and reports each
//! registered child independently.  No candidate is initialized, migrated, or
//! opened through a write-capable Workspace connection.

use std::collections::HashMap;

use forge_domain::{LocationId, LocationRevision, RegisteredWorkspace, WorkspaceId};
use forge_persistence::WorkspaceStore;
use forge_workspace::{WorkspaceCandidate, WorkspaceLocator, WorkspaceStateLayout};

use crate::service::{
    ForgeControl, MAX_WORKSPACE_CATALOG_ENTRIES, ResolvedWorkspaceScope, map_location_error,
};
use crate::{ControlError, ControlErrorCode};

/// Read-only inventory of registered Workspaces at one observed Location
/// revision.  Entries retain discovery order: the Location root comes first,
/// followed by direct children in native-byte path order.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceInventory {
    location_id: LocationId,
    location_revision: LocationRevision,
    entries: Vec<WorkspaceInventoryEntry>,
}

impl WorkspaceInventory {
    const fn new(
        location_id: LocationId,
        location_revision: LocationRevision,
        entries: Vec<WorkspaceInventoryEntry>,
    ) -> Self {
        Self {
            location_id,
            location_revision,
            entries,
        }
    }

    pub const fn location_id(&self) -> LocationId {
        self.location_id
    }

    pub const fn location_revision(&self) -> LocationRevision {
        self.location_revision
    }

    pub fn entries(&self) -> &[WorkspaceInventoryEntry] {
        &self.entries
    }
}

/// One bounded inventory row.  A diagnostic row never carries a fabricated
/// scope: `known_workspace_id` is populated only when a separate read-only
/// identity observation could verify the durable UUID.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceInventoryEntry {
    Registered {
        scope: ResolvedWorkspaceScope,
        workspace: RegisteredWorkspace,
        display_name: String,
    },
    Unavailable {
        locator: WorkspaceLocator,
        code: ControlErrorCode,
        known_workspace_id: Option<WorkspaceId>,
    },
}

impl WorkspaceInventoryEntry {
    pub const fn locator(&self) -> &WorkspaceLocator {
        match self {
            Self::Registered { scope, .. } => scope.locator(),
            Self::Unavailable { locator, .. } => locator,
        }
    }

    pub const fn registered_scope(&self) -> Option<&ResolvedWorkspaceScope> {
        match self {
            Self::Registered { scope, .. } => Some(scope),
            Self::Unavailable { .. } => None,
        }
    }

    pub const fn registered_workspace(&self) -> Option<&RegisteredWorkspace> {
        match self {
            Self::Registered { workspace, .. } => Some(workspace),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn display_name(&self) -> Option<&str> {
        match self {
            Self::Registered { display_name, .. } => Some(display_name),
            Self::Unavailable { .. } => None,
        }
    }

    pub const fn unavailable_code(&self) -> Option<ControlErrorCode> {
        match self {
            Self::Registered { .. } => None,
            Self::Unavailable { code, .. } => Some(*code),
        }
    }

    pub const fn known_workspace_id(&self) -> Option<WorkspaceId> {
        match self {
            Self::Registered { workspace, .. } => Some(workspace.id()),
            Self::Unavailable {
                known_workspace_id, ..
            } => *known_workspace_id,
        }
    }
}

impl ForgeControl {
    /// Return every currently registered root/direct-child Workspace at one
    /// Location.  Uninitialized discovery candidates are omitted; malformed,
    /// foreign, or corrupt candidates remain explicit diagnostics so one bad
    /// child cannot hide healthy siblings.
    pub fn registered_workspace_inventory(
        &self,
        location_id: LocationId,
        expected_revision: LocationRevision,
    ) -> Result<WorkspaceInventory, ControlError> {
        let discovery = self
            .locations
            .discover_current(location_id, expected_revision)
            .map_err(map_location_error)?;
        let candidates = discovery.candidates();
        if candidates.len() > MAX_WORKSPACE_CATALOG_ENTRIES {
            return Err(ControlError::new(ControlErrorCode::CapacityExceeded));
        }

        let mut entries = Vec::with_capacity(candidates.len());
        let mut known_ids: HashMap<WorkspaceId, Vec<usize>> = HashMap::new();
        for candidate in candidates {
            let locator = candidate
                .key()
                .locator(expected_revision)
                .map_err(|source| {
                    ControlError::with_source(ControlErrorCode::InvalidInput, source)
                })?;
            match self.inspect_resolved_workspace(location_id, expected_revision, &locator) {
                Ok((scope, _layout, workspace)) => {
                    let entry_index = entries.len();
                    known_ids
                        .entry(workspace.id())
                        .or_default()
                        .push(entry_index);
                    entries.push(WorkspaceInventoryEntry::Registered {
                        scope,
                        workspace,
                        display_name: candidate.display_label().into_owned(),
                    });
                }
                Err(error) if error.code() == ControlErrorCode::WorkspaceNotInitialized => {}
                Err(error) => {
                    let known_workspace_id = known_workspace_id(candidate);
                    let entry_index = entries.len();
                    if let Some(workspace_id) = known_workspace_id {
                        known_ids.entry(workspace_id).or_default().push(entry_index);
                    }
                    entries.push(WorkspaceInventoryEntry::Unavailable {
                        locator,
                        code: error.code(),
                        known_workspace_id,
                    });
                }
            }
        }

        classify_duplicate_identities(&mut entries, known_ids);

        // Discovery and each per-candidate inspection are individually
        // revision-fenced.  Recheck once more before publishing the aggregate
        // so a Location transition during the bounded read is never hidden.
        self.locations
            .get_current_location(location_id, expected_revision)
            .map_err(map_location_error)?;

        Ok(WorkspaceInventory::new(
            location_id,
            expected_revision,
            entries,
        ))
    }
}

fn known_workspace_id(candidate: &WorkspaceCandidate) -> Option<WorkspaceId> {
    let layout = WorkspaceStateLayout::inspect_existing(candidate.absolute_root()).ok()??;
    WorkspaceStore::inspect_existing_identity_live_read_only(&layout)
        .ok()
        .map(|workspace| workspace.id())
}

fn classify_duplicate_identities(
    entries: &mut [WorkspaceInventoryEntry],
    known_ids: HashMap<WorkspaceId, Vec<usize>>,
) {
    for (workspace_id, indices) in known_ids {
        if indices.len() < 2 {
            continue;
        }
        for index in indices {
            let locator = entries[index].locator().clone();
            entries[index] = WorkspaceInventoryEntry::Unavailable {
                locator,
                code: ControlErrorCode::WorkspaceIdentityConflict,
                known_workspace_id: Some(workspace_id),
            };
        }
    }
}

#[cfg(test)]
mod tests;
