//! Crate-private authority for journaling an already admitted execution.
//!
//! An [`ExecutionJournalAuthority`] is minted only from the checked Workspace
//! store used by admission. It retains the original scope and physical layout
//! so output and terminal facts can still be written after the Location's
//! current revision changes. It cannot admit another execution or authorize a
//! source effect.

use forge_domain::{
    ActivityId, CompleteExecution, ExecutionAgentProvenance, ExecutionId, ExecutionOutputCursor,
    ExecutionOutputEvent, ExecutionOutputSequence, ExecutionRequestDigest, ExecutionState,
    FailExecution, GeneratedPackageManifest, MAX_EXECUTION_OUTPUT_READ_BYTES,
    MAX_EXECUTION_OUTPUT_READ_EVENTS, RegisteredExecution, WorkspaceId,
};
use forge_persistence::{WorkspaceJournalBinding, WorkspaceStore};
use forge_workspace::ExistingWorkspaceStateLayout;
use std::fmt;

use crate::error::{ControlError, ControlErrorCode};
use crate::service::{
    ForgeControl, ResolvedWorkspaceScope, map_activity_store_error, map_state_layout_error,
};

const JOURNAL_RECONCILIATION_PAGE_EVENTS: usize = MAX_EXECUTION_OUTPUT_READ_EVENTS;

/// Opaque capability for output and terminal journaling of one admitted
/// execution. Its fields are intentionally private to this control module.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExecutionJournalAuthority {
    scope: ResolvedWorkspaceScope,
    layout: ExistingWorkspaceStateLayout,
    binding: WorkspaceJournalBinding,
    execution_id: ExecutionId,
    activity_id: ActivityId,
    request_digest: ExecutionRequestDigest,
    provenance: Option<ExecutionAgentProvenance>,
}

/// Outcome of one authority-bound reconciliation read. An unavailable or
/// invalid read remains the `Err` path so callers cannot mistake uncertainty
/// for a durable classification.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalReadback {
    Confirmed,
    Absent,
    Mismatch,
}

/// Exact terminal command retained across `QueueFull` and unknown-result retry.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum JournalTerminalCommand {
    Complete {
        command: CompleteExecution,
        manifest: Option<GeneratedPackageManifest>,
    },
    Fail {
        command: FailExecution,
    },
}

impl fmt::Debug for JournalTerminalCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, manifest_present) = match self {
            Self::Complete { manifest, .. } => ("complete", manifest.is_some()),
            Self::Fail { .. } => ("fail", false),
        };
        formatter
            .debug_struct("JournalTerminalCommand")
            .field("id", &self.id())
            .field("expected_revision", &self.expected_revision())
            .field("observed_at", &self.observed_at())
            .field("kind", &kind)
            .field("manifest_present", &manifest_present)
            .finish_non_exhaustive()
    }
}

impl JournalTerminalCommand {
    pub(crate) const fn id(&self) -> ExecutionId {
        match self {
            Self::Complete { command, .. } => command.id(),
            Self::Fail { command } => command.id(),
        }
    }

    pub(crate) const fn expected_revision(&self) -> forge_domain::ExecutionRevision {
        match self {
            Self::Complete { command, .. } => command.expected_revision(),
            Self::Fail { command } => command.expected_revision(),
        }
    }

    pub(crate) const fn observed_at(&self) -> forge_domain::TimestampMillis {
        match self {
            Self::Complete { command, .. } => command.observed_at(),
            Self::Fail { command } => command.observed_at(),
        }
    }
}

impl fmt::Debug for ExecutionJournalAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionJournalAuthority")
            .field("workspace_id", &self.scope.workspace_id())
            .field("activity_id", &self.activity_id)
            .field("execution_id", &self.execution_id)
            .finish_non_exhaustive()
    }
}

impl ExecutionJournalAuthority {
    /// Mint the capability from the exact checked admission store and record.
    /// No caller can supply a replacement root, binding, Workspace, or digest.
    pub(crate) fn capture(
        scope: &ResolvedWorkspaceScope,
        layout: &ExistingWorkspaceStateLayout,
        store: &WorkspaceStore,
        record: &RegisteredExecution,
    ) -> Result<Self, ControlError> {
        let workspace = store.workspace().map_err(map_activity_store_error)?;
        validate_scope_layout(scope, layout, &workspace)?;
        let admitted = store
            .get_execution(record.id())
            .map_err(map_activity_store_error)?
            .ok_or_else(|| ControlError::new(ControlErrorCode::ExecutionNotFound))?;
        if admitted != *record {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        validate_record_identity(
            scope.workspace_id(),
            &admitted,
            record.id(),
            record.activity_id(),
            record.request_digest(),
            record.provenance(),
        )?;
        let binding = store.journal_binding().map_err(map_activity_store_error)?;
        Ok(Self {
            scope: scope.clone(),
            layout: layout.clone(),
            binding,
            execution_id: record.id(),
            activity_id: record.activity_id(),
            request_digest: record.request_digest(),
            provenance: record.provenance().cloned(),
        })
    }

    pub(crate) const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub(crate) const fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }
}

impl ForgeControl {
    /// Append output through the captured current-schema Workspace journal.
    pub(crate) fn execution_journal_output<E>(
        authority: &ExecutionJournalAuthority,
        events: E,
    ) -> Result<(), ControlError>
    where
        E: AsRef<[ExecutionOutputEvent]>,
    {
        let events = events.as_ref();
        validate_output_events(authority.execution_id, events)?;
        let mut store = open_journal_store(authority)?;
        let before = journal_record(&store, authority)?;
        store
            .append_execution_output_events(events)
            .map_err(map_activity_store_error)?;
        let after = journal_record(&store, authority).map_err(|_| ControlError::committed())?;
        validate_record_identity(
            authority.scope.workspace_id(),
            &after,
            before.id(),
            authority.activity_id,
            authority.request_digest,
            authority.provenance.as_ref(),
        )
        .map_err(|_| ControlError::committed())
    }

    /// Complete an admitted execution through its captured journal authority.
    pub(crate) fn execution_journal_complete(
        authority: &ExecutionJournalAuthority,
        command: &CompleteExecution,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
    ) -> Result<RegisteredExecution, ControlError> {
        validate_complete_command(authority, command)?;
        validate_closure_identity(authority, closure.as_ref())?;
        let mut store = open_journal_store(authority)?;
        let before = journal_record(&store, authority)?;
        validate_expected_revision(before.revision(), command.expected_revision())?;
        let record = store
            .complete_execution_with_native_closure(command, None, closure)
            .map_err(map_activity_store_error)?;
        post_commit_record(authority.scope.workspace_id(), &store, authority, &record)?;
        Ok(record)
    }

    /// Complete a generated-package execution with the same sealed journal
    /// authority and exact manifest identity.
    pub(crate) fn execution_journal_complete_generated(
        authority: &ExecutionJournalAuthority,
        command: &CompleteExecution,
        manifest: GeneratedPackageManifest,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
    ) -> Result<RegisteredExecution, ControlError> {
        validate_complete_command(authority, command)?;
        validate_closure_identity(authority, closure.as_ref())?;
        validate_generated_manifest_identity(
            authority.execution_id,
            authority.scope.workspace_id(),
            manifest,
        )?;
        let mut store = open_journal_store(authority)?;
        let before = journal_record(&store, authority)?;
        validate_expected_revision(before.revision(), command.expected_revision())?;
        let record = store
            .complete_execution_with_native_closure(command, Some(manifest), closure)
            .map_err(map_activity_store_error)?;
        post_commit_record(authority.scope.workspace_id(), &store, authority, &record)?;
        Ok(record)
    }

    /// Persist a typed launch or supervision failure for the admitted record.
    pub(crate) fn execution_journal_fail(
        authority: &ExecutionJournalAuthority,
        command: FailExecution,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
    ) -> Result<RegisteredExecution, ControlError> {
        validate_closure_identity(authority, closure.as_ref())?;
        if command.id() != authority.execution_id {
            return Err(ControlError::new(
                ControlErrorCode::ExecutionProvenanceConflict,
            ));
        }
        let mut store = open_journal_store(authority)?;
        let before = journal_record(&store, authority)?;
        validate_expected_revision(before.revision(), command.expected_revision())?;
        let record = store
            .fail_execution_with_native_closure(command, closure)
            .map_err(map_activity_store_error)?;
        post_commit_record(authority.scope.workspace_id(), &store, authority, &record)?;
        Ok(record)
    }

    /// Reconcile one exact retained output prefix through the captured store.
    /// Later durable events are permitted once the requested prefix matches.
    pub(crate) fn execution_journal_reconcile_output(
        authority: &ExecutionJournalAuthority,
        before: &RegisteredExecution,
        expected: &[ExecutionOutputEvent],
    ) -> Result<JournalReadback, ControlError> {
        validate_record_identity(
            authority.scope.workspace_id(),
            before,
            authority.execution_id,
            authority.activity_id,
            authority.request_digest,
            authority.provenance.as_ref(),
        )?;
        if !before.state().is_active() {
            return Ok(JournalReadback::Mismatch);
        }
        validate_output_events(authority.execution_id, expected)?;
        if expected.len() > MAX_EXECUTION_OUTPUT_READ_EVENTS {
            return Err(ControlError::new(ControlErrorCode::CapacityExceeded));
        }

        let store = open_journal_store(authority)?;
        let current = reconciliation_record(&store, authority)?;
        if !same_execution_definition(before, &current) {
            return Err(ControlError::committed());
        }
        if expected.is_empty() {
            ensure_record_stable(&store, authority, &current)?;
            return Ok(if current == *before {
                JournalReadback::Absent
            } else {
                JournalReadback::Mismatch
            });
        }

        let first_sequence = expected[0].sequence();
        let mut cursor = cursor_before(authority.execution_id, first_sequence)?;
        let mut matched = 0_usize;
        loop {
            let read = store
                .read_execution_output_events(
                    cursor,
                    MAX_EXECUTION_OUTPUT_READ_BYTES,
                    JOURNAL_RECONCILIATION_PAGE_EVENTS,
                )
                .map_err(|_| ControlError::committed())?;
            for event in read.events() {
                if matched == expected.len() {
                    break;
                }
                if event != &expected[matched] {
                    let after = reconciliation_record(&store, authority)?;
                    if after != current || !same_execution_definition(before, &after) {
                        return Err(ControlError::committed());
                    }
                    return Ok(JournalReadback::Mismatch);
                }
                matched += 1;
            }
            if matched == expected.len() {
                let after = reconciliation_record(&store, authority)?;
                if !same_execution_definition(before, &after) {
                    return Err(ControlError::committed());
                }
                if after != current {
                    return Err(ControlError::committed());
                }
                return Ok(JournalReadback::Confirmed);
            }
            if !read.truncated() {
                let after = reconciliation_record(&store, authority)?;
                if after != current {
                    return Err(ControlError::committed());
                }
                return Ok(if matched == 0 && current == *before {
                    JournalReadback::Absent
                } else {
                    JournalReadback::Mismatch
                });
            }
            let next = read.next_cursor();
            if next == cursor {
                return Err(ControlError::committed());
            }
            cursor = next;
        }
    }

    /// Reconcile an exact terminal command and optional generated manifest.
    pub(crate) fn execution_journal_reconcile_terminal(
        authority: &ExecutionJournalAuthority,
        before: &RegisteredExecution,
        command: &JournalTerminalCommand,
        closure: Option<forge_domain::ExecutionNativeClosureFact>,
    ) -> Result<JournalReadback, ControlError> {
        validate_closure_identity(authority, closure.as_ref())?;
        validate_record_identity(
            authority.scope.workspace_id(),
            before,
            authority.execution_id,
            authority.activity_id,
            authority.request_digest,
            authority.provenance.as_ref(),
        )?;
        if !before.state().is_active() {
            return Ok(JournalReadback::Mismatch);
        }
        if command.id() != authority.execution_id
            || command.expected_revision() != before.revision()
        {
            return Ok(JournalReadback::Mismatch);
        }

        let store = open_journal_store(authority)?;
        let snapshot = store
            .execution_native_closure_snapshot(authority.execution_id)
            .map_err(|_| ControlError::committed())?
            .ok_or_else(ControlError::committed)?;
        let current = snapshot.record();
        let manifest = snapshot.manifest();
        let actual_closure = snapshot.closure();
        validate_record_identity(
            authority.scope.workspace_id(),
            current,
            authority.execution_id,
            authority.activity_id,
            authority.request_digest,
            authority.provenance.as_ref(),
        )
        .map_err(|_| ControlError::committed())?;
        if !same_execution_definition(before, current) {
            return Ok(JournalReadback::Mismatch);
        }
        if current == before && manifest.is_none() && actual_closure.is_none() {
            return Ok(JournalReadback::Absent);
        }
        let expected_revision = before
            .revision()
            .checked_next()
            .map_err(|_| ControlError::committed())?;
        if current.revision() != expected_revision
            || current.timestamps().updated_at() != command.observed_at()
        {
            return Ok(JournalReadback::Mismatch);
        }

        let exact = match command {
            JournalTerminalCommand::Complete {
                command,
                manifest: expected_manifest,
            } => {
                let expected_state = forge_domain::execution_state_for_outcome(command.outcome());
                current.state() == expected_state
                    && current.outcome() == Some(command.outcome())
                    && current.failure_code().is_none()
                    && manifest == *expected_manifest
            }
            JournalTerminalCommand::Fail { command } => {
                current.state() == ExecutionState::Failed
                    && current.outcome().is_none()
                    && current.failure_code() == Some(command.failure_code())
                    && manifest.is_none()
            }
        };
        Ok(if exact && actual_closure == closure {
            JournalReadback::Confirmed
        } else {
            JournalReadback::Mismatch
        })
    }
}

fn validate_closure_identity(
    authority: &ExecutionJournalAuthority,
    closure: Option<&forge_domain::ExecutionNativeClosureFact>,
) -> Result<(), ControlError> {
    if let Some(closure) = closure
        && (closure.attribution().id() != authority.execution_id
            || closure.attribution().workspace_id() != authority.scope.workspace_id()
            || closure.attribution().activity_id() != authority.activity_id
            || closure.request_digest() != authority.request_digest)
    {
        return Err(ControlError::new(
            ControlErrorCode::ExecutionProvenanceConflict,
        ));
    }
    Ok(())
}

fn open_journal_store(
    authority: &ExecutionJournalAuthority,
) -> Result<WorkspaceStore, ControlError> {
    WorkspaceStore::open_existing_journal(&authority.layout, &authority.binding)
        .map_err(map_activity_store_error)
}

fn reconciliation_record(
    store: &WorkspaceStore,
    authority: &ExecutionJournalAuthority,
) -> Result<RegisteredExecution, ControlError> {
    let record = store
        .get_execution(authority.execution_id)
        .map_err(|_| ControlError::committed())?;
    let record = record.ok_or_else(ControlError::committed)?;
    validate_record_identity(
        authority.scope.workspace_id(),
        &record,
        authority.execution_id,
        authority.activity_id,
        authority.request_digest,
        authority.provenance.as_ref(),
    )
    .map_err(|_| ControlError::committed())?;
    Ok(record)
}

fn ensure_record_stable(
    store: &WorkspaceStore,
    authority: &ExecutionJournalAuthority,
    current: &RegisteredExecution,
) -> Result<(), ControlError> {
    let after = reconciliation_record(store, authority)?;
    if after == *current {
        Ok(())
    } else {
        Err(ControlError::committed())
    }
}

fn cursor_before(
    execution_id: ExecutionId,
    sequence: ExecutionOutputSequence,
) -> Result<ExecutionOutputCursor, ControlError> {
    if sequence == ExecutionOutputSequence::INITIAL {
        return Ok(ExecutionOutputCursor::initial(execution_id));
    }
    let previous = sequence
        .get()
        .checked_sub(1)
        .and_then(|value| ExecutionOutputSequence::new(value).ok())
        .ok_or_else(|| ControlError::new(ControlErrorCode::ExecutionConflict))?;
    Ok(ExecutionOutputCursor::from_sequence(execution_id, previous))
}

fn journal_record(
    store: &WorkspaceStore,
    authority: &ExecutionJournalAuthority,
) -> Result<RegisteredExecution, ControlError> {
    let record = store
        .get_execution(authority.execution_id)
        .map_err(map_activity_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::ExecutionNotFound))?;
    validate_record_identity(
        authority.scope.workspace_id(),
        &record,
        authority.execution_id,
        authority.activity_id,
        authority.request_digest,
        authority.provenance.as_ref(),
    )?;
    Ok(record)
}

fn validate_scope_layout(
    scope: &ResolvedWorkspaceScope,
    layout: &ExistingWorkspaceStateLayout,
    workspace: &forge_domain::RegisteredWorkspace,
) -> Result<(), ControlError> {
    let root_fingerprint = layout.root_fingerprint().map_err(map_state_layout_error)?;
    if workspace.id() != scope.workspace_id() {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ));
    }
    if workspace.revision() != scope.workspace_revision() {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceRevisionConflict,
        ));
    }
    if workspace.location_id() != scope.locator().location_id() {
        return Err(ControlError::new(
            ControlErrorCode::WorkspaceIdentityConflict,
        ));
    }
    if workspace.root().as_path() != layout.workspace_root()
        || workspace.root_fingerprint() != root_fingerprint
    {
        return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
    }
    Ok(())
}

fn validate_record_identity(
    workspace_id: WorkspaceId,
    record: &RegisteredExecution,
    expected_execution_id: ExecutionId,
    expected_activity_id: ActivityId,
    expected_digest: ExecutionRequestDigest,
    expected_provenance: Option<&ExecutionAgentProvenance>,
) -> Result<(), ControlError> {
    if record.id().into_uuid().is_nil()
        || record.workspace_id().into_uuid().is_nil()
        || record.activity_id().into_uuid().is_nil()
        || record.id() != expected_execution_id
        || record.workspace_id() != workspace_id
        || record.activity_id() != expected_activity_id
        || record.request_digest() != expected_digest
        || record.provenance() != expected_provenance
    {
        return Err(ControlError::new(
            ControlErrorCode::ExecutionProvenanceConflict,
        ));
    }
    Ok(())
}

fn same_execution_definition(before: &RegisteredExecution, current: &RegisteredExecution) -> bool {
    before.id() == current.id()
        && before.workspace_id() == current.workspace_id()
        && before.activity_id() == current.activity_id()
        && before.mode() == current.mode()
        && before.cwd() == current.cwd()
        && before.limits() == current.limits()
        && before.permissions() == current.permissions()
        && before.request_digest() == current.request_digest()
        && before.provenance() == current.provenance()
}

fn post_commit_record(
    workspace_id: WorkspaceId,
    store: &WorkspaceStore,
    authority: &ExecutionJournalAuthority,
    record: &RegisteredExecution,
) -> Result<(), ControlError> {
    validate_record_identity(
        workspace_id,
        record,
        authority.execution_id,
        authority.activity_id,
        authority.request_digest,
        authority.provenance.as_ref(),
    )
    .map_err(|_| ControlError::committed())?;
    let _post_record = journal_record(store, authority).map_err(|_| ControlError::committed())?;
    Ok(())
}

fn validate_output_events(
    execution_id: ExecutionId,
    events: &[ExecutionOutputEvent],
) -> Result<(), ControlError> {
    if events
        .iter()
        .all(|event| event.execution_id() == execution_id)
    {
        Ok(())
    } else {
        Err(ControlError::new(
            ControlErrorCode::ExecutionProvenanceConflict,
        ))
    }
}

fn validate_complete_command(
    authority: &ExecutionJournalAuthority,
    command: &CompleteExecution,
) -> Result<(), ControlError> {
    validate_complete_identity(authority.execution_id, command)
}

fn validate_complete_identity(
    expected_execution_id: ExecutionId,
    command: &CompleteExecution,
) -> Result<(), ControlError> {
    if command.id() != expected_execution_id || command.outcome().id() != expected_execution_id {
        return Err(ControlError::new(
            ControlErrorCode::ExecutionProvenanceConflict,
        ));
    }
    Ok(())
}

fn validate_expected_revision(
    actual: forge_domain::ExecutionRevision,
    expected: forge_domain::ExecutionRevision,
) -> Result<(), ControlError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ControlError::new(ControlErrorCode::ExecutionConflict))
    }
}

fn validate_generated_manifest_identity(
    expected_execution_id: ExecutionId,
    expected_workspace_id: WorkspaceId,
    manifest: GeneratedPackageManifest,
) -> Result<(), ControlError> {
    if manifest.execution_id() == expected_execution_id
        && manifest.workspace_id() == expected_workspace_id
    {
        Ok(())
    } else {
        Err(ControlError::new(
            ControlErrorCode::ExecutionProvenanceConflict,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{
        BeginExecution, BoundedExecutionOutput, CreateActivity, EstablishWorkspace,
        ExecutionAttribution, ExecutionCompletionStatus, ExecutionKind, ExecutionLimits,
        ExecutionOutputChunk, ExecutionOutputLimit, ExecutionOutputSequence, ExecutionOutputStream,
        ExecutionPermissions, ExecutionProgram, ExecutionRequest, ExecutionRequestDigest,
        ExecutionRevision, ExecutionTermination, ExecutionTimeoutMillis, FailExecution,
        FileByteCount, FileContentHash, LocationId, LocationRevision, LocationState,
        MarkExecutionRunning, RuntimeInstanceId, SetLocationState, TimestampMillis, WorkspaceId,
        WorkspaceRevision, WorkspaceRoot,
    };
    use forge_persistence::{GlobalRegistry, WorkspaceStore};
    use forge_workspace::{LocationService, WorkspaceLocator, WorkspaceStateLayout};
    use std::fs;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn execution(value: u128) -> ExecutionId {
        ExecutionId::from_uuid(Uuid::from_u128(value))
    }

    fn outcome(execution_id: ExecutionId) -> forge_domain::ExecutionOutcome {
        outcome_with_exit(execution_id, Some(0))
    }

    fn outcome_with_exit(
        execution_id: ExecutionId,
        exit_code: Option<i32>,
    ) -> forge_domain::ExecutionOutcome {
        forge_domain::ExecutionOutcome::new(
            execution_id,
            ExecutionTermination::new(ExecutionCompletionStatus::Exited, exit_code, None),
            1,
            BoundedExecutionOutput::new(b"stdout".to_vec(), 6, false),
            BoundedExecutionOutput::new(Vec::new(), 0, false),
        )
    }

    fn max_chunks(
        execution_id: ExecutionId,
        first_sequence: u64,
        count: usize,
        byte: u8,
    ) -> Result<Vec<ExecutionOutputEvent>, Box<dyn std::error::Error>> {
        let bytes = vec![byte; forge_domain::EXECUTION_OUTPUT_CHUNK_BYTES];
        (0..count)
            .map(|offset| {
                let sequence =
                    ExecutionOutputSequence::new(first_sequence + u64::try_from(offset)?)?;
                Ok(ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
                    execution_id,
                    sequence,
                    ExecutionOutputStream::Stdout,
                    &bytes,
                )?))
            })
            .collect()
    }

    struct NativeJournalFixture {
        root: PathBuf,
        registry_path: PathBuf,
        layout: forge_workspace::ExistingWorkspaceStateLayout,
        scope: ResolvedWorkspaceScope,
        location_id: LocationId,
        workspace_id: WorkspaceId,
        activity_id: ActivityId,
    }

    impl NativeJournalFixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let root = std::env::temp_dir()
                .join(format!("forge-execution-journal-native-{}", Uuid::now_v7()));
            let location_root = root.join("location");
            let workspace_root = location_root.join("workspace");
            fs::create_dir_all(&workspace_root)?;
            let registry_path = root.join("registry.sqlite3");
            let location_id = LocationId::from_uuid(Uuid::now_v7());
            let mut locations = LocationService::new(GlobalRegistry::open(&registry_path)?);
            let _location = locations.register_selected_path(
                location_id,
                "Journal fixture",
                &location_root,
                TimestampMillis::new(1)?,
            )?;
            drop(locations);

            let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
            let workspace_id = WorkspaceId::from_uuid(Uuid::now_v7());
            let establish = EstablishWorkspace::new(
                workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(workspace_root.clone())?,
                layout.root_fingerprint()?,
                TimestampMillis::new(2)?,
            );
            let mut store = WorkspaceStore::open(&layout, &establish)?;
            let activity_id = ActivityId::from_uuid(Uuid::now_v7());
            store.create_activity(&CreateActivity::new(
                activity_id,
                workspace_id,
                WorkspaceRevision::INITIAL,
                TimestampMillis::new(3)?,
            ))?;
            drop(store);
            let existing = WorkspaceStateLayout::inspect_existing(&workspace_root)?
                .ok_or("journal fixture layout disappeared")?;
            let locator = WorkspaceLocator::new(
                location_id,
                LocationRevision::INITIAL,
                Path::new("workspace"),
            )?;
            let scope = ResolvedWorkspaceScope::from_observation(
                workspace_id,
                WorkspaceRevision::INITIAL,
                locator,
            );
            Ok(Self {
                root,
                registry_path,
                layout: existing,
                scope,
                location_id,
                workspace_id,
                activity_id,
            })
        }

        fn admit(
            &self,
            raw_id: u128,
            observed_at: i64,
        ) -> Result<(ExecutionJournalAuthority, RegisteredExecution), Box<dyn std::error::Error>>
        {
            self.admit_with_output_limit(raw_id, observed_at, 8_192)
        }

        fn admit_with_output_limit(
            &self,
            raw_id: u128,
            observed_at: i64,
            output_limit: u64,
        ) -> Result<(ExecutionJournalAuthority, RegisteredExecution), Box<dyn std::error::Error>>
        {
            let execution_id = execution(raw_id);
            let request = ExecutionRequest::new(
                ExecutionAttribution::new(execution_id, self.workspace_id, self.activity_id),
                ExecutionKind::Structured {
                    program: ExecutionProgram::new(PathBuf::from("/usr/bin/true"))?,
                    arguments: Vec::new(),
                },
                None,
                ExecutionLimits::new(
                    ExecutionTimeoutMillis::new(30_000)?,
                    ExecutionOutputLimit::new(output_limit)?,
                ),
                ExecutionPermissions::new(false, false, false),
            )?;
            let mut store = WorkspaceStore::open_existing(&self.layout)?;
            let begin = BeginExecution::from_request(
                &request,
                ExecutionRequestDigest::from_bytes([0x71; 32]),
                TimestampMillis::new(observed_at)?,
            )
            .with_runtime_owner(RuntimeInstanceId::from_uuid(Uuid::now_v7()));
            let admitted = store.begin_execution(&begin)?;
            let running = store.mark_execution_running(MarkExecutionRunning::new(
                execution_id,
                admitted.record().revision(),
                TimestampMillis::new(observed_at + 1)?,
            ))?;
            let authority =
                ExecutionJournalAuthority::capture(&self.scope, &self.layout, &store, &running)?;
            Ok((authority, running))
        }

        fn disable(&self) -> Result<(), Box<dyn std::error::Error>> {
            let mut locations = LocationService::new(GlobalRegistry::open(&self.registry_path)?);
            locations.set_location_state(&SetLocationState::new(
                self.location_id,
                LocationRevision::INITIAL,
                LocationState::Disabled,
                TimestampMillis::new(20)?,
            ))?;
            Ok(())
        }

        fn cleanup(self) -> Result<(), Box<dyn std::error::Error>> {
            fs::remove_dir_all(self.root)?;
            Ok(())
        }
    }

    #[test]
    fn foreign_terminal_command_is_rejected_before_store_access() -> Result<(), ControlError> {
        let expected = execution(1);
        let command = CompleteExecution::new(
            ExecutionRevision::INITIAL,
            TimestampMillis::new(1).map_err(|_| ControlError::new(ControlErrorCode::Internal))?,
            outcome(execution(2)),
        );
        let error = validate_complete_identity(expected, &command)
            .err()
            .ok_or_else(|| ControlError::new(ControlErrorCode::Internal))?;
        assert_eq!(error.code(), ControlErrorCode::ExecutionProvenanceConflict);
        Ok(())
    }

    #[test]
    fn stale_terminal_revision_is_rejected_before_store_access() -> Result<(), ControlError> {
        let error = validate_expected_revision(
            ExecutionRevision::new(2).map_err(|_| ControlError::new(ControlErrorCode::Internal))?,
            ExecutionRevision::INITIAL,
        )
        .err()
        .ok_or_else(|| ControlError::new(ControlErrorCode::Internal))?;
        assert_eq!(error.code(), ControlErrorCode::ExecutionConflict);
        Ok(())
    }

    #[test]
    fn foreign_generated_manifest_is_rejected_before_store_access() -> Result<(), ControlError> {
        let manifest = GeneratedPackageManifest::new(
            WorkspaceId::from_uuid(Uuid::from_u128(2)),
            execution(2),
            FileContentHash::from_bytes([0xA5; 32]),
            FileByteCount::new(1),
        );
        let error = validate_generated_manifest_identity(
            execution(1),
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            manifest,
        )
        .err()
        .ok_or_else(|| ControlError::new(ControlErrorCode::Internal))?;
        assert_eq!(error.code(), ControlErrorCode::ExecutionProvenanceConflict);
        Ok(())
    }

    #[test]
    fn output_events_are_bound_to_one_execution_identity() -> Result<(), Box<dyn std::error::Error>>
    {
        let expected = execution(1);
        let matching = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            expected,
            ExecutionOutputSequence::INITIAL,
            ExecutionOutputStream::Stdout,
            b"ok",
        )?);
        validate_output_events(expected, std::slice::from_ref(&matching))?;

        let foreign = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            execution(2),
            ExecutionOutputSequence::INITIAL,
            ExecutionOutputStream::Stdout,
            b"foreign",
        )?);
        let error = validate_output_events(expected, std::slice::from_ref(&foreign))
            .err()
            .ok_or_else(|| std::io::Error::other("foreign output event was accepted"))?;
        assert_eq!(error.code(), ControlErrorCode::ExecutionProvenanceConflict);
        Ok(())
    }

    fn assert_native_output_reconciliation(
        authority: &ExecutionJournalAuthority,
        running: &RegisteredExecution,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            running.id(),
            ExecutionOutputSequence::INITIAL,
            ExecutionOutputStream::Stdout,
            b"native-journal",
        )?);
        assert_eq!(
            ForgeControl::execution_journal_reconcile_output(
                authority,
                running,
                std::slice::from_ref(&event),
            )?,
            JournalReadback::Absent
        );
        ForgeControl::execution_journal_output(authority, std::slice::from_ref(&event))?;
        assert_eq!(
            ForgeControl::execution_journal_reconcile_output(
                authority,
                running,
                std::slice::from_ref(&event),
            )?,
            JournalReadback::Confirmed
        );

        let later = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            running.id(),
            ExecutionOutputSequence::new(2)?,
            ExecutionOutputStream::Stdout,
            b"later",
        )?);
        ForgeControl::execution_journal_output(authority, std::slice::from_ref(&later))?;
        assert_eq!(
            ForgeControl::execution_journal_reconcile_output(
                authority,
                running,
                std::slice::from_ref(&later),
            )?,
            JournalReadback::Confirmed
        );

        let mismatch = ExecutionOutputEvent::Chunk(ExecutionOutputChunk::new(
            running.id(),
            ExecutionOutputSequence::INITIAL,
            ExecutionOutputStream::Stdout,
            b"different",
        )?);
        assert_eq!(
            ForgeControl::execution_journal_reconcile_output(
                authority,
                running,
                std::slice::from_ref(&mismatch),
            )?,
            JournalReadback::Mismatch
        );
        Ok(())
    }

    fn assert_native_complete_reconciliation(
        authority: &ExecutionJournalAuthority,
        running: &RegisteredExecution,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let terminal = JournalTerminalCommand::Complete {
            command: CompleteExecution::new(
                running.revision(),
                TimestampMillis::new(30)?,
                outcome(running.id()),
            ),
            manifest: None,
        };
        assert_eq!(
            ForgeControl::execution_journal_reconcile_terminal(
                authority, running, &terminal, None
            )?,
            JournalReadback::Absent
        );
        let completed = match &terminal {
            JournalTerminalCommand::Complete { command, .. } => {
                ForgeControl::execution_journal_complete(authority, command, None)?
            }
            JournalTerminalCommand::Fail { .. } => {
                return Err("fixture terminal command was not complete".into());
            }
        };
        assert_eq!(completed.state(), forge_domain::ExecutionState::Completed);
        let expected_closure = forge_domain::ExecutionNativeClosureFact::from_parts(
            forge_domain::ExecutionNativeClosureFactParts {
                attribution: forge_domain::ExecutionAttribution::new(
                    running.id(),
                    running.workspace_id(),
                    running.activity_id(),
                ),
                request_digest: running.request_digest(),
                before_revision: running.revision(),
                after_revision: completed.revision(),
                output_cursor: ExecutionOutputCursor::initial(running.id()),
                launch: forge_domain::NativeClosureLaunch::Baseline,
                runtime: forge_domain::NativeClosureRuntime::NotApplicable,
                process: forge_domain::NativeClosureProcess::NoChildSpawned,
                observed_at: completed.timestamps().updated_at(),
            },
        )?;
        assert_eq!(
            ForgeControl::execution_journal_reconcile_terminal(
                authority,
                running,
                &terminal,
                Some(expected_closure)
            )?,
            JournalReadback::Mismatch,
            "terminal without its requested fact cannot confirm native closure"
        );
        assert_eq!(
            ForgeControl::execution_journal_reconcile_terminal(
                authority, running, &terminal, None
            )?,
            JournalReadback::Confirmed
        );

        let wrong_timestamp = JournalTerminalCommand::Complete {
            command: CompleteExecution::new(
                running.revision(),
                TimestampMillis::new(31)?,
                outcome(running.id()),
            ),
            manifest: None,
        };
        assert_eq!(
            ForgeControl::execution_journal_reconcile_terminal(
                authority,
                running,
                &wrong_timestamp,
                None,
            )?,
            JournalReadback::Mismatch
        );
        let wrong_outcome = JournalTerminalCommand::Complete {
            command: CompleteExecution::new(
                running.revision(),
                TimestampMillis::new(30)?,
                outcome_with_exit(running.id(), Some(1)),
            ),
            manifest: None,
        };
        assert_eq!(
            ForgeControl::execution_journal_reconcile_terminal(
                authority,
                running,
                &wrong_outcome,
                None
            )?,
            JournalReadback::Mismatch
        );
        Ok(())
    }

    fn assert_native_fail_reconciliation(
        authority: &ExecutionJournalAuthority,
        running: &RegisteredExecution,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fail_terminal = JournalTerminalCommand::Fail {
            command: FailExecution::new(
                running.id(),
                running.revision(),
                TimestampMillis::new(40)?,
                forge_domain::ExecutionFailureCode::ProcessSpawn,
            ),
        };
        assert_eq!(
            ForgeControl::execution_journal_reconcile_terminal(
                authority,
                running,
                &fail_terminal,
                None
            )?,
            JournalReadback::Absent
        );
        let failed = match &fail_terminal {
            JournalTerminalCommand::Fail { command } => {
                ForgeControl::execution_journal_fail(authority, *command, None)?
            }
            JournalTerminalCommand::Complete { .. } => {
                return Err("fixture terminal command was not fail".into());
            }
        };
        assert_eq!(failed.state(), forge_domain::ExecutionState::Failed);
        assert_eq!(
            ForgeControl::execution_journal_reconcile_terminal(
                authority,
                running,
                &fail_terminal,
                None
            )?,
            JournalReadback::Confirmed
        );
        Ok(())
    }

    #[test]
    fn native_journal_reconciles_output_and_terminal_after_location_disable()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = NativeJournalFixture::new()?;
        let (authority, running) = fixture.admit(0xA001, 10)?;
        let (fail_authority, fail_running) = fixture.admit(0xA002, 12)?;
        fixture.disable()?;
        assert_native_output_reconciliation(&authority, &running)?;
        assert_native_complete_reconciliation(&authority, &running)?;
        assert_native_fail_reconciliation(&fail_authority, &fail_running)?;
        let workspace_root = fixture.root.join("location/workspace");
        let moved_root = fixture.root.join("location/workspace-moved");
        fs::rename(&workspace_root, &moved_root)?;
        let missing_root =
            ForgeControl::execution_journal_reconcile_output(&authority, &running, &[]);
        assert!(missing_root.is_err());
        fs::rename(moved_root, workspace_root)?;
        fixture.cleanup()?;
        Ok(())
    }

    #[test]
    fn native_journal_confirms_max_prefix_with_truncated_later_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = NativeJournalFixture::new()?;
        let (authority, running) = fixture.admit_with_output_limit(0xA101, 10, 1_048_576)?;
        fixture.disable()?;
        let expected = max_chunks(running.id(), 1, MAX_EXECUTION_OUTPUT_READ_EVENTS, 0x61)?;

        ForgeControl::execution_journal_output(&authority, &expected[..1])?;
        assert_eq!(
            ForgeControl::execution_journal_reconcile_output(&authority, &running, &expected[..2],)?,
            JournalReadback::Mismatch
        );
        ForgeControl::execution_journal_output(&authority, &expected[1..])?;
        let later = max_chunks(running.id(), 129, MAX_EXECUTION_OUTPUT_READ_EVENTS, 0x62)?;
        ForgeControl::execution_journal_output(&authority, &later)?;

        let store = open_journal_store(&authority)?;
        let page = store.read_execution_output_events(
            ExecutionOutputCursor::initial(running.id()),
            MAX_EXECUTION_OUTPUT_READ_BYTES,
            MAX_EXECUTION_OUTPUT_READ_EVENTS,
        )?;
        assert!(page.truncated());
        assert_eq!(page.events(), expected.as_slice());
        drop(store);

        assert_eq!(
            ForgeControl::execution_journal_reconcile_output(&authority, &running, &expected)?,
            JournalReadback::Confirmed
        );
        fixture.cleanup()?;
        Ok(())
    }
}
