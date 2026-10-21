use std::path::Path;

use crate::source_tree::{
    SourceTreeMaterializationError, SourceTreeMutationRequest, TreePatchEvidence,
    materialize_source_tree_request,
};
use forge_domain::{
    AbandonDiffEvidence, ActivityId, ActivityState, BeginDiffEvidence, BeginFileMutation,
    BeginFileMutationResult, BeginFileMutationStatus, ChangeSetAttribution, ChangeSetId,
    ChangeSetState, CompleteDiffEvidence, CompleteFileMutation, DiffAttribution, DiffChangeKind,
    DiffContractVersions, DiffEntrySubject, DiffEntrySummary, DiffEvidenceState, DiffId,
    DiffPayloadProjection, DiffRenderKind, DiffRevision, FailFileMutation, FileByteCount,
    FileContentHash, FileListOptions, FileMutationId, FileMutationIdentity, FileMutationKind,
    FileMutationPlan, FileMutationRecord, FileMutationScope, FilePatch, GoalWorkAttribution,
    RegisteredDiffEvidence, RuntimeInstanceId, SourceLineRange, SourceTreeRequestDigest,
    SourceWriteAuthority, TextSearchOptions, TextSearchQuery, TimestampMillis,
    TreeChangeSetAdmissionStatus, TreeChangeSetIntent, TreeMutationId, WorkspaceRelativePath,
};
use forge_persistence::{
    BeginFileMutationDiffResult, WorkspaceStore, WorkspaceStoreError, WriterLeaseStoreError,
};
use forge_workspace::{
    CapturedDiffSource, ConfinedFileRead, ConfinedFilesystemError, ConfinedWorkspace,
    DiffArtifactStore, DiffArtifactStoreError, DiffRenderError, PatchReview, PreparedFileMutation,
    RenderedDiffEvidence, RenderedTextDiff, SourceTreeApplyError, StagedDiffArtifact,
    WorkspaceStateLayout, bounded_binary_content_hash, bounded_write_content_hash,
    render_diff_evidence, render_patch_diff_evidence,
};

use crate::error::{ControlError, ControlErrorCode, ControlErrorDetails};
use crate::service::{
    ForgeControl, ResolvedWorkspaceScope, map_activity_store_error, map_location_error,
    map_state_layout_error,
};
use crate::writer_lease::map_writer_lease_store_error;

fn map_file_mutation_store_error(error: WorkspaceStoreError) -> ControlError {
    if let WorkspaceStoreError::WriterLease(WriterLeaseStoreError::ScopeConflict {
        conflicting_lease_id,
    }) = &error
    {
        let lease_id = *conflicting_lease_id;
        return ControlError::with_source(ControlErrorCode::WriterLeaseConflict, error)
            .with_details(ControlErrorDetails::WriterLeaseConflict { lease_id });
    }
    if matches!(&error, WorkspaceStoreError::WriterLease(_)) {
        map_writer_lease_store_error(error)
    } else if matches!(
        &error,
        WorkspaceStoreError::ChangeSet(forge_persistence::ChangeSetStoreError::IdentityConflict)
            | WorkspaceStoreError::WorkCut(forge_persistence::WorkCutError::Conflict(_))
    ) {
        ControlError::with_source(ControlErrorCode::FileConflict, error)
    } else {
        map_activity_store_error(error)
    }
}

fn resolve_source_write_session(
    control: &ForgeControl,
    authority: SourceWriteAuthority,
) -> Result<(), ControlError> {
    let _session = control.agent_session_resolve(crate::AgentSessionResolveRequest {
        session_id: authority.session_id(),
        principal: authority.principal(),
    })?;
    Ok(())
}

const MAX_EFFECT_LOCATIONS: u32 = 1_000;
const MAX_EFFECT_LOCATIONS_USIZE: usize = 1_000;

/// Live Activity attribution required for one file request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileActivityScope {
    pub activity_id: ActivityId,
    pub runtime_instance_id: RuntimeInstanceId,
    pub observed_at: TimestampMillis,
}

/// Explicit transport/UI-neutral request for one confined file read.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReadRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
    pub path: WorkspaceRelativePath,
}

/// Confined read result. It exposes no absolute root or runtime lease owner.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReadResult {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    path: WorkspaceRelativePath,
    read: ConfinedFileRead,
}

/// Explicit transport/UI-neutral request for one bounded directory listing.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileListRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
    pub directory: Option<WorkspaceRelativePath>,
    pub options: FileListOptions,
}

/// Directory listing result carrying the exact scope and Activity attribution
/// used for the observation.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileListResult {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    result: forge_domain::FileListResult,
}

impl FileListResult {
    fn new(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        result: forge_domain::FileListResult,
    ) -> Self {
        Self {
            scope,
            activity_id,
            result,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn result(&self) -> &forge_domain::FileListResult {
        &self.result
    }

    pub fn directory(&self) -> Option<&WorkspaceRelativePath> {
        self.result.directory()
    }

    pub fn entries(&self) -> &[forge_domain::FileListEntry] {
        self.result.entries()
    }

    pub const fn scanned_entries(&self) -> usize {
        self.result.scanned_entries()
    }

    pub const fn truncated(&self) -> bool {
        self.result.truncated()
    }
}

/// Explicit transport/UI-neutral request for recursive literal source search.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSearchRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
    pub root: Option<WorkspaceRelativePath>,
    pub query: TextSearchQuery,
    pub options: TextSearchOptions,
}

/// Bounded source-search result with no native root disclosure.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextSearchResult {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    result: forge_domain::TextSearchResult,
}

impl TextSearchResult {
    fn new(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        result: forge_domain::TextSearchResult,
    ) -> Self {
        Self {
            scope,
            activity_id,
            result,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub const fn result(&self) -> &forge_domain::TextSearchResult {
        &self.result
    }

    pub fn root(&self) -> Option<&WorkspaceRelativePath> {
        self.result.root()
    }

    pub fn matches(&self) -> &[forge_domain::TextSearchMatch] {
        self.result.matches()
    }

    pub const fn scanned_entries(&self) -> usize {
        self.result.scanned_entries()
    }

    pub const fn scanned_files(&self) -> usize {
        self.result.scanned_files()
    }

    pub const fn truncated(&self) -> bool {
        self.result.truncated()
    }
}

/// Explicit transport/UI-neutral request for one bounded source line slice.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReadSliceRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
    pub path: WorkspaceRelativePath,
    pub line_range: SourceLineRange,
}

/// Source slice result. Whole-file and range hashes remain distinct in the
/// domain result and are exposed through separate accessors.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileReadSliceResult {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    path: WorkspaceRelativePath,
    result: forge_domain::FileReadSlice,
}

impl FileReadSliceResult {
    fn new(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        path: WorkspaceRelativePath,
        result: forge_domain::FileReadSlice,
    ) -> Self {
        Self {
            scope,
            activity_id,
            path,
            result,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn result(&self) -> &forge_domain::FileReadSlice {
        &self.result
    }

    pub const fn whole_file_hash(&self) -> FileContentHash {
        self.result.whole_file_hash()
    }

    pub const fn range_hash(&self) -> forge_domain::SourceRangeHash {
        self.result.range_hash()
    }

    pub const fn line_range(&self) -> SourceLineRange {
        self.result.line_range()
    }

    pub const fn total_lines(&self) -> u64 {
        self.result.total_lines()
    }

    pub fn content(&self) -> &[u8] {
        self.result.content()
    }

    pub fn line_hashes(&self) -> &[forge_domain::SourceRangeHash] {
        self.result.line_hashes()
    }

    pub const fn eol(&self) -> forge_domain::SourceEol {
        self.result.eol()
    }

    pub const fn has_final_newline(&self) -> bool {
        self.result.has_final_newline()
    }
}

/// Internal staged source-edit operation. Move is intentionally absent until
/// two-endpoint ChangeSet/Diff/checkpoint authority exists.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileApplyPatchOperation {
    Add {
        path: WorkspaceRelativePath,
        content: Vec<u8>,
    },
    Update {
        path: WorkspaceRelativePath,
        patch: FilePatch,
    },
    Delete {
        path: WorkspaceRelativePath,
        expected_whole_file_hash: FileContentHash,
    },
}

/// Activity-attributed source-edit request. Each operation is one durable
/// single-path `ChangeSet` and uses the existing checkpoint/Diff lifecycle.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileApplyPatchRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
    pub goal: Option<GoalWorkAttribution>,
    pub write_authority: SourceWriteAuthority,
    pub change_set_id: ChangeSetId,
    pub mutation_id: FileMutationId,
    pub operation: FileApplyPatchOperation,
}

/// Source-edit result uses the same durable mutation projection as legacy
/// create/replace/delete, allowing Diff and `ChangeSet` consumers to share one
/// result contract.
pub type FileApplyPatchResult = FileMutationResult;

impl FileReadResult {
    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn read(&self) -> &ConfinedFileRead {
        &self.read
    }
}

/// Explicit one-file V1 mutation request.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMutationRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
    pub goal: Option<GoalWorkAttribution>,
    pub write_authority: SourceWriteAuthority,
    pub change_set_id: ChangeSetId,
    pub mutation_id: FileMutationId,
    pub plan: FileMutationPlan,
    pub content: Option<Vec<u8>>,
}

/// One bounded tree-level source transaction request. Caller-authored patch
/// intent remains unmaterialized here so exact retries can be admitted by the
/// durable request digest before reading source that may already have changed.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTreeTransactionRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
    pub write_authority: SourceWriteAuthority,
    pub change_set_id: ChangeSetId,
    pub request_digest: SourceTreeRequestDigest,
    pub mutations: Vec<SourceTreeMutationRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceTreeTransactionStatus {
    Applied,
    AlreadyApplied,
    RecoveryRequired,
    TerminalFailed,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceTreeTransactionResult {
    scope: ResolvedWorkspaceScope,
    change_set_id: ChangeSetId,
    status: SourceTreeTransactionStatus,
    applied_mutations: Vec<TreeMutationId>,
    uncertain_mutation: Option<TreeMutationId>,
}

impl SourceTreeTransactionResult {
    fn new(
        scope: ResolvedWorkspaceScope,
        change_set_id: ChangeSetId,
        status: SourceTreeTransactionStatus,
        applied_mutations: Vec<TreeMutationId>,
        uncertain_mutation: Option<TreeMutationId>,
    ) -> Self {
        Self {
            scope,
            change_set_id,
            status,
            applied_mutations,
            uncertain_mutation,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }
    pub const fn change_set_id(&self) -> ChangeSetId {
        self.change_set_id
    }
    pub const fn status(&self) -> SourceTreeTransactionStatus {
        self.status
    }
    pub fn applied_mutations(&self) -> &[TreeMutationId] {
        &self.applied_mutations
    }
    pub const fn uncertain_mutation(&self) -> Option<TreeMutationId> {
        self.uncertain_mutation
    }
}

/// Durable/effect outcome without exposing adapter paths or errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileMutationStatus {
    Applied,
    AlreadyApplied,
    RecoveryRequired,
    TerminalFailed,
    CommittedButUnconfirmed,
}

/// Activity-attributed mutation record returned by the control boundary.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMutationResult {
    scope: ResolvedWorkspaceScope,
    record: FileMutationRecord,
    status: FileMutationStatus,
}

impl FileMutationResult {
    fn new(
        scope: ResolvedWorkspaceScope,
        record: FileMutationRecord,
        status: FileMutationStatus,
    ) -> Self {
        Self {
            scope,
            record,
            status,
        }
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn record(&self) -> &FileMutationRecord {
        &self.record
    }

    pub const fn status(&self) -> FileMutationStatus {
        self.status
    }
}

#[derive(Debug)]
struct PreparedDiffEvidence {
    files: Vec<DiffEntrySummary>,
    versions: DiffContractVersions,
    payload: PreparedDiffPayload,
}

#[derive(Debug)]
enum PreparedDiffPayload {
    Text(StagedDiffArtifact),
    SummaryOnly(DiffRenderKind),
}

struct PreparedSourceOperation {
    plan: FileMutationPlan,
    intended_hash: Option<FileContentHash>,
    evidence: PreparedSourceEvidence,
    effect: PreparedMutationEffect,
}

enum PreparedSourceEvidence {
    Whole(CapturedDiffSource),
    Patch(PatchReview),
}

struct TreeMutationContext<'a> {
    scope: ResolvedWorkspaceScope,
    request: &'a SourceTreeTransactionRequest,
    store: &'a mut WorkspaceStore,
    artifacts: DiffArtifactStore,
    diff: PreparedDiffEvidence,
}

struct AdmittedFileMutation<'a> {
    scope: ResolvedWorkspaceScope,
    layout: forge_workspace::ExistingWorkspaceStateLayout,
    store: WorkspaceStore,
    request: &'a FileMutationRequest,
    identity: FileMutationIdentity,
    prepared: PreparedFileMutation,
    diff_artifacts: DiffArtifactStore,
    prepared_diff: PreparedDiffEvidence,
    begin: &'a BeginFileMutationDiffResult,
    effect: PreparedMutationEffect,
}

/// The first file mutation contract keeps its 8 KiB payload bound. Source
/// patches are a separate, explicitly bounded effect and use the workspace
/// adapter's source-patch limit instead of widening that legacy contract.
#[derive(Debug)]
enum PreparedMutationEffect {
    Legacy,
    BinaryImport,
    SourcePatch(Vec<u8>),
}

#[derive(Clone, Copy)]
enum FilePayloadKind {
    Small,
    BinaryImport,
}

struct DefiniteFileMutationFailure<'a> {
    scope: ResolvedWorkspaceScope,
    store: &'a mut WorkspaceStore,
    request: &'a FileMutationRequest,
    identity: FileMutationIdentity,
    diff_artifacts: &'a DiffArtifactStore,
    prepared_diff: PreparedDiffEvidence,
    begin: &'a BeginFileMutationDiffResult,
}

struct AppliedFileMutationContext<'a> {
    scope: ResolvedWorkspaceScope,
    store: &'a mut WorkspaceStore,
    request: &'a FileMutationRequest,
    identity: FileMutationIdentity,
    diff_artifacts: &'a DiffArtifactStore,
    prepared_diff: PreparedDiffEvidence,
    begin: &'a BeginFileMutationDiffResult,
    checkpoint: &'a mut Option<crate::checkpoint::MutationCheckpoint>,
    applied: &'a forge_workspace::AppliedFileMutation,
}

impl PreparedDiffEvidence {
    fn begin_command(
        &self,
        scope: &ResolvedWorkspaceScope,
        request: &FileMutationRequest,
    ) -> Result<BeginDiffEvidence, ControlError> {
        self.begin(
            DiffAttribution::for_file_mutation(
                DiffId::for_change_set(request.change_set_id),
                scope.workspace_id(),
                request.activity.activity_id,
                request.change_set_id,
                request.mutation_id,
            ),
            request.activity.observed_at,
        )
    }

    fn begin(
        &self,
        attribution: DiffAttribution,
        observed_at: TimestampMillis,
    ) -> Result<BeginDiffEvidence, ControlError> {
        let payload = match &self.payload {
            PreparedDiffPayload::Text(staged) => DiffPayloadProjection::IntentText {
                pending_relative_path: staged
                    .pending_relative_path()
                    .map_err(map_diff_artifact_error)?,
                final_relative_path: staged
                    .final_relative_path()
                    .map_err(map_diff_artifact_error)?,
                compressed_hash: staged.compressed_hash(),
                uncompressed_hash: staged.uncompressed_hash(),
                compressed_size: staged.compressed_size(),
                uncompressed_size: staged.uncompressed_size(),
            },
            PreparedDiffPayload::SummaryOnly(render_kind) => DiffPayloadProjection::IntentSummary {
                render_kind: *render_kind,
            },
        };
        BeginDiffEvidence::new(
            attribution,
            self.files.clone(),
            payload,
            observed_at,
            self.versions,
        )
        .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))
    }

    fn publish(self, store: &DiffArtifactStore) -> Result<DiffPayloadProjection, ControlError> {
        match self.payload {
            PreparedDiffPayload::Text(staged) => {
                let published = store.publish(staged).map_err(map_diff_artifact_error)?;
                let expected = published.expectation();
                Ok(DiffPayloadProjection::Ready {
                    relative_path: published.relative_path().map_err(map_diff_artifact_error)?,
                    compressed_hash: expected.compressed_hash(),
                    uncompressed_hash: expected.uncompressed_hash(),
                    compressed_size: expected.compressed_size(),
                    uncompressed_size: expected.uncompressed_size(),
                })
            }
            PreparedDiffPayload::SummaryOnly(render_kind) => {
                Ok(DiffPayloadProjection::SummaryOnly { render_kind })
            }
        }
    }

    fn abandon(self, store: &DiffArtifactStore) -> Result<(), ControlError> {
        match self.payload {
            PreparedDiffPayload::Text(staged) => {
                store.abandon(staged).map_err(map_diff_artifact_error)
            }
            PreparedDiffPayload::SummaryOnly(_) => Ok(()),
        }
    }
}

/// Settle an admission step before any requested source effect, while the
/// prepared filesystem mutation still owns the workspace mutation lock.
/// An error can occur after commit: preserve artifacts unless fresh, bound
/// reads prove that neither a `ChangeSet` header nor a Diff exists.
fn finish_diff_admission_step<T>(
    result: Result<T, ControlError>,
    store: &WorkspaceStore,
    change_set_id: ChangeSetId,
    artifacts: &DiffArtifactStore,
    diff: PreparedDiffEvidence,
) -> Result<(T, PreparedDiffEvidence), ControlError> {
    match result {
        Ok(value) => Ok((value, diff)),
        Err(error) => {
            if matches!(store.has_change_set(change_set_id), Ok(false))
                && matches!(store.get_diff_for_change_set(change_set_id), Ok(None))
            {
                diff.abandon(artifacts)?;
            }
            Err(error)
        }
    }
}

impl ForgeControl {
    /// Revalidate one authenticated participant admission against fresh durable
    /// state. Activity heartbeat ownership is not participation authority;
    /// durable Open state and the exact Workspace scope are the fence here.
    pub(crate) fn authorize_activity_request(
        &self,
        scope: &ResolvedWorkspaceScope,
        activity: FileActivityScope,
    ) -> Result<(), ControlError> {
        let (fresh_scope, _layout, store) = self.open_effect_workspace(scope)?;
        authorize_activity(&store, activity)?;
        if !self.committed_scope_matches_with_store(&fresh_scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(())
    }

    /// Read one regular file after exact Workspace and Open Activity validation.
    /// Read-only source observations use the selected descriptor-confined root;
    /// they do not claim exclusive effect ownership against other Workspaces.
    /// Mutation and execution paths retain the overlap fence. The transport
    /// authenticates the participant; heartbeat ownership remains observational.
    pub fn file_read(&self, request: &FileReadRequest) -> Result<FileReadResult, ControlError> {
        let (scope, layout, store) = self.open_effect_workspace(&request.scope)?;
        authorize_activity(&store, request.activity)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let read = filesystem
            .read(&request.path)
            .map_err(map_filesystem_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(FileReadResult {
            scope,
            activity_id: request.activity.activity_id,
            path: request.path.clone(),
            read,
        })
    }

    /// List one explicitly selected Workspace directory through the bounded,
    /// no-follow source adapter. Directory listing is observational and never
    /// creates Workspace state or changes durable records.
    pub fn file_list(&self, request: &FileListRequest) -> Result<FileListResult, ControlError> {
        let (scope, layout, store) = self.open_effect_workspace(&request.scope)?;
        authorize_activity(&store, request.activity)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let result = filesystem
            .file_list(request.directory.as_ref(), request.options)
            .map_err(map_filesystem_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(FileListResult::new(
            scope,
            request.activity.activity_id,
            result,
        ))
    }

    /// Search source text under an explicit Workspace scope. The adapter owns
    /// generated-path filtering and bounded traversal; control owns scope and
    /// Open Activity authorization.
    pub fn text_search(
        &self,
        request: &TextSearchRequest,
    ) -> Result<TextSearchResult, ControlError> {
        let (scope, layout, store) = self.open_effect_workspace(&request.scope)?;
        authorize_activity(&store, request.activity)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let result = filesystem
            .text_search(request.root.as_ref(), &request.query, request.options)
            .map_err(map_filesystem_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(TextSearchResult::new(
            scope,
            request.activity.activity_id,
            result,
        ))
    }

    /// Read one explicit line range while streaming the complete source hash.
    /// The whole-file hash and selected-range hash remain separate in the
    /// returned domain value.
    pub fn file_read_slice(
        &self,
        request: &FileReadSliceRequest,
    ) -> Result<FileReadSliceResult, ControlError> {
        let (scope, layout, store) = self.open_effect_workspace(&request.scope)?;
        authorize_activity(&store, request.activity)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let result = filesystem
            .file_read_slice(&request.path, request.line_range)
            .map_err(map_filesystem_error)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(FileReadSliceResult::new(
            scope,
            request.activity.activity_id,
            request.path.clone(),
            result,
        ))
    }

    /// Apply one staged Add, Update, or Delete source operation. Update first
    /// compiles against the exact whole-file and line-range hashes, then uses
    /// the existing durable `ChangeSet` → Diff → checkpoint lifecycle. Move is
    /// intentionally not represented until its two-endpoint authority exists.
    pub fn file_apply_patch(
        &self,
        request: &FileApplyPatchRequest,
    ) -> Result<FileApplyPatchResult, ControlError> {
        resolve_source_write_session(self, request.write_authority)?;
        let (scope, layout, mut store) = self.open_effect_workspace(&request.scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        let activity = authorize_activity(&store, request.activity)?;
        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;

        let PreparedSourceOperation {
            plan,
            intended_hash,
            evidence,
            effect,
        } = prepare_source_operation(&filesystem, &store, request)?;

        let internal_request = FileMutationRequest {
            scope: scope.clone(),
            activity: request.activity,
            goal: request.goal,
            write_authority: request.write_authority,
            change_set_id: request.change_set_id,
            mutation_id: request.mutation_id,
            plan,
            content: None,
        };

        if let Some(existing) =
            find_existing_mutation(&mut store, &internal_request, intended_hash, &scope)?
        {
            // Update is rejected above until a durable patch digest is
            // available; Add/Delete preserve their exact identity replay.
            return Ok(existing);
        }

        let prepared = filesystem
            .prepare_mutation(&internal_request.plan)
            .map_err(|error| map_source_prepare_error(error, &request.operation))?;
        let diff_artifacts = filesystem
            .diff_artifact_store()
            .map_err(map_filesystem_error)?;
        let prepared_diff = match evidence {
            PreparedSourceEvidence::Whole(post) => prepare_diff_evidence_with_post(
                &diff_artifacts,
                &prepared,
                &internal_request,
                &post,
            )?,
            PreparedSourceEvidence::Patch(review) => {
                let rendered = render_patch_diff_evidence(internal_request.plan.path(), &review)
                    .map_err(map_diff_render_error)?;
                prepare_rendered_diff(
                    &diff_artifacts,
                    &internal_request,
                    rendered,
                    DiffContractVersions::V2,
                )?
            }
        };
        let identity = FileMutationIdentity::new(request.change_set_id, request.mutation_id);
        let attempt = (|| {
            let command = BeginFileMutation::new(
                identity,
                FileMutationScope::new(
                    scope.workspace_id(),
                    scope.workspace_revision(),
                    activity.id(),
                    request.activity.runtime_instance_id,
                    activity.lease_revision(),
                ),
                internal_request.plan.clone(),
                intended_hash,
                prepared.pre_state(),
                request.activity.observed_at,
            )
            .map_err(|error| ControlError::with_source(ControlErrorCode::FileConflict, error))?;
            let diff_command = prepared_diff.begin_command(&scope, &internal_request)?;
            store
                .begin_file_mutation_for_goal(
                    &command,
                    &diff_command,
                    request.goal,
                    request.write_authority,
                )
                .map_err(map_file_mutation_store_error)
        })();
        let (begin, prepared_diff) = finish_diff_admission_step(
            attempt,
            &store,
            request.change_set_id,
            &diff_artifacts,
            prepared_diff,
        )?;
        if let Some(result) = resumed_begin_result(&scope, begin.file()) {
            cleanup_resumed_diff(&diff_artifacts, prepared_diff, begin.status());
            return Ok(result);
        }
        self.finish_prepared_mutation(AdmittedFileMutation {
            scope,
            layout,
            store,
            request: &internal_request,
            identity,
            prepared,
            diff_artifacts,
            prepared_diff,
            begin: &begin,
            effect,
        })
    }

    pub fn source_tree_apply(
        &self,
        request: &SourceTreeTransactionRequest,
    ) -> Result<SourceTreeTransactionResult, ControlError> {
        resolve_source_write_session(self, request.write_authority)?;
        let (scope, layout, mut store) = self.open_effect_workspace(&request.scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        let activity = authorize_activity(&store, request.activity)?;
        let attribution = ChangeSetAttribution::new(
            request.change_set_id,
            scope.workspace_id(),
            scope.workspace_revision(),
            activity.id(),
            request.activity.runtime_instance_id,
            activity.lease_revision(),
        );
        let mut request_paths = Vec::with_capacity(request.mutations.len() * 2);
        for mutation in &request.mutations {
            request_paths.push(mutation.primary_path());
            if let Some(path) = mutation.secondary_path() {
                request_paths.push(path);
            }
        }
        if let Some(admission) = store
            .inspect_source_tree_request(
                attribution,
                request.request_digest,
                request.activity.observed_at,
                request.write_authority,
                &request_paths,
            )
            .map_err(map_file_mutation_store_error)?
            && let Some(resumed) =
                source_tree_admission_result(&scope, request, &store, admission.status())?
        {
            return Ok(resumed);
        }

        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let materialized = materialize_source_tree_request(&filesystem, request.mutations.clone())
            .map_err(|error| match error {
                SourceTreeMaterializationError::Filesystem(source) => map_filesystem_error(source),
                SourceTreeMaterializationError::Intent(source) => {
                    ControlError::with_source(ControlErrorCode::InvalidInput, source)
                }
            })?;
        let draft = materialized.draft();
        let intent =
            TreeChangeSetIntent::from_draft(attribution, draft, request.activity.observed_at)
                .map_err(|error| {
                    ControlError::with_source(ControlErrorCode::InvalidInput, error)
                })?;
        let prepared = filesystem
            .prepare_source_tree_transaction(draft.plan())
            .map_err(map_filesystem_error)?;
        let artifacts = filesystem
            .diff_artifact_store()
            .map_err(map_filesystem_error)?;
        let diff = prepare_tree_diff(&artifacts, &intent, materialized.patch_evidence())?;
        let attempt = (|| {
            let intent = intent
                .with_diff_entries(diff.files.clone())
                .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
            let diff_intent = source_tree_diff_intent(&intent, &diff)?;
            let admission = store
                .begin_source_tree_change_set(
                    &intent,
                    &diff_intent,
                    request.request_digest,
                    request.write_authority,
                )
                .map_err(map_file_mutation_store_error)?;
            Ok((intent, admission))
        })();
        let ((intent, admission), diff) =
            finish_diff_admission_step(attempt, &store, request.change_set_id, &artifacts, diff)?;
        if let Some(resumed) =
            source_tree_admission_result(&scope, request, &store, admission.status())?
        {
            if !matches!(
                admission.status(),
                TreeChangeSetAdmissionStatus::RecoveryRequired
            ) {
                diff.abandon(&artifacts)
                    .map_err(|_| ControlError::committed())?;
            }
            return Ok(resumed);
        }
        let applied = prepared.apply_with_journal(
            &filesystem,
            &intent,
            materialized.payloads(),
            |mutation_id| store.mark_tree_mutation_applied(request.change_set_id, mutation_id),
        );
        finish_source_tree_apply(
            TreeMutationContext {
                scope,
                request,
                store: &mut store,
                artifacts,
                diff,
            },
            applied,
        )
    }

    /// Execute one one-path mutation using durable-intent -> confined effect
    /// -> durable terminal metadata. No automatic replay occurs on uncertainty.
    pub fn file_mutate(
        &self,
        request: &FileMutationRequest,
    ) -> Result<FileMutationResult, ControlError> {
        self.file_mutate_with_hook(request, || {})
    }

    /// Import at most 4 MiB of binary create/replace content. Uses the ordinary
    /// exact source authority, durable intent, Diff/checkpoint and recovery
    /// lifecycle. Ordinary file writes and text patches retain their limits.
    pub fn file_import_binary(
        &self,
        request: &FileMutationRequest,
    ) -> Result<FileMutationResult, ControlError> {
        self.file_mutate_with_payload(request, FilePayloadKind::BinaryImport, || {})
    }

    fn file_mutate_with_hook<Hook>(
        &self,
        request: &FileMutationRequest,
        after_initial_check: Hook,
    ) -> Result<FileMutationResult, ControlError>
    where
        Hook: FnOnce(),
    {
        self.file_mutate_with_payload(request, FilePayloadKind::Small, after_initial_check)
    }

    fn file_mutate_with_payload<Hook>(
        &self,
        request: &FileMutationRequest,
        payload: FilePayloadKind,
        after_initial_check: Hook,
    ) -> Result<FileMutationResult, ControlError>
    where
        Hook: FnOnce(),
    {
        resolve_source_write_session(self, request.write_authority)?;
        let (scope, layout, mut store) = self.open_effect_workspace(&request.scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        let activity = authorize_activity(&store, request.activity)?;
        let identity = FileMutationIdentity::new(request.change_set_id, request.mutation_id);
        let intended_hash = intended_content_hash(request, payload)?;
        if let Some(existing) = find_existing_mutation(&mut store, request, intended_hash, &scope)?
        {
            return Ok(existing);
        }
        after_initial_check();

        let filesystem = ConfinedWorkspace::open(&layout).map_err(map_filesystem_error)?;
        let diff_artifacts = filesystem
            .diff_artifact_store()
            .map_err(map_filesystem_error)?;
        let prepared = match filesystem.prepare_mutation(&request.plan) {
            Ok(prepared) => prepared,
            Err(error)
                if matches!(
                    error,
                    ConfinedFilesystemError::NotFound
                        | ConfinedFilesystemError::PathConflict
                        | ConfinedFilesystemError::StaleWrite
                ) =>
            {
                if let Some(existing) =
                    find_existing_mutation(&mut store, request, intended_hash, &scope)?
                {
                    return Ok(existing);
                }
                return Err(map_filesystem_error(error));
            }
            Err(error) => return Err(map_filesystem_error(error)),
        };
        if let Some(existing) = find_existing_mutation(&mut store, request, intended_hash, &scope)?
        {
            return Ok(existing);
        }
        let prepared_diff = prepare_diff_evidence(&diff_artifacts, &prepared, request, payload)?;
        let attempt = (|| {
            let command = BeginFileMutation::new(
                identity,
                FileMutationScope::new(
                    scope.workspace_id(),
                    scope.workspace_revision(),
                    activity.id(),
                    request.activity.runtime_instance_id,
                    activity.lease_revision(),
                ),
                request.plan.clone(),
                intended_hash,
                prepared.pre_state(),
                request.activity.observed_at,
            )
            .map_err(|error| ControlError::with_source(ControlErrorCode::FileConflict, error))?;
            let diff_command = prepared_diff.begin_command(&scope, request)?;
            store
                .begin_file_mutation_for_goal(
                    &command,
                    &diff_command,
                    request.goal,
                    request.write_authority,
                )
                .map_err(map_file_mutation_store_error)
        })();
        let (begin, prepared_diff) = finish_diff_admission_step(
            attempt,
            &store,
            request.change_set_id,
            &diff_artifacts,
            prepared_diff,
        )?;
        if let Some(result) = resumed_begin_result(&scope, begin.file()) {
            cleanup_resumed_diff(&diff_artifacts, prepared_diff, begin.status());
            return Ok(result);
        }
        self.finish_prepared_mutation(AdmittedFileMutation {
            scope,
            layout,
            store,
            request,
            identity,
            prepared,
            diff_artifacts,
            prepared_diff,
            begin: &begin,
            effect: match payload {
                FilePayloadKind::Small => PreparedMutationEffect::Legacy,
                FilePayloadKind::BinaryImport => PreparedMutationEffect::BinaryImport,
            },
        })
    }

    fn finish_prepared_mutation(
        &self,
        execution: AdmittedFileMutation<'_>,
    ) -> Result<FileMutationResult, ControlError> {
        let AdmittedFileMutation {
            scope,
            layout,
            mut store,
            request,
            identity,
            prepared,
            diff_artifacts,
            prepared_diff,
            begin,
            effect,
        } = execution;
        let mut checkpoint = begin_best_effort_checkpoint(&layout, &mut store, &scope, request);
        let applied = apply_prepared_effect(
            prepared,
            request.mutation_id,
            request.content.as_deref(),
            effect,
        );
        let applied = match applied {
            Ok(applied) => applied,
            Err(error) if error.effect_may_have_committed() => {
                tracing::warn!(
                    changeset_id = %request.change_set_id,
                    mutation_id = %request.mutation_id,
                    failure_code = ?error.failure_code(),
                    "file effect committed but POST evidence is unconfirmed"
                );
                if checkpoint.is_some() {
                    tracing::warn!(
                        changeset_id = %request.change_set_id,
                        "mutation unconfirmed; captured checkpoint remains Starting"
                    );
                }
                return Ok(recovery_required_result(scope, begin));
            }
            Err(error) => {
                return finish_definite_file_mutation_failure(
                    DefiniteFileMutationFailure {
                        scope,
                        store: &mut store,
                        request,
                        identity,
                        diff_artifacts: &diff_artifacts,
                        prepared_diff,
                        begin,
                    },
                    error,
                );
            }
        };
        finish_applied_file_mutation(
            self,
            AppliedFileMutationContext {
                scope,
                store: &mut store,
                request,
                identity,
                diff_artifacts: &diff_artifacts,
                prepared_diff,
                begin,
                checkpoint: &mut checkpoint,
                applied: &applied,
            },
        )
    }

    pub(crate) fn open_effect_workspace(
        &self,
        scope: &ResolvedWorkspaceScope,
    ) -> Result<
        (
            ResolvedWorkspaceScope,
            forge_workspace::ExistingWorkspaceStateLayout,
            WorkspaceStore,
        ),
        ControlError,
    > {
        let (fresh_scope, layout, store) = self.open_resolved_workspace_with_layout(
            scope.locator().location_id(),
            scope.locator().expected_revision(),
            scope.locator(),
        )?;
        if fresh_scope != *scope {
            return Err(ControlError::new(
                ControlErrorCode::WorkspaceRevisionConflict,
            ));
        }
        Ok((fresh_scope, layout, store))
    }

    pub(crate) fn ensure_non_overlapping_effect_scope(
        &self,
        scope: &ResolvedWorkspaceScope,
        selected_root: &Path,
    ) -> Result<(), ControlError> {
        let limit = forge_domain::LocationListLimit::new(MAX_EFFECT_LOCATIONS)
            .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
        let locations = self
            .locations
            .list_locations(limit)
            .map_err(map_location_error)?;
        validate_effect_location_count(locations.len())?;
        for location in locations {
            if location.id() == scope.locator().location_id()
                || location.state() != forge_domain::LocationState::Enabled
            {
                continue;
            }
            let location_root = location.root().as_path();
            if !paths_overlap(selected_root, location_root) {
                continue;
            }
            // Equal or nested Location roots still reserve an overlapping
            // effect boundary. A strictly outer discovery Location does not
            // own the selected repository merely by containing its path.
            if location_root.starts_with(selected_root) {
                return Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap));
            }
            // Inspect every intervening ancestor, not only the Location root:
            // a Workspace initialized between that root and the selected
            // repository also owns these files under a different lease store.
            // This bounded path walk neither scans sibling repositories nor
            // weakens descriptor confinement inside the selected Workspace.
            for ancestor in selected_root
                .ancestors()
                .skip(1)
                .take_while(|ancestor| ancestor.starts_with(location_root))
            {
                if WorkspaceStateLayout::inspect_existing(ancestor)
                    .map_err(map_state_layout_error)?
                    .is_some()
                {
                    return Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap));
                }
            }
        }

        let discovery = self
            .locations
            .discover_current(
                scope.locator().location_id(),
                scope.locator().expected_revision(),
            )
            .map_err(map_location_error)?;
        for candidate in discovery.candidates() {
            if candidate.absolute_root() == selected_root
                || !paths_overlap(selected_root, candidate.absolute_root())
            {
                continue;
            }
            if WorkspaceStateLayout::inspect_existing(candidate.absolute_root())
                .map_err(map_state_layout_error)?
                .is_some()
            {
                return Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap));
            }
        }
        Ok(())
    }
}

fn finish_applied_file_mutation(
    control: &ForgeControl,
    context: AppliedFileMutationContext<'_>,
) -> Result<FileMutationResult, ControlError> {
    let AppliedFileMutationContext {
        scope,
        store,
        request,
        identity,
        diff_artifacts,
        prepared_diff,
        begin,
        checkpoint,
        applied,
    } = context;
    let terminal_diff = match prepared_diff.publish(diff_artifacts) {
        Ok(payload) => payload,
        Err(error) => {
            tracing::warn!(
                changeset_id = %request.change_set_id,
                mutation_id = %request.mutation_id,
                code = error.code().as_str(),
                "file effect committed but Diff artifact publish is unconfirmed"
            );
            return Ok(recovery_required_result(scope, begin));
        }
    };
    let complete = CompleteFileMutation::new(
        identity,
        begin.record().change_set().revision(),
        begin.record().mutation().revision(),
        applied.post_state(),
        request.activity.observed_at,
    );
    let diff_revision = begin
        .diff()
        .filter(|diff| diff.state() == DiffEvidenceState::Intent)
        .map(RegisteredDiffEvidence::revision)
        .ok_or_else(|| ControlError::new(ControlErrorCode::Internal))?;
    let complete_diff = CompleteDiffEvidence::new(
        DiffId::for_change_set(request.change_set_id),
        diff_revision,
        terminal_diff,
        request.activity.observed_at,
    )
    .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
    let record = match store.complete_file_mutation(
        &complete,
        &complete_diff,
        change_set_producer(request.write_authority),
    ) {
        Ok(record) => record,
        Err(store_error) => {
            let code = map_activity_store_error(store_error).code();
            tracing::warn!(
                changeset_id = %request.change_set_id,
                mutation_id = %request.mutation_id,
                code = code.as_str(),
                "file effect committed but terminal ChangeSet persistence is unconfirmed"
            );
            return Ok(recovery_required_result(scope, begin));
        }
    };
    complete_best_effort_checkpoint(checkpoint, store, request);
    let status = if control.committed_scope_matches_with_store(&scope, store) {
        FileMutationStatus::Applied
    } else {
        FileMutationStatus::CommittedButUnconfirmed
    };
    Ok(FileMutationResult::new(
        scope,
        record.file().clone(),
        status,
    ))
}

fn apply_prepared_effect(
    prepared: PreparedFileMutation,
    mutation_id: FileMutationId,
    legacy_content: Option<&[u8]>,
    effect: PreparedMutationEffect,
) -> Result<forge_workspace::AppliedFileMutation, ConfinedFilesystemError> {
    match effect {
        PreparedMutationEffect::Legacy => prepared.apply(mutation_id, legacy_content),
        PreparedMutationEffect::BinaryImport => prepared.apply_binary_import(
            mutation_id,
            legacy_content.ok_or(ConfinedFilesystemError::InvalidPayload)?,
        ),
        PreparedMutationEffect::SourcePatch(content) => {
            prepared.apply_source_patch(mutation_id, &content)
        }
    }
}

fn begin_best_effort_checkpoint(
    layout: &forge_workspace::ExistingWorkspaceStateLayout,
    store: &mut WorkspaceStore,
    scope: &ResolvedWorkspaceScope,
    request: &FileMutationRequest,
) -> Option<crate::checkpoint::MutationCheckpoint> {
    let checkpoint = crate::checkpoint::capture_pre(
        layout,
        forge_domain::CheckpointAttribution::new(
            forge_domain::CheckpointId::from_uuid(uuid::Uuid::now_v7()),
            request.change_set_id,
            scope.workspace_id(),
            scope.workspace_revision(),
            request.activity.activity_id,
        ),
        request.plan.path().clone(),
        request.activity.observed_at,
    )?;
    if crate::checkpoint::persist_starting(&checkpoint, store) {
        return Some(checkpoint);
    }
    tracing::warn!(
        changeset_id = %request.change_set_id,
        mutation_id = %request.mutation_id,
        "checkpoint PRE persistence failed; proceeding without a checkpoint row"
    );
    None
}

fn complete_best_effort_checkpoint(
    checkpoint: &mut Option<crate::checkpoint::MutationCheckpoint>,
    store: &mut WorkspaceStore,
    request: &FileMutationRequest,
) {
    let Some(checkpoint) = checkpoint.as_mut() else {
        return;
    };
    if let Err(error) =
        crate::checkpoint::complete_post(checkpoint, store, request.activity.observed_at)
    {
        tracing::warn!(
            changeset_id = %request.change_set_id,
            mutation_id = %request.mutation_id,
            error = ?error,
            "checkpoint POST completion failed; row remains Starting"
        );
    }
}

fn finish_definite_file_mutation_failure(
    context: DefiniteFileMutationFailure<'_>,
    error: ConfinedFilesystemError,
) -> Result<FileMutationResult, ControlError> {
    let DefiniteFileMutationFailure {
        scope,
        store,
        request,
        identity,
        diff_artifacts,
        prepared_diff,
        begin,
    } = context;
    if let Err(cleanup_error) = prepared_diff.abandon(diff_artifacts) {
        tracing::warn!(
            changeset_id = %request.change_set_id,
            mutation_id = %request.mutation_id,
            code = cleanup_error.code().as_str(),
            "file effect failed but pending Diff cleanup is unconfirmed"
        );
        return Ok(FileMutationResult::new(
            scope,
            begin.record().clone(),
            FileMutationStatus::RecoveryRequired,
        ));
    }
    let failure = FailFileMutation::new(
        identity,
        begin.record().change_set().revision(),
        begin.record().mutation().revision(),
        error.failure_code(),
        request.activity.observed_at,
    );
    let abandon = AbandonDiffEvidence::new(
        DiffId::for_change_set(request.change_set_id),
        begin.diff().map_or(
            forge_domain::DiffRevision::INITIAL,
            RegisteredDiffEvidence::revision,
        ),
        request.activity.observed_at,
    );
    if let Err(store_error) = store.fail_file_mutation(
        &failure,
        abandon,
        change_set_producer(request.write_authority),
    ) {
        let code = map_activity_store_error(store_error).code();
        tracing::warn!(
            changeset_id = %request.change_set_id,
            mutation_id = %request.mutation_id,
            code = code.as_str(),
            "file effect failed and terminal ChangeSet persistence is unconfirmed"
        );
        return Err(ControlError::committed());
    }
    Err(map_filesystem_error(error))
}

fn prepare_diff_evidence(
    artifacts: &DiffArtifactStore,
    prepared: &PreparedFileMutation,
    request: &FileMutationRequest,
    payload: FilePayloadKind,
) -> Result<PreparedDiffEvidence, ControlError> {
    let post = match payload {
        FilePayloadKind::Small => prepared.intended_post_source(request.content.as_deref()),
        FilePayloadKind::BinaryImport => prepared.intended_binary_post_source(
            request
                .content
                .as_deref()
                .ok_or_else(|| ControlError::new(ControlErrorCode::FileConflict))?,
        ),
    }
    .map_err(map_filesystem_error)?;
    prepare_diff_evidence_with_post(artifacts, prepared, request, &post)
}

fn prepare_diff_evidence_with_post(
    artifacts: &DiffArtifactStore,
    prepared: &PreparedFileMutation,
    request: &FileMutationRequest,
    post: &CapturedDiffSource,
) -> Result<PreparedDiffEvidence, ControlError> {
    let kind = diff_change_kind(request.plan.kind());
    let rendered = render_diff_evidence(request.plan.path(), kind, prepared.pre_source(), post)
        .map_err(map_diff_render_error)?;
    prepare_rendered_diff(artifacts, request, rendered, DiffContractVersions::V1)
}

const fn diff_change_kind(kind: FileMutationKind) -> DiffChangeKind {
    match kind {
        FileMutationKind::Create => DiffChangeKind::Created,
        FileMutationKind::Replace => DiffChangeKind::Modified,
        FileMutationKind::Delete => DiffChangeKind::Deleted,
    }
}

fn prepare_rendered_diff(
    artifacts: &DiffArtifactStore,
    request: &FileMutationRequest,
    rendered: RenderedDiffEvidence,
    versions: DiffContractVersions,
) -> Result<PreparedDiffEvidence, ControlError> {
    let file = DiffEntrySummary::new(
        DiffEntrySubject::File,
        request.plan.path().clone(),
        None,
        diff_change_kind(request.plan.kind()),
        rendered.additions(),
        rendered.deletions(),
    )
    .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
    let payload = stage_rendered_diff(
        artifacts,
        DiffId::for_change_set(request.change_set_id),
        rendered,
    )?;
    Ok(PreparedDiffEvidence {
        files: vec![file],
        versions,
        payload,
    })
}

fn stage_rendered_diff(
    artifacts: &DiffArtifactStore,
    id: DiffId,
    rendered: RenderedDiffEvidence,
) -> Result<PreparedDiffPayload, ControlError> {
    Ok(match rendered {
        RenderedDiffEvidence::Text(rendered) => match artifacts.stage(id, &rendered) {
            Ok(staged) => PreparedDiffPayload::Text(staged),
            Err(DiffArtifactStoreError::CompressedTooLarge { .. }) => {
                PreparedDiffPayload::SummaryOnly(DiffRenderKind::Oversized)
            }
            Err(error) => return Err(map_diff_artifact_error(error)),
        },
        RenderedDiffEvidence::SummaryOnly { render_kind } => {
            PreparedDiffPayload::SummaryOnly(render_kind)
        }
    })
}

fn source_content_hash(content: &[u8]) -> Result<FileContentHash, ControlError> {
    if content.len() > forge_domain::MAX_SOURCE_PATCH_BYTES {
        return Err(ControlError::new(ControlErrorCode::FileCapacityExceeded));
    }
    if content.contains(&0) || std::str::from_utf8(content).is_err() {
        return Err(ControlError::new(ControlErrorCode::FileSourceNotText));
    }
    Ok(FileContentHash::from_bytes(
        *blake3::hash(content).as_bytes(),
    ))
}

fn map_source_prepare_error(
    error: ConfinedFilesystemError,
    operation: &FileApplyPatchOperation,
) -> ControlError {
    if matches!(error, ConfinedFilesystemError::StaleWrite)
        && !matches!(operation, FileApplyPatchOperation::Add { .. })
    {
        return ControlError::with_source(ControlErrorCode::FileWholeHashConflict, error);
    }
    map_filesystem_error(error)
}

fn prepare_source_operation(
    filesystem: &ConfinedWorkspace,
    store: &WorkspaceStore,
    request: &FileApplyPatchRequest,
) -> Result<PreparedSourceOperation, ControlError> {
    match &request.operation {
        FileApplyPatchOperation::Add { path, content } => {
            let intended_hash = source_content_hash(content)?;
            let post_source = captured_source(content)?;
            Ok(PreparedSourceOperation {
                plan: FileMutationPlan::new(
                    path.clone(),
                    FileMutationKind::Create,
                    forge_domain::FilePrecondition::Absent,
                ),
                intended_hash: Some(intended_hash),
                evidence: PreparedSourceEvidence::Whole(post_source),
                effect: PreparedMutationEffect::SourcePatch(content.clone()),
            })
        }
        FileApplyPatchOperation::Update { path, patch } => {
            // The current durable schema records the resulting content hash
            // but not the full source-patch digest. A retry cannot be proven
            // to represent the same hunk/context request, so fail closed.
            if store
                .get_file_mutation(request.change_set_id)
                .map_err(map_activity_store_error)?
                .is_some()
            {
                return Err(ControlError::new(ControlErrorCode::FileConflict));
            }
            let (compiled, review) = filesystem
                .compile_file_patch(path, patch)
                .map_err(map_filesystem_error)?
                .into_parts();
            Ok(PreparedSourceOperation {
                plan: FileMutationPlan::new(
                    path.clone(),
                    FileMutationKind::Replace,
                    forge_domain::FilePrecondition::Matches(patch.expected_whole_file_hash()),
                ),
                intended_hash: Some(compiled.result_hash()),
                evidence: PreparedSourceEvidence::Patch(review),
                effect: PreparedMutationEffect::SourcePatch(compiled.into_content()),
            })
        }
        FileApplyPatchOperation::Delete {
            path,
            expected_whole_file_hash,
        } => Ok(PreparedSourceOperation {
            plan: FileMutationPlan::new(
                path.clone(),
                FileMutationKind::Delete,
                forge_domain::FilePrecondition::Matches(*expected_whole_file_hash),
            ),
            intended_hash: None,
            evidence: PreparedSourceEvidence::Whole(CapturedDiffSource::Absent),
            effect: PreparedMutationEffect::Legacy,
        }),
    }
}

fn captured_source(content: &[u8]) -> Result<CapturedDiffSource, ControlError> {
    let size = FileByteCount::new(
        u64::try_from(content.len())
            .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?,
    );
    if content.len() > forge_workspace::MAX_DIFF_SOURCE_BYTES {
        return Ok(CapturedDiffSource::Oversized { size });
    }
    let text = std::str::from_utf8(content)
        .map_err(|_| ControlError::new(ControlErrorCode::FileSourceNotText))?;
    if text.as_bytes().contains(&0) {
        return Err(ControlError::new(ControlErrorCode::FileSourceNotText));
    }
    Ok(CapturedDiffSource::Text(text.to_owned()))
}

fn cleanup_resumed_diff(
    artifacts: &DiffArtifactStore,
    prepared: PreparedDiffEvidence,
    status: BeginFileMutationStatus,
) {
    if matches!(
        status,
        BeginFileMutationStatus::AlreadyApplied | BeginFileMutationStatus::TerminalFailed
    ) && let Err(error) = prepared.abandon(artifacts)
    {
        tracing::warn!(
            code = error.code().as_str(),
            "terminal file mutation retry left an unconfirmed pending Diff cleanup"
        );
    }
}

fn resumed_begin_result(
    scope: &ResolvedWorkspaceScope,
    begin: &BeginFileMutationResult,
) -> Option<FileMutationResult> {
    let status = match begin.status() {
        BeginFileMutationStatus::Started => return None,
        BeginFileMutationStatus::AlreadyApplied => FileMutationStatus::AlreadyApplied,
        BeginFileMutationStatus::RecoveryRequired => FileMutationStatus::RecoveryRequired,
        BeginFileMutationStatus::TerminalFailed => FileMutationStatus::TerminalFailed,
    };
    Some(FileMutationResult::new(
        scope.clone(),
        begin.record().clone(),
        status,
    ))
}

fn recovery_required_result(
    scope: ResolvedWorkspaceScope,
    begin: &BeginFileMutationDiffResult,
) -> FileMutationResult {
    FileMutationResult::new(
        scope,
        begin.record().clone(),
        FileMutationStatus::RecoveryRequired,
    )
}

fn map_diff_render_error(error: DiffRenderError) -> ControlError {
    ControlError::with_source(ControlErrorCode::Internal, error)
}

pub(crate) fn map_diff_artifact_error(error: DiffArtifactStoreError) -> ControlError {
    let code = match &error {
        DiffArtifactStoreError::Scope(source) => match source {
            ConfinedFilesystemError::WorkspaceUnavailable
            | ConfinedFilesystemError::PathChanged
            | ConfinedFilesystemError::CommittedPathChanged => {
                ControlErrorCode::WorkspaceRootConflict
            }
            ConfinedFilesystemError::FileTooLarge { .. }
            | ConfinedFilesystemError::WriteTooLarge { .. }
            | ConfinedFilesystemError::LockBusy => ControlErrorCode::FileCapacityExceeded,
            _ => ControlErrorCode::PersistenceFailure,
        },
        DiffArtifactStoreError::DirectoryPathChanged => ControlErrorCode::WorkspaceRootConflict,
        DiffArtifactStoreError::CompressedTooLarge { .. }
        | DiffArtifactStoreError::RenderedTooLarge { .. } => ControlErrorCode::FileCapacityExceeded,
        DiffArtifactStoreError::IdentityCollision => ControlErrorCode::FileConflict,
        DiffArtifactStoreError::AtomicPublishUnsupported
        | DiffArtifactStoreError::Missing
        | DiffArtifactStoreError::CorruptPayload
        | DiffArtifactStoreError::SizeOverflow
        | DiffArtifactStoreError::InvalidRelativePath(_)
        | DiffArtifactStoreError::InvalidInventoryName
        | DiffArtifactStoreError::Syscall { .. }
        | DiffArtifactStoreError::Io { .. } => ControlErrorCode::PersistenceFailure,
    };
    ControlError::with_source(code, error)
}

fn prepare_tree_diff(
    artifacts: &DiffArtifactStore,
    intent: &TreeChangeSetIntent,
    evidence: &TreePatchEvidence,
) -> Result<PreparedDiffEvidence, ControlError> {
    let reviews = match evidence {
        TreePatchEvidence::Windows(reviews) => reviews,
        TreePatchEvidence::SummaryOnly(kind) => return Ok(summary_tree_diff(intent, *kind)),
    };
    let expected = intent.diff_entries();
    if reviews.len() != intent.mutations().len() || reviews.len() != expected.len() {
        return Err(ControlError::new(ControlErrorCode::Internal));
    }
    let mut files = Vec::with_capacity(reviews.len());
    let mut parts = Vec::with_capacity(reviews.len());
    let mut rendered_bytes = 0_usize;
    for (mutation, entry) in intent.mutations().iter().zip(expected) {
        let review = reviews
            .get(&mutation.id())
            .ok_or_else(|| ControlError::new(ControlErrorCode::Internal))?;
        let forge_domain::TreeMutationPlan::UpdateFile {
            expected_hash,
            intended_hash,
            ..
        } = mutation.plan()
        else {
            return Err(ControlError::new(ControlErrorCode::Internal));
        };
        if *expected_hash != review.source_hash() || *intended_hash != review.result_hash() {
            return Err(ControlError::new(ControlErrorCode::Internal));
        }
        let rendered = render_patch_diff_evidence(entry.primary_path(), review)
            .map_err(map_diff_render_error)?;
        let RenderedDiffEvidence::Text(text) = rendered else {
            return Ok(summary_tree_diff(intent, DiffRenderKind::Oversized));
        };
        rendered_bytes = rendered_bytes.saturating_add(text.bytes().len());
        if rendered_bytes > forge_workspace::MAX_DIFF_RENDERED_BYTES {
            return Ok(summary_tree_diff(intent, DiffRenderKind::Oversized));
        }
        files.push(
            DiffEntrySummary::new(
                entry.subject(),
                entry.primary_path().clone(),
                entry.secondary_path().cloned(),
                entry.kind(),
                text.additions(),
                text.deletions(),
            )
            .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?,
        );
        parts.push(text);
    }
    let payload = stage_rendered_diff(
        artifacts,
        DiffId::for_change_set(intent.attribution().id()),
        RenderedTextDiff::combine(parts),
    )?;
    Ok(PreparedDiffEvidence {
        files,
        versions: DiffContractVersions::V2,
        payload,
    })
}

fn summary_tree_diff(intent: &TreeChangeSetIntent, kind: DiffRenderKind) -> PreparedDiffEvidence {
    PreparedDiffEvidence {
        files: intent.diff_entries().to_vec(),
        versions: if kind == DiffRenderKind::Structured {
            DiffContractVersions::V1
        } else {
            DiffContractVersions::V2
        },
        payload: PreparedDiffPayload::SummaryOnly(kind),
    }
}

fn source_tree_diff_intent(
    intent: &TreeChangeSetIntent,
    diff: &PreparedDiffEvidence,
) -> Result<BeginDiffEvidence, ControlError> {
    let attribution = intent.attribution();
    diff.begin(
        DiffAttribution::for_tree_change_set(
            DiffId::for_change_set(attribution.id()),
            attribution.workspace_id(),
            attribution.activity_id(),
            attribution.id(),
        ),
        intent.observed_at(),
    )
}

fn source_tree_diff_completion(
    request: &SourceTreeTransactionRequest,
    payload: DiffPayloadProjection,
) -> Result<CompleteDiffEvidence, ControlError> {
    CompleteDiffEvidence::new(
        DiffId::for_change_set(request.change_set_id),
        DiffRevision::INITIAL,
        payload,
        request.activity.observed_at,
    )
    .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))
}

/// The producer of the `ChangeSet` is exactly the holder of the Writer Lease
/// that admitted the durable intent: the authenticated Agent (and session)
/// carried by the request's validated `SourceWriteAuthority`. The producer
/// identity reaches the effect-fact append inside the same authoritative
/// terminalization transaction.
fn change_set_producer(authority: SourceWriteAuthority) -> forge_domain::ChangeSetProducer {
    forge_domain::ChangeSetProducer::new(authority.agent_id(), authority.session_id())
}

fn source_tree_diff_abandonment(request: &SourceTreeTransactionRequest) -> AbandonDiffEvidence {
    AbandonDiffEvidence::new(
        DiffId::for_change_set(request.change_set_id),
        DiffRevision::INITIAL,
        request.activity.observed_at,
    )
}

pub(crate) fn source_tree_admission_result(
    scope: &ResolvedWorkspaceScope,
    request: &SourceTreeTransactionRequest,
    store: &WorkspaceStore,
    status: TreeChangeSetAdmissionStatus,
) -> Result<Option<SourceTreeTransactionResult>, ControlError> {
    let result_status = match status {
        TreeChangeSetAdmissionStatus::Started => return Ok(None),
        TreeChangeSetAdmissionStatus::AlreadyApplied => SourceTreeTransactionStatus::AlreadyApplied,
        TreeChangeSetAdmissionStatus::RecoveryRequired => {
            SourceTreeTransactionStatus::RecoveryRequired
        }
        TreeChangeSetAdmissionStatus::TerminalFailed => SourceTreeTransactionStatus::TerminalFailed,
    };
    let applied = if matches!(
        status,
        TreeChangeSetAdmissionStatus::AlreadyApplied
            | TreeChangeSetAdmissionStatus::RecoveryRequired
    ) {
        store
            .tree_change_set_applied_mutations(request.change_set_id)
            .map_err(map_file_mutation_store_error)?
    } else {
        Vec::new()
    };
    Ok(Some(SourceTreeTransactionResult::new(
        scope.clone(),
        request.change_set_id,
        result_status,
        applied,
        None,
    )))
}

fn finish_source_tree_apply<JournalError>(
    context: TreeMutationContext<'_>,
    applied: Result<
        forge_workspace::AppliedSourceTreeTransaction,
        SourceTreeApplyError<JournalError>,
    >,
) -> Result<SourceTreeTransactionResult, ControlError> {
    match applied {
        Ok(applied) => Ok(finish_successful_source_tree_apply(context, &applied)),
        Err(SourceTreeApplyError::Filesystem {
            applied_mutations,
            uncertain_mutation,
            source,
        }) => {
            finish_failed_source_tree_apply(context, applied_mutations, uncertain_mutation, &source)
        }
        Err(SourceTreeApplyError::Journal {
            applied_mutations,
            uncertain_mutation,
            ..
        }) => Ok(SourceTreeTransactionResult::new(
            context.scope,
            context.request.change_set_id,
            SourceTreeTransactionStatus::RecoveryRequired,
            applied_mutations,
            Some(uncertain_mutation),
        )),
    }
}

fn finish_successful_source_tree_apply(
    context: TreeMutationContext<'_>,
    applied: &forge_workspace::AppliedSourceTreeTransaction,
) -> SourceTreeTransactionResult {
    let TreeMutationContext {
        scope,
        request,
        store,
        artifacts,
        diff,
    } = context;
    let status = if diff
        .publish(&artifacts)
        .and_then(|payload| source_tree_diff_completion(request, payload))
        .and_then(|diff_command| {
            store
                .complete_tree_change_set(
                    request.change_set_id,
                    &diff_command,
                    request.activity.observed_at,
                    change_set_producer(request.write_authority),
                )
                .map_err(map_file_mutation_store_error)
        })
        .is_ok()
    {
        SourceTreeTransactionStatus::Applied
    } else {
        SourceTreeTransactionStatus::RecoveryRequired
    };
    SourceTreeTransactionResult::new(
        scope,
        request.change_set_id,
        status,
        applied.applied_mutations().to_vec(),
        None,
    )
}

fn finish_failed_source_tree_apply(
    context: TreeMutationContext<'_>,
    applied_mutations: Vec<TreeMutationId>,
    uncertain_mutation: Option<TreeMutationId>,
    source: &ConfinedFilesystemError,
) -> Result<SourceTreeTransactionResult, ControlError> {
    let TreeMutationContext {
        scope,
        request,
        store,
        artifacts,
        diff,
    } = context;
    if applied_mutations.is_empty() && uncertain_mutation.is_none() {
        if diff.abandon(&artifacts).is_err() {
            return Ok(SourceTreeTransactionResult::new(
                scope,
                request.change_set_id,
                SourceTreeTransactionStatus::RecoveryRequired,
                applied_mutations,
                uncertain_mutation,
            ));
        }
        let _failed = store
            .fail_tree_change_set_without_effect(
                request.change_set_id,
                source_tree_diff_abandonment(request),
                source.failure_code(),
                request.activity.observed_at,
                change_set_producer(request.write_authority),
            )
            .map_err(map_file_mutation_store_error)?;
        return Ok(SourceTreeTransactionResult::new(
            scope,
            request.change_set_id,
            SourceTreeTransactionStatus::TerminalFailed,
            Vec::new(),
            None,
        ));
    }
    Ok(SourceTreeTransactionResult::new(
        scope,
        request.change_set_id,
        SourceTreeTransactionStatus::RecoveryRequired,
        applied_mutations,
        uncertain_mutation,
    ))
}

pub(crate) fn authorize_activity(
    store: &WorkspaceStore,
    scope: FileActivityScope,
) -> Result<forge_domain::RegisteredActivity, ControlError> {
    let activity = store
        .get_activity(scope.activity_id)
        .map_err(map_activity_store_error)?
        .ok_or_else(|| ControlError::new(ControlErrorCode::ActivityNotFound))?;
    if activity.state() != ActivityState::Open {
        return Err(ControlError::new(ControlErrorCode::ActivityConflict));
    }
    Ok(activity)
}

/// Authorize a native effect whose caller is not represented by a durable
/// Agent/session provenance record. These paths must still prove that the
/// supplied runtime owns the Activity heartbeat and that the lease is live at
/// the observation time; authenticated participant reads and Agent-attributed
/// mutations use [`authorize_activity`] instead.
pub(crate) fn authorize_owned_live_activity(
    store: &WorkspaceStore,
    scope: FileActivityScope,
) -> Result<forge_domain::RegisteredActivity, ControlError> {
    let activity = authorize_activity(store, scope)?;
    if activity.lease_owner_id() != Some(scope.runtime_instance_id)
        || activity
            .lease_until()
            .is_none_or(|until| until.get() <= scope.observed_at.get())
    {
        return Err(ControlError::new(ControlErrorCode::ActivityLeaseConflict));
    }
    Ok(activity)
}

fn validate_existing_request(
    record: &FileMutationRecord,
    request: &FileMutationRequest,
    intended_hash: Option<FileContentHash>,
) -> Result<(), ControlError> {
    let matches = record.change_set().id() == request.change_set_id
        && record.change_set().workspace_id() == request.scope.workspace_id()
        && record.change_set().workspace_revision() == request.scope.workspace_revision()
        && record.change_set().activity_id() == request.activity.activity_id
        && record.change_set().runtime_instance_id() == request.activity.runtime_instance_id
        && record.mutation().id() == request.mutation_id
        && record.mutation().path() == request.plan.path()
        && record.mutation().kind() == request.plan.kind()
        && record.mutation().precondition() == request.plan.precondition()
        && record.mutation().intended_content_hash() == intended_hash;
    if matches {
        Ok(())
    } else {
        Err(ControlError::new(ControlErrorCode::FileConflict))
    }
}

fn find_existing_mutation(
    store: &mut WorkspaceStore,
    request: &FileMutationRequest,
    intended_hash: Option<FileContentHash>,
    scope: &ResolvedWorkspaceScope,
) -> Result<Option<FileMutationResult>, ControlError> {
    let Some(record) = store
        .inspect_file_mutation_request(
            scope.workspace_id(),
            request.activity.activity_id,
            request.write_authority,
            request.activity.observed_at,
            request.plan.path(),
            request.change_set_id,
        )
        .map_err(map_file_mutation_store_error)?
    else {
        return Ok(None);
    };
    validate_existing_request(&record, request, intended_hash)?;
    Ok(Some(existing_result(scope.clone(), record)))
}

fn intended_content_hash(
    request: &FileMutationRequest,
    payload: FilePayloadKind,
) -> Result<Option<FileContentHash>, ControlError> {
    match (request.plan.kind(), request.content.as_deref()) {
        (FileMutationKind::Create | FileMutationKind::Replace, Some(content)) => match payload {
            FilePayloadKind::Small => bounded_write_content_hash(content),
            FilePayloadKind::BinaryImport => bounded_binary_content_hash(content),
        }
        .map(Some)
        .map_err(map_filesystem_error),
        (FileMutationKind::Delete, None) if matches!(payload, FilePayloadKind::Small) => Ok(None),
        (FileMutationKind::Delete, None) => Err(ControlError::new(ControlErrorCode::FileConflict)),
        (FileMutationKind::Create | FileMutationKind::Replace, None)
        | (FileMutationKind::Delete, Some(_)) => {
            Err(ControlError::new(ControlErrorCode::FileConflict))
        }
    }
}

fn validate_effect_location_count(count: usize) -> Result<(), ControlError> {
    if count >= MAX_EFFECT_LOCATIONS_USIZE {
        Err(ControlError::new(ControlErrorCode::WorkspaceScopeOverlap))
    } else {
        Ok(())
    }
}

fn existing_result(
    scope: ResolvedWorkspaceScope,
    record: FileMutationRecord,
) -> FileMutationResult {
    let status = match record.change_set().state() {
        ChangeSetState::Starting => FileMutationStatus::RecoveryRequired,
        ChangeSetState::Applied => FileMutationStatus::AlreadyApplied,
        ChangeSetState::Failed => FileMutationStatus::TerminalFailed,
    };
    FileMutationResult::new(scope, record, status)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

pub(crate) fn map_filesystem_error(error: ConfinedFilesystemError) -> ControlError {
    let code = match &error {
        ConfinedFilesystemError::ProtectedPath
        | ConfinedFilesystemError::InvalidPath
        | ConfinedFilesystemError::TooManyComponents
        | ConfinedFilesystemError::GeneratedPath
        | ConfinedFilesystemError::SymlinkRejected
        | ConfinedFilesystemError::NonDirectoryAncestor
        | ConfinedFilesystemError::NonRegularLeaf
        | ConfinedFilesystemError::HardlinkRejected => ControlErrorCode::FilePathDenied,
        ConfinedFilesystemError::InvalidPathKind { .. } => ControlErrorCode::InvalidPathKind,
        ConfinedFilesystemError::NotFound => ControlErrorCode::FileNotFound,
        ConfinedFilesystemError::PathConflict
        | ConfinedFilesystemError::StaleWrite
        | ConfinedFilesystemError::PathChanged
        | ConfinedFilesystemError::CommittedPathChanged
        | ConfinedFilesystemError::CommittedObservationFailed
        | ConfinedFilesystemError::PostStateMismatch => ControlErrorCode::FileConflict,
        ConfinedFilesystemError::FileTooLarge { .. }
        | ConfinedFilesystemError::StateRemovalTooLarge { .. }
        | ConfinedFilesystemError::StateRemovalTooDeep { .. }
        | ConfinedFilesystemError::WriteTooLarge { .. }
        | ConfinedFilesystemError::LockBusy
        | ConfinedFilesystemError::OutputTooLarge { .. } => ControlErrorCode::FileCapacityExceeded,
        ConfinedFilesystemError::SourcePatch(error) => match error {
            forge_domain::FilePatchError::StaleWholeFileHash => {
                ControlErrorCode::FileWholeHashConflict
            }
            forge_domain::FilePatchError::StaleRangeHash { .. }
            | forge_domain::FilePatchError::HunkOutOfBounds { .. }
            | forge_domain::FilePatchError::LineRangeTooLarge { .. }
            | forge_domain::FilePatchError::SourceHasNoLines => ControlErrorCode::FileRangeConflict,
            forge_domain::FilePatchError::BinarySource
            | forge_domain::FilePatchError::NonUtf8Source
            | forge_domain::FilePatchError::BinaryReplacement
            | forge_domain::FilePatchError::NonUtf8Replacement => {
                ControlErrorCode::FileSourceNotText
            }
            forge_domain::FilePatchError::NoHunks
            | forge_domain::FilePatchError::TooManyHunks { .. }
            | forge_domain::FilePatchError::HunksOverlap { .. } => ControlErrorCode::InvalidInput,
            forge_domain::FilePatchError::ReplacementTooLarge { .. }
            | forge_domain::FilePatchError::PatchPayloadTooLarge { .. }
            | forge_domain::FilePatchError::SourceTooLarge { .. }
            | forge_domain::FilePatchError::OutputTooLarge { .. } => {
                ControlErrorCode::FileCapacityExceeded
            }
        },
        ConfinedFilesystemError::SourceSlice(error) => match error {
            forge_domain::FileReadSliceError::RangeOutOfBounds { .. } => {
                ControlErrorCode::FileReadRangeOutOfBounds
            }
            forge_domain::FileReadSliceError::OutputTooLarge { .. }
            | forge_domain::FileReadSliceError::TooManyLines => {
                ControlErrorCode::FileCapacityExceeded
            }
            forge_domain::FileReadSliceError::LineHashCountMismatch { .. }
            | forge_domain::FileReadSliceError::RangeHashMismatch => ControlErrorCode::Internal,
        },
        ConfinedFilesystemError::SourceSearchNonUtf8 => ControlErrorCode::FileSourceNotText,
        ConfinedFilesystemError::SourceSearchLineOverflow
        | ConfinedFilesystemError::TextSearchMatch(_)
        | ConfinedFilesystemError::TextSearchResult(_)
        | ConfinedFilesystemError::FileListResult(_) => ControlErrorCode::Internal,
        ConfinedFilesystemError::WorkspaceUnavailable
        | ConfinedFilesystemError::WorkspaceRootTooDeep => ControlErrorCode::WorkspaceRootConflict,
        ConfinedFilesystemError::InvalidPayload
        | ConfinedFilesystemError::AtomicCreateUnsupported
        | ConfinedFilesystemError::AtomicMoveUnsupported
        | ConfinedFilesystemError::Syscall { .. }
        | ConfinedFilesystemError::StdIo { .. } => ControlErrorCode::PersistenceFailure,
    };
    let details = match &error {
        ConfinedFilesystemError::SourceSlice(
            forge_domain::FileReadSliceError::RangeOutOfBounds {
                end_line,
                total_lines,
            },
        ) => ControlErrorDetails::SourceReadRange {
            end_line: *end_line,
            total_lines: *total_lines,
        },
        ConfinedFilesystemError::InvalidPathKind { expected, actual } => {
            ControlErrorDetails::PathKind {
                expected: *expected,
                actual: *actual,
            }
        }
        _ => ControlErrorDetails::None,
    };
    ControlError::with_source(code, error).with_details(details)
}

#[cfg(test)]
#[path = "source_write_test_support.rs"]
pub(crate) mod source_write_test_support;

#[cfg(test)]
mod tests {
    mod binary_import;
    mod binding_activation;
    mod binding_reservation;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{
        ActivityLeaseRevision, BootstrapActivity, DiffEvidenceState, DiffListLimit,
        DiffPayloadProjection, EstablishWorkspace, FileContentHash, FileEntryKind, FileListOptions,
        FileMutationKind, FilePatch, FilePatchHunk, LocationId, LocationRevision,
        RuntimeInstanceId, SourceLineRange, SourceRangeHash, TextSearchOptions, TextSearchQuery,
        TimestampMillis, TreeMutationId, WorkspaceId, WorkspaceRevision, WorkspaceRoot,
    };
    use forge_persistence::GlobalRegistry;
    use forge_workspace::{
        ConfinedWorkspace, DiffArtifactExpectation, FORGE_GIT_PROGRAM, GitCheckpointStore,
        LocationService, WorkspaceLocator, WorkspaceStateLayout,
    };
    use uuid::Uuid;

    use super::*;
    use crate::worker::ForgeControlWorker;
    use crate::{
        DiffDoctorRequest, DiffListRequest, DiffReadRequest, WorkspaceCheckpointStoreStatus,
        WorkspaceDoctorAggregateOutcome, WorkspaceDoctorObservationConsistency,
        WorkspaceDoctorRequest,
    };

    struct Fixture {
        root: PathBuf,
        control: ForgeControl,
        scope: ResolvedWorkspaceScope,
        activity: FileActivityScope,
        write_authority: SourceWriteAuthority,
    }

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn timestamp(value: i64) -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        Ok(TimestampMillis::new(value)?)
    }

    fn timestamp_now() -> Result<TimestampMillis, Box<dyn std::error::Error>> {
        let millis = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?;
        Ok(TimestampMillis::new(millis)?)
    }

    fn fixture(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-control-file-{label}-{unique}"));
        let location_root = root.join("location");
        fixture_at(root, &location_root)
    }

    fn fixture_at(
        root: PathBuf,
        location_root: &Path,
    ) -> Result<Fixture, Box<dyn std::error::Error>> {
        let workspace_root = location_root.join("workspace");
        fs::create_dir_all(&workspace_root)?;
        let registry = GlobalRegistry::open(root.join("registry.sqlite3"))?;
        let mut locations = LocationService::new(registry);
        let location_id = LocationId::from_uuid(id(0xC100));
        locations.register_selected_path(location_id, "Location", location_root, timestamp(1)?)?;
        let layout = WorkspaceStateLayout::initialize(&workspace_root)?;
        let workspace_id = WorkspaceId::from_uuid(id(0xC101));
        let activity_id = ActivityId::from_uuid(id(0xC102));
        let runtime_id = RuntimeInstanceId::from_uuid(id(0xC103));
        let lease_until = TimestampMillis::new(
            timestamp_now()?
                .get()
                .checked_add(60_000)
                .ok_or("Activity lease deadline overflow")?,
        )?;
        let mut store = WorkspaceStore::open(
            &layout,
            EstablishWorkspace::new(
                workspace_id,
                location_id,
                WorkspaceRoot::from_canonical(layout.workspace_root().to_path_buf())?,
                layout.root_fingerprint()?,
                timestamp(2)?,
            ),
        )?;
        store.bootstrap_activity(&BootstrapActivity::new(
            activity_id,
            workspace_id,
            WorkspaceRevision::INITIAL,
            runtime_id,
            lease_until,
            timestamp(3)?,
        ))?;
        drop(store);
        let control =
            ForgeControl::from_location_service(locations, root.join("agent-sessions.sqlite3"));
        let locator = WorkspaceLocator::new(
            location_id,
            LocationRevision::INITIAL,
            Path::new("workspace"),
        )?;
        let scope = control.resolve_workspace(location_id, LocationRevision::INITIAL, &locator)?;
        let observed_at = timestamp(10)?;
        let write_authority = source_write_test_support::seed_source_write_authority(
            &control,
            &scope,
            &source_write_test_support::SourceWriteTestRequest::new(
                activity_id,
                observed_at,
                0xC1_F000,
                &[
                    "binary.rs",
                    "created-restore.txt",
                    "created.txt",
                    "deleted.txt",
                    "doctor.txt",
                    "file.txt",
                    "history.txt",
                    "restore.txt",
                    "source.rs",
                    "src/main.rs",
                    "tree-delete.txt",
                    "tree-dir-destination",
                    "tree-dir-source",
                    "tree-move.txt",
                    "tree-moved.txt",
                    "tree-new",
                    "tree-new/new.txt",
                    "tree-preflight-create.txt",
                    "tree-patch.rs",
                    "tree-update.txt",
                ],
            ),
        )?;
        Ok(Fixture {
            root,
            control,
            scope,
            activity: FileActivityScope {
                activity_id,
                runtime_instance_id: runtime_id,
                observed_at,
            },
            write_authority,
        })
    }

    fn workspace_root(fixture: &Fixture) -> PathBuf {
        fixture.root.join("location/workspace")
    }

    fn assert_source_tree_mixed_changeset_result(
        fixture: &Fixture,
        root: &Path,
        request: &SourceTreeTransactionRequest,
        mutation_ids: &[TreeMutationId],
        create_bytes: &[u8],
        updated_bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let applied = fixture.control.source_tree_apply(request)?;
        assert_eq!(applied.status(), SourceTreeTransactionStatus::Applied);
        assert_eq!(applied.applied_mutations(), mutation_ids);
        assert_eq!(fs::read(root.join("tree-new/new.txt"))?, create_bytes);
        assert_eq!(fs::read(root.join("tree-update.txt"))?, updated_bytes);
        assert!(!root.join("tree-move.txt").exists());
        assert_eq!(fs::read(root.join("tree-moved.txt"))?, b"move");
        assert!(!root.join("tree-delete.txt").exists());

        let layout = WorkspaceStateLayout::inspect_existing(root)?
            .ok_or("workspace layout missing after tree apply")?;
        let attribution = request.write_authority.attribution();
        let store = WorkspaceStore::open_existing(&layout)?;
        assert_mixed_source_tree_diff(&store, request.change_set_id)?;
        let evidence = store.list_goal_evidence(attribution.goal_id(), 10)?;
        assert_eq!(
            evidence
                .iter()
                .filter(|record| {
                    record.evidence()
                        == forge_domain::GoalEvidenceRef::ChangeSet(request.change_set_id)
                })
                .count(),
            1
        );
        let dag = store
            .get_current_dag(attribution.goal_id())?
            .ok_or("source tree Goal DAG missing")?;
        let node_evidence = dag
            .evidence()
            .iter()
            .find(|summary| summary.node_id() == attribution.node_id())
            .ok_or("source tree node evidence missing")?;
        assert_eq!(node_evidence.count(), 1);
        drop(store);

        let retry = fixture.control.source_tree_apply(request)?;
        assert_eq!(retry.status(), SourceTreeTransactionStatus::AlreadyApplied);
        assert_eq!(retry.applied_mutations(), mutation_ids);
        assert!(retry.uncertain_mutation().is_none());

        let store = WorkspaceStore::open_existing(&layout)?;
        let evidence = store.list_goal_evidence(attribution.goal_id(), 10)?;
        assert_eq!(
            evidence
                .iter()
                .filter(|record| {
                    record.evidence()
                        == forge_domain::GoalEvidenceRef::ChangeSet(request.change_set_id)
                })
                .count(),
            1
        );
        let dag = store
            .get_current_dag(attribution.goal_id())?
            .ok_or("source tree Goal DAG missing after retry")?;
        let node_evidence = dag
            .evidence()
            .iter()
            .find(|summary| summary.node_id() == attribution.node_id())
            .ok_or("source tree node evidence missing after retry")?;
        assert_eq!(node_evidence.count(), 1);

        fs::remove_dir_all(&fixture.root)?;
        Ok(())
    }

    fn fixture_with_git(label: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-control-file-{label}-{unique}"));
        let location_root = root.join("location");
        fs::create_dir_all(&location_root)?;
        let output = Command::new(FORGE_GIT_PROGRAM)
            .arg("-C")
            .arg(&location_root)
            .args(["init", "-q"])
            .env_clear()
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", "/usr/bin:/bin")
            .output()?;
        if !output.status.success() {
            return Err("git init failed for fixture".into());
        }
        fixture_at(root, &location_root)
    }

    fn create_mutation_request(
        fixture: &Fixture,
        change_set: u128,
        mutation: u128,
        name: &str,
        content: &[u8],
    ) -> Result<FileMutationRequest, Box<dyn std::error::Error>> {
        Ok(FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(change_set)),
            mutation_id: FileMutationId::from_uuid(id(mutation)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from(name))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(content.to_vec()),
        })
    }

    fn checkpoint_for_change_set(
        store: &WorkspaceStore,
        workspace_id: WorkspaceId,
        change_set: u128,
    ) -> Result<forge_domain::RegisteredCheckpoint, Box<dyn std::error::Error>> {
        store
            .list_checkpoints(workspace_id, 16)?
            .into_iter()
            .find(|checkpoint| checkpoint.change_set_id() == ChangeSetId::from_uuid(id(change_set)))
            .ok_or_else(|| "checkpoint missing".into())
    }

    fn assert_source_tree_request_was_not_admitted(
        fixture: &Fixture,
        request: &SourceTreeTransactionRequest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(fixture))?
            .ok_or("workspace layout missing after rejected source-tree request")?;
        let mut store = WorkspaceStore::open_existing(&layout)?;
        let activity = store
            .get_activity(request.activity.activity_id)?
            .ok_or("activity missing after rejected source-tree request")?;
        let mut paths = Vec::with_capacity(request.mutations.len() * 2);
        for mutation in &request.mutations {
            paths.push(mutation.primary_path());
            if let Some(path) = mutation.secondary_path() {
                paths.push(path);
            }
        }
        let attribution = ChangeSetAttribution::new(
            request.change_set_id,
            request.scope.workspace_id(),
            request.scope.workspace_revision(),
            request.activity.activity_id,
            request.activity.runtime_instance_id,
            activity.lease_revision(),
        );
        assert!(
            store
                .inspect_source_tree_request(
                    attribution,
                    request.request_digest,
                    request.activity.observed_at,
                    request.write_authority,
                    &paths,
                )?
                .is_none(),
            "rejected source-tree request unexpectedly has durable admission"
        );
        assert!(
            store
                .get_diff_for_change_set(request.change_set_id)?
                .is_none(),
            "rejected source-tree request unexpectedly has durable Diff"
        );
        Ok(())
    }

    fn direct_restore_request(
        fixture: &Fixture,
        checkpoint_id: forge_domain::CheckpointId,
        initiator: RuntimeInstanceId,
        observed_at: i64,
    ) -> Result<crate::checkpoint::CheckpointRestoreRequest, Box<dyn std::error::Error>> {
        Ok(crate::checkpoint::CheckpointRestoreRequest {
            scope: fixture.scope.clone(),
            checkpoint_id,
            initiator,
            activity_id: fixture.activity.activity_id,
            observed_at: timestamp(observed_at)?,
            approval_request_id: None,
        })
    }

    fn assert_direct_restore_provenance(
        fixture: &Fixture,
        restore: &forge_domain::RegisteredCheckpointRestore,
        checkpoint_id: forge_domain::CheckpointId,
    ) {
        assert_eq!(restore.checkpoint_id(), checkpoint_id);
        assert_eq!(restore.workspace_id(), fixture.scope.workspace_id());
        assert_eq!(
            restore.attribution().initiator(),
            fixture.activity.runtime_instance_id
        );
        assert_eq!(
            restore.attribution().activity_id(),
            fixture.activity.activity_id
        );
        assert!(restore.attribution().approval_request_id().is_none());
        assert_eq!(
            restore.attribution().fence(),
            forge_domain::CheckpointRestoreFence::Direct
        );
    }

    #[test]
    fn control_file_read_requires_open_activity_and_redacts_scope_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("read")?;
        fs::write(workspace_root(&fixture).join("read.txt"), b"hello")?;
        let request = FileReadRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            path: WorkspaceRelativePath::new(PathBuf::from("read.txt"))?,
        };
        assert_eq!(
            fixture.control.file_read(&request)?.read().content(),
            b"hello"
        );
        let mut other_runtime = request;
        other_runtime.activity.runtime_instance_id = RuntimeInstanceId::from_uuid(id(0xFFFF));
        assert_eq!(
            fixture.control.file_read(&other_runtime)?.read().content(),
            b"hello"
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn activity_admission_revalidates_fresh_scope_but_not_heartbeat_owner_or_ttl()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("activity-admission")?;
        assert!(
            fixture
                .control
                .authorize_activity_request(&fixture.scope, fixture.activity)
                .is_ok()
        );

        let wrong_owner = FileActivityScope {
            runtime_instance_id: RuntimeInstanceId::from_uuid(id(0xCAFE)),
            ..fixture.activity
        };
        assert!(
            fixture
                .control
                .authorize_activity_request(&fixture.scope, wrong_owner)
                .is_ok()
        );

        let expired = FileActivityScope {
            observed_at: timestamp(1_000)?,
            ..fixture.activity
        };
        assert!(
            fixture
                .control
                .authorize_activity_request(&fixture.scope, expired)
                .is_ok()
        );

        let stale_scope = ResolvedWorkspaceScope::from_observation(
            fixture.scope.workspace_id(),
            WorkspaceRevision::new(2)?,
            fixture.scope.locator().clone(),
        );
        assert_eq!(
            fixture
                .control
                .authorize_activity_request(&stale_scope, fixture.activity)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::WorkspaceRevisionConflict)
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn source_observations_are_bounded_confined_and_activity_attributed()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-observe")?;
        let root = workspace_root(&fixture);
        fs::create_dir_all(root.join("src/nested"))?;
        fs::create_dir_all(root.join("target"))?;
        fs::write(root.join("src/main.rs"), b"fn main() {\n    needle();\n}\n")?;
        fs::write(root.join("src/nested/lib.rs"), b"pub fn needle() {}\n")?;
        fs::write(
            root.join("target/generated.rs"),
            b"needle should be hidden\n",
        )?;

        let listed = fixture.control.file_list(&FileListRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            directory: Some(WorkspaceRelativePath::new(PathBuf::from("src"))?),
            options: FileListOptions::default(),
        })?;
        assert_eq!(listed.entries().len(), 2);
        assert!(
            listed
                .entries()
                .iter()
                .all(|entry| entry.path().as_path().starts_with("src"))
        );

        let searched = fixture.control.text_search(&TextSearchRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            root: None,
            query: TextSearchQuery::new("needle".to_owned())?,
            options: TextSearchOptions::default(),
        })?;
        assert_eq!(searched.matches().len(), 2);
        assert!(
            searched
                .matches()
                .iter()
                .all(|item| !item.path().as_path().starts_with("target"))
        );

        let sliced = fixture.control.file_read_slice(&FileReadSliceRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            path: WorkspaceRelativePath::new(PathBuf::from("src/main.rs"))?,
            line_range: SourceLineRange::new(2, 2)?,
        })?;
        assert_eq!(sliced.content(), b"    needle();\n");
        assert_eq!(
            sliced.whole_file_hash(),
            FileContentHash::from_bytes(
                *blake3::hash(b"fn main() {\n    needle();\n}\n").as_bytes()
            )
        );
        assert_eq!(
            sliced.range_hash(),
            SourceRangeHash::from_bytes(*blake3::hash(b"    needle();\n").as_bytes())
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn source_read_range_out_of_bounds_preserves_safe_line_counts()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-range-bounds")?;
        fs::write(
            workspace_root(&fixture).join("source.rs"),
            b"fn main() {\n    value();\n}\n",
        )?;
        let Err(error) = fixture.control.file_read_slice(&FileReadSliceRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            path: WorkspaceRelativePath::new(PathBuf::from("source.rs"))?,
            line_range: SourceLineRange::new(4, 4)?,
        }) else {
            return Err("out-of-bounds read unexpectedly succeeded".into());
        };
        assert_eq!(error.code(), ControlErrorCode::FileReadRangeOutOfBounds);
        assert_eq!(
            error.view().details(),
            ControlErrorDetails::SourceReadRange {
                end_line: 4,
                total_lines: 3,
            }
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn source_read_directory_reports_typed_path_kind_details()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-path-kind")?;
        fs::create_dir(workspace_root(&fixture).join("directory"))?;
        let Err(error) = fixture.control.file_read_slice(&FileReadSliceRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            path: WorkspaceRelativePath::new(PathBuf::from("directory"))?,
            line_range: SourceLineRange::new(1, 1)?,
        }) else {
            return Err("directory path must be rejected as a source file".into());
        };
        assert_eq!(error.code(), ControlErrorCode::InvalidPathKind);
        assert_eq!(
            error.view().details(),
            ControlErrorDetails::PathKind {
                expected: FileEntryKind::RegularFile,
                actual: FileEntryKind::Directory,
            }
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn large_source_patch_persists_bounded_diff_and_preserves_duplicate_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("source-patch")?;
        let root = workspace_root(&fixture);
        let source_file = root.join("source.rs");
        let original = b"unchanged\n".repeat(12_000);
        fs::write(&source_file, &original)?;
        let path = WorkspaceRelativePath::new(PathBuf::from("source.rs"))?;
        let source_patch = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(&original).as_bytes()),
            vec![FilePatchHunk::new(
                SourceLineRange::new(10_000, 10_000)?,
                SourceRangeHash::from_bytes(*blake3::hash(b"unchanged\n").as_bytes()),
                b"changed\n".to_vec(),
            )?],
        )?;
        let request = FileApplyPatchRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE100)),
            mutation_id: FileMutationId::from_uuid(id(0xE101)),
            operation: FileApplyPatchOperation::Update {
                path: path.clone(),
                patch: source_patch,
            },
        };
        let applied = fixture.control.file_apply_patch(&request)?;
        assert_eq!(applied.status(), FileMutationStatus::Applied);
        let mut expected = b"unchanged\n".repeat(9_999);
        expected.extend_from_slice(b"changed\n");
        expected.extend_from_slice(&b"unchanged\n".repeat(2_000));
        assert_eq!(fs::read(root.join("source.rs"))?, expected);

        let layout =
            WorkspaceStateLayout::inspect_existing(&root)?.ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let diff = store
            .get_diff_for_change_set(request.change_set_id)?
            .ok_or("source patch Diff Evidence missing")?;
        assert_eq!(diff.state(), DiffEvidenceState::Ready);
        assert_eq!(
            diff.renderer_version(),
            forge_domain::DiffRendererVersion::V2
        );
        assert_eq!(
            diff.redaction_policy_version(),
            forge_domain::DiffRedactionPolicyVersion::V2
        );
        assert_eq!(diff.payload().render_kind(), DiffRenderKind::Text);
        drop(store);

        let read = fixture.control.diff_read(&DiffReadRequest {
            scope: fixture.scope.clone(),
            diff_id: diff.id(),
        })?;
        let text = read.content().ok_or("large patch has no reviewable Diff")?;
        assert!(text.contains("@@ -9997,7 +9997,7 @@"));
        assert!(text.contains("-unchanged\n+changed\n"));
        assert!(text.len() < 1_024);

        // Update retries are intentionally fail-closed until the durable
        // schema stores a request-level patch digest. The resulting file hash
        // alone cannot prove that the hunk/context request was identical.
        assert_eq!(
            fixture
                .control
                .file_apply_patch(&request)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileConflict)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn delegated_file_effects_emit_change_set_facts_through_control()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("changeset-fact-control")?;
        let root = workspace_root(&fixture);
        let original = b"fn main() {}\n";
        fs::write(root.join("source.rs"), original)?;
        let digest = *blake3::hash(original).as_bytes();

        // Seal the source delegation exactly as trusted Orchestration does.
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("layout missing")?;
        let mut store = WorkspaceStore::open_existing(&layout)?;
        let freeze = store.freeze_agent_operations(
            &forge_persistence::AgentOperationsFreezeRequest::new(
                id(0xE220),
                id(0xE221),
                timestamp(20)?,
            )?,
        )?;
        drop(store);
        let delegated = fixture.control.delegate_agent_operations(
            &crate::AgentOperationsDelegationRequest {
                scope: fixture.scope.clone(),
                freeze,
                manifest_digest: [0xBE; 32],
                observed_at: timestamp(21)?,
            },
        )?;

        let request = FileApplyPatchRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE224)),
            mutation_id: FileMutationId::from_uuid(id(0xE225)),
            operation: FileApplyPatchOperation::Update {
                path: WorkspaceRelativePath::new("source.rs".into())?,
                patch: FilePatch::new(
                    FileContentHash::from_bytes(digest),
                    vec![FilePatchHunk::new(
                        SourceLineRange::new(1, 1)?,
                        SourceRangeHash::from_bytes(digest),
                        b"fn changed() {}\n".to_vec(),
                    )?],
                )?,
            },
        };
        assert_eq!(
            fixture.control.file_apply_patch(&request)?.status(),
            FileMutationStatus::Applied
        );

        let facts = fixture
            .control
            .effect_fact_outbox(&crate::EffectFactOutboxReadRequest {
                scope: fixture.scope.clone(),
                migration_id: delegated.migration_id(),
                destination_id: delegated.destination_id(),
                after: 0,
                limit: 64,
            })?;
        assert_eq!(facts.len(), 1);
        match facts[0].fact() {
            forge_persistence::EffectFact::ChangeSetTerminal(fact) => {
                assert_eq!(fact.change_set_id(), request.change_set_id);
                assert_eq!(fact.activity_id(), fixture.activity.activity_id);
                assert_eq!(fact.state(), ChangeSetState::Applied);
                assert_eq!(fact.failure_code(), None);
                assert_eq!(
                    fact.diff_id(),
                    forge_domain::DiffId::for_change_set(request.change_set_id)
                );
                assert_eq!(fact.diff_state(), DiffEvidenceState::Ready);
                assert_eq!(
                    fact.change_set_revision(),
                    forge_domain::ChangeSetRevision::new(2)?
                );
                assert_eq!(fact.diff_revision(), forge_domain::DiffRevision::new(2)?);
            }
            forge_persistence::EffectFact::ExecutionTerminal(_) => {
                unreachable!("file effects must not produce an execution fact")
            }
            forge_persistence::EffectFact::AssignmentReviewed(_) => {
                unreachable!("file effects must not produce an assignment-review fact")
            }
            forge_persistence::EffectFact::AssignmentOffered(_) => {
                unreachable!("file effects must not produce an assignment-offer fact")
            }
            forge_persistence::EffectFact::AssignmentSubmitted(_) => {
                unreachable!("file effects must not produce an assignment-submission fact")
            }
        }
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn source_patch_render_overflow_keeps_the_valid_write_and_truthful_summary()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-patch-render-limit")?;
        let root = workspace_root(&fixture);
        let original = vec![b'a'; 65_525];
        let replacement = vec![b'b'; 65_525];
        fs::write(root.join("source.rs"), &original)?;
        let digest = *blake3::hash(&original).as_bytes();
        let request = FileApplyPatchRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE110)),
            mutation_id: FileMutationId::from_uuid(id(0xE111)),
            operation: FileApplyPatchOperation::Update {
                path: WorkspaceRelativePath::new("source.rs".into())?,
                patch: FilePatch::new(
                    FileContentHash::from_bytes(digest),
                    vec![FilePatchHunk::new(
                        SourceLineRange::new(1, 1)?,
                        SourceRangeHash::from_bytes(digest),
                        replacement.clone(),
                    )?],
                )?,
            },
        };
        assert_eq!(
            fixture.control.file_apply_patch(&request)?.status(),
            FileMutationStatus::Applied
        );
        assert_eq!(fs::read(root.join("source.rs"))?, replacement);
        let read = fixture.control.diff_read(&DiffReadRequest {
            scope: fixture.scope.clone(),
            diff_id: DiffId::for_change_set(request.change_set_id),
        })?;
        assert_eq!(read.evidence().state(), DiffEvidenceState::SummaryOnly);
        assert_eq!(
            read.evidence().payload().render_kind(),
            DiffRenderKind::Oversized
        );
        assert!(read.content().is_none());
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn source_patch_conflicts_and_non_text_are_typed_before_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-errors")?;
        let root = workspace_root(&fixture);
        let path = root.join("source.rs");
        fs::write(&path, b"one\ntwo\n")?;
        let relative = WorkspaceRelativePath::new(PathBuf::from("source.rs"))?;
        let stale_patch = FilePatch::new(
            FileContentHash::from_bytes([9; FileContentHash::BYTE_LEN]),
            vec![FilePatchHunk::new(
                SourceLineRange::new(1, 1)?,
                SourceRangeHash::from_bytes(*blake3::hash(b"one\n").as_bytes()),
                b"changed\n".to_vec(),
            )?],
        )?;
        let stale = FileApplyPatchRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE200)),
            mutation_id: FileMutationId::from_uuid(id(0xE201)),
            operation: FileApplyPatchOperation::Update {
                path: relative.clone(),
                patch: stale_patch,
            },
        };
        assert_eq!(
            fixture
                .control
                .file_apply_patch(&stale)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileWholeHashConflict)
        );
        assert_eq!(fs::read(&path)?, b"one\ntwo\n");

        let stale_context = FileApplyPatchRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE204)),
            mutation_id: FileMutationId::from_uuid(id(0xE205)),
            operation: FileApplyPatchOperation::Update {
                path: relative.clone(),
                patch: FilePatch::new(
                    FileContentHash::from_bytes(*blake3::hash(b"one\ntwo\n").as_bytes()),
                    vec![FilePatchHunk::new(
                        SourceLineRange::new(1, 1)?,
                        SourceRangeHash::from_bytes([8; SourceRangeHash::BYTE_LEN]),
                        b"changed\n".to_vec(),
                    )?],
                )?,
            },
        };
        assert_eq!(
            fixture
                .control
                .file_apply_patch(&stale_context)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileRangeConflict)
        );
        assert_eq!(fs::read(&path)?, b"one\ntwo\n");

        let add = FileApplyPatchRequest {
            scope: fixture.scope,
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE202)),
            mutation_id: FileMutationId::from_uuid(id(0xE203)),
            operation: FileApplyPatchOperation::Add {
                path: WorkspaceRelativePath::new(PathBuf::from("binary.rs"))?,
                content: b"text\0binary".to_vec(),
            },
        };
        assert_eq!(
            fixture
                .control
                .file_apply_patch(&add)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileSourceNotText)
        );
        assert!(!root.join("binary.rs").exists());
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn control_mutation_is_durable_activity_attributed_and_retry_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("mutate")?;
        let request = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xC200)),
            mutation_id: FileMutationId::from_uuid(id(0xC201)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"token = actual-secret\ncreated\n".to_vec()),
        };
        let applied = fixture.control.file_mutate(&request)?;
        assert_eq!(applied.status(), FileMutationStatus::Applied);
        assert_eq!(
            applied.record().change_set().activity_id(),
            fixture.activity.activity_id
        );
        assert_eq!(
            fs::read(workspace_root(&fixture).join("created.txt"))?,
            b"token = actual-secret\ncreated\n"
        );
        let existing = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("Workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&existing)?;
        let diff = store
            .get_diff_for_change_set(request.change_set_id)?
            .ok_or("Diff Evidence missing")?;
        assert_eq!(diff.state(), DiffEvidenceState::Ready);
        let DiffPayloadProjection::Ready {
            compressed_hash,
            uncompressed_hash,
            compressed_size,
            uncompressed_size,
            ..
        } = diff.payload()
        else {
            return Err("expected ready text Diff".into());
        };
        let expectation = DiffArtifactExpectation::new(
            diff.id(),
            *compressed_hash,
            *uncompressed_hash,
            *compressed_size,
            *uncompressed_size,
        );
        let artifact_store = ConfinedWorkspace::open(&existing)?.diff_artifact_store()?;
        let rendered = artifact_store.read(&expectation)?;
        let rendered = std::str::from_utf8(&rendered)?;
        assert!(rendered.contains("+created"));
        assert!(!rendered.contains("actual-secret"));
        assert!(rendered.contains("[REDACTED]"));
        drop(store);
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::AlreadyApplied
        );
        let mut mismatched_retry = request;
        mismatched_retry.content = Some(b"different".to_vec());
        assert_eq!(
            fixture
                .control
                .file_mutate(&mismatched_retry)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileConflict)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn initialized_parent_workspace_overlap_blocks_child_effects()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = fixture("overlap")?;
        fixture.control.locations.register_selected_path(
            LocationId::from_uuid(id(0xC302)),
            "Discovery ancestor",
            &fixture.root,
            timestamp(4)?,
        )?;
        let child_root = workspace_root(&fixture);
        fs::write(child_root.join("read.txt"), b"selected child\n")?;
        let request = FileReadRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            path: WorkspaceRelativePath::new(PathBuf::from("read.txt"))?,
        };
        assert_eq!(
            fixture.control.file_read(&request)?.read().content(),
            b"selected child\n"
        );
        let mutation = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xC303)),
            mutation_id: FileMutationId::from_uuid(id(0xC304)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"child-owned effect\n".to_vec()),
        };
        assert_eq!(
            fixture.control.file_mutate(&mutation)?.status(),
            FileMutationStatus::Applied
        );
        assert_eq!(
            fs::read(child_root.join("created.txt"))?,
            b"child-owned effect\n"
        );

        // A discovery root is not a second work owner. An initialized
        // intermediate ancestor is, even if the outer Location has no state.
        let location_root = fixture.root.join("location");
        let parent_layout = WorkspaceStateLayout::initialize(&location_root)?;
        let parent_store = WorkspaceStore::open(
            &parent_layout,
            EstablishWorkspace::new(
                WorkspaceId::from_uuid(id(0xC300)),
                fixture.scope.locator().location_id(),
                WorkspaceRoot::from_canonical(parent_layout.workspace_root().to_path_buf())?,
                parent_layout.root_fingerprint()?,
                timestamp(20)?,
            ),
        )?;
        drop(parent_store);
        // An overlapping writer domain must not hide read-only source in the
        // exact selected Workspace. Actual mutation stays fenced below.
        assert_eq!(
            fixture.control.file_read(&request)?.read().content(),
            b"selected child\n"
        );
        assert_eq!(
            fixture
                .control
                .file_mutate(&mutation)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::WorkspaceScopeOverlap)
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn diff_history_surfaces_require_scope_but_not_a_live_lease()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("diff-history")?;
        let change_set_id = ChangeSetId::from_uuid(id(0xC250));
        let applied = fixture.control.file_mutate(&FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id,
            mutation_id: FileMutationId::from_uuid(id(0xC251)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("history.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"history\n".to_vec()),
        })?;
        assert_eq!(applied.status(), FileMutationStatus::Applied);
        let diff_id = DiffId::for_change_set(change_set_id);
        let listed = fixture.control.diff_list(&DiffListRequest {
            scope: fixture.scope.clone(),
            activity_id: fixture.activity.activity_id,
            limit: DiffListLimit::new(10)?,
        })?;
        assert_eq!(listed.diffs().len(), 1);
        assert_eq!(listed.diffs()[0].id(), diff_id);
        let read = fixture.control.diff_read(&DiffReadRequest {
            scope: fixture.scope.clone(),
            diff_id,
        })?;
        assert_eq!(read.health(), forge_domain::DiffArtifactHealth::Available);
        assert!(
            read.content()
                .is_some_and(|content| content.contains("+history"))
        );
        let doctor = fixture.control.diff_doctor(&DiffDoctorRequest {
            scope: fixture.scope,
            diff_id,
        })?;
        assert_eq!(doctor.health(), forge_domain::DiffArtifactHealth::Available);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn stale_hash_is_rejected_before_intent_without_overwriting_external_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("stale")?;
        let file = workspace_root(&fixture).join("file.txt");
        fs::write(&file, b"current")?;
        let stale = FileContentHash::from_bytes([1; FileContentHash::BYTE_LEN]);
        let request = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xC400)),
            mutation_id: FileMutationId::from_uuid(id(0xC401)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("file.txt"))?,
                FileMutationKind::Replace,
                forge_domain::FilePrecondition::Matches(stale),
            ),
            content: Some(b"forge".to_vec()),
        };
        let Err(error) = fixture.control.file_mutate(&request) else {
            return Err("stale source hash was accepted".into());
        };
        assert_eq!(
            error.code(),
            ControlErrorCode::FileConflict,
            "unexpected source: {:?}",
            std::error::Error::source(&error)
        );
        assert_eq!(fs::read(&file)?, b"current");
        let existing = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("layout missing")?;
        let store = WorkspaceStore::open_existing(&existing)?;
        assert_eq!(store.get_file_mutation(request.change_set_id)?, None);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn current_lease_revision_is_observed_internally_not_supplied_by_caller()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("lease-revision")?;
        let existing = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("layout missing")?;
        let mut store = WorkspaceStore::open_existing(&existing)?;
        let activity = store
            .get_activity(fixture.activity.activity_id)?
            .ok_or("activity missing")?;
        let renewed = store.renew_activity_lease(&forge_domain::RenewActivityLease::new(
            activity.id(),
            fixture.activity.runtime_instance_id,
            ActivityLeaseRevision::INITIAL,
            timestamp(2_000)?,
            timestamp(11)?,
        ))?;
        drop(store);
        let request = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: FileActivityScope {
                observed_at: timestamp(12)?,
                ..fixture.activity
            },
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xC500)),
            mutation_id: FileMutationId::from_uuid(id(0xC501)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"created".to_vec()),
        };
        let result = fixture.control.file_mutate(&request)?;
        assert_eq!(
            result.record().change_set().activity_lease_revision(),
            renewed.lease_revision()
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn truncated_location_scan_fails_closed_before_effect_authorization() {
        assert!(validate_effect_location_count(MAX_EFFECT_LOCATIONS_USIZE - 1).is_ok());
        assert_eq!(
            validate_effect_location_count(MAX_EFFECT_LOCATIONS_USIZE)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::WorkspaceScopeOverlap)
        );
    }

    #[test]
    fn worker_stamps_file_authorization_at_execution_time() -> Result<(), Box<dyn std::error::Error>>
    {
        let Fixture {
            root,
            control,
            scope,
            activity,
            ..
        } = fixture("worker-clock")?;
        fs::write(root.join("location/workspace/read.txt"), b"hello")?;
        let (client, mut worker) = ForgeControlWorker::start(control)?;
        let request = FileReadRequest {
            scope: scope.clone(),
            activity: FileActivityScope {
                observed_at: TimestampMillis::new(0)?,
                ..activity
            },
            path: WorkspaceRelativePath::new(PathBuf::from("read.txt"))?,
        };
        assert!(client.file_read(request).is_ok());
        assert!(
            client
                .authorize_activity(
                    scope.clone(),
                    FileActivityScope {
                        observed_at: TimestampMillis::new(0)?,
                        ..activity
                    },
                )
                .is_ok()
        );
        worker.shutdown()?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn applied_changeset_from_old_workspace_revision_cannot_replay_after_root_rebind()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("rebind-replay")?;
        let request = FileMutationRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            goal: None,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xC600)),
            mutation_id: FileMutationId::from_uuid(id(0xC601)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"created".to_vec()),
        };
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::Applied
        );
        let old_root = workspace_root(&fixture);
        let moved_root = fixture.root.join("location/workspace-moved");
        fs::rename(&old_root, &moved_root)?;
        let moved_layout = WorkspaceStateLayout::initialize(&moved_root)?;
        let rebound = WorkspaceStore::open(
            &moved_layout,
            EstablishWorkspace::new(
                fixture.scope.workspace_id(),
                fixture.scope.locator().location_id(),
                WorkspaceRoot::from_canonical(moved_layout.workspace_root().to_path_buf())?,
                moved_layout.root_fingerprint()?,
                timestamp(20)?,
            ),
        )?;
        assert_eq!(rebound.workspace()?.revision().get(), 2);
        drop(rebound);
        let locator = WorkspaceLocator::new(
            fixture.scope.locator().location_id(),
            LocationRevision::INITIAL,
            "workspace-moved",
        )?;
        let rebound_scope = fixture.control.resolve_workspace(
            fixture.scope.locator().location_id(),
            LocationRevision::INITIAL,
            &locator,
        )?;
        let rebound_request = FileMutationRequest {
            scope: rebound_scope,
            ..request
        };
        assert_eq!(
            fixture
                .control
                .file_mutate(&rebound_request)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileConflict)
        );
        assert_eq!(fs::read(moved_root.join("created.txt"))?, b"created");
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn concurrent_identical_mutation_retry_converges_without_spurious_conflict()
    -> Result<(), Box<dyn std::error::Error>> {
        let Fixture {
            root,
            control,
            scope,
            activity,
            write_authority,
        } = fixture("concurrent-idempotency")?;
        drop(control);
        let request = FileMutationRequest {
            scope,
            activity,
            goal: None,
            write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xC700)),
            mutation_id: FileMutationId::from_uuid(id(0xC701)),
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Create,
                forge_domain::FilePrecondition::Absent,
            ),
            content: Some(b"created".to_vec()),
        };
        let barrier = Arc::new(Barrier::new(2));
        let first_control = ForgeControl::new(GlobalRegistry::open(root.join("registry.sqlite3"))?);
        let second_control =
            ForgeControl::new(GlobalRegistry::open(root.join("registry.sqlite3"))?);
        let first_request = request.clone();
        let second_request = request;
        let first_barrier = Arc::clone(&barrier);
        let second_barrier = Arc::clone(&barrier);
        let first = thread::spawn(move || {
            first_control.file_mutate_with_hook(&first_request, || {
                first_barrier.wait();
            })
        });
        let second = thread::spawn(move || {
            second_control.file_mutate_with_hook(&second_request, || {
                second_barrier.wait();
            })
        });
        let first = first.join().map_err(|_| "first mutation thread panicked")?;
        let second = second
            .join()
            .map_err(|_| "second mutation thread panicked")?;
        let first = first?;
        let second = second?;
        assert!(matches!(
            (first.status(), second.status()),
            (
                FileMutationStatus::Applied,
                FileMutationStatus::AlreadyApplied | FileMutationStatus::RecoveryRequired
            ) | (
                FileMutationStatus::AlreadyApplied | FileMutationStatus::RecoveryRequired,
                FileMutationStatus::Applied
            )
        ));
        assert_eq!(
            fs::read(root.join("location/workspace/created.txt"))?,
            b"created"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn git_backed_mutation_captures_ready_checkpoint_in_owned_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("capture")?;
        let request = create_mutation_request(&fixture, 0xD10, 0xD11, "created.txt", b"v1\n")?;
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::Applied
        );

        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoints = store.list_checkpoints(fixture.scope.workspace_id(), 16)?;
        assert_eq!(checkpoints.len(), 1);
        let ready = &checkpoints[0];
        assert_eq!(ready.state(), forge_domain::CheckpointState::Ready);
        assert_eq!(ready.change_set_id(), ChangeSetId::from_uuid(id(0xD10)));
        let post_blob = match ready.post() {
            Some(forge_domain::CheckpointPathState::Regular { blob, .. }) => *blob,
            other => return Err(format!("unexpected POST state {other:?}").into()),
        };

        let adapter = GitCheckpointStore::new(layout.workspace_root(), layout.checkpoints())?;
        assert_eq!(adapter.read_blob(post_blob)?, b"v1\n");
        // The user repository namespace stays untouched.
        assert!(
            !fixture
                .root
                .join("location/.git/refs/heterarchy-forge")
                .exists()
        );
        drop(store);

        // A second mutation adds a second checkpoint whose PRE captured v1.
        let update = FileMutationRequest {
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
                FileMutationKind::Replace,
                forge_domain::FilePrecondition::Matches(
                    forge_workspace::bounded_write_content_hash(b"v1\n")?,
                ),
            ),
            content: Some(b"v2\n".to_vec()),
            change_set_id: ChangeSetId::from_uuid(id(0xD12)),
            mutation_id: FileMutationId::from_uuid(id(0xD13)),
            ..request
        };
        assert_eq!(
            fixture.control.file_mutate(&update)?.status(),
            FileMutationStatus::Applied
        );
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoints = store.list_checkpoints(fixture.scope.workspace_id(), 16)?;
        assert_eq!(checkpoints.len(), 2);
        let pre_blob = match checkpoints
            .iter()
            .find(|checkpoint| checkpoint.change_set_id() == ChangeSetId::from_uuid(id(0xD12)))
            .ok_or("second checkpoint missing")?
            .pre()
        {
            forge_domain::CheckpointPathState::Regular { blob, .. } => *blob,
            forge_domain::CheckpointPathState::Absent => {
                return Err("unexpected absent PRE state".into());
            }
        };
        let adapter = GitCheckpointStore::new(layout.workspace_root(), layout.checkpoints())?;
        assert_eq!(adapter.read_blob(pre_blob)?, b"v1\n");

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn git_backed_checkpoint_restore_round_trips_owned_store_and_provenance()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("restore")?;
        let create = create_mutation_request(&fixture, 0xD40, 0xD41, "restore.txt", b"v1\n")?;
        assert_eq!(
            fixture.control.file_mutate(&create)?.status(),
            FileMutationStatus::Applied
        );
        let replace = FileMutationRequest {
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("restore.txt"))?,
                FileMutationKind::Replace,
                forge_domain::FilePrecondition::Matches(
                    forge_workspace::bounded_write_content_hash(b"v1\n")?,
                ),
            ),
            content: Some(b"v2\n".to_vec()),
            change_set_id: ChangeSetId::from_uuid(id(0xD42)),
            mutation_id: FileMutationId::from_uuid(id(0xD43)),
            ..create
        };
        assert_eq!(
            fixture.control.file_mutate(&replace)?.status(),
            FileMutationStatus::Applied
        );
        assert_eq!(
            fs::read(workspace_root(&fixture).join("restore.txt"))?,
            b"v2\n"
        );

        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoint = checkpoint_for_change_set(&store, fixture.scope.workspace_id(), 0xD42)?;
        assert_eq!(checkpoint.state(), forge_domain::CheckpointState::Ready);
        assert!(
            store
                .list_checkpoint_restores(fixture.scope.workspace_id(), 16)?
                .is_empty()
        );
        drop(store);

        let wrong_owner = direct_restore_request(
            &fixture,
            checkpoint.id(),
            RuntimeInstanceId::from_uuid(id(0xD4FF)),
            20,
        )?;
        assert_eq!(
            fixture
                .control
                .checkpoint_restore(&wrong_owner)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::ActivityLeaseConflict)
        );
        let store = WorkspaceStore::open_existing(&layout)?;
        assert!(
            store
                .list_checkpoint_restores(fixture.scope.workspace_id(), 16)?
                .is_empty(),
            "failed admission must not create a restore journal"
        );
        drop(store);

        let request = direct_restore_request(
            &fixture,
            checkpoint.id(),
            fixture.activity.runtime_instance_id,
            21,
        )?;
        let outcome = fixture.control.checkpoint_restore(&request)?;
        assert_eq!(
            outcome.state,
            forge_domain::CheckpointRestoreState::Restored
        );
        assert!(outcome.failure_code.is_none());
        assert_eq!(
            fs::read(workspace_root(&fixture).join("restore.txt"))?,
            b"v1\n"
        );

        let store = WorkspaceStore::open_existing(&layout)?;
        let restore = store
            .get_checkpoint_restore(outcome.restore_id)?
            .ok_or("restore journal missing")?;
        assert_direct_restore_provenance(&fixture, &restore, checkpoint.id());
        assert_eq!(
            restore.state(),
            forge_domain::CheckpointRestoreState::Restored
        );
        assert!(
            !fixture
                .root
                .join("location/.git/refs/heterarchy-forge")
                .exists(),
            "restore must not mutate the user repository namespace"
        );

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn checkpoint_restore_finishes_with_stable_healthy_workspace_doctor()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("restore-doctor")?;
        let create = create_mutation_request(&fixture, 0xD80, 0xD81, "doctor.txt", b"v1\n")?;
        assert_eq!(
            fixture.control.file_mutate(&create)?.status(),
            FileMutationStatus::Applied
        );
        let replace = FileMutationRequest {
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("doctor.txt"))?,
                FileMutationKind::Replace,
                forge_domain::FilePrecondition::Matches(
                    forge_workspace::bounded_write_content_hash(b"v1\n")?,
                ),
            ),
            content: Some(b"v2\n".to_vec()),
            change_set_id: ChangeSetId::from_uuid(id(0xD82)),
            mutation_id: FileMutationId::from_uuid(id(0xD83)),
            ..create
        };
        assert_eq!(
            fixture.control.file_mutate(&replace)?.status(),
            FileMutationStatus::Applied
        );
        assert_eq!(
            fs::read(workspace_root(&fixture).join("doctor.txt"))?,
            b"v2\n"
        );

        let target = workspace_root(&fixture).join("doctor.txt");
        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("Workspace layout missing before restore Doctor")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoint = checkpoint_for_change_set(&store, fixture.scope.workspace_id(), 0xD82)?;
        assert_eq!(checkpoint.state(), forge_domain::CheckpointState::Ready);
        drop(store);
        let restore = direct_restore_request(
            &fixture,
            checkpoint.id(),
            fixture.activity.runtime_instance_id,
            21,
        )?;
        let scope = fixture.scope.clone();
        let root = fixture.root.clone();
        let (client, mut worker) = ForgeControlWorker::start(fixture.control)?;
        let outcome = client.checkpoint_restore(restore)?;
        assert_eq!(
            outcome.state,
            forge_domain::CheckpointRestoreState::Restored
        );
        assert!(outcome.failure_code.is_none());
        assert_eq!(fs::read(&target)?, b"v1\n");

        let doctor = client.workspace_doctor(WorkspaceDoctorRequest {
            scope: scope.clone(),
        })?;
        assert_eq!(
            doctor.observation_consistency(),
            WorkspaceDoctorObservationConsistency::Stable
        );
        assert_eq!(doctor.outcome(), WorkspaceDoctorAggregateOutcome::Healthy);
        assert!(doctor.checkpoint_store().is_complete());
        assert!(
            doctor.checkpoint_store().findings().iter().all(|finding| {
                finding.status() == WorkspaceCheckpointStoreStatus::OwnedAvailable
            })
        );
        worker.shutdown()?;

        let store = WorkspaceStore::open_existing(&layout)?;
        let journal = store
            .get_checkpoint_restore(outcome.restore_id)?
            .ok_or("restore journal missing after stable Doctor")?;
        assert_eq!(
            journal.state(),
            forge_domain::CheckpointRestoreState::Restored
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn created_file_restore_removes_checkpoint_post_state() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = fixture_with_git("restore-create")?;
        let create =
            create_mutation_request(&fixture, 0xD60, 0xD61, "created-restore.txt", b"new\n")?;
        assert_eq!(
            fixture.control.file_mutate(&create)?.status(),
            FileMutationStatus::Applied
        );
        let target = workspace_root(&fixture).join("created-restore.txt");
        assert_eq!(fs::read(&target)?, b"new\n");

        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoint = store
            .list_checkpoints(fixture.scope.workspace_id(), 16)?
            .into_iter()
            .find(|checkpoint| checkpoint.change_set_id() == ChangeSetId::from_uuid(id(0xD60)))
            .ok_or("create checkpoint missing")?;
        assert!(matches!(
            checkpoint.pre(),
            forge_domain::CheckpointPathState::Absent
        ));
        drop(store);

        let outcome =
            fixture
                .control
                .checkpoint_restore(&crate::checkpoint::CheckpointRestoreRequest {
                    scope: fixture.scope.clone(),
                    checkpoint_id: checkpoint.id(),
                    initiator: fixture.activity.runtime_instance_id,
                    activity_id: fixture.activity.activity_id,
                    observed_at: timestamp(23)?,
                    approval_request_id: None,
                })?;
        assert_eq!(
            outcome.state,
            forge_domain::CheckpointRestoreState::Restored
        );
        assert!(!target.exists());

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn deleted_file_restore_recreates_checkpoint_content_and_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("restore-delete")?;
        let create = create_mutation_request(&fixture, 0xD50, 0xD51, "deleted.txt", b"keep\n")?;
        assert_eq!(
            fixture.control.file_mutate(&create)?.status(),
            FileMutationStatus::Applied
        );
        let target = workspace_root(&fixture).join("deleted.txt");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640))?;

        let delete = FileMutationRequest {
            plan: FileMutationPlan::new(
                WorkspaceRelativePath::new(PathBuf::from("deleted.txt"))?,
                FileMutationKind::Delete,
                forge_domain::FilePrecondition::Matches(
                    forge_workspace::bounded_write_content_hash(b"keep\n")?,
                ),
            ),
            content: None,
            change_set_id: ChangeSetId::from_uuid(id(0xD52)),
            mutation_id: FileMutationId::from_uuid(id(0xD53)),
            ..create
        };
        assert_eq!(
            fixture.control.file_mutate(&delete)?.status(),
            FileMutationStatus::Applied
        );
        assert!(!target.exists());

        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let checkpoint = store
            .list_checkpoints(fixture.scope.workspace_id(), 16)?
            .into_iter()
            .find(|checkpoint| checkpoint.change_set_id() == ChangeSetId::from_uuid(id(0xD52)))
            .ok_or("delete checkpoint missing")?;
        let expected_mode = match checkpoint.pre() {
            forge_domain::CheckpointPathState::Regular { mode, .. } => *mode,
            forge_domain::CheckpointPathState::Absent => {
                return Err("delete checkpoint PRE unexpectedly absent".into());
            }
        };
        assert_eq!(expected_mode.get(), 0o640);
        drop(store);

        let outcome =
            fixture
                .control
                .checkpoint_restore(&crate::checkpoint::CheckpointRestoreRequest {
                    scope: fixture.scope.clone(),
                    checkpoint_id: checkpoint.id(),
                    initiator: fixture.activity.runtime_instance_id,
                    activity_id: fixture.activity.activity_id,
                    observed_at: timestamp(22)?,
                    approval_request_id: None,
                })?;
        assert_eq!(
            outcome.state,
            forge_domain::CheckpointRestoreState::Restored
        );
        assert_eq!(fs::read(&target)?, b"keep\n");
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o640);

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn non_git_workspace_mutations_skip_checkpoints() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("no-git")?;
        let request = create_mutation_request(&fixture, 0xD20, 0xD21, "created.txt", b"x\n")?;
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::Applied
        );
        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert!(
            store
                .list_checkpoints(fixture.scope.workspace_id(), 16)?
                .is_empty()
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    fn assert_mixed_source_tree_diff(
        store: &WorkspaceStore,
        change_set_id: ChangeSetId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let diff = store
            .get_diff_for_change_set(change_set_id)?
            .ok_or("tree aggregate Diff missing")?;
        assert_eq!(diff.origin(), forge_domain::DiffOrigin::TreeChangeSet);
        assert_eq!(diff.state(), DiffEvidenceState::SummaryOnly);
        assert_eq!(diff.payload().render_kind(), DiffRenderKind::Structured);
        assert_eq!(diff.entries().len(), 5);
        assert_eq!(
            diff.entries()[0].subject(),
            forge_domain::DiffEntrySubject::Directory
        );
        assert_eq!(diff.entries()[0].kind(), DiffChangeKind::Created);
        assert_eq!(
            diff.entries()[0].primary_path().as_path(),
            Path::new("tree-new")
        );
        assert_eq!(
            diff.entries()[1].subject(),
            forge_domain::DiffEntrySubject::File
        );
        assert_eq!(diff.entries()[1].kind(), DiffChangeKind::Created);
        assert_eq!(
            diff.entries()[1].primary_path().as_path(),
            Path::new("tree-new/new.txt")
        );
        assert_eq!(diff.entries()[2].kind(), DiffChangeKind::Modified);
        assert_eq!(
            diff.entries()[2].primary_path().as_path(),
            Path::new("tree-update.txt")
        );
        assert_eq!(diff.entries()[3].kind(), DiffChangeKind::Moved);
        assert_eq!(
            diff.entries()[3].primary_path().as_path(),
            Path::new("tree-move.txt")
        );
        assert_eq!(
            diff.entries()[3]
                .secondary_path()
                .map(WorkspaceRelativePath::as_path),
            Some(Path::new("tree-moved.txt"))
        );
        assert_eq!(diff.entries()[4].kind(), DiffChangeKind::Deleted);
        assert_eq!(
            diff.entries()[4].primary_path().as_path(),
            Path::new("tree-delete.txt")
        );
        Ok(())
    }

    #[test]
    fn source_tree_mixed_changeset_applies_and_exact_retry_is_idempotent()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-tree-mixed")?;
        let root = workspace_root(&fixture);
        fs::write(root.join("tree-update.txt"), b"old")?;
        fs::write(root.join("tree-move.txt"), b"move")?;
        fs::write(root.join("tree-delete.txt"), b"delete")?;

        let create_dir_id = TreeMutationId::from_uuid(id(0xE101));
        let create_file_id = TreeMutationId::from_uuid(id(0xE102));
        let update_id = TreeMutationId::from_uuid(id(0xE103));
        let move_id = TreeMutationId::from_uuid(id(0xE104));
        let delete_id = TreeMutationId::from_uuid(id(0xE105));
        let create_bytes = b"new";
        let updated_bytes = b"updated";
        let mutation_ids = vec![create_dir_id, create_file_id, update_id, move_id, delete_id];
        let request = SourceTreeTransactionRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE100)),
            request_digest: SourceTreeRequestDigest::from_bytes([0xE1; 32]),
            mutations: vec![
                SourceTreeMutationRequest::CreateDirectory {
                    mutation_id: create_dir_id,
                    path: WorkspaceRelativePath::new(PathBuf::from("tree-new"))?,
                },
                SourceTreeMutationRequest::CreateFile {
                    mutation_id: create_file_id,
                    path: WorkspaceRelativePath::new(PathBuf::from("tree-new/new.txt"))?,
                    content: create_bytes.to_vec(),
                },
                SourceTreeMutationRequest::UpdateFile {
                    mutation_id: update_id,
                    path: WorkspaceRelativePath::new(PathBuf::from("tree-update.txt"))?,
                    expected_whole_file_hash: FileContentHash::from_bytes(
                        *blake3::hash(b"old").as_bytes(),
                    ),
                    content: updated_bytes.to_vec(),
                },
                SourceTreeMutationRequest::MoveFile {
                    mutation_id: move_id,
                    source: WorkspaceRelativePath::new(PathBuf::from("tree-move.txt"))?,
                    destination: WorkspaceRelativePath::new(PathBuf::from("tree-moved.txt"))?,
                    expected_whole_file_hash: FileContentHash::from_bytes(
                        *blake3::hash(b"move").as_bytes(),
                    ),
                },
                SourceTreeMutationRequest::DeleteFile {
                    mutation_id: delete_id,
                    path: WorkspaceRelativePath::new(PathBuf::from("tree-delete.txt"))?,
                    expected_whole_file_hash: FileContentHash::from_bytes(
                        *blake3::hash(b"delete").as_bytes(),
                    ),
                },
            ],
        };

        assert_source_tree_mixed_changeset_result(
            &fixture,
            &root,
            &request,
            &mutation_ids,
            create_bytes,
            updated_bytes,
        )
    }

    #[test]
    fn source_tree_preflight_stale_member_keeps_entire_changeset_zero_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-tree-preflight")?;
        let root = workspace_root(&fixture);
        fs::write(root.join("tree-update.txt"), b"actual")?;
        let create_id = TreeMutationId::from_uuid(id(0xE201));
        let update_id = TreeMutationId::from_uuid(id(0xE202));
        let create_bytes = b"must-not-appear";
        let request = SourceTreeTransactionRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE200)),
            request_digest: SourceTreeRequestDigest::from_bytes([0xE2; 32]),
            mutations: vec![
                SourceTreeMutationRequest::CreateFile {
                    mutation_id: create_id,
                    path: WorkspaceRelativePath::new(PathBuf::from("tree-preflight-create.txt"))?,
                    content: create_bytes.to_vec(),
                },
                SourceTreeMutationRequest::UpdateFile {
                    mutation_id: update_id,
                    path: WorkspaceRelativePath::new(PathBuf::from("tree-update.txt"))?,
                    expected_whole_file_hash: FileContentHash::from_bytes(
                        *blake3::hash(b"stale").as_bytes(),
                    ),
                    content: b"replacement".to_vec(),
                },
            ],
        };

        assert_eq!(
            fixture
                .control
                .source_tree_apply(&request)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileConflict)
        );
        assert!(!root.join("tree-preflight-create.txt").exists());
        assert_eq!(fs::read(root.join("tree-update.txt"))?, b"actual");
        let layout = WorkspaceStateLayout::inspect_existing(&root)?
            .ok_or("workspace layout missing after failed preflight")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert!(
            store
                .get_diff_for_change_set(request.change_set_id)?
                .is_none()
        );
        drop(store);

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn source_tree_duplicate_path_is_rejected_before_effect_or_durable_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-tree-duplicate-path")?;
        let root = workspace_root(&fixture);
        let path = root.join("tree-update.txt");
        fs::write(&path, b"keep")?;
        let relative_path = WorkspaceRelativePath::new(PathBuf::from("tree-update.txt"))?;
        let expected_hash = FileContentHash::from_bytes(*blake3::hash(b"keep").as_bytes());
        let request = SourceTreeTransactionRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE500)),
            request_digest: SourceTreeRequestDigest::from_bytes([0xE5; 32]),
            mutations: vec![
                SourceTreeMutationRequest::UpdateFile {
                    mutation_id: TreeMutationId::from_uuid(id(0xE501)),
                    path: relative_path.clone(),
                    expected_whole_file_hash: expected_hash,
                    content: b"first".to_vec(),
                },
                SourceTreeMutationRequest::UpdateFile {
                    mutation_id: TreeMutationId::from_uuid(id(0xE502)),
                    path: relative_path,
                    expected_whole_file_hash: expected_hash,
                    content: b"second".to_vec(),
                },
            ],
        };

        let error = fixture
            .control
            .source_tree_apply(&request)
            .err()
            .ok_or("expected duplicate path rejection")?;
        assert_eq!(error.code(), ControlErrorCode::InvalidInput);
        assert_eq!(fs::read(&path)?, b"keep");
        assert_source_tree_request_was_not_admitted(&fixture, &request)?;

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn source_tree_ancestor_conflict_is_rejected_before_effect_or_durable_admission()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-tree-ancestor-conflict")?;
        let root = workspace_root(&fixture);
        let parent = root.join("tree-new");
        let child = parent.join("new.txt");
        fs::create_dir_all(&parent)?;
        fs::write(&child, b"keep-child")?;
        let parent_path = WorkspaceRelativePath::new(PathBuf::from("tree-new"))?;
        let child_path = WorkspaceRelativePath::new(PathBuf::from("tree-new/new.txt"))?;
        let request = SourceTreeTransactionRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE510)),
            request_digest: SourceTreeRequestDigest::from_bytes([0xE6; 32]),
            mutations: vec![
                SourceTreeMutationRequest::DeleteDirectory {
                    mutation_id: TreeMutationId::from_uuid(id(0xE511)),
                    path: parent_path,
                },
                SourceTreeMutationRequest::DeleteFile {
                    mutation_id: TreeMutationId::from_uuid(id(0xE512)),
                    path: child_path,
                    expected_whole_file_hash: FileContentHash::from_bytes(
                        *blake3::hash(b"keep-child").as_bytes(),
                    ),
                },
            ],
        };

        let error = fixture
            .control
            .source_tree_apply(&request)
            .err()
            .ok_or("expected ancestor conflict rejection")?;
        assert_eq!(error.code(), ControlErrorCode::InvalidInput);
        assert!(parent.is_dir());
        assert_eq!(fs::read(&child)?, b"keep-child");
        assert_source_tree_request_was_not_admitted(&fixture, &request)?;

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn source_tree_move_directory_preserves_nested_tree_and_uses_noreplace()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-tree-move-dir")?;
        let root = workspace_root(&fixture);
        fs::create_dir_all(root.join("tree-dir-source/nested"))?;
        fs::write(root.join("tree-dir-source/nested/file.txt"), b"nested")?;
        let mutation_id = TreeMutationId::from_uuid(id(0xE301));
        let request = SourceTreeTransactionRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE300)),
            request_digest: SourceTreeRequestDigest::from_bytes([0xE3; 32]),
            mutations: vec![SourceTreeMutationRequest::MoveDirectory {
                mutation_id,
                source: WorkspaceRelativePath::new(PathBuf::from("tree-dir-source"))?,
                destination: WorkspaceRelativePath::new(PathBuf::from("tree-dir-destination"))?,
            }],
        };
        let result = fixture.control.source_tree_apply(&request)?;
        assert_eq!(result.status(), SourceTreeTransactionStatus::Applied);
        assert!(!root.join("tree-dir-source").exists());
        assert_eq!(
            fs::read(root.join("tree-dir-destination/nested/file.txt"))?,
            b"nested"
        );
        let layout = WorkspaceStateLayout::inspect_existing(&root)?
            .ok_or("workspace layout missing after directory move")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        let diff = store
            .get_diff_for_change_set(request.change_set_id)?
            .ok_or("directory move aggregate Diff missing")?;
        assert_eq!(diff.origin(), forge_domain::DiffOrigin::TreeChangeSet);
        assert_eq!(diff.state(), DiffEvidenceState::SummaryOnly);
        assert_eq!(diff.payload().render_kind(), DiffRenderKind::Structured);
        assert_eq!(diff.entries().len(), 1);
        let entry = &diff.entries()[0];
        assert_eq!(entry.subject(), forge_domain::DiffEntrySubject::Directory);
        assert_eq!(entry.kind(), DiffChangeKind::Moved);
        assert_eq!(entry.primary_path().as_path(), Path::new("tree-dir-source"));
        assert_eq!(
            entry.secondary_path().map(WorkspaceRelativePath::as_path),
            Some(Path::new("tree-dir-destination"))
        );
        drop(store);

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn source_tree_patch_file_retry_is_admitted_before_recompile()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("source-tree-patch-retry")?;
        let root = workspace_root(&fixture);
        let original = b"one\ntwo\n";
        fs::write(root.join("tree-patch.rs"), original)?;
        let mutation_id = TreeMutationId::from_uuid(id(0xE401));
        let change_set_id = ChangeSetId::from_uuid(id(0xE400));
        let patch = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(original).as_bytes()),
            vec![FilePatchHunk::new(
                SourceLineRange::new(2, 2)?,
                SourceRangeHash::from_bytes(*blake3::hash(b"two\n").as_bytes()),
                b"patched\n".to_vec(),
            )?],
        )?;
        let request = SourceTreeTransactionRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            write_authority: fixture.write_authority,
            change_set_id,
            request_digest: SourceTreeRequestDigest::from_bytes([0xE4; 32]),
            mutations: vec![SourceTreeMutationRequest::PatchFile {
                mutation_id,
                path: WorkspaceRelativePath::new(PathBuf::from("tree-patch.rs"))?,
                patch: patch.clone(),
            }],
        };

        let applied = fixture.control.source_tree_apply(&request)?;
        assert_eq!(applied.status(), SourceTreeTransactionStatus::Applied);
        assert_eq!(fs::read(root.join("tree-patch.rs"))?, b"one\npatched\n");

        let read = fixture.control.diff_read(&DiffReadRequest {
            scope: fixture.scope.clone(),
            diff_id: DiffId::for_change_set(change_set_id),
        })?;
        assert_eq!(
            read.evidence().renderer_version(),
            forge_domain::DiffRendererVersion::V2
        );
        assert!(
            read.content()
                .is_some_and(|text| text.contains("-two\n+patched\n"))
        );

        let retry = fixture.control.source_tree_apply(&request)?;
        assert_eq!(retry.status(), SourceTreeTransactionStatus::AlreadyApplied);
        assert_eq!(retry.applied_mutations(), [mutation_id]);

        let conflicting = SourceTreeTransactionRequest {
            request_digest: SourceTreeRequestDigest::from_bytes([0xE5; 32]),
            mutations: vec![SourceTreeMutationRequest::PatchFile {
                mutation_id,
                path: WorkspaceRelativePath::new(PathBuf::from("tree-patch.rs"))?,
                patch: FilePatch::new(
                    FileContentHash::from_bytes(*blake3::hash(original).as_bytes()),
                    vec![FilePatchHunk::new(
                        SourceLineRange::new(2, 2)?,
                        SourceRangeHash::from_bytes(*blake3::hash(b"two\n").as_bytes()),
                        b"different\n".to_vec(),
                    )?],
                )?,
            }],
            ..request.clone()
        };
        assert_eq!(
            fixture
                .control
                .source_tree_apply(&conflicting)
                .err()
                .map(|error| error.code()),
            Some(ControlErrorCode::FileConflict)
        );
        assert_eq!(fs::read(root.join("tree-patch.rs"))?, b"one\npatched\n");

        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn source_tree_large_patch_bundle_preserves_each_file_and_absolute_hunks()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("large-patch-bundle")?;
        let root = workspace_root(&fixture);
        let original = b"unchanged\n".repeat(12_000);
        let mut mutations = Vec::new();
        // Deliberately reverse canonical path order: review belongs to its ID.
        for (name, mutation_id, line, replacement) in [
            (
                "tree-patch.rs",
                0xE901,
                10_000,
                b"tree changed\n".as_slice(),
            ),
            ("source.rs", 0xE902, 100, b"source changed\n".as_slice()),
        ] {
            fs::write(root.join(name), &original)?;
            mutations.push(SourceTreeMutationRequest::PatchFile {
                mutation_id: TreeMutationId::from_uuid(id(mutation_id)),
                path: WorkspaceRelativePath::new(name.into())?,
                patch: FilePatch::new(
                    FileContentHash::from_bytes(*blake3::hash(&original).as_bytes()),
                    vec![FilePatchHunk::new(
                        SourceLineRange::new(line, line)?,
                        SourceRangeHash::from_bytes(*blake3::hash(b"unchanged\n").as_bytes()),
                        replacement.to_vec(),
                    )?],
                )?,
            });
        }
        let request = SourceTreeTransactionRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xE900)),
            request_digest: SourceTreeRequestDigest::from_bytes([0xE9; 32]),
            mutations,
        };
        let applied = fixture.control.source_tree_apply(&request)?;
        assert_eq!(applied.status(), SourceTreeTransactionStatus::Applied);
        assert_eq!(applied.applied_mutations().len(), 2);
        let read = fixture.control.diff_read(&DiffReadRequest {
            scope: fixture.scope.clone(),
            diff_id: DiffId::for_change_set(request.change_set_id),
        })?;
        assert_eq!(read.evidence().entries().len(), 2);
        for entry in read.evidence().entries() {
            assert_eq!(entry.additions(), forge_domain::DiffLineCount::new(1));
            assert_eq!(entry.deletions(), forge_domain::DiffLineCount::new(1));
        }
        let text = read.content().ok_or("tree patch bundle missing text")?;
        assert!(text.contains("--- a/source.rs\n+++ b/source.rs\n"));
        assert!(text.contains("--- a/tree-patch.rs\n+++ b/tree-patch.rs\n"));
        assert!(text.contains("--- a/source.rs\n+++ b/source.rs\n@@ -97,7 +97,7 @@"));
        assert!(text.contains("--- a/tree-patch.rs\n+++ b/tree-patch.rs\n@@ -9997,7 +9997,7 @@"));
        assert!(text.contains("+source changed\n"));
        assert!(text.contains("+tree changed\n"));
        assert!(text.len() < 2_048);
        let retry = fixture.control.source_tree_apply(&request)?;
        assert_eq!(retry.status(), SourceTreeTransactionStatus::AlreadyApplied);
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    #[test]
    fn rolled_back_goal_admission_abandons_pending_diff_before_source_effect()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture("rejected-diff-admission")?;
        let root = workspace_root(&fixture);
        let mut request =
            create_mutation_request(&fixture, 0xEB00, 0xEB01, "created.txt", b"safe\n")?;
        request.goal = Some(GoalWorkAttribution::Goal(
            forge_domain::GoalAttribution::new(
                forge_domain::GoalId::from_uuid(id(0xEB99)),
                forge_domain::GoalRevision::INITIAL,
            ),
        ));
        assert!(fixture.control.file_mutate(&request).is_err());
        assert!(!root.join("created.txt").exists());
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("test layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert!(!store.has_change_set(request.change_set_id)?);
        assert!(
            store
                .get_diff_for_change_set(request.change_set_id)?
                .is_none()
        );
        assert!(
            fs::read_dir(root.join(".heterarchy-forge/diffs"))?
                .next()
                .is_none()
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }

    struct StagedTreeDiffFixture {
        fixture: Fixture,
        request: SourceTreeTransactionRequest,
        filesystem: ConfinedWorkspace,
        materialized: crate::source_tree::MaterializedSourceTreeRequest,
        intent: TreeChangeSetIntent,
        store: WorkspaceStore,
        artifacts: DiffArtifactStore,
        diff: PreparedDiffEvidence,
        pending_path: PathBuf,
    }

    fn staged_tree_diff_fixture(
        label: &str,
    ) -> Result<StagedTreeDiffFixture, Box<dyn std::error::Error>> {
        let fixture = fixture(label)?;
        let root = workspace_root(&fixture);
        fs::write(root.join("source.rs"), b"before\n")?;
        let request = SourceTreeTransactionRequest {
            scope: fixture.scope.clone(),
            activity: fixture.activity,
            write_authority: fixture.write_authority,
            change_set_id: ChangeSetId::from_uuid(id(0xEA00)),
            request_digest: SourceTreeRequestDigest::from_bytes([0xEA; 32]),
            mutations: vec![SourceTreeMutationRequest::PatchFile {
                mutation_id: TreeMutationId::from_uuid(id(0xEA01)),
                path: WorkspaceRelativePath::new("source.rs".into())?,
                patch: FilePatch::new(
                    FileContentHash::from_bytes(*blake3::hash(b"before\n").as_bytes()),
                    vec![FilePatchHunk::new(
                        SourceLineRange::new(1, 1)?,
                        SourceRangeHash::from_bytes(*blake3::hash(b"before\n").as_bytes()),
                        b"after\n".to_vec(),
                    )?],
                )?,
            }],
        };
        let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("test layout missing")?;
        let mut store = WorkspaceStore::open_existing(&layout)?;
        let activity = authorize_activity(&store, fixture.activity)?;
        let filesystem = ConfinedWorkspace::open(&layout)?;
        let materialized = materialize_source_tree_request(&filesystem, request.mutations.clone())?;
        let intent = TreeChangeSetIntent::from_draft(
            ChangeSetAttribution::new(
                request.change_set_id,
                fixture.scope.workspace_id(),
                fixture.scope.workspace_revision(),
                activity.id(),
                fixture.activity.runtime_instance_id,
                activity.lease_revision(),
            ),
            materialized.draft(),
            fixture.activity.observed_at,
        )?;
        let artifacts = filesystem.diff_artifact_store()?;
        let diff = prepare_tree_diff(&artifacts, &intent, materialized.patch_evidence())?;
        let intent = intent.with_diff_entries(diff.files.clone())?;
        let diff_intent = source_tree_diff_intent(&intent, &diff)?;
        let admission = store.begin_source_tree_change_set(
            &intent,
            &diff_intent,
            request.request_digest,
            request.write_authority,
        )?;
        assert_eq!(admission.status(), TreeChangeSetAdmissionStatus::Started);
        let PreparedDiffPayload::Text(staged) = &diff.payload else {
            return Err("test expected pending text Diff".into());
        };
        let pending_path = root
            .join(".heterarchy-forge")
            .join(staged.pending_relative_path()?.as_path());
        Ok(StagedTreeDiffFixture {
            fixture,
            request,
            filesystem,
            materialized,
            intent,
            store,
            artifacts,
            diff,
            pending_path,
        })
    }

    #[test]
    fn admission_error_keeps_pending_diff_when_durable_intent_exists()
    -> Result<(), Box<dyn std::error::Error>> {
        let case = staged_tree_diff_fixture("admission-present")?;
        let _prepared = case
            .filesystem
            .prepare_source_tree_transaction(case.materialized.draft().plan())?;
        let error = finish_diff_admission_step::<()>(
            Err(ControlError::new(ControlErrorCode::FileConflict)),
            &case.store,
            case.request.change_set_id,
            &case.artifacts,
            case.diff,
        )
        .err()
        .ok_or("expected admission error")?;
        assert_eq!(error.code(), ControlErrorCode::FileConflict);
        assert!(!error.view().committed());
        assert!(case.store.has_change_set(case.request.change_set_id)?);
        assert!(case.pending_path.is_file());
        fs::remove_dir_all(case.fixture.root)?;
        Ok(())
    }

    #[test]
    fn admission_probe_binding_failure_preserves_pending_artifact()
    -> Result<(), Box<dyn std::error::Error>> {
        let case = staged_tree_diff_fixture("admission-probe-failure")?;
        let _prepared = case
            .filesystem
            .prepare_source_tree_transaction(case.materialized.draft().plan())?;
        let state = workspace_root(&case.fixture).join(".heterarchy-forge");
        let database = state.join("state.sqlite3");
        let moved_database = state.join("state-held.sqlite3");
        fs::rename(&database, &moved_database)?;
        let error = finish_diff_admission_step::<()>(
            Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict)),
            &case.store,
            case.request.change_set_id,
            &case.artifacts,
            case.diff,
        )
        .err()
        .ok_or("expected binding error")?;
        assert_eq!(error.code(), ControlErrorCode::WorkspaceRootConflict);
        assert!(case.pending_path.is_file());
        fs::rename(&moved_database, &database)?;
        assert!(case.store.has_change_set(case.request.change_set_id)?);
        fs::remove_dir_all(case.fixture.root)?;
        Ok(())
    }

    #[test]
    fn failed_tree_journal_keeps_current_mutation_unconfirmed()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut case = staged_tree_diff_fixture("tree-journal-loss")?;
        let current = case.intent.mutations()[0].id();
        let prepared = case
            .filesystem
            .prepare_source_tree_transaction(case.materialized.draft().plan())?;
        let outcome = prepared.apply_with_journal(
            &case.filesystem,
            &case.intent,
            case.materialized.payloads(),
            |_mutation_id| Err::<(), ()>(()),
        );
        let result = finish_source_tree_apply(
            TreeMutationContext {
                scope: case.fixture.scope.clone(),
                request: &case.request,
                store: &mut case.store,
                artifacts: case.artifacts,
                diff: case.diff,
            },
            outcome,
        )?;
        assert_eq!(
            result.status(),
            SourceTreeTransactionStatus::RecoveryRequired
        );
        assert!(result.applied_mutations().is_empty());
        assert_eq!(result.uncertain_mutation(), Some(current));
        assert_eq!(
            fs::read(workspace_root(&case.fixture).join("source.rs"))?,
            b"after\n"
        );
        let snapshot = case
            .store
            .source_tree_read_snapshot(case.request.change_set_id)?
            .ok_or("durable source-tree intent missing")?;
        assert_eq!(snapshot.change_set().state(), ChangeSetState::Starting);
        assert!(snapshot.applied_mutations().is_empty());
        assert_eq!(snapshot.mutation_count(), 1);
        assert_eq!(snapshot.request_digest(), case.request.request_digest);
        fs::remove_dir_all(case.fixture.root)?;
        Ok(())
    }

    #[test]
    fn lost_tree_diff_publish_preserves_applied_mutations_for_recovery()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut case = staged_tree_diff_fixture("patch-publish-loss")?;
        let prepared = case
            .filesystem
            .prepare_source_tree_transaction(case.materialized.draft().plan())?;
        let applied = prepared
            .apply_with_journal(
                &case.filesystem,
                &case.intent,
                case.materialized.payloads(),
                |mutation_id| {
                    case.store
                        .mark_tree_mutation_applied(case.request.change_set_id, mutation_id)
                },
            )
            .map_err(|_| "test source application failed")?;
        fs::remove_file(&case.pending_path)?;
        let result = finish_successful_source_tree_apply(
            TreeMutationContext {
                scope: case.fixture.scope.clone(),
                request: &case.request,
                store: &mut case.store,
                artifacts: case.artifacts,
                diff: case.diff,
            },
            &applied,
        );
        assert_eq!(
            result.status(),
            SourceTreeTransactionStatus::RecoveryRequired
        );
        assert_eq!(result.applied_mutations().len(), 1);
        assert_eq!(
            fs::read(workspace_root(&case.fixture).join("source.rs"))?,
            b"after\n"
        );
        let diff = case
            .store
            .get_diff_for_change_set(case.request.change_set_id)?
            .ok_or("pending Diff missing")?;
        assert_eq!(diff.state(), DiffEvidenceState::Intent);
        fs::remove_dir_all(case.fixture.root)?;
        Ok(())
    }

    #[test]
    fn failed_pre_effect_artifact_cleanup_does_not_claim_terminal_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut case = staged_tree_diff_fixture("patch-cleanup-failure")?;
        fs::remove_file(&case.pending_path)?;
        fs::create_dir(&case.pending_path)?;
        let result = finish_failed_source_tree_apply(
            TreeMutationContext {
                scope: case.fixture.scope.clone(),
                request: &case.request,
                store: &mut case.store,
                artifacts: case.artifacts,
                diff: case.diff,
            },
            Vec::new(),
            None,
            &ConfinedFilesystemError::StaleWrite,
        )?;
        assert_eq!(
            result.status(),
            SourceTreeTransactionStatus::RecoveryRequired
        );
        assert!(result.applied_mutations().is_empty());
        assert!(case.pending_path.is_dir());
        assert_eq!(
            fs::read(workspace_root(&case.fixture).join("source.rs"))?,
            b"before\n"
        );
        let diff = case
            .store
            .get_diff_for_change_set(case.request.change_set_id)?
            .ok_or("pending Diff missing")?;
        assert_eq!(diff.state(), DiffEvidenceState::Intent);
        fs::remove_dir_all(case.fixture.root)?;
        Ok(())
    }

    #[test]
    fn repeated_identical_mutation_does_not_duplicate_checkpoints()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = fixture_with_git("retry")?;
        let request = create_mutation_request(&fixture, 0xD30, 0xD31, "created.txt", b"same\n")?;
        assert_eq!(
            fixture.control.file_mutate(&request)?.status(),
            FileMutationStatus::Applied
        );
        let replayed = fixture.control.file_mutate(&request)?;
        assert_eq!(replayed.status(), FileMutationStatus::AlreadyApplied);
        let layout = WorkspaceStateLayout::inspect_existing(workspace_root(&fixture))?
            .ok_or("workspace layout missing")?;
        let store = WorkspaceStore::open_existing(&layout)?;
        assert_eq!(
            store
                .list_checkpoints(fixture.scope.workspace_id(), 16)?
                .len(),
            1
        );
        fs::remove_dir_all(fixture.root)?;
        Ok(())
    }
}
