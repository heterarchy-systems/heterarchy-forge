use std::collections::BTreeMap;

use forge_domain::{
    DiffRenderKind, FileContentHash, FilePatch, TreeChangeSetDraft, TreeChangeSetIntentError,
    TreeMutationDraft, TreeMutationId, TreeMutationPlan, WorkspaceRelativePath,
};
use forge_workspace::{
    ConfinedFilesystemError, ConfinedWorkspace, MAX_PATCH_REVIEW_BYTES,
    MAX_SOURCE_TREE_PAYLOAD_BYTES, PatchReview, SourceTreeMutationPayload, SourceTreePayloadSet,
    bounded_write_content_hash,
};
use thiserror::Error;

/// Caller-authored source-tree mutation retained until control can materialize
/// every payload and patch against one descriptor-confined source snapshot.
///
/// This request form deliberately stays above [`forge_domain::TreeMutationPlan`]:
/// `PatchFile` does not know its intended content hash until the exact source
/// preconditions have been verified and the patch has been compiled.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceTreeMutationRequest {
    CreateDirectory {
        mutation_id: TreeMutationId,
        path: WorkspaceRelativePath,
    },
    CreateFile {
        mutation_id: TreeMutationId,
        path: WorkspaceRelativePath,
        content: Vec<u8>,
    },
    UpdateFile {
        mutation_id: TreeMutationId,
        path: WorkspaceRelativePath,
        expected_whole_file_hash: FileContentHash,
        content: Vec<u8>,
    },
    PatchFile {
        mutation_id: TreeMutationId,
        path: WorkspaceRelativePath,
        patch: FilePatch,
    },
    DeleteFile {
        mutation_id: TreeMutationId,
        path: WorkspaceRelativePath,
        expected_whole_file_hash: FileContentHash,
    },
    MoveFile {
        mutation_id: TreeMutationId,
        source: WorkspaceRelativePath,
        destination: WorkspaceRelativePath,
        expected_whole_file_hash: FileContentHash,
    },
    MoveDirectory {
        mutation_id: TreeMutationId,
        source: WorkspaceRelativePath,
        destination: WorkspaceRelativePath,
    },
    DeleteDirectory {
        mutation_id: TreeMutationId,
        path: WorkspaceRelativePath,
    },
}

impl SourceTreeMutationRequest {
    pub const fn mutation_id(&self) -> TreeMutationId {
        match self {
            Self::CreateDirectory { mutation_id, .. }
            | Self::CreateFile { mutation_id, .. }
            | Self::UpdateFile { mutation_id, .. }
            | Self::PatchFile { mutation_id, .. }
            | Self::DeleteFile { mutation_id, .. }
            | Self::MoveFile { mutation_id, .. }
            | Self::MoveDirectory { mutation_id, .. }
            | Self::DeleteDirectory { mutation_id, .. } => *mutation_id,
        }
    }

    pub const fn primary_path(&self) -> &WorkspaceRelativePath {
        match self {
            Self::CreateDirectory { path, .. }
            | Self::CreateFile { path, .. }
            | Self::UpdateFile { path, .. }
            | Self::PatchFile { path, .. }
            | Self::DeleteFile { path, .. }
            | Self::DeleteDirectory { path, .. } => path,
            Self::MoveFile { source, .. } | Self::MoveDirectory { source, .. } => source,
        }
    }

    pub const fn secondary_path(&self) -> Option<&WorkspaceRelativePath> {
        match self {
            Self::MoveFile { destination, .. } | Self::MoveDirectory { destination, .. } => {
                Some(destination)
            }
            Self::CreateDirectory { .. }
            | Self::CreateFile { .. }
            | Self::UpdateFile { .. }
            | Self::PatchFile { .. }
            | Self::DeleteFile { .. }
            | Self::DeleteDirectory { .. } => None,
        }
    }
}

/// Transient source-patch review evidence retained for one materialized tree
/// request. The bytes remain outside the durable domain intent and are dropped
/// entirely when the bounded review aggregate cannot be retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TreePatchEvidence {
    Windows(BTreeMap<TreeMutationId, PatchReview>),
    SummaryOnly(DiffRenderKind),
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MaterializedSourceTreeRequest {
    draft: TreeChangeSetDraft,
    payloads: SourceTreePayloadSet,
    patch_evidence: TreePatchEvidence,
}

impl MaterializedSourceTreeRequest {
    pub(crate) const fn draft(&self) -> &TreeChangeSetDraft {
        &self.draft
    }

    pub(crate) const fn payloads(&self) -> &SourceTreePayloadSet {
        &self.payloads
    }

    pub(crate) const fn patch_evidence(&self) -> &TreePatchEvidence {
        &self.patch_evidence
    }
}

#[derive(Debug, Error)]
pub(crate) enum SourceTreeMaterializationError {
    #[error(transparent)]
    Filesystem(#[from] ConfinedFilesystemError),
    #[error(transparent)]
    Intent(#[from] TreeChangeSetIntentError),
}

pub(crate) fn materialize_source_tree_request(
    filesystem: &ConfinedWorkspace,
    mutations: Vec<SourceTreeMutationRequest>,
) -> Result<MaterializedSourceTreeRequest, SourceTreeMaterializationError> {
    let mut drafts = Vec::with_capacity(mutations.len());
    let mut payloads = Vec::new();
    let mut payload_bytes = 0_usize;
    let mut all_patch_files = true;
    let mut patch_review_oversized = false;
    let mut patch_review_bytes = 0_usize;
    let mut patch_reviews = BTreeMap::new();
    for mutation in mutations {
        let materialized = materialize_mutation(filesystem, mutation)?;
        let MaterializedMutation {
            draft,
            payload,
            patch_review,
        } = materialized;
        drafts.push(draft);
        if let Some((mutation_id, review)) = patch_review {
            if all_patch_files && !patch_review_oversized {
                let next_total = if review.disposition().is_ready() {
                    patch_review_raw_bytes(&review)
                        .and_then(|bytes| patch_review_bytes.checked_add(bytes))
                        .filter(|total| *total <= MAX_PATCH_REVIEW_BYTES)
                } else {
                    None
                };
                if let Some(total) = next_total {
                    patch_review_bytes = total;
                    if patch_reviews.insert(mutation_id, review).is_some() {
                        return Err(TreeChangeSetIntentError::DuplicateMutationId.into());
                    }
                } else {
                    patch_review_oversized = true;
                    patch_reviews.clear();
                }
            }
        } else {
            all_patch_files = false;
            patch_reviews.clear();
        }
        if let Some(payload) = payload {
            payload_bytes = payload_bytes.checked_add(payload.content().len()).ok_or(
                ConfinedFilesystemError::WriteTooLarge {
                    actual: usize::MAX,
                    maximum: MAX_SOURCE_TREE_PAYLOAD_BYTES,
                },
            )?;
            if payload_bytes > MAX_SOURCE_TREE_PAYLOAD_BYTES {
                return Err(ConfinedFilesystemError::WriteTooLarge {
                    actual: payload_bytes,
                    maximum: MAX_SOURCE_TREE_PAYLOAD_BYTES,
                }
                .into());
            }
            payloads.push(payload);
        }
    }
    let patch_evidence = if !all_patch_files {
        TreePatchEvidence::SummaryOnly(DiffRenderKind::Structured)
    } else if patch_review_oversized {
        TreePatchEvidence::SummaryOnly(DiffRenderKind::Oversized)
    } else {
        TreePatchEvidence::Windows(patch_reviews)
    };
    Ok(MaterializedSourceTreeRequest {
        draft: TreeChangeSetDraft::new(&drafts)?,
        payloads: SourceTreePayloadSet::new(payloads)?,
        patch_evidence,
    })
}

#[must_use]
struct MaterializedMutation {
    draft: TreeMutationDraft,
    payload: Option<SourceTreeMutationPayload>,
    patch_review: Option<(TreeMutationId, PatchReview)>,
}

fn materialize_mutation(
    filesystem: &ConfinedWorkspace,
    mutation: SourceTreeMutationRequest,
) -> Result<MaterializedMutation, SourceTreeMaterializationError> {
    let (mutation_id, plan, payload, patch_review) = match mutation {
        SourceTreeMutationRequest::CreateDirectory { mutation_id, path } => (
            mutation_id,
            TreeMutationPlan::create_directory(path),
            None,
            None,
        ),
        SourceTreeMutationRequest::CreateFile {
            mutation_id,
            path,
            content,
        } => {
            let intended_hash = bounded_write_content_hash(&content)?;
            (
                mutation_id,
                TreeMutationPlan::create_file(path, intended_hash),
                Some(SourceTreeMutationPayload::new(mutation_id, content)?),
                None,
            )
        }
        SourceTreeMutationRequest::UpdateFile {
            mutation_id,
            path,
            expected_whole_file_hash,
            content,
        } => {
            let intended_hash = bounded_write_content_hash(&content)?;
            (
                mutation_id,
                TreeMutationPlan::update_file(path, expected_whole_file_hash, intended_hash),
                Some(SourceTreeMutationPayload::new(mutation_id, content)?),
                None,
            )
        }
        SourceTreeMutationRequest::PatchFile {
            mutation_id,
            path,
            patch,
        } => {
            let prepared = filesystem.compile_file_patch(&path, &patch)?;
            let (compiled, review) = prepared.into_parts();
            let plan =
                TreeMutationPlan::update_file(path, compiled.source_hash(), compiled.result_hash());
            (
                mutation_id,
                plan,
                Some(SourceTreeMutationPayload::from_compiled_patch(
                    mutation_id,
                    compiled,
                )),
                Some((mutation_id, review)),
            )
        }
        SourceTreeMutationRequest::DeleteFile {
            mutation_id,
            path,
            expected_whole_file_hash,
        } => (
            mutation_id,
            TreeMutationPlan::delete_file(path, expected_whole_file_hash),
            None,
            None,
        ),
        SourceTreeMutationRequest::MoveFile {
            mutation_id,
            source,
            destination,
            expected_whole_file_hash,
        } => (
            mutation_id,
            TreeMutationPlan::move_file(source, destination, expected_whole_file_hash),
            None,
            None,
        ),
        SourceTreeMutationRequest::MoveDirectory {
            mutation_id,
            source,
            destination,
        } => (
            mutation_id,
            TreeMutationPlan::move_directory(source, destination),
            None,
            None,
        ),
        SourceTreeMutationRequest::DeleteDirectory { mutation_id, path } => (
            mutation_id,
            TreeMutationPlan::delete_directory(path),
            None,
            None,
        ),
    };
    Ok(MaterializedMutation {
        draft: TreeMutationDraft::new(mutation_id, plan),
        payload,
        patch_review,
    })
}

fn patch_review_raw_bytes(review: &PatchReview) -> Option<usize> {
    review.windows().iter().try_fold(0_usize, |total, window| {
        let source_bytes = window.source().bytes().len();
        let result_bytes = window.result().bytes().len();
        total
            .checked_add(source_bytes)
            .and_then(|total| total.checked_add(result_bytes))
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{FilePatchHunk, SourceLineRange, SourceRangeHash};
    use forge_workspace::{MAX_PATCH_REVIEW_BYTES, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::*;

    fn workspace(
        label: &str,
        files: &[(&str, &[u8])],
    ) -> Result<(PathBuf, ConfinedWorkspace), Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!("forge-control-source-tree-{label}-{unique}"));
        fs::create_dir_all(&root)?;
        for (path, content) in files {
            fs::write(root.join(path), content)?;
        }
        WorkspaceStateLayout::initialize(&root)?;
        let existing = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
        let filesystem = ConfinedWorkspace::open(&existing)?;
        Ok((root, filesystem))
    }

    fn patch_mutation(
        mutation_id: u128,
        file_name: &str,
        source: &[u8],
        replacement: Vec<u8>,
    ) -> Result<SourceTreeMutationRequest, Box<dyn std::error::Error>> {
        let relative = WorkspaceRelativePath::new(PathBuf::from(file_name))?;
        let patch = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(source).as_bytes()),
            vec![FilePatchHunk::new(
                SourceLineRange::new(1, 1)?,
                SourceRangeHash::from_bytes(*blake3::hash(source).as_bytes()),
                replacement,
            )?],
        )?;
        Ok(SourceTreeMutationRequest::PatchFile {
            mutation_id: TreeMutationId::from_uuid(Uuid::from_u128(mutation_id)),
            path: relative,
            patch,
        })
    }

    #[test]
    fn materialization_retains_patch_reviews_for_patch_only_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"old\n";
        let (root, filesystem) = workspace("patch-only", &[("target.txt", source)])?;
        let mutation = patch_mutation(1, "target.txt", source, b"new\n".to_vec())?;
        let materialized = materialize_source_tree_request(&filesystem, vec![mutation])?;

        let TreePatchEvidence::Windows(entries) = materialized.patch_evidence() else {
            return Err("patch-only materialization unexpectedly summarized".into());
        };
        assert_eq!(entries.len(), 1);
        let review = entries
            .get(&TreeMutationId::from_uuid(Uuid::from_u128(1)))
            .ok_or("patch review lost mutation identity")?;
        assert!(review.disposition().is_ready());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn materialization_summarizes_mixed_tree_operations() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = b"old\n";
        let (root, filesystem) = workspace("mixed", &[("target.txt", source)])?;
        let patch = patch_mutation(2, "target.txt", source, b"new\n".to_vec())?;
        let create = SourceTreeMutationRequest::CreateFile {
            mutation_id: TreeMutationId::from_uuid(Uuid::from_u128(3)),
            path: WorkspaceRelativePath::new(PathBuf::from("created.txt"))?,
            content: b"created\n".to_vec(),
        };
        let materialized = materialize_source_tree_request(&filesystem, vec![patch, create])?;
        assert!(matches!(
            materialized.patch_evidence(),
            TreePatchEvidence::SummaryOnly(DiffRenderKind::Structured)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn materialization_drops_all_reviews_when_one_review_is_oversized()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut source = vec![b'x'; MAX_PATCH_REVIEW_BYTES + 1];
        source.push(b'\n');
        let (root, filesystem) = workspace("oversized", &[("target.txt", &source)])?;
        let mutation = patch_mutation(4, "target.txt", &source, b"small\n".to_vec())?;
        let materialized = materialize_source_tree_request(&filesystem, vec![mutation])?;
        assert!(matches!(
            materialized.patch_evidence(),
            TreePatchEvidence::SummaryOnly(DiffRenderKind::Oversized)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn materialization_summarizes_when_ready_reviews_overflow_aggregate_cap()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut first = vec![b'a'; MAX_PATCH_REVIEW_BYTES / 2];
        first.push(b'\n');
        let mut second = vec![b'b'; MAX_PATCH_REVIEW_BYTES / 2];
        second.push(b'\n');
        let (root, filesystem) = workspace(
            "aggregate-cap",
            &[("first.txt", &first), ("second.txt", &second)],
        )?;
        let mutations = vec![
            patch_mutation(5, "first.txt", &first, b"first\n".to_vec())?,
            patch_mutation(6, "second.txt", &second, b"second\n".to_vec())?,
        ];
        let materialized = materialize_source_tree_request(&filesystem, mutations)?;
        assert!(matches!(
            materialized.patch_evidence(),
            TreePatchEvidence::SummaryOnly(DiffRenderKind::Oversized)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
