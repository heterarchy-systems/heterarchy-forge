use std::os::unix::ffi::OsStrExt;

use forge_domain::SourceTreeRequestDigest;

use crate::SourceTreeMutationRequest;

const SOURCE_TREE_REQUEST_DIGEST_DOMAIN: &[u8] = b"heterarchy-forge:source-tree-request:v1\0";

pub fn source_tree_request_digest(
    mutations: &[SourceTreeMutationRequest],
) -> SourceTreeRequestDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_TREE_REQUEST_DIGEST_DOMAIN);
    update_count(&mut hasher, mutations.len());
    for mutation in mutations {
        update_mutation(&mut hasher, mutation);
    }
    SourceTreeRequestDigest::from_bytes(*hasher.finalize().as_bytes())
}

fn update_mutation(hasher: &mut blake3::Hasher, mutation: &SourceTreeMutationRequest) {
    update_bytes(hasher, mutation.mutation_id().into_uuid().as_bytes());
    match mutation {
        SourceTreeMutationRequest::CreateDirectory { path, .. } => {
            hasher.update(&[0]);
            update_path(hasher, path);
        }
        SourceTreeMutationRequest::CreateFile { path, content, .. } => {
            hasher.update(&[1]);
            update_path(hasher, path);
            update_bytes(hasher, content);
        }
        SourceTreeMutationRequest::UpdateFile {
            path,
            expected_whole_file_hash,
            content,
            ..
        } => {
            hasher.update(&[2]);
            update_path(hasher, path);
            hasher.update(expected_whole_file_hash.as_bytes());
            update_bytes(hasher, content);
        }
        SourceTreeMutationRequest::PatchFile { path, patch, .. } => {
            hasher.update(&[3]);
            update_path(hasher, path);
            hasher.update(patch.expected_whole_file_hash().as_bytes());
            update_count(hasher, patch.hunks().len());
            for hunk in patch.hunks() {
                let range = hunk.range();
                hasher.update(&range.start_line().to_le_bytes());
                hasher.update(&range.end_line().to_le_bytes());
                hasher.update(hunk.expected_range_hash().as_bytes());
                update_bytes(hasher, hunk.replacement());
            }
        }
        SourceTreeMutationRequest::DeleteFile {
            path,
            expected_whole_file_hash,
            ..
        } => {
            hasher.update(&[4]);
            update_path(hasher, path);
            hasher.update(expected_whole_file_hash.as_bytes());
        }
        SourceTreeMutationRequest::MoveFile {
            source,
            destination,
            expected_whole_file_hash,
            ..
        } => {
            hasher.update(&[5]);
            update_path(hasher, source);
            update_path(hasher, destination);
            hasher.update(expected_whole_file_hash.as_bytes());
        }
        SourceTreeMutationRequest::MoveDirectory {
            source,
            destination,
            ..
        } => {
            hasher.update(&[6]);
            update_path(hasher, source);
            update_path(hasher, destination);
        }
        SourceTreeMutationRequest::DeleteDirectory { path, .. } => {
            hasher.update(&[7]);
            update_path(hasher, path);
        }
    }
}

fn update_path(hasher: &mut blake3::Hasher, path: &forge_domain::WorkspaceRelativePath) {
    update_bytes(hasher, path.as_path().as_os_str().as_bytes());
}

fn update_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    update_count(hasher, bytes.len());
    hasher.update(bytes);
}

fn update_count(hasher: &mut blake3::Hasher, value: usize) {
    hasher.update(&(value as u64).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::PathBuf;

    use forge_domain::{
        FileContentHash, FilePatch, FilePatchHunk, SourceLineRange, SourceRangeHash,
        TreeMutationId, WorkspaceRelativePath,
    };
    use uuid::Uuid;

    use crate::SourceTreeMutationRequest;

    use super::source_tree_request_digest;

    fn mutation_id(value: u128) -> TreeMutationId {
        TreeMutationId::from_uuid(Uuid::from_u128(value))
    }

    fn relative(path: &str) -> Result<WorkspaceRelativePath, Box<dyn Error>> {
        Ok(WorkspaceRelativePath::new(PathBuf::from(path))?)
    }

    #[test]
    fn digest_is_stable_and_payload_sensitive() -> Result<(), Box<dyn Error>> {
        let base = vec![SourceTreeMutationRequest::CreateFile {
            mutation_id: mutation_id(1),
            path: relative("src/lib.rs")?,
            content: b"one\n".to_vec(),
        }];
        assert_eq!(
            source_tree_request_digest(&base).into_bytes(),
            [
                0x42, 0x13, 0x61, 0x4d, 0x32, 0xdd, 0xc2, 0x87, 0x8a, 0x25, 0x01, 0x36, 0x29, 0x2a,
                0xb3, 0x70, 0xe5, 0x34, 0xb2, 0x7f, 0xad, 0x0a, 0xc1, 0xa1, 0x3a, 0xae, 0x6d, 0x4d,
                0x40, 0xe5, 0x9d, 0x97,
            ]
        );

        let changed = vec![SourceTreeMutationRequest::CreateFile {
            mutation_id: mutation_id(1),
            path: relative("src/lib.rs")?,
            content: b"two\n".to_vec(),
        }];
        assert_ne!(
            source_tree_request_digest(&base),
            source_tree_request_digest(&changed)
        );
        Ok(())
    }

    #[test]
    fn patch_replacement_changes_digest() -> Result<(), Box<dyn Error>> {
        let expected_whole = FileContentHash::from_bytes([1; 32]);
        let expected_range = SourceRangeHash::from_bytes([2; 32]);
        let patch = |replacement: &[u8]| -> Result<FilePatch, Box<dyn Error>> {
            Ok(FilePatch::new(
                expected_whole,
                vec![FilePatchHunk::new(
                    SourceLineRange::new(1, 1)?,
                    expected_range,
                    replacement.to_vec(),
                )?],
            )?)
        };
        let first = vec![SourceTreeMutationRequest::PatchFile {
            mutation_id: mutation_id(2),
            path: relative("src/lib.rs")?,
            patch: patch(b"one\n")?,
        }];
        let second = vec![SourceTreeMutationRequest::PatchFile {
            mutation_id: mutation_id(2),
            path: relative("src/lib.rs")?,
            patch: patch(b"two\n")?,
        }];
        assert_ne!(
            source_tree_request_digest(&first),
            source_tree_request_digest(&second)
        );
        Ok(())
    }
}
