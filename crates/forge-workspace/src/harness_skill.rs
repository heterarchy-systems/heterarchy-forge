//! Bounded inspection of optional local Harness Skill sources.
//!
//! A registered Skill is one owner-selected directory whose canonical basename
//! becomes its install key and whose root contains a regular `SKILL.md`. The
//! complete regular-file tree is inspected without execution so references and
//! helper scripts remain part of the deterministic content identity.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use forge_domain::{
    HarnessContentHash, HarnessSkillDescriptor, HarnessSkillId, HarnessSkillName,
    MAX_HARNESS_SKILL_FILES,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const HARNESS_SKILL_ENTRY_FILE: &str = "SKILL.md";
pub const MAX_HARNESS_SKILL_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_HARNESS_SKILL_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_HARNESS_SKILL_PATH_BYTES: usize = 4_096;
const MAX_HARNESS_SKILL_PATH_COMPONENTS: usize = 16;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessSkillAsset {
    relative_path: PathBuf,
    bytes: Vec<u8>,
}

impl HarnessSkillAsset {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedHarnessSkill {
    source_root: PathBuf,
    descriptor: HarnessSkillDescriptor,
    assets: Vec<HarnessSkillAsset>,
}

impl InspectedHarnessSkill {
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    pub const fn descriptor(&self) -> &HarnessSkillDescriptor {
        &self.descriptor
    }

    pub fn assets(&self) -> &[HarnessSkillAsset] {
        &self.assets
    }
}

#[derive(Debug, Error)]
pub enum HarnessSkillInspectionError {
    #[error("Harness Skill source root is missing")]
    MissingSourceRoot,
    #[error("Harness Skill source root is not a directory")]
    SourceRootNotDirectory,
    #[error("Harness Skill source basename is invalid")]
    InvalidName,
    #[error("Harness Skill source must contain a regular top-level SKILL.md")]
    MissingEntryFile,
    #[error("Harness Skill source contains a symbolic link or unsupported file type")]
    InvalidAssetType,
    #[error("Harness Skill relative path exceeds the bounded policy")]
    InvalidPath,
    #[error("Harness Skill source exceeds the bounded file/byte capacity")]
    CapacityExceeded,
    #[error("Harness Skill source I/O failed")]
    Io(#[source] std::io::Error),
    #[error("Harness Skill descriptor is invalid")]
    InvalidDescriptor,
}

impl From<std::io::Error> for HarnessSkillInspectionError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

/// Inspect an owner-selected Skill source without executing any content.
pub fn inspect_harness_skill(
    selected_root: &Path,
    id: HarnessSkillId,
) -> Result<InspectedHarnessSkill, HarnessSkillInspectionError> {
    let source_root = canonical_skill_root(selected_root)?;
    let name = source_root
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(HarnessSkillInspectionError::InvalidName)
        .and_then(|value| {
            HarnessSkillName::new(value.to_owned())
                .map_err(|_| HarnessSkillInspectionError::InvalidName)
        })?;
    require_entry_file(&source_root)?;
    let assets = load_skill_assets(&source_root)?;
    let file_count =
        u16::try_from(assets.len()).map_err(|_| HarnessSkillInspectionError::CapacityExceeded)?;
    let content_hash = aggregate_skill_hash(&assets);
    let descriptor = HarnessSkillDescriptor::new(id, name, content_hash, file_count)
        .map_err(|_| HarnessSkillInspectionError::InvalidDescriptor)?;
    Ok(InspectedHarnessSkill {
        source_root,
        descriptor,
        assets,
    })
}

fn canonical_skill_root(selected_root: &Path) -> Result<PathBuf, HarnessSkillInspectionError> {
    let metadata = fs::symlink_metadata(selected_root).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            HarnessSkillInspectionError::MissingSourceRoot
        } else {
            HarnessSkillInspectionError::Io(source)
        }
    })?;
    if !metadata.file_type().is_dir() {
        return Err(HarnessSkillInspectionError::SourceRootNotDirectory);
    }
    fs::canonicalize(selected_root).map_err(HarnessSkillInspectionError::from)
}

fn require_entry_file(source_root: &Path) -> Result<(), HarnessSkillInspectionError> {
    let entry = source_root.join(HARNESS_SKILL_ENTRY_FILE);
    let metadata = match fs::symlink_metadata(entry) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(HarnessSkillInspectionError::MissingEntryFile);
        }
        Err(source) => return Err(HarnessSkillInspectionError::Io(source)),
    };
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(HarnessSkillInspectionError::MissingEntryFile);
    }
    Ok(())
}

fn load_skill_assets(
    source_root: &Path,
) -> Result<Vec<HarnessSkillAsset>, HarnessSkillInspectionError> {
    let mut paths = Vec::new();
    collect_skill_paths(source_root, Path::new(""), &mut paths)?;
    paths.sort();
    if paths.is_empty() || paths.len() > usize::from(MAX_HARNESS_SKILL_FILES) {
        return Err(HarnessSkillInspectionError::CapacityExceeded);
    }
    let mut total = 0_u64;
    let mut assets = Vec::with_capacity(paths.len());
    for relative_path in paths {
        let absolute = source_root.join(&relative_path);
        let metadata = fs::symlink_metadata(&absolute)?;
        let size = metadata.len();
        if size > MAX_HARNESS_SKILL_FILE_BYTES {
            return Err(HarnessSkillInspectionError::CapacityExceeded);
        }
        total = total
            .checked_add(size)
            .ok_or(HarnessSkillInspectionError::CapacityExceeded)?;
        if total > MAX_HARNESS_SKILL_TOTAL_BYTES {
            return Err(HarnessSkillInspectionError::CapacityExceeded);
        }
        let bytes = fs::read(absolute)?;
        if u64::try_from(bytes.len()).ok() != Some(size) {
            return Err(HarnessSkillInspectionError::Io(std::io::Error::other(
                "Harness Skill asset changed during inspection",
            )));
        }
        assets.push(HarnessSkillAsset {
            relative_path,
            bytes,
        });
    }
    Ok(assets)
}

fn collect_skill_paths(
    source_root: &Path,
    relative_directory: &Path,
    output: &mut Vec<PathBuf>,
) -> Result<(), HarnessSkillInspectionError> {
    let directory = source_root.join(relative_directory);
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let file_name = entry.file_name();
        let relative = relative_directory.join(file_name);
        validate_skill_relative_path(&relative)?;
        let metadata = fs::symlink_metadata(entry.path())?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(HarnessSkillInspectionError::InvalidAssetType);
        }
        if file_type.is_dir() {
            collect_skill_paths(source_root, &relative, output)?;
        } else if file_type.is_file() && metadata.nlink() == 1 {
            output.push(relative);
            if output.len() > usize::from(MAX_HARNESS_SKILL_FILES) {
                return Err(HarnessSkillInspectionError::CapacityExceeded);
            }
        } else {
            return Err(HarnessSkillInspectionError::InvalidAssetType);
        }
    }
    Ok(())
}

fn validate_skill_relative_path(path: &Path) -> Result<(), HarnessSkillInspectionError> {
    let encoded = path.as_os_str().as_encoded_bytes();
    if encoded.is_empty()
        || encoded.len() > MAX_HARNESS_SKILL_PATH_BYTES
        || encoded.contains(&0)
        || path.components().count() > MAX_HARNESS_SKILL_PATH_COMPONENTS
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(HarnessSkillInspectionError::InvalidPath);
    }
    Ok(())
}

fn aggregate_skill_hash(assets: &[HarnessSkillAsset]) -> HarnessContentHash {
    let mut digest = Sha256::new();
    digest.update(b"heterarchy-forge:harness-skill:v1\0");
    for asset in assets {
        update_hash_field(
            &mut digest,
            asset.relative_path.as_os_str().as_encoded_bytes(),
        );
        update_hash_field(&mut digest, &asset.bytes);
    }
    HarnessContentHash::from_bytes(digest.finalize().into())
}

fn update_hash_field(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use uuid::Uuid;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn fixture_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-skill-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("references"))?;
        fs::write(root.join(HARNESS_SKILL_ENTRY_FILE), b"# Skill\n")?;
        fs::write(root.join("references/guide.md"), b"# Guide\n")?;
        Ok(root)
    }

    #[test]
    fn skill_inspection_hashes_complete_regular_tree_and_detects_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root("valid")?;
        let id = HarnessSkillId::from_uuid(Uuid::from_u128(0x4602));
        let first = inspect_harness_skill(&root, id)?;
        assert_eq!(first.descriptor().file_count(), 2);
        let first_hash = first.descriptor().content_hash();
        fs::write(root.join("references/guide.md"), b"# Changed\n")?;
        let changed = inspect_harness_skill(&root, id)?;
        assert_ne!(changed.descriptor().content_hash(), first_hash);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn skill_inspection_requires_entry_and_rejects_symlinks()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root("unsafe")?;
        let id = HarnessSkillId::from_uuid(Uuid::from_u128(0x4603));
        let outside = root
            .parent()
            .ok_or("fixture parent missing")?
            .join(format!("forge-skill-outside-{}", std::process::id()));
        fs::write(&outside, b"outside")?;
        symlink(&outside, root.join("references/link.md"))?;
        assert!(matches!(
            inspect_harness_skill(&root, id),
            Err(HarnessSkillInspectionError::InvalidAssetType)
        ));
        fs::remove_dir_all(root)?;
        fs::remove_file(outside)?;
        Ok(())
    }
}
