//! Bounded inspection of user-registered local Harness Bundles.
//!
//! A Harness Bundle is owner-provided content rooted at a canonical local
//! directory with a strict `harness.toml` manifest. Registration inspects the
//! bundle without executing it. Verifier execution remains a later sandboxed
//! command boundary.

use std::collections::BTreeSet;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use forge_domain::{
    FileByteCount, FileContentHash, FilePathState, HarnessBundleDescriptor, HarnessBundleId,
    HarnessContentHash, HarnessName, HarnessVersion, MAX_HARNESS_MANAGED_FILES, MAX_HARNESS_SKILLS,
    MAX_HARNESS_VERIFIERS, WorkspaceRelativePath,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use toml::Value as TomlValue;

use crate::{ConfinedFilesystemError, ConfinedWorkspace};

pub const HARNESS_MANIFEST_FILE_NAME: &str = "harness.toml";
pub const HARNESS_MANAGED_STATE_PATH: &str = ".agents/.heterarchy.toml";
const HARNESS_MANAGED_STATE_SCHEMA_VERSION: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
pub const MAX_HARNESS_MANAGED_FILE_BYTES: usize = 2 * 1024 * 1024;
const MAX_MANAGED_FILE_BYTES: u64 = MAX_HARNESS_MANAGED_FILE_BYTES as u64;
const MAX_TOTAL_MANAGED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
const MAX_PATH_COMPONENTS: usize = 16;
const MAX_VERIFIER_NAME_BYTES: usize = 128;
const MAX_VERIFIER_PROGRAM_BYTES: usize = 1_024;
const MAX_VERIFIER_ARGUMENTS: usize = 64;
const MAX_VERIFIER_ARGUMENT_BYTES: usize = 4_096;
const MAX_VERIFIER_PATH_BYTES: usize = 16 * 1024;
const MAX_VERIFIER_PATH_ENTRIES: usize = 64;

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessManagedAsset {
    relative_path: PathBuf,
    bytes: Vec<u8>,
}

impl HarnessManagedAsset {
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessVerifierSpec {
    name: String,
    program: String,
    arguments: Vec<String>,
}

impl HarnessVerifierSpec {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }
}

#[derive(Debug, Error)]
pub enum HarnessVerifierProgramError {
    #[error("Harness verifier program is empty or contains a control character")]
    InvalidProgram,
    #[error(
        "Harness verifier program uses a relative path; only a basename or absolute path is accepted"
    )]
    RelativePath,
    #[error("Harness verifier PATH is missing or exceeds the bounded policy")]
    InvalidPathEnvironment,
    #[error("Harness verifier program could not be resolved to an executable regular file")]
    NotFound,
    #[error("Harness verifier program path I/O failed")]
    Io(#[source] std::io::Error),
}

/// Resolve one declared verifier program without invoking a shell.
///
/// Bare program names are searched only through a bounded set of absolute PATH
/// entries. Relative paths (including `./tool`) are rejected so no process CWD
/// becomes executable authority. The returned path is canonical and must be a
/// regular file with at least one executable bit.
pub fn resolve_harness_verifier_program(
    program: &str,
) -> Result<PathBuf, HarnessVerifierProgramError> {
    if program.is_empty() || program.chars().any(char::is_control) {
        return Err(HarnessVerifierProgramError::InvalidProgram);
    }
    let declared = Path::new(program);
    if declared.is_absolute() {
        return resolve_executable_candidate(declared);
    }
    if declared.components().count() != 1 || program.contains('/') {
        return Err(HarnessVerifierProgramError::RelativePath);
    }
    let path = env::var_os("PATH").ok_or(HarnessVerifierProgramError::InvalidPathEnvironment)?;
    if path.as_encoded_bytes().len() > MAX_VERIFIER_PATH_BYTES {
        return Err(HarnessVerifierProgramError::InvalidPathEnvironment);
    }
    let mut entries = env::split_paths(&path);
    for index in 0..=MAX_VERIFIER_PATH_ENTRIES {
        let Some(directory) = entries.next() else {
            break;
        };
        if index == MAX_VERIFIER_PATH_ENTRIES {
            return Err(HarnessVerifierProgramError::InvalidPathEnvironment);
        }
        if !directory.is_absolute() {
            continue;
        }
        let candidate = directory.join(declared);
        match resolve_executable_candidate(&candidate) {
            Ok(resolved) => return Ok(resolved),
            Err(HarnessVerifierProgramError::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Err(HarnessVerifierProgramError::NotFound)
}

fn resolve_executable_candidate(path: &Path) -> Result<PathBuf, HarnessVerifierProgramError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(HarnessVerifierProgramError::NotFound);
        }
        Err(source) => return Err(HarnessVerifierProgramError::Io(source)),
    };
    if !(metadata.file_type().is_file() || metadata.file_type().is_symlink()) {
        return Err(HarnessVerifierProgramError::NotFound);
    }
    let canonical = fs::canonicalize(path).map_err(HarnessVerifierProgramError::Io)?;
    let canonical_metadata = fs::metadata(&canonical).map_err(HarnessVerifierProgramError::Io)?;
    if !canonical_metadata.is_file() || canonical_metadata.permissions().mode() & 0o111 == 0 {
        return Err(HarnessVerifierProgramError::NotFound);
    }
    Ok(canonical)
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedHarnessBundle {
    source_root: PathBuf,
    descriptor: HarnessBundleDescriptor,
    install_root: PathBuf,
    agents_template: Option<HarnessManagedAsset>,
    managed_files: Vec<HarnessManagedAsset>,
    skills: Vec<String>,
    verifiers: Vec<HarnessVerifierSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarnessPreviewKind {
    ManagedFile,
    AgentsFile,
    ManagedManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarnessPreviewDisposition {
    Create,
    Merge,
    Unchanged,
    Conflict,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessPreviewItem {
    path: WorkspaceRelativePath,
    kind: HarnessPreviewKind,
    disposition: HarnessPreviewDisposition,
    source_hash: FileContentHash,
    source_size: FileByteCount,
}

impl HarnessPreviewItem {
    pub fn path(&self) -> &WorkspaceRelativePath {
        &self.path
    }

    pub const fn kind(&self) -> HarnessPreviewKind {
        self.kind
    }

    pub const fn disposition(&self) -> HarnessPreviewDisposition {
        self.disposition
    }

    pub const fn source_hash(&self) -> FileContentHash {
        self.source_hash
    }

    pub const fn source_size(&self) -> FileByteCount {
        self.source_size
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessInstallPreview {
    descriptor: HarnessBundleDescriptor,
    items: Vec<HarnessPreviewItem>,
    creates: usize,
    merges: usize,
    unchanged: usize,
    conflicts: usize,
}

impl HarnessInstallPreview {
    pub const fn descriptor(&self) -> &HarnessBundleDescriptor {
        &self.descriptor
    }

    pub fn items(&self) -> &[HarnessPreviewItem] {
        &self.items
    }

    pub const fn creates(&self) -> usize {
        self.creates
    }

    pub const fn merges(&self) -> usize {
        self.merges
    }

    pub const fn unchanged(&self) -> usize {
        self.unchanged
    }

    pub const fn conflicts(&self) -> usize {
        self.conflicts
    }

    pub fn can_apply_without_merge(&self) -> bool {
        self.conflicts == 0
            && self
                .items
                .iter()
                .all(|item| item.disposition() != HarnessPreviewDisposition::Merge)
    }

    pub fn can_apply_with_agents_merge(&self) -> bool {
        self.conflicts == 0
            && self.items.iter().all(|item| {
                item.disposition() != HarnessPreviewDisposition::Merge
                    || item.kind() == HarnessPreviewKind::AgentsFile
            })
    }
}

#[derive(Debug, Error)]
pub enum HarnessPreviewError {
    #[error("Harness Preview target path is invalid")]
    InvalidTarget,
    #[error("Harness Preview source size exceeds the supported bound")]
    SourceTooLarge,
    #[error("Harness Preview filesystem observation failed")]
    Filesystem(#[from] ConfinedFilesystemError),
    #[error("Harness AGENTS.md template or existing managed block is invalid")]
    InvalidAgentsDocument,
    #[error("Harness managed manifest exceeds the supported bound")]
    ManagedManifestTooLarge,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessMaterializationReceipt {
    preview: HarnessInstallPreview,
    written_files: usize,
    merged_agents: bool,
}

impl HarnessMaterializationReceipt {
    pub const fn preview(&self) -> &HarnessInstallPreview {
        &self.preview
    }

    pub const fn written_files(&self) -> usize {
        self.written_files
    }

    pub const fn merged_agents(&self) -> bool {
        self.merged_agents
    }
}

#[derive(Debug, Error)]
pub enum HarnessMaterializationError {
    #[error(transparent)]
    Preview(#[from] HarnessPreviewError),
    #[error("Harness Apply Preview is stale")]
    PreviewChanged,
    #[error("Harness Apply requires conflict resolution before materialization")]
    Conflict,
    #[error("Harness Apply filesystem effect failed")]
    Filesystem(#[from] ConfinedFilesystemError),
}

impl InspectedHarnessBundle {
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    pub const fn descriptor(&self) -> &HarnessBundleDescriptor {
        &self.descriptor
    }

    pub fn install_root(&self) -> &Path {
        &self.install_root
    }

    pub const fn agents_template(&self) -> Option<&HarnessManagedAsset> {
        self.agents_template.as_ref()
    }

    pub fn managed_files(&self) -> &[HarnessManagedAsset] {
        &self.managed_files
    }

    pub fn skills(&self) -> &[String] {
        &self.skills
    }

    pub fn verifiers(&self) -> &[HarnessVerifierSpec] {
        &self.verifiers
    }
}

#[derive(Debug, Error)]
pub enum HarnessBundleInspectionError {
    #[error("Harness Bundle source root is missing")]
    MissingSourceRoot,
    #[error("Harness Bundle source root is not a directory")]
    SourceRootNotDirectory,
    #[error("Harness Bundle manifest is missing")]
    MissingManifest,
    #[error("Harness Bundle source contains a symlink, hardlink, or non-regular managed asset")]
    InvalidAssetType,
    #[error("Harness Bundle manifest or managed content exceeds the bounded policy")]
    CapacityExceeded,
    #[error("Harness Bundle manifest contains an unsafe or non-canonical relative path")]
    InvalidPath,
    #[error("Harness Bundle manifest does not match the strict schema")]
    InvalidManifest,
    #[error("Harness Bundle manifest contains a duplicate managed file")]
    DuplicateManagedFile,
    #[error("Harness Bundle identity or bounded metadata is invalid")]
    InvalidDomainMetadata,
    #[error("Harness Bundle source I/O failed")]
    Io(#[source] std::io::Error),
}

impl From<std::io::Error> for HarnessBundleInspectionError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

#[derive(Debug)]
struct ParsedHarnessManifest {
    id: HarnessBundleId,
    name: HarnessName,
    version: HarnessVersion,
    install_root: PathBuf,
    managed_paths: Vec<PathBuf>,
    agents_template_path: Option<PathBuf>,
    skills: Vec<String>,
    verifiers: Vec<HarnessVerifierSpec>,
}

/// Inspect one owner-selected local Harness Bundle without executing it.
pub fn inspect_harness_bundle(
    selected_root: &Path,
) -> Result<InspectedHarnessBundle, HarnessBundleInspectionError> {
    let source_root = canonical_source_root(selected_root)?;
    let manifest = read_manifest(&source_root)?;
    let parsed = parse_manifest(&manifest)?;
    let managed_files = load_managed_assets(&source_root, &parsed.managed_paths)?;
    let agents_template = parsed
        .agents_template_path
        .as_deref()
        .map(|relative| load_managed_asset(&source_root, relative))
        .transpose()?;
    let content_hash = aggregate_hash(&manifest, &managed_files, agents_template.as_ref());
    let descriptor = HarnessBundleDescriptor::new(
        parsed.id,
        parsed.name,
        parsed.version,
        content_hash,
        bounded_count(managed_files.len())?,
        bounded_count(parsed.skills.len())?,
        bounded_count(parsed.verifiers.len())?,
    )
    .map_err(|_| HarnessBundleInspectionError::InvalidDomainMetadata)?;

    Ok(InspectedHarnessBundle {
        source_root,
        descriptor,
        install_root: parsed.install_root,
        agents_template,
        managed_files,
        skills: parsed.skills,
        verifiers: parsed.verifiers,
    })
}

pub fn preview_harness_install(
    filesystem: &ConfinedWorkspace,
    bundle: &InspectedHarnessBundle,
) -> Result<HarnessInstallPreview, HarnessPreviewError> {
    let additional = usize::from(bundle.agents_template().is_some()).saturating_add(1);
    let mut items = Vec::with_capacity(bundle.managed_files().len().saturating_add(additional));
    for asset in bundle.managed_files() {
        let target = bundle.install_root().join(asset.relative_path());
        items.push(preview_item(
            filesystem,
            WorkspaceRelativePath::new(target).map_err(|_| HarnessPreviewError::InvalidTarget)?,
            HarnessPreviewKind::ManagedFile,
            asset.bytes(),
        )?);
    }
    if let Some(template) = bundle.agents_template() {
        items.push(preview_agents_item(filesystem, bundle, template)?);
    }
    let managed_manifest = managed_manifest_bytes(bundle)?;
    items.push(preview_item(
        filesystem,
        WorkspaceRelativePath::new(PathBuf::from(HARNESS_MANAGED_STATE_PATH))
            .map_err(|_| HarnessPreviewError::InvalidTarget)?,
        HarnessPreviewKind::ManagedManifest,
        &managed_manifest,
    )?);
    let (creates, merges, unchanged, conflicts) = items.iter().fold(
        (0_usize, 0_usize, 0_usize, 0_usize),
        |(creates, merges, unchanged, conflicts), item| match item.disposition() {
            HarnessPreviewDisposition::Create => (creates + 1, merges, unchanged, conflicts),
            HarnessPreviewDisposition::Merge => (creates, merges + 1, unchanged, conflicts),
            HarnessPreviewDisposition::Unchanged => (creates, merges, unchanged + 1, conflicts),
            HarnessPreviewDisposition::Conflict => (creates, merges, unchanged, conflicts + 1),
        },
    );
    Ok(HarnessInstallPreview {
        descriptor: bundle.descriptor().clone(),
        items,
        creates,
        merges,
        unchanged,
        conflicts,
    })
}

pub fn materialize_harness_install(
    filesystem: &ConfinedWorkspace,
    bundle: &InspectedHarnessBundle,
    expected_preview: &HarnessInstallPreview,
) -> Result<HarnessMaterializationReceipt, HarnessMaterializationError> {
    if expected_preview.descriptor() != bundle.descriptor()
        || !expected_preview.can_apply_with_agents_merge()
    {
        return Err(HarnessMaterializationError::Conflict);
    }
    let write_guard = filesystem.acquire_write_guard()?;
    let current_preview = preview_harness_install(filesystem, bundle)?;
    if &current_preview != expected_preview {
        return Err(HarnessMaterializationError::PreviewChanged);
    }

    let mut written_files = 0_usize;
    for asset in bundle.managed_files() {
        let target = WorkspaceRelativePath::new(bundle.install_root().join(asset.relative_path()))
            .map_err(|_| HarnessPreviewError::InvalidTarget)?;
        let state =
            filesystem.observe_bounded_file_state(&target, MAX_HARNESS_MANAGED_FILE_BYTES)?;
        let source_hash = FileContentHash::from_bytes(*blake3::hash(asset.bytes()).as_bytes());
        let source_size = FileByteCount::new(
            u64::try_from(asset.bytes().len()).map_err(|_| HarnessPreviewError::SourceTooLarge)?,
        );
        if state
            == (FilePathState::Regular {
                hash: source_hash,
                size: source_size,
            })
        {
            continue;
        }
        if state != FilePathState::Absent {
            return Err(HarnessMaterializationError::PreviewChanged);
        }
        ensure_parent_tree(filesystem, &write_guard, &target)?;
        let _post = filesystem.write_bounded_atomic(
            &write_guard,
            &target,
            FilePathState::Absent,
            asset.bytes(),
            MAX_HARNESS_MANAGED_FILE_BYTES,
        )?;
        written_files += 1;
    }

    let merged_agents = if let Some(template) = bundle.agents_template() {
        materialize_agents(
            filesystem,
            &write_guard,
            bundle,
            template,
            &mut written_files,
        )?
    } else {
        false
    };

    let managed_manifest = managed_manifest_bytes(bundle)?;
    let manifest_path = WorkspaceRelativePath::new(PathBuf::from(HARNESS_MANAGED_STATE_PATH))
        .map_err(|_| HarnessPreviewError::InvalidTarget)?;
    let manifest_state =
        filesystem.observe_bounded_file_state(&manifest_path, MAX_HARNESS_MANAGED_FILE_BYTES)?;
    let manifest_hash = FileContentHash::from_bytes(*blake3::hash(&managed_manifest).as_bytes());
    let manifest_size = FileByteCount::new(
        u64::try_from(managed_manifest.len()).map_err(|_| HarnessPreviewError::SourceTooLarge)?,
    );
    if manifest_state
        != (FilePathState::Regular {
            hash: manifest_hash,
            size: manifest_size,
        })
    {
        if manifest_state != FilePathState::Absent {
            return Err(HarnessMaterializationError::PreviewChanged);
        }
        ensure_parent_tree(filesystem, &write_guard, &manifest_path)?;
        let _post = filesystem.write_bounded_atomic(
            &write_guard,
            &manifest_path,
            FilePathState::Absent,
            &managed_manifest,
            MAX_HARNESS_MANAGED_FILE_BYTES,
        )?;
        written_files += 1;
    }

    let final_preview = preview_harness_install(filesystem, bundle)?;
    if final_preview
        .items()
        .iter()
        .any(|item| !matches!(item.disposition(), HarnessPreviewDisposition::Unchanged))
    {
        return Err(HarnessMaterializationError::PreviewChanged);
    }
    Ok(HarnessMaterializationReceipt {
        preview: final_preview,
        written_files,
        merged_agents,
    })
}

fn preview_item(
    filesystem: &ConfinedWorkspace,
    path: WorkspaceRelativePath,
    kind: HarnessPreviewKind,
    source: &[u8],
) -> Result<HarnessPreviewItem, HarnessPreviewError> {
    if source.len() > MAX_HARNESS_MANAGED_FILE_BYTES {
        return Err(HarnessPreviewError::SourceTooLarge);
    }
    let source_hash = FileContentHash::from_bytes(*blake3::hash(source).as_bytes());
    let source_size = FileByteCount::new(
        u64::try_from(source.len()).map_err(|_| HarnessPreviewError::SourceTooLarge)?,
    );
    let observed = filesystem.observe_bounded_file_state(&path, MAX_HARNESS_MANAGED_FILE_BYTES)?;
    let disposition = match observed {
        FilePathState::Absent => HarnessPreviewDisposition::Create,
        FilePathState::Regular { hash, size } if hash == source_hash && size == source_size => {
            HarnessPreviewDisposition::Unchanged
        }
        FilePathState::Regular { .. } => HarnessPreviewDisposition::Conflict,
    };
    Ok(HarnessPreviewItem {
        path,
        kind,
        disposition,
        source_hash,
        source_size,
    })
}

fn preview_agents_item(
    filesystem: &ConfinedWorkspace,
    bundle: &InspectedHarnessBundle,
    template: &HarnessManagedAsset,
) -> Result<HarnessPreviewItem, HarnessPreviewError> {
    let path = WorkspaceRelativePath::new(PathBuf::from("AGENTS.md"))
        .map_err(|_| HarnessPreviewError::InvalidTarget)?;
    let existing = filesystem.read_bounded_file(&path, MAX_HARNESS_MANAGED_FILE_BYTES)?;
    let (content, disposition) = render_agents_document(
        existing.as_ref().map(crate::ConfinedFileRead::content),
        bundle.descriptor().id(),
        template.bytes(),
    )?;
    let source_hash = FileContentHash::from_bytes(*blake3::hash(&content).as_bytes());
    let source_size = FileByteCount::new(
        u64::try_from(content.len()).map_err(|_| HarnessPreviewError::SourceTooLarge)?,
    );
    Ok(HarnessPreviewItem {
        path,
        kind: HarnessPreviewKind::AgentsFile,
        disposition,
        source_hash,
        source_size,
    })
}

fn materialize_agents(
    filesystem: &ConfinedWorkspace,
    write_guard: &crate::ConfinedWorkspaceWriteGuard,
    bundle: &InspectedHarnessBundle,
    template: &HarnessManagedAsset,
    written_files: &mut usize,
) -> Result<bool, HarnessMaterializationError> {
    let path = WorkspaceRelativePath::new(PathBuf::from("AGENTS.md"))
        .map_err(|_| HarnessPreviewError::InvalidTarget)?;
    let existing = filesystem.read_bounded_file(&path, MAX_HARNESS_MANAGED_FILE_BYTES)?;
    let expected = existing
        .as_ref()
        .map_or(FilePathState::Absent, crate::ConfinedFileRead::state);
    let (content, disposition) = render_agents_document(
        existing.as_ref().map(crate::ConfinedFileRead::content),
        bundle.descriptor().id(),
        template.bytes(),
    )?;
    match disposition {
        HarnessPreviewDisposition::Unchanged => Ok(false),
        HarnessPreviewDisposition::Create | HarnessPreviewDisposition::Merge => {
            let _post = filesystem.write_bounded_atomic(
                write_guard,
                &path,
                expected,
                &content,
                MAX_HARNESS_MANAGED_FILE_BYTES,
            )?;
            *written_files += 1;
            Ok(disposition == HarnessPreviewDisposition::Merge)
        }
        HarnessPreviewDisposition::Conflict => Err(HarnessMaterializationError::Conflict),
    }
}

fn ensure_parent_tree(
    filesystem: &ConfinedWorkspace,
    write_guard: &crate::ConfinedWorkspaceWriteGuard,
    path: &WorkspaceRelativePath,
) -> Result<(), HarnessMaterializationError> {
    let Some(parent) = path.as_path().parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let parent = WorkspaceRelativePath::new(parent.to_path_buf())
        .map_err(|_| HarnessPreviewError::InvalidTarget)?;
    filesystem.ensure_directory_tree(write_guard, &parent)?;
    Ok(())
}

fn render_agents_document(
    existing: Option<&[u8]>,
    bundle_id: HarnessBundleId,
    template: &[u8],
) -> Result<(Vec<u8>, HarnessPreviewDisposition), HarnessPreviewError> {
    let template =
        std::str::from_utf8(template).map_err(|_| HarnessPreviewError::InvalidAgentsDocument)?;
    if template.as_bytes().contains(&0) {
        return Err(HarnessPreviewError::InvalidAgentsDocument);
    }
    let start = format!("<!-- heterarchy:harness:start {bundle_id} -->");
    let end = format!("<!-- heterarchy:harness:end {bundle_id} -->");
    let mut block = String::with_capacity(start.len() + template.len() + end.len() + 4);
    block.push_str(&start);
    block.push('\n');
    block.push_str(template.trim_end_matches('\n'));
    block.push('\n');
    block.push_str(&end);
    block.push('\n');

    let Some(existing) = existing else {
        return Ok((block.into_bytes(), HarnessPreviewDisposition::Create));
    };
    let existing =
        std::str::from_utf8(existing).map_err(|_| HarnessPreviewError::InvalidAgentsDocument)?;
    if existing.as_bytes().contains(&0) {
        return Err(HarnessPreviewError::InvalidAgentsDocument);
    }
    let generic_start = "<!-- heterarchy:harness:start ";
    let generic_end = "<!-- heterarchy:harness:end ";
    let start_matches = existing.match_indices(&start).collect::<Vec<_>>();
    let end_matches = existing.match_indices(&end).collect::<Vec<_>>();
    if start_matches.is_empty() && end_matches.is_empty() {
        if existing.contains(generic_start) || existing.contains(generic_end) {
            return Ok((block.into_bytes(), HarnessPreviewDisposition::Conflict));
        }
        let mut merged = String::with_capacity(existing.len() + block.len() + 2);
        merged.push_str(existing);
        if !existing.is_empty() && !existing.ends_with('\n') {
            merged.push('\n');
        }
        if !existing.is_empty() && !existing.ends_with("\n\n") {
            merged.push('\n');
        }
        merged.push_str(&block);
        return Ok((merged.into_bytes(), HarnessPreviewDisposition::Merge));
    }
    if start_matches.len() != 1 || end_matches.len() != 1 {
        return Ok((block.into_bytes(), HarnessPreviewDisposition::Conflict));
    }
    if existing
        .replace(&start, "")
        .replace(&end, "")
        .contains(generic_start)
        || existing
            .replace(&start, "")
            .replace(&end, "")
            .contains(generic_end)
    {
        return Ok((block.into_bytes(), HarnessPreviewDisposition::Conflict));
    }
    let start_index = start_matches[0].0;
    let after_end = end_matches[0]
        .0
        .checked_add(end.len())
        .ok_or(HarnessPreviewError::InvalidAgentsDocument)?;
    if start_index >= end_matches[0].0 {
        return Ok((block.into_bytes(), HarnessPreviewDisposition::Conflict));
    }
    let mut merged = String::with_capacity(existing.len() + block.len());
    merged.push_str(&existing[..start_index]);
    merged.push_str(&block);
    let suffix = &existing[after_end..];
    merged.push_str(suffix.strip_prefix('\n').unwrap_or(suffix));
    let disposition = if merged == existing {
        HarnessPreviewDisposition::Unchanged
    } else {
        HarnessPreviewDisposition::Merge
    };
    Ok((merged.into_bytes(), disposition))
}

fn managed_manifest_bytes(bundle: &InspectedHarnessBundle) -> Result<Vec<u8>, HarnessPreviewError> {
    let install_root = bundle
        .install_root()
        .to_str()
        .ok_or(HarnessPreviewError::InvalidTarget)?;
    let mut output = String::new();
    writeln!(
        &mut output,
        "schema_version = {HARNESS_MANAGED_STATE_SCHEMA_VERSION}"
    )
    .map_err(|_| HarnessPreviewError::ManagedManifestTooLarge)?;
    push_toml_string_field(
        &mut output,
        "bundle_id",
        &bundle.descriptor().id().to_string(),
    );
    push_toml_string_field(
        &mut output,
        "bundle_version",
        bundle.descriptor().version().as_str(),
    );
    push_toml_string_field(
        &mut output,
        "content_hash",
        &bundle.descriptor().content_hash().to_string(),
    );
    push_toml_string_field(&mut output, "install_root", install_root);
    writeln!(
        &mut output,
        "agents_managed = {}",
        bundle.agents_template().is_some()
    )
    .map_err(|_| HarnessPreviewError::ManagedManifestTooLarge)?;
    output.push_str("deletion_authority = false\n");
    for asset in bundle.managed_files() {
        let target = bundle.install_root().join(asset.relative_path());
        let target = target.to_str().ok_or(HarnessPreviewError::InvalidTarget)?;
        output.push_str("\n[[managed_files]]\n");
        push_toml_string_field(&mut output, "path", target);
        let hash = FileContentHash::from_bytes(*blake3::hash(asset.bytes()).as_bytes());
        push_toml_string_field(&mut output, "hash", &hash.to_string());
        writeln!(&mut output, "size = {}", asset.bytes().len())
            .map_err(|_| HarnessPreviewError::ManagedManifestTooLarge)?;
    }
    if output.len() > MAX_HARNESS_MANAGED_FILE_BYTES {
        return Err(HarnessPreviewError::ManagedManifestTooLarge);
    }
    Ok(output.into_bytes())
}

fn push_toml_string_field(output: &mut String, key: &str, value: &str) {
    output.push_str(key);
    output.push_str(" = \"");
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '"' => output.push_str("\\\""),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character => output.push(character),
        }
    }
    output.push_str("\"\n");
}

fn canonical_source_root(selected_root: &Path) -> Result<PathBuf, HarnessBundleInspectionError> {
    let selected = fs::symlink_metadata(selected_root).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            HarnessBundleInspectionError::MissingSourceRoot
        } else {
            HarnessBundleInspectionError::Io(source)
        }
    })?;
    if !selected.file_type().is_dir() {
        return Err(HarnessBundleInspectionError::SourceRootNotDirectory);
    }
    fs::canonicalize(selected_root).map_err(HarnessBundleInspectionError::from)
}

fn read_manifest(source_root: &Path) -> Result<Vec<u8>, HarnessBundleInspectionError> {
    read_regular_asset(
        source_root,
        Path::new(HARNESS_MANIFEST_FILE_NAME),
        MAX_MANIFEST_BYTES,
    )
    .map_err(|error| match error {
        HarnessBundleInspectionError::Io(source)
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            HarnessBundleInspectionError::MissingManifest
        }
        other => other,
    })
}

fn parse_manifest(manifest: &[u8]) -> Result<ParsedHarnessManifest, HarnessBundleInspectionError> {
    let manifest_text =
        std::str::from_utf8(manifest).map_err(|_| HarnessBundleInspectionError::InvalidManifest)?;
    let document: TomlValue =
        toml::from_str(manifest_text).map_err(|_| HarnessBundleInspectionError::InvalidManifest)?;
    let root_table = document
        .as_table()
        .ok_or(HarnessBundleInspectionError::InvalidManifest)?;
    ensure_exact_keys(
        root_table.keys().map(String::as_str),
        &["harness", "verifiers"],
    )?;
    let harness = root_table
        .get("harness")
        .and_then(TomlValue::as_table)
        .ok_or(HarnessBundleInspectionError::InvalidManifest)?;
    ensure_exact_keys(
        harness.keys().map(String::as_str),
        &[
            "agents_template",
            "id",
            "install_root",
            "managed_files",
            "name",
            "skills",
            "version",
        ],
    )?;

    let id = required_string(harness, "id")?
        .parse::<HarnessBundleId>()
        .map_err(|_| HarnessBundleInspectionError::InvalidDomainMetadata)?;
    let name = HarnessName::new(required_string(harness, "name")?.to_owned())
        .map_err(|_| HarnessBundleInspectionError::InvalidDomainMetadata)?;
    let version = HarnessVersion::new(required_string(harness, "version")?.to_owned())
        .map_err(|_| HarnessBundleInspectionError::InvalidDomainMetadata)?;
    let install_root = safe_install_root(required_string(harness, "install_root")?)?;
    let managed_paths = parse_managed_paths(harness)?;
    let skills = optional_string_array(harness, "skills")?;
    if skills.len() > usize::from(MAX_HARNESS_SKILLS) {
        return Err(HarnessBundleInspectionError::CapacityExceeded);
    }
    validate_unique_labels(&skills)?;
    let verifiers = parse_verifiers(root_table.get("verifiers"))?;
    let agents_template_path = harness
        .get("agents_template")
        .map(|value| {
            value
                .as_str()
                .ok_or(HarnessBundleInspectionError::InvalidManifest)
                .and_then(safe_relative_path)
        })
        .transpose()?;
    if agents_template_path.as_deref() == Some(Path::new(HARNESS_MANIFEST_FILE_NAME)) {
        return Err(HarnessBundleInspectionError::InvalidPath);
    }

    Ok(ParsedHarnessManifest {
        id,
        name,
        version,
        install_root,
        managed_paths,
        agents_template_path,
        skills,
        verifiers,
    })
}

fn parse_managed_paths(
    harness: &toml::map::Map<String, TomlValue>,
) -> Result<Vec<PathBuf>, HarnessBundleInspectionError> {
    let raw_paths = required_string_array(harness, "managed_files")?;
    if raw_paths.is_empty() || raw_paths.len() > usize::from(MAX_HARNESS_MANAGED_FILES) {
        return Err(HarnessBundleInspectionError::CapacityExceeded);
    }
    let mut unique = BTreeSet::new();
    raw_paths
        .into_iter()
        .map(|raw| {
            let relative = safe_relative_path(raw)?;
            if relative == Path::new(HARNESS_MANIFEST_FILE_NAME) || !unique.insert(relative.clone())
            {
                return Err(HarnessBundleInspectionError::DuplicateManagedFile);
            }
            Ok(relative)
        })
        .collect()
}

fn load_managed_assets(
    source_root: &Path,
    managed_paths: &[PathBuf],
) -> Result<Vec<HarnessManagedAsset>, HarnessBundleInspectionError> {
    let mut total_bytes = 0_u64;
    managed_paths
        .iter()
        .map(|relative| {
            let asset = load_managed_asset(source_root, relative)?;
            total_bytes = total_bytes
                .checked_add(
                    u64::try_from(asset.bytes.len())
                        .map_err(|_| HarnessBundleInspectionError::CapacityExceeded)?,
                )
                .ok_or(HarnessBundleInspectionError::CapacityExceeded)?;
            if total_bytes > MAX_TOTAL_MANAGED_BYTES {
                return Err(HarnessBundleInspectionError::CapacityExceeded);
            }
            Ok(asset)
        })
        .collect()
}

fn load_managed_asset(
    source_root: &Path,
    relative: &Path,
) -> Result<HarnessManagedAsset, HarnessBundleInspectionError> {
    Ok(HarnessManagedAsset {
        relative_path: relative.to_path_buf(),
        bytes: read_regular_asset(source_root, relative, MAX_MANAGED_FILE_BYTES)?,
    })
}

fn bounded_count(value: usize) -> Result<u16, HarnessBundleInspectionError> {
    u16::try_from(value).map_err(|_| HarnessBundleInspectionError::CapacityExceeded)
}

fn ensure_exact_keys<'a>(
    mut actual: impl Iterator<Item = &'a str>,
    allowed: &[&str],
) -> Result<(), HarnessBundleInspectionError> {
    if actual.all(|key| allowed.contains(&key)) {
        Ok(())
    } else {
        Err(HarnessBundleInspectionError::InvalidManifest)
    }
}

fn required_string<'a>(
    table: &'a toml::map::Map<String, TomlValue>,
    key: &str,
) -> Result<&'a str, HarnessBundleInspectionError> {
    table
        .get(key)
        .and_then(TomlValue::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(HarnessBundleInspectionError::InvalidManifest)
}

fn required_string_array<'a>(
    table: &'a toml::map::Map<String, TomlValue>,
    key: &str,
) -> Result<Vec<&'a str>, HarnessBundleInspectionError> {
    table
        .get(key)
        .and_then(TomlValue::as_array)
        .ok_or(HarnessBundleInspectionError::InvalidManifest)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|entry| !entry.is_empty())
                .ok_or(HarnessBundleInspectionError::InvalidManifest)
        })
        .collect()
}

fn optional_string_array(
    table: &toml::map::Map<String, TomlValue>,
    key: &str,
) -> Result<Vec<String>, HarnessBundleInspectionError> {
    let Some(values) = table.get(key) else {
        return Ok(Vec::new());
    };
    values
        .as_array()
        .ok_or(HarnessBundleInspectionError::InvalidManifest)?
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .filter(|entry| !entry.is_empty())
                .ok_or(HarnessBundleInspectionError::InvalidManifest)?;
            if value.len() > 256 || value.chars().any(char::is_control) {
                return Err(HarnessBundleInspectionError::InvalidManifest);
            }
            Ok(value.to_owned())
        })
        .collect()
}

fn validate_unique_labels(values: &[String]) -> Result<(), HarnessBundleInspectionError> {
    let mut seen = BTreeSet::new();
    if values.iter().all(|value| seen.insert(value.as_str())) {
        Ok(())
    } else {
        Err(HarnessBundleInspectionError::InvalidManifest)
    }
}

fn parse_verifiers(
    value: Option<&TomlValue>,
) -> Result<Vec<HarnessVerifierSpec>, HarnessBundleInspectionError> {
    let Some(values) = value else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .ok_or(HarnessBundleInspectionError::InvalidManifest)?;
    if values.len() > usize::from(MAX_HARNESS_VERIFIERS) {
        return Err(HarnessBundleInspectionError::CapacityExceeded);
    }
    let mut names = BTreeSet::new();
    values
        .iter()
        .map(|value| {
            let table = value
                .as_table()
                .ok_or(HarnessBundleInspectionError::InvalidManifest)?;
            ensure_exact_keys(
                table.keys().map(String::as_str),
                &["args", "name", "program"],
            )?;
            let name = required_string(table, "name")?;
            let program = required_string(table, "program")?;
            if name.len() > MAX_VERIFIER_NAME_BYTES
                || program.len() > MAX_VERIFIER_PROGRAM_BYTES
                || name.chars().any(char::is_control)
                || program.chars().any(char::is_control)
                || !names.insert(name)
            {
                return Err(HarnessBundleInspectionError::InvalidManifest);
            }
            let arguments = optional_string_array(table, "args")?;
            if arguments.len() > MAX_VERIFIER_ARGUMENTS
                || arguments
                    .iter()
                    .any(|argument| argument.len() > MAX_VERIFIER_ARGUMENT_BYTES)
            {
                return Err(HarnessBundleInspectionError::CapacityExceeded);
            }
            Ok(HarnessVerifierSpec {
                name: name.to_owned(),
                program: program.to_owned(),
                arguments,
            })
        })
        .collect()
}

fn safe_install_root(value: &str) -> Result<PathBuf, HarnessBundleInspectionError> {
    let path = safe_relative_path(value)?;
    let mut components = path.components();
    if components.next() != Some(Component::Normal(std::ffi::OsStr::new(".agents")))
        || components.next().is_none()
    {
        return Err(HarnessBundleInspectionError::InvalidPath);
    }
    Ok(path)
}

fn safe_relative_path(value: &str) -> Result<PathBuf, HarnessBundleInspectionError> {
    let path = Path::new(value);
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_RELATIVE_PATH_BYTES
        || path.is_absolute()
        || value.chars().any(char::is_control)
    {
        return Err(HarnessBundleInspectionError::InvalidPath);
    }
    let mut count = 0_usize;
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err(HarnessBundleInspectionError::InvalidPath);
        }
        count += 1;
        if count > MAX_PATH_COMPONENTS {
            return Err(HarnessBundleInspectionError::InvalidPath);
        }
    }
    Ok(path.to_path_buf())
}

fn read_regular_asset(
    root: &Path,
    relative: &Path,
    maximum: u64,
) -> Result<Vec<u8>, HarnessBundleInspectionError> {
    let mut current = root.to_path_buf();
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err(HarnessBundleInspectionError::InvalidPath);
        };
        current.push(name);
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() {
            return Err(HarnessBundleInspectionError::InvalidAssetType);
        }
        let is_last = index + 1 == components.len();
        if is_last {
            if !metadata.file_type().is_file() || metadata.nlink() != 1 {
                return Err(HarnessBundleInspectionError::InvalidAssetType);
            }
            if metadata.len() > maximum {
                return Err(HarnessBundleInspectionError::CapacityExceeded);
            }
        } else if !metadata.file_type().is_dir() {
            return Err(HarnessBundleInspectionError::InvalidAssetType);
        }
    }
    fs::read(current).map_err(HarnessBundleInspectionError::from)
}

fn aggregate_hash(
    manifest: &[u8],
    managed_files: &[HarnessManagedAsset],
    agents_template: Option<&HarnessManagedAsset>,
) -> HarnessContentHash {
    let mut digest = Sha256::new();
    hash_record(&mut digest, HARNESS_MANIFEST_FILE_NAME.as_bytes(), manifest);
    for asset in managed_files {
        hash_record(
            &mut digest,
            asset.relative_path.as_os_str().as_encoded_bytes(),
            &asset.bytes,
        );
    }
    if let Some(asset) = agents_template {
        hash_record(
            &mut digest,
            asset.relative_path.as_os_str().as_encoded_bytes(),
            &asset.bytes,
        );
    }
    HarnessContentHash::from_bytes(digest.finalize().into())
}

fn hash_record(digest: &mut Sha256, path: &[u8], bytes: &[u8]) {
    digest.update(u64::try_from(path.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(path);
    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(bytes);
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    fn fixture_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-{label}-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("rules"))?;
        fs::create_dir_all(root.join("skills/rust"))?;
        fs::write(root.join("rules/base.md"), b"# Rules\n")?;
        fs::write(root.join("skills/rust/SKILL.md"), b"# Skill\n")?;
        fs::write(root.join("AGENTS.md.template"), b"Read managed rules.\n")?;
        fs::write(
            root.join(HARNESS_MANIFEST_FILE_NAME),
            r#"[harness]
id = "00000000-0000-0000-0000-000000000041"
name = "Rust Dev Harness"
version = "3.0.0"
install_root = ".agents/rust_dev_harness"
agents_template = "AGENTS.md.template"
managed_files = ["rules/base.md", "skills/rust/SKILL.md"]
skills = ["rust-engineering"]

[[verifiers]]
name = "rules"
program = "cargo"
args = ["xtask", "rules"]
"#,
        )?;
        Ok(root)
    }

    #[test]
    fn generic_bundle_inspection_is_bounded_and_hash_detects_source_drift()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root("valid")?;
        let first = inspect_harness_bundle(&root)?;
        assert_eq!(first.descriptor().name().as_str(), "Rust Dev Harness");
        assert_eq!(first.descriptor().version().as_str(), "3.0.0");
        assert_eq!(first.descriptor().managed_file_count(), 2);
        assert_eq!(first.descriptor().skill_count(), 1);
        assert_eq!(first.descriptor().verifier_count(), 1);
        assert_eq!(first.install_root(), Path::new(".agents/rust_dev_harness"));
        assert_eq!(first.verifiers()[0].program(), "cargo");
        let first_hash = first.descriptor().content_hash();

        fs::write(root.join("rules/base.md"), b"# Changed rules\n")?;
        let changed = inspect_harness_bundle(&root)?;
        assert_ne!(changed.descriptor().content_hash(), first_hash);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn bundle_rejects_escape_and_symlinked_managed_assets() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = fixture_root("unsafe")?;
        let outside = root
            .parent()
            .ok_or("fixture parent missing")?
            .join("outside-rule.md");
        fs::write(&outside, b"outside")?;
        symlink(&outside, root.join("rules/link.md"))?;
        let manifest = fs::read_to_string(root.join(HARNESS_MANIFEST_FILE_NAME))?
            .replace("\"rules/base.md\"", "\"rules/link.md\"");
        fs::write(root.join(HARNESS_MANIFEST_FILE_NAME), manifest)?;
        assert!(matches!(
            inspect_harness_bundle(&root),
            Err(HarnessBundleInspectionError::InvalidAssetType)
        ));
        fs::remove_dir_all(root)?;
        fs::remove_file(outside)?;
        Ok(())
    }

    #[test]
    fn verifier_program_resolution_is_shell_free_and_rejects_relative_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolved = resolve_harness_verifier_program("/usr/bin/true")?;
        assert!(resolved.is_absolute());
        assert!(fs::metadata(&resolved)?.is_file());
        assert!(matches!(
            resolve_harness_verifier_program("./tool"),
            Err(HarnessVerifierProgramError::RelativePath)
        ));
        Ok(())
    }

    #[test]
    fn harness_preview_and_materialization_preserve_user_agents_and_converge()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = fixture_root("preview-source")?;
        let bundle = inspect_harness_bundle(&source)?;
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let workspace = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-preview-workspace-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&workspace)?;
        let layout = crate::WorkspaceStateLayout::initialize(&workspace)?;
        let existing = crate::WorkspaceStateLayout::inspect_existing(&workspace)?
            .ok_or("workspace layout missing")?;
        let filesystem = ConfinedWorkspace::open(&existing)?;

        fs::write(
            workspace.join("AGENTS.md"),
            b"# Project instructions\n\nKeep this user-authored section.\n",
        )?;
        let create_preview = preview_harness_install(&filesystem, &bundle)?;
        assert_eq!(create_preview.creates(), 3);
        assert_eq!(create_preview.unchanged(), 0);
        assert_eq!(create_preview.conflicts(), 0);
        assert!(!create_preview.can_apply_without_merge());
        assert!(create_preview.can_apply_with_agents_merge());
        assert_eq!(
            create_preview
                .items()
                .iter()
                .find(|item| item.kind() == HarnessPreviewKind::AgentsFile)
                .map(HarnessPreviewItem::disposition),
            Some(HarnessPreviewDisposition::Merge)
        );
        assert!(
            !workspace
                .join(".agents/rust_dev_harness/rules/base.md")
                .exists()
        );

        let receipt = materialize_harness_install(&filesystem, &bundle, &create_preview)?;
        assert_eq!(receipt.written_files(), 4);
        assert!(receipt.merged_agents());
        assert!(workspace.join(HARNESS_MANAGED_STATE_PATH).is_file());
        assert!(
            fs::read_to_string(workspace.join(HARNESS_MANAGED_STATE_PATH))?
                .contains("deletion_authority = false")
        );
        assert_eq!(
            fs::read(workspace.join(".agents/rust_dev_harness/rules/base.md"))?,
            b"# Rules\n"
        );
        let agents = fs::read_to_string(workspace.join("AGENTS.md"))?;
        assert!(agents.starts_with("# Project instructions\n\nKeep this user-authored section.\n"));
        assert!(
            agents
                .contains("<!-- heterarchy:harness:start 00000000-0000-0000-0000-000000000041 -->")
        );
        assert!(agents.contains("Read managed rules."));
        assert!(
            agents.contains("<!-- heterarchy:harness:end 00000000-0000-0000-0000-000000000041 -->")
        );

        let unchanged_preview = preview_harness_install(&filesystem, &bundle)?;
        assert_eq!(unchanged_preview.creates(), 0);
        assert_eq!(unchanged_preview.unchanged(), 4);
        assert_eq!(unchanged_preview.conflicts(), 0);
        assert!(unchanged_preview.can_apply_without_merge());
        let retry = materialize_harness_install(&filesystem, &bundle, &unchanged_preview)?;
        assert_eq!(retry.written_files(), 0);
        assert!(!retry.merged_agents());

        fs::write(
            workspace.join(".agents/rust_dev_harness/rules/base.md"),
            b"# User drift\n",
        )?;
        let conflict_preview = preview_harness_install(&filesystem, &bundle)?;
        assert_eq!(conflict_preview.conflicts(), 1);
        assert!(!conflict_preview.can_apply_with_agents_merge());
        assert!(matches!(
            materialize_harness_install(&filesystem, &bundle, &conflict_preview),
            Err(HarnessMaterializationError::Conflict)
        ));

        drop(filesystem);
        drop(layout);
        fs::remove_dir_all(source)?;
        fs::remove_dir_all(workspace)?;
        Ok(())
    }

    #[test]
    fn harness_materialization_rejects_stale_preview_before_first_write()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = fixture_root("stale-apply-source")?;
        let bundle = inspect_harness_bundle(&source)?;
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let workspace = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-stale-apply-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&workspace)?;
        let _layout = crate::WorkspaceStateLayout::initialize(&workspace)?;
        let existing = crate::WorkspaceStateLayout::inspect_existing(&workspace)?
            .ok_or("workspace layout missing")?;
        let filesystem = ConfinedWorkspace::open(&existing)?;
        let preview = preview_harness_install(&filesystem, &bundle)?;

        fs::create_dir_all(workspace.join(".agents/rust_dev_harness/rules"))?;
        fs::write(
            workspace.join(".agents/rust_dev_harness/rules/base.md"),
            b"external change\n",
        )?;
        assert!(matches!(
            materialize_harness_install(&filesystem, &bundle, &preview),
            Err(HarnessMaterializationError::PreviewChanged)
        ));
        assert!(!workspace.join(HARNESS_MANAGED_STATE_PATH).exists());
        assert!(!workspace.join("AGENTS.md").exists());
        assert!(
            !workspace
                .join(".agents/rust_dev_harness/skills/rust/SKILL.md")
                .exists()
        );

        drop(filesystem);
        fs::remove_dir_all(source)?;
        fs::remove_dir_all(workspace)?;
        Ok(())
    }

    #[test]
    fn partial_materialization_without_manifest_retries_to_complete()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = fixture_root("partial-retry-source")?;
        let bundle = inspect_harness_bundle(&source)?;
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let workspace = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-partial-retry-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&workspace)?;
        let _layout = crate::WorkspaceStateLayout::initialize(&workspace)?;

        fs::create_dir_all(workspace.join(".agents/rust_dev_harness/rules"))?;
        fs::write(
            workspace.join(".agents/rust_dev_harness/rules/base.md"),
            b"# Rules\n",
        )?;
        assert!(!workspace.join(HARNESS_MANAGED_STATE_PATH).exists());

        let existing = crate::WorkspaceStateLayout::inspect_existing(&workspace)?
            .ok_or("workspace layout missing")?;
        let filesystem = ConfinedWorkspace::open(&existing)?;
        let retry_preview = preview_harness_install(&filesystem, &bundle)?;
        assert_eq!(retry_preview.unchanged(), 1);
        assert_eq!(retry_preview.creates(), 3);
        assert_eq!(retry_preview.conflicts(), 0);
        let receipt = materialize_harness_install(&filesystem, &bundle, &retry_preview)?;
        assert_eq!(receipt.written_files(), 3);
        assert!(workspace.join(HARNESS_MANAGED_STATE_PATH).is_file());
        assert!(workspace.join("AGENTS.md").is_file());
        assert!(
            workspace
                .join(".agents/rust_dev_harness/skills/rust/SKILL.md")
                .is_file()
        );
        assert!(
            receipt
                .preview()
                .items()
                .iter()
                .all(|item| { item.disposition() == HarnessPreviewDisposition::Unchanged })
        );

        drop(filesystem);
        fs::remove_dir_all(source)?;
        fs::remove_dir_all(workspace)?;
        Ok(())
    }

    #[test]
    fn harness_preview_rejects_symlinked_workspace_target() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = fixture_root("preview-symlink-source")?;
        let bundle = inspect_harness_bundle(&source)?;
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let workspace = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-preview-symlink-workspace-{}-{serial}",
            std::process::id()
        ));
        let outside = std::env::temp_dir().join(format!(
            "heterarchy-forge-harness-preview-outside-{}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&workspace)?;
        fs::write(&outside, b"outside")?;
        let _layout = crate::WorkspaceStateLayout::initialize(&workspace)?;
        fs::create_dir_all(workspace.join(".agents/rust_dev_harness/rules"))?;
        symlink(
            &outside,
            workspace.join(".agents/rust_dev_harness/rules/base.md"),
        )?;
        let existing = crate::WorkspaceStateLayout::inspect_existing(&workspace)?
            .ok_or("workspace layout missing")?;
        let filesystem = ConfinedWorkspace::open(&existing)?;

        assert!(matches!(
            preview_harness_install(&filesystem, &bundle),
            Err(HarnessPreviewError::Filesystem(
                ConfinedFilesystemError::SymlinkRejected
            ))
        ));

        drop(filesystem);
        fs::remove_dir_all(source)?;
        fs::remove_dir_all(workspace)?;
        fs::remove_file(outside)?;
        Ok(())
    }
}
