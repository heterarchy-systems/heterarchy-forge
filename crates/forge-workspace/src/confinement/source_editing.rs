//! Bounded source discovery and editing operations over a descriptor-rooted
//! [`super::ConfinedWorkspace`].
//!
//! The module deliberately keeps source editing below the existing durable
//! `ChangeSet` boundary: discovery and patch compilation are read-only here;
//! callers publish the returned content through the normal prepared mutation
//! lifecycle.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

mod text_search;

use forge_domain::{
    CompiledFilePatch, FileByteCount, FileEntryKind, FileListEntry, FileListOptions,
    FileListResult, FilePatch, FileReadSlice, FileReadSliceError, MAX_SOURCE_PATCH_BYTES,
    MAX_SOURCE_SLICE_BYTES, MAX_SOURCE_SLICE_SCAN_BYTES, SourceEol, SourceLineRange,
    SourceRangeHash,
};
use rustix::fs::{AtFlags, Dir, FileType, fstat, statat};

use super::{
    ConfinedFilesystemError, ConfinedWorkspace, MAX_FILE_PATH_COMPONENTS, directory_identity,
    ensure_directory_identity, is_excluded_workspace_component, open_regular_leaf,
    validate_not_protected, walk_directories,
};

/// Maximum number of directory entries retained while sorting one listing.
pub const MAX_FILE_LIST_SCAN_ENTRIES: usize = 16 * 1024;
/// Maximum bytes read from one candidate file during a literal source search.
pub const MAX_TEXT_SEARCH_FILE_BYTES: usize = 16 * 1024 * 1024;

/// One validated patch and its bounded, transient review projection.
#[must_use]
pub struct PreparedSourcePatch {
    compiled: CompiledFilePatch,
    review: crate::PatchReview,
}

impl PreparedSourcePatch {
    pub fn into_parts(self) -> (CompiledFilePatch, crate::PatchReview) {
        (self.compiled, self.review)
    }
}

impl std::fmt::Debug for PreparedSourcePatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSourcePatch")
            .field("content_bytes", &self.compiled.content().len())
            .field("review", &self.review)
            .finish()
    }
}

#[derive(Debug, Clone)]
struct DirectoryEntryObservation {
    name: OsString,
    kind: FileEntryKind,
    size: Option<FileByteCount>,
}

impl DirectoryEntryObservation {
    fn raw_name(&self) -> &[u8] {
        self.name.as_bytes()
    }
}

impl ConfinedWorkspace {
    /// List one descriptor-confined directory. `None` denotes the Workspace
    /// root. Generated/Forge-owned directory names are omitted recursively by
    /// policy, and `truncated` is truthful when scan/result/output bounds hit.
    pub fn file_list(
        &self,
        directory: Option<&forge_domain::WorkspaceRelativePath>,
        options: FileListOptions,
    ) -> Result<FileListResult, ConfinedFilesystemError> {
        self.ensure_root_for_source(false)?;
        let (directory_fd, components) = self.open_source_directory(directory)?;
        let directory_identity = directory_identity(&directory_fd)?;
        let (mut observations, mut truncated, scanned_entries) =
            read_directory_entries(&directory_fd, MAX_FILE_LIST_SCAN_ENTRIES, || false)?;
        observations.sort_by(|left, right| left.raw_name().cmp(right.raw_name()));

        let mut entries = Vec::with_capacity(options.max_results());
        let mut output_bytes = 0_usize;
        if observations.len() > options.max_results() {
            truncated = true;
        }
        for observation in observations.into_iter().take(options.max_results()) {
            let path = join_components(&components, &observation.name)?;
            let estimated_bytes = path.as_path().as_os_str().as_encoded_bytes().len();
            let next_output = output_bytes.checked_add(estimated_bytes).ok_or(
                ConfinedFilesystemError::OutputTooLarge {
                    actual: usize::MAX,
                    maximum: options.max_output_bytes(),
                },
            )?;
            if next_output > options.max_output_bytes() {
                truncated = true;
                break;
            }
            output_bytes = next_output;
            entries.push(FileListEntry::new(path, observation.kind, observation.size));
        }

        ensure_directory_identity(&directory_fd, directory_identity, false)?;
        if let Some(directory) = directory {
            let reopened = self.open_source_directory(Some(directory))?.0;
            ensure_directory_identity(&reopened, directory_identity, false)?;
        }
        self.ensure_root_for_source(false)?;
        FileListResult::new(directory.cloned(), entries, scanned_entries, truncated)
            .map_err(ConfinedFilesystemError::FileListResult)
    }

    /// Read one one-based inclusive line range while streaming the complete
    /// file hash. Only selected bytes and fixed-size hash state are retained.
    pub fn file_read_slice(
        &self,
        path: &forge_domain::WorkspaceRelativePath,
        line_range: SourceLineRange,
    ) -> Result<FileReadSlice, ConfinedFilesystemError> {
        validate_source_path(path)?;
        self.ensure_root_for_source(false)?;
        let (parent, basename, _) = self.open_parent(path)?;
        let Some(fd) = open_regular_leaf(&parent, &basename)? else {
            return Err(ConfinedFilesystemError::NotFound);
        };
        let before = fstat(&fd).map_err(super::pre_syscall)?;
        let size =
            usize::try_from(before.st_size).map_err(|_| ConfinedFilesystemError::FileTooLarge {
                actual: usize::MAX,
                maximum: MAX_SOURCE_SLICE_SCAN_BYTES,
            })?;
        if size > MAX_SOURCE_SLICE_SCAN_BYTES {
            return Err(ConfinedFilesystemError::FileTooLarge {
                actual: size,
                maximum: MAX_SOURCE_SLICE_SCAN_BYTES,
            });
        }
        let mut file = File::from(fd);
        let mut accumulator = SourceSliceAccumulator::new(line_range);
        let mut buffer = [0_u8; 16 * 1024];
        let mut whole_hasher = blake3::Hasher::new();
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|source| ConfinedFilesystemError::StdIo {
                    operation: super::FilesystemOperation::ReadSourceSlice,
                    committed: false,
                    source,
                })?;
            if read == 0 {
                break;
            }
            whole_hasher.update(&buffer[..read]);
            accumulator.push_bytes(&buffer[..read])?;
        }
        accumulator.finish()?;
        let after = fstat(&file).map_err(super::pre_syscall)?;
        if after.st_dev != before.st_dev
            || after.st_ino != before.st_ino
            || after.st_size != before.st_size
        {
            return Err(ConfinedFilesystemError::StaleWrite);
        }
        self.ensure_root_for_source(false)?;
        let whole_file_hash =
            forge_domain::FileContentHash::from_bytes(*whole_hasher.finalize().as_bytes());
        let slice = accumulator.into_slice(whole_file_hash)?;
        Ok(slice)
    }

    /// Read, hash, validate, and compile one exact line-hunk patch. The
    /// resulting content is bounded and remains unpublished until the caller
    /// uses the normal durable mutation boundary.
    pub fn compile_file_patch(
        &self,
        path: &forge_domain::WorkspaceRelativePath,
        source_patch: &FilePatch,
    ) -> Result<PreparedSourcePatch, ConfinedFilesystemError> {
        validate_source_path(path)?;
        self.ensure_root_for_source(false)?;
        let (parent, basename, _) = self.open_parent(path)?;
        let Some(fd) = open_regular_leaf(&parent, &basename)? else {
            return Err(ConfinedFilesystemError::NotFound);
        };
        let before = fstat(&fd).map_err(super::pre_syscall)?;
        let size =
            usize::try_from(before.st_size).map_err(|_| ConfinedFilesystemError::FileTooLarge {
                actual: usize::MAX,
                maximum: MAX_SOURCE_PATCH_BYTES,
            })?;
        if size > MAX_SOURCE_PATCH_BYTES {
            return Err(ConfinedFilesystemError::FileTooLarge {
                actual: size,
                maximum: MAX_SOURCE_PATCH_BYTES,
            });
        }
        let mut source = Vec::with_capacity(size);
        let file = File::from(fd);
        (&file)
            .take((MAX_SOURCE_PATCH_BYTES + 1) as u64)
            .read_to_end(&mut source)
            .map_err(|source| ConfinedFilesystemError::StdIo {
                operation: super::FilesystemOperation::ReadSourcePatch,
                committed: false,
                source,
            })?;
        if source.len() > MAX_SOURCE_PATCH_BYTES {
            return Err(ConfinedFilesystemError::FileTooLarge {
                actual: source.len(),
                maximum: MAX_SOURCE_PATCH_BYTES,
            });
        }
        let after = fstat(&file).map_err(super::pre_syscall)?;
        if after.st_dev != before.st_dev
            || after.st_ino != before.st_ino
            || after.st_size != before.st_size
        {
            return Err(ConfinedFilesystemError::StaleWrite);
        }
        let compiled = source_patch
            .compile(&source)
            .map_err(ConfinedFilesystemError::SourcePatch)?;
        let review = crate::patch_review::build_patch_review(&source, &compiled);
        self.ensure_root_for_source(false)?;
        Ok(PreparedSourcePatch { compiled, review })
    }

    fn open_source_directory(
        &self,
        directory: Option<&forge_domain::WorkspaceRelativePath>,
    ) -> Result<(OwnedFd, Vec<OsString>), ConfinedFilesystemError> {
        let components = if let Some(directory) = directory {
            validate_source_path(directory)?;
            super::collect_components(directory)?
        } else {
            Vec::new()
        };
        let fd = walk_directories(&self.root, &components, false)?;
        Ok((fd, components))
    }

    fn ensure_root_for_source(&self, committed: bool) -> Result<(), ConfinedFilesystemError> {
        self.ensure_root_with_committed(committed)
    }
}

fn read_directory_entries(
    directory: &OwnedFd,
    scan_limit: usize,
    mut stopped: impl FnMut() -> bool,
) -> Result<(Vec<DirectoryEntryObservation>, bool, usize), ConfinedFilesystemError> {
    let stream = Dir::read_from(directory).map_err(|source| ConfinedFilesystemError::Syscall {
        operation: super::FilesystemOperation::OpenDirectoryStream,
        committed: false,
        source,
    })?;
    let mut entries = Vec::new();
    let mut truncated = false;
    let mut scanned_entries = 0_usize;
    for entry in stream {
        if stopped() {
            truncated = true;
            break;
        }
        let entry = entry.map_err(|source| ConfinedFilesystemError::Syscall {
            operation: super::FilesystemOperation::ReadDirectory,
            committed: false,
            source,
        })?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." || is_excluded_workspace_component(bytes) {
            continue;
        }
        scanned_entries = scanned_entries.saturating_add(1);
        if scanned_entries > scan_limit {
            truncated = true;
            break;
        }
        if entries.len() >= scan_limit {
            truncated = true;
            break;
        }
        let name = OsString::from_vec(bytes.to_vec());
        let stat = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
            ConfinedFilesystemError::Syscall {
                operation: super::FilesystemOperation::InspectDirectoryEntry,
                committed: false,
                source,
            }
        })?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        let (kind, size) = if file_type.is_dir() {
            (FileEntryKind::Directory, None)
        } else if file_type.is_file() {
            if stat.st_nlink != 1 {
                return Err(ConfinedFilesystemError::HardlinkRejected);
            }
            let size = u64::try_from(stat.st_size).ok().map(FileByteCount::new);
            (FileEntryKind::RegularFile, size)
        } else if file_type.is_symlink() {
            (FileEntryKind::SymbolicLink, None)
        } else {
            (FileEntryKind::Other, None)
        };
        entries.push(DirectoryEntryObservation { name, kind, size });
    }
    Ok((entries, truncated, scanned_entries.min(scan_limit)))
}

fn join_components(
    components: &[OsString],
    name: &OsStr,
) -> Result<forge_domain::WorkspaceRelativePath, ConfinedFilesystemError> {
    if components.len() >= MAX_FILE_PATH_COMPONENTS {
        return Err(ConfinedFilesystemError::TooManyComponents);
    }
    let mut path = PathBuf::new();
    for component in components {
        path.push(component);
    }
    path.push(name);
    forge_domain::WorkspaceRelativePath::new(path).map_err(|_| ConfinedFilesystemError::InvalidPath)
}

fn validate_source_path(
    path: &forge_domain::WorkspaceRelativePath,
) -> Result<(), ConfinedFilesystemError> {
    validate_not_protected(path)?;
    if path
        .components()
        .any(|component| is_excluded_workspace_component(component.as_bytes()))
    {
        return Err(ConfinedFilesystemError::GeneratedPath);
    }
    Ok(())
}

#[derive(Debug)]
struct SourceSliceAccumulator {
    range: SourceLineRange,
    selected: Vec<u8>,
    range_hasher: blake3::Hasher,
    line_hashes: Vec<SourceRangeHash>,
    current_line_hasher: blake3::Hasher,
    current_line: u64,
    line_has_bytes: bool,
    pending_cr: bool,
    total_lines: u64,
    eol: Option<SourceEol>,
    final_newline: bool,
}

impl SourceSliceAccumulator {
    fn new(range: SourceLineRange) -> Self {
        Self {
            range,
            selected: Vec::new(),
            range_hasher: blake3::Hasher::new(),
            line_hashes: Vec::new(),
            current_line_hasher: blake3::Hasher::new(),
            current_line: 1,
            line_has_bytes: false,
            pending_cr: false,
            total_lines: 0,
            eol: None,
            final_newline: false,
        }
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> Result<(), ConfinedFilesystemError> {
        for &byte in bytes {
            if self.pending_cr {
                if byte == b'\n' {
                    self.append_byte(byte)?;
                    self.commit_line(LineEnding::CrLf)?;
                    self.pending_cr = false;
                    continue;
                }
                self.commit_line(LineEnding::Cr)?;
                self.pending_cr = false;
            }
            match byte {
                b'\r' => {
                    self.append_byte(byte)?;
                    self.pending_cr = true;
                }
                b'\n' => {
                    self.append_byte(byte)?;
                    self.commit_line(LineEnding::Lf)?;
                }
                _ => self.append_byte(byte)?,
            }
        }
        Ok(())
    }

    fn append_byte(&mut self, byte: u8) -> Result<(), ConfinedFilesystemError> {
        self.line_has_bytes = true;
        if self.range.contains(self.current_line) {
            if self.selected.len() >= MAX_SOURCE_SLICE_BYTES {
                return Err(ConfinedFilesystemError::SourceSlice(
                    FileReadSliceError::OutputTooLarge {
                        actual: self.selected.len().saturating_add(1),
                        maximum: MAX_SOURCE_SLICE_BYTES,
                    },
                ));
            }
            self.selected.push(byte);
            self.range_hasher.update(&[byte]);
            self.current_line_hasher.update(&[byte]);
        }
        Ok(())
    }

    fn commit_line(&mut self, ending: LineEnding) -> Result<(), ConfinedFilesystemError> {
        self.total_lines =
            self.total_lines
                .checked_add(1)
                .ok_or(ConfinedFilesystemError::SourceSlice(
                    FileReadSliceError::TooManyLines,
                ))?;
        self.final_newline = true;
        self.note_eol(ending);
        if self.range.contains(self.current_line) {
            self.line_hashes.push(SourceRangeHash::from_bytes(
                *self.current_line_hasher.finalize().as_bytes(),
            ));
        }
        self.current_line =
            self.current_line
                .checked_add(1)
                .ok_or(ConfinedFilesystemError::SourceSlice(
                    FileReadSliceError::TooManyLines,
                ))?;
        self.current_line_hasher = blake3::Hasher::new();
        self.line_has_bytes = false;
        Ok(())
    }

    fn note_eol(&mut self, ending: LineEnding) {
        let observed = match ending {
            LineEnding::Lf => SourceEol::Lf,
            LineEnding::CrLf => SourceEol::CrLf,
            LineEnding::Cr => SourceEol::Cr,
        };
        self.eol = Some(match self.eol {
            None => observed,
            Some(current) if current == observed || current == SourceEol::Mixed => current,
            Some(_) => SourceEol::Mixed,
        });
    }

    fn finish(&mut self) -> Result<(), ConfinedFilesystemError> {
        if self.pending_cr {
            self.commit_line(LineEnding::Cr)?;
            self.pending_cr = false;
        } else if self.line_has_bytes {
            self.final_newline = false;
            self.total_lines =
                self.total_lines
                    .checked_add(1)
                    .ok_or(ConfinedFilesystemError::SourceSlice(
                        FileReadSliceError::TooManyLines,
                    ))?;
            if self.range.contains(self.current_line) {
                self.line_hashes.push(SourceRangeHash::from_bytes(
                    *self.current_line_hasher.finalize().as_bytes(),
                ));
            }
        }
        Ok(())
    }

    fn into_slice(
        self,
        whole_file_hash: forge_domain::FileContentHash,
    ) -> Result<FileReadSlice, ConfinedFilesystemError> {
        if self.total_lines < self.range.end_line() {
            return Err(ConfinedFilesystemError::SourceSlice(
                FileReadSliceError::RangeOutOfBounds {
                    end_line: self.range.end_line(),
                    total_lines: self.total_lines,
                },
            ));
        }
        let eol = self.eol.unwrap_or(SourceEol::None);
        let range_hash = SourceRangeHash::from_bytes(*self.range_hasher.finalize().as_bytes());
        FileReadSlice::from_parts(
            forge_domain::FileReadSliceMetadata::new(
                whole_file_hash,
                range_hash,
                self.range,
                self.total_lines,
                eol,
                self.final_newline,
            ),
            self.selected,
            self.line_hashes,
        )
        .map_err(ConfinedFilesystemError::SourceSlice)
    }
}

#[derive(Debug, Clone, Copy)]
enum LineEnding {
    Lf,
    CrLf,
    Cr,
}
