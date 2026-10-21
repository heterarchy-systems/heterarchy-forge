//! Descriptor-confined source replica for Rust CI verification launches.
//!
//! A published verification input remains the durable source of truth.  This
//! module creates a fresh, execution-local read-only replica so the child can
//! run with no access to the Workspace or its durable Forge state.  The
//! replica is intentionally not self-cleaning: runtime cleanup and quarantine
//! decisions belong to the execution owner.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use forge_domain::{
    FileContentHash, MAX_VERIFICATION_INPUT_ENTRIES, VerificationInputEntry,
    VerificationInputEntryKind,
};
use forge_workspace::{
    MAX_FILE_PATH_COMPONENTS, PublishedVerificationInput, VerificationInputError,
};
use rustix_process::fs::{
    AtFlags, Dir, FileType, Mode, OFlags, fchmod, fstat, fsync, mkdirat, openat, statat,
};
use rustix_process::io::Errno;
use thiserror::Error;

use super::{
    FilesystemIdentity, RustCiDiscoveryError, RustCiRuntimePaths, directory_open_flags,
    filesystem_identity_from_fd, filesystem_identity_from_stat, open_verified_directory_path,
};

const VERIFICATION_SOURCE_DIRECTORY: &str = "verification-source";
const VERIFICATION_SOURCE_DIRECTORY_MODE: u16 = 0o700;
const VERIFICATION_SOURCE_ROOT_MODE: u16 = 0o555;
const SEALED_WRITE_MASK: u16 = 0o222;
const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// `mode_t` is u16 on macOS and u32 on Linux; the sealed constants stay u16
/// and widen exactly at the rustix boundary (same pattern as the confinement
/// filesystem adapter).
fn from_sealed_mode(mode: u16) -> Mode {
    #[cfg(target_os = "linux")]
    {
        Mode::from_raw_mode(u32::from(mode))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Mode::from_raw_mode(mode)
    }
}

fn mode_bits_from_stat(stat: &rustix_process::fs::Stat) -> u32 {
    #[cfg(target_os = "linux")]
    {
        Mode::from_raw_mode(stat.st_mode).bits()
    }
    #[cfg(not(target_os = "linux"))]
    {
        u32::from(Mode::from_raw_mode(stat.st_mode).bits())
    }
}

static NO_CANCELLATION: AtomicBool = AtomicBool::new(false);

/// Failure from the execution-local verification source boundary.
///
/// Error messages deliberately carry no source or runtime paths.  The input
/// error remains typed so callers can distinguish a stale durable snapshot
/// from a runtime descriptor or replica mismatch.
#[derive(Debug, Error)]
pub enum VerificationExecutionSourceError {
    #[error("verification source filesystem operation failed")]
    Io(#[source] io::Error),
    #[error("published verification input is invalid")]
    Input(#[source] VerificationInputError),
    #[error("verification source does not match its execution contract")]
    Mismatch,
}

/// Fresh execution-local copy of one published verification input.
///
/// The type is crate-visible only so the runner can retain it across process
/// admission and revalidate it immediately before spawn.  Its root path is
/// always derived from the runtime's exact execution directory.
#[must_use]
pub(crate) struct VerificationExecutionSource {
    root: PathBuf,
    root_identity: FilesystemIdentity,
}

impl fmt::Debug for VerificationExecutionSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerificationExecutionSource")
            .field("root_bound", &true)
            .finish_non_exhaustive()
    }
}

impl VerificationExecutionSource {
    /// Create a new, never-reused source directory and copy exactly the
    /// published manifest into it.
    pub(crate) fn prepare(
        runtime: &RustCiRuntimePaths,
        input: &PublishedVerificationInput,
    ) -> Result<Self, VerificationExecutionSourceError> {
        runtime.revalidate().map_err(map_runtime_error)?;
        input
            .validate()
            .map_err(VerificationExecutionSourceError::Input)?;

        let execution = open_runtime_execution_directory(runtime)?;
        let source_name = OsStr::new(VERIFICATION_SOURCE_DIRECTORY);
        mkdirat(
            &execution,
            source_name,
            from_sealed_mode(VERIFICATION_SOURCE_DIRECTORY_MODE),
        )
        .map_err(map_create_error)?;

        // The leaf was created with mkdirat(O_EXCL-equivalent directory
        // creation semantics).  Opening it again through the already-bound
        // execution descriptor prevents a path replacement from becoming the
        // authority for the copy.
        let source = openat(
            &execution,
            source_name,
            directory_open_flags(),
            Mode::empty(),
        )
        .map_err(map_errno)?;
        let source_identity = verify_new_source_root(&execution, source_name, &source)?;
        fchmod(
            &source,
            from_sealed_mode(VERIFICATION_SOURCE_DIRECTORY_MODE),
        )
        .map_err(|source| VerificationExecutionSourceError::Io(source.into()))?;
        fsync(&source).map_err(|source| VerificationExecutionSourceError::Io(source.into()))?;
        verify_directory_mode(&source, VERIFICATION_SOURCE_DIRECTORY_MODE)?;

        copy_manifest(&source, input)?;
        seal_manifest_directories(&source, input)?;
        fchmod(&source, from_sealed_mode(VERIFICATION_SOURCE_ROOT_MODE))
            .map_err(|source| VerificationExecutionSourceError::Io(source.into()))?;
        fsync(&source).map_err(|source| VerificationExecutionSourceError::Io(source.into()))?;

        let prepared = Self {
            root: runtime.execution_root().join(VERIFICATION_SOURCE_DIRECTORY),
            root_identity: source_identity,
        };
        // This is the post-copy coverage fence.  It checks the path binding,
        // every manifest entry, file hashes and modes, and unexpected entries
        // before the object can be handed to the sandbox builder.
        prepared.validate(runtime, input)?;
        Ok(prepared)
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Validate the retained root and complete manifest coverage through
    /// fresh no-follow descriptors.  This is safe to call immediately before
    /// process spawn and after process completion.
    pub(crate) fn validate(
        &self,
        runtime: &RustCiRuntimePaths,
        input: &PublishedVerificationInput,
    ) -> Result<(), VerificationExecutionSourceError> {
        if self.root != runtime.execution_root().join(VERIFICATION_SOURCE_DIRECTORY) {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        runtime.revalidate().map_err(map_runtime_error)?;
        input
            .validate()
            .map_err(VerificationExecutionSourceError::Input)?;

        let execution = open_runtime_execution_directory(runtime)?;
        let source_name = OsStr::new(VERIFICATION_SOURCE_DIRECTORY);
        let source = openat(
            &execution,
            source_name,
            directory_open_flags(),
            Mode::empty(),
        )
        .map_err(map_errno)?;
        let actual_identity = filesystem_identity_from_fd(&source).map_err(map_io)?;
        if actual_identity != self.root_identity {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        let entry_stat =
            statat(&execution, source_name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
        if filesystem_identity_from_stat(&entry_stat).map_err(map_io)? != self.root_identity
            || !FileType::from_raw_mode(entry_stat.st_mode).is_dir()
        {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        verify_directory_mode(&source, VERIFICATION_SOURCE_ROOT_MODE)?;

        let expected = manifest_entries(input);
        let mut seen = BTreeSet::new();
        validate_tree(
            &source,
            Path::new(""),
            &expected,
            &mut seen,
            VERIFICATION_SOURCE_ROOT_MODE,
            0,
        )?;
        if seen.len() != expected.len() {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        // Detect binding changes during the complete walk. This does not make
        // the later OS spawn atomic with filesystem observation; the product
        // cache remains a trusted host-storage boundary.
        runtime.revalidate().map_err(map_runtime_error)?;
        input
            .validate()
            .map_err(VerificationExecutionSourceError::Input)?;
        let execution_after = open_runtime_execution_directory(runtime)?;
        let source_after = openat(
            &execution_after,
            source_name,
            directory_open_flags(),
            Mode::empty(),
        )
        .map_err(map_errno)?;
        if filesystem_identity_from_fd(&source_after).map_err(map_io)? != self.root_identity {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        Ok(())
    }
}

fn open_runtime_execution_directory(
    runtime: &RustCiRuntimePaths,
) -> Result<OwnedFd, VerificationExecutionSourceError> {
    let execution = open_verified_directory_path(runtime.execution_root()).map_err(map_io)?;
    let identity = filesystem_identity_from_fd(&execution).map_err(map_io)?;
    if identity != runtime.execution_identity {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    Ok(execution)
}

fn verify_new_source_root(
    execution: &OwnedFd,
    name: &OsStr,
    source: &OwnedFd,
) -> Result<FilesystemIdentity, VerificationExecutionSourceError> {
    let identity = filesystem_identity_from_fd(source).map_err(map_io)?;
    let entry_stat = statat(execution, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
    let entry_identity = filesystem_identity_from_stat(&entry_stat).map_err(map_io)?;
    if entry_identity != identity || !FileType::from_raw_mode(entry_stat.st_mode).is_dir() {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    Ok(identity)
}

fn copy_manifest(
    destination_root: &OwnedFd,
    input: &PublishedVerificationInput,
) -> Result<(), VerificationExecutionSourceError> {
    for entry in input.manifest().entries() {
        let components = path_components(entry)?;
        let (basename, ancestors) = components
            .split_last()
            .ok_or(VerificationExecutionSourceError::Mismatch)?;
        let parent = open_destination_parent(destination_root, ancestors)?;
        match entry.kind() {
            VerificationInputEntryKind::Directory => {
                create_destination_directory(&parent, basename)?;
            }
            VerificationInputEntryKind::File { size, content_hash } => {
                copy_destination_file(&parent, basename, entry, size.get(), content_hash, input)?;
            }
        }
    }
    Ok(())
}

fn seal_manifest_directories(
    destination_root: &OwnedFd,
    input: &PublishedVerificationInput,
) -> Result<(), VerificationExecutionSourceError> {
    for entry in input.manifest().entries().iter().rev() {
        if !matches!(entry.kind(), VerificationInputEntryKind::Directory) {
            continue;
        }
        let components = path_components(entry)?;
        let (basename, ancestors) = components
            .split_last()
            .ok_or(VerificationExecutionSourceError::Mismatch)?;
        let parent = open_destination_parent(destination_root, ancestors)?;
        let directory =
            openat(&parent, basename, directory_open_flags(), Mode::empty()).map_err(map_errno)?;
        let before = statat(&parent, basename, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
        if filesystem_identity_from_fd(&directory).map_err(map_io)?
            != filesystem_identity_from_stat(&before).map_err(map_io)?
        {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        let mode = entry.mode() & !SEALED_WRITE_MASK;
        fchmod(&directory, from_sealed_mode(mode))
            .map_err(|source| VerificationExecutionSourceError::Io(source.into()))?;
        verify_directory_mode(&directory, mode)?;
        fsync(&directory).map_err(|source| VerificationExecutionSourceError::Io(source.into()))?;
    }
    Ok(())
}

/// Prepare the retained verification replica for the runtime owner's
/// descriptor-confined recursive cleanup.  This is called only after the
/// caller has positively established that no child process can still hold the
/// replica open or mutate it.
pub(super) fn prepare_runtime_source_cleanup(
    runtime: &RustCiRuntimePaths,
) -> Result<(), RustCiDiscoveryError> {
    let execution = open_verified_directory_path(runtime.execution_root()).map_err(|source| {
        RustCiDiscoveryError::Inspect {
            component: super::RustCiSourceComponent::ProductRuntime,
            source,
        }
    })?;
    if filesystem_identity_from_fd(&execution).map_err(cleanup_inspect)?
        != runtime.execution_identity
    {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }

    let source_name = OsStr::new(VERIFICATION_SOURCE_DIRECTORY);
    let source_stat = match statat(&execution, source_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::NOENT) => return Ok(()),
        Err(Errno::LOOP) => return Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry),
        Err(source) => return Err(cleanup_inspect(source.into())),
    };
    if !FileType::from_raw_mode(source_stat.st_mode).is_dir() {
        return Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry);
    }
    let source = openat(
        &execution,
        source_name,
        directory_open_flags(),
        Mode::empty(),
    )
    .map_err(map_cleanup_open_error)?;
    let source_identity = filesystem_identity_from_fd(&source).map_err(cleanup_inspect)?;
    if source_identity != filesystem_identity_from_stat(&source_stat).map_err(cleanup_inspect)? {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }

    let mut budget = 0_usize;
    prepare_source_directory_cleanup(&source, 0, &mut budget)?;
    fchmod(
        &source,
        from_sealed_mode(VERIFICATION_SOURCE_DIRECTORY_MODE),
    )
    .map_err(|source| cleanup_materialize(source.into()))?;
    if filesystem_identity_from_fd(&source).map_err(cleanup_inspect)? != source_identity {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    ensure_cleanup_entry_identity(&execution, source_name, source_identity)?;
    if filesystem_identity_from_fd(&execution).map_err(cleanup_inspect)?
        != runtime.execution_identity
    {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    Ok(())
}

fn prepare_source_directory_cleanup(
    directory: &OwnedFd,
    depth: usize,
    budget: &mut usize,
) -> Result<(), RustCiDiscoveryError> {
    if depth > MAX_FILE_PATH_COMPONENTS {
        return Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry);
    }
    let directory_stat = fstat(directory).map_err(|source| cleanup_inspect(source.into()))?;
    if !FileType::from_raw_mode(directory_stat.st_mode).is_dir() {
        return Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry);
    }
    let stream = Dir::read_from(directory).map_err(|source| cleanup_inspect(source.into()))?;
    let mut names = Vec::new();
    for entry in stream {
        let entry = entry.map_err(|source| cleanup_inspect(source.into()))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *budget = budget
            .checked_add(1)
            .ok_or(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry)?;
        if *budget > MAX_VERIFICATION_INPUT_ENTRIES {
            return Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry);
        }
        names.push(OsString::from_vec(name.to_bytes().to_vec()));
    }

    for name in names {
        let before = match statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::LOOP) => {
                return Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry);
            }
            Err(source) => return Err(cleanup_inspect(source.into())),
        };
        let identity = filesystem_identity_from_stat(&before).map_err(cleanup_inspect)?;
        let file_type = FileType::from_raw_mode(before.st_mode);
        if file_type.is_dir() {
            if depth >= MAX_FILE_PATH_COMPONENTS {
                return Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry);
            }
            let child = openat(directory, &name, directory_open_flags(), Mode::empty())
                .map_err(map_cleanup_open_error)?;
            if filesystem_identity_from_fd(&child).map_err(cleanup_inspect)? != identity {
                return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
            }
            prepare_source_directory_cleanup(&child, depth + 1, budget)?;
            ensure_cleanup_entry_identity(directory, &name, identity)?;
            fchmod(&child, from_sealed_mode(VERIFICATION_SOURCE_DIRECTORY_MODE))
                .map_err(|source| cleanup_materialize(source.into()))?;
            ensure_cleanup_entry_identity(directory, &name, identity)?;
            continue;
        }
        if !file_type.is_file() || before.st_nlink != 1 {
            return Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry);
        }
        let file = openat(
            directory,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(map_cleanup_open_error)?;
        let file_stat = fstat(&file).map_err(|source| cleanup_inspect(source.into()))?;
        if !FileType::from_raw_mode(file_stat.st_mode).is_file()
            || file_stat.st_nlink != 1
            || filesystem_identity_from_stat(&file_stat).map_err(cleanup_inspect)? != identity
        {
            return Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry);
        }
        ensure_cleanup_entry_identity(directory, &name, identity)?;
    }
    Ok(())
}

fn ensure_cleanup_entry_identity(
    parent: &OwnedFd,
    name: &OsStr,
    expected: FilesystemIdentity,
) -> Result<(), RustCiDiscoveryError> {
    let stat = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|source| {
        if source == Errno::LOOP {
            RustCiDiscoveryError::ProductRuntimeUnexpectedEntry
        } else {
            cleanup_inspect(source.into())
        }
    })?;
    if filesystem_identity_from_stat(&stat).map_err(cleanup_inspect)? != expected {
        return Err(RustCiDiscoveryError::ProductRuntimeMismatch);
    }
    Ok(())
}

fn map_cleanup_open_error(source: Errno) -> RustCiDiscoveryError {
    match source {
        Errno::LOOP | Errno::NOTDIR => RustCiDiscoveryError::ProductRuntimeUnexpectedEntry,
        source => cleanup_inspect(source.into()),
    }
}

fn cleanup_inspect(source: io::Error) -> RustCiDiscoveryError {
    RustCiDiscoveryError::Inspect {
        component: super::RustCiSourceComponent::ProductRuntime,
        source,
    }
}

fn cleanup_materialize(source: io::Error) -> RustCiDiscoveryError {
    RustCiDiscoveryError::Materialize {
        component: super::RustCiSourceComponent::ProductRuntime,
        source,
    }
}

fn path_components(
    entry: &VerificationInputEntry,
) -> Result<Vec<OsString>, VerificationExecutionSourceError> {
    let mut components = Vec::new();
    for component in entry.path().components() {
        if components.len() >= MAX_FILE_PATH_COMPONENTS {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        components.push(component.to_os_string());
    }
    if components.is_empty() {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    Ok(components)
}

fn open_destination_parent(
    root: &OwnedFd,
    ancestors: &[OsString],
) -> Result<OwnedFd, VerificationExecutionSourceError> {
    let mut current = rustix_process::io::dup(root).map_err(map_errno)?;
    verify_directory_mode(&current, VERIFICATION_SOURCE_DIRECTORY_MODE)?;
    for component in ancestors {
        let stat = statat(&current, component, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
        if !FileType::from_raw_mode(stat.st_mode).is_dir() {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        let child = openat(&current, component, directory_open_flags(), Mode::empty())
            .map_err(map_errno)?;
        let identity = filesystem_identity_from_fd(&child).map_err(map_io)?;
        if filesystem_identity_from_stat(&stat).map_err(map_io)? != identity {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        verify_directory_mode(&child, VERIFICATION_SOURCE_DIRECTORY_MODE)?;
        current = child;
    }
    Ok(current)
}

fn create_destination_directory(
    parent: &OwnedFd,
    name: &OsStr,
) -> Result<(), VerificationExecutionSourceError> {
    mkdirat(
        parent,
        name,
        from_sealed_mode(VERIFICATION_SOURCE_DIRECTORY_MODE),
    )
    .map_err(map_create_error)?;
    let child = openat(parent, name, directory_open_flags(), Mode::empty()).map_err(map_errno)?;
    let stat = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
    if filesystem_identity_from_fd(&child).map_err(map_io)?
        != filesystem_identity_from_stat(&stat).map_err(map_io)?
    {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    fchmod(&child, from_sealed_mode(VERIFICATION_SOURCE_DIRECTORY_MODE))
        .map_err(|source| VerificationExecutionSourceError::Io(source.into()))?;
    verify_directory_mode(&child, VERIFICATION_SOURCE_DIRECTORY_MODE)?;
    fsync(&child).map_err(|source| VerificationExecutionSourceError::Io(source.into()))?;
    Ok(())
}

fn copy_destination_file(
    parent: &OwnedFd,
    name: &OsStr,
    entry: &VerificationInputEntry,
    expected_size: u64,
    expected_hash: FileContentHash,
    input: &PublishedVerificationInput,
) -> Result<(), VerificationExecutionSourceError> {
    let bytes = input
        .read_execution_file(entry.path(), &NO_CANCELLATION)
        .map_err(VerificationExecutionSourceError::Input)?;
    if u64::try_from(bytes.len()).map_err(|_| VerificationExecutionSourceError::Mismatch)?
        != expected_size
        || FileContentHash::from_bytes(*blake3::hash(&bytes).as_bytes()) != expected_hash
    {
        return Err(VerificationExecutionSourceError::Mismatch);
    }

    let output_mode = entry.mode() & !SEALED_WRITE_MASK;
    let fd = openat(
        parent,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        from_sealed_mode(output_mode),
    )
    .map_err(map_create_error)?;
    let stat = fstat(&fd).map_err(map_errno)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() || stat.st_nlink != 1 {
        return Err(VerificationExecutionSourceError::Mismatch);
    }

    let mut output = File::from(fd);
    output
        .write_all(&bytes)
        .map_err(VerificationExecutionSourceError::Io)?;
    output
        .sync_all()
        .map_err(VerificationExecutionSourceError::Io)?;
    fchmod(&output, from_sealed_mode(output_mode))
        .map_err(|source| VerificationExecutionSourceError::Io(source.into()))?;
    output
        .sync_all()
        .map_err(VerificationExecutionSourceError::Io)?;
    verify_file_contents(&mut output, output_mode, expected_size, expected_hash)
}

fn verify_file_contents(
    file: &mut File,
    expected_mode: u16,
    expected_size: u64,
    expected_hash: FileContentHash,
) -> Result<(), VerificationExecutionSourceError> {
    let before = fstat(&*file).map_err(map_errno)?;
    if !FileType::from_raw_mode(before.st_mode).is_file()
        || before.st_nlink != 1
        || u64::try_from(before.st_size).map_err(|_| VerificationExecutionSourceError::Mismatch)?
            != expected_size
        || (mode_bits_from_stat(&before) & 0o777) as u16 != expected_mode
    {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(VerificationExecutionSourceError::Io)?;
    let mut hasher = blake3::Hasher::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(VerificationExecutionSourceError::Io)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(read).map_err(|_| VerificationExecutionSourceError::Mismatch)?,
            )
            .ok_or(VerificationExecutionSourceError::Mismatch)?;
        if total > expected_size {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        hasher.update(&buffer[..read]);
    }
    let after = fstat(&*file).map_err(map_errno)?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_size != before.st_size
        || after.st_nlink != before.st_nlink
        || (mode_bits_from_stat(&after) & 0o777) as u16 != expected_mode
        || total != expected_size
        || FileContentHash::from_bytes(*hasher.finalize().as_bytes()) != expected_hash
    {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    Ok(())
}

fn manifest_entries(
    input: &PublishedVerificationInput,
) -> BTreeMap<Vec<u8>, &VerificationInputEntry> {
    input
        .manifest()
        .entries()
        .iter()
        .map(|entry| {
            (
                entry
                    .path()
                    .as_path()
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec(),
                entry,
            )
        })
        .collect()
}

fn validate_tree(
    directory: &OwnedFd,
    relative: &Path,
    expected: &BTreeMap<Vec<u8>, &VerificationInputEntry>,
    seen: &mut BTreeSet<Vec<u8>>,
    expected_directory_mode: u16,
    depth: usize,
) -> Result<(), VerificationExecutionSourceError> {
    if depth > MAX_FILE_PATH_COMPONENTS {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    let before_directory = fstat(directory).map_err(map_errno)?;
    if !FileType::from_raw_mode(before_directory.st_mode).is_dir()
        || (mode_bits_from_stat(&before_directory) & 0o7777) as u16 != expected_directory_mode
    {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    let stream = Dir::read_from(directory).map_err(map_errno)?;
    for entry in stream {
        let entry = entry.map_err(map_errno)?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let name = OsString::from_vec(name.to_bytes().to_vec());
        let child_path = relative.join(&name);
        let child_domain_path = forge_domain::WorkspaceRelativePath::new(child_path.clone())
            .map_err(|_| VerificationExecutionSourceError::Mismatch)?;
        let key = child_domain_path
            .as_path()
            .as_os_str()
            .as_encoded_bytes()
            .to_vec();
        let expected_entry = expected
            .get(&key)
            .ok_or(VerificationExecutionSourceError::Mismatch)?;
        if !seen.insert(key) {
            return Err(VerificationExecutionSourceError::Mismatch);
        }
        let before = statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
        let file_type = FileType::from_raw_mode(before.st_mode);
        match expected_entry.kind() {
            VerificationInputEntryKind::Directory if file_type.is_dir() => {
                let child = openat(directory, &name, directory_open_flags(), Mode::empty())
                    .map_err(map_errno)?;
                if filesystem_identity_from_fd(&child).map_err(map_io)?
                    != filesystem_identity_from_stat(&before).map_err(map_io)?
                {
                    return Err(VerificationExecutionSourceError::Mismatch);
                }
                validate_tree(
                    &child,
                    &child_path,
                    expected,
                    seen,
                    expected_entry.mode() & !SEALED_WRITE_MASK,
                    depth + 1,
                )?;
                ensure_unchanged(directory, &name, &before)?;
            }
            VerificationInputEntryKind::File { size, content_hash } if file_type.is_file() => {
                if before.st_nlink != 1
                    || (mode_bits_from_stat(&before) & 0o777) as u16
                        != expected_entry.mode() & !SEALED_WRITE_MASK
                {
                    return Err(VerificationExecutionSourceError::Mismatch);
                }
                let file = openat(
                    directory,
                    &name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(map_errno)?;
                let mut file = File::from(file);
                verify_file_contents(
                    &mut file,
                    expected_entry.mode() & !SEALED_WRITE_MASK,
                    size.get(),
                    content_hash,
                )?;
                ensure_unchanged(directory, &name, &before)?;
            }
            _ => return Err(VerificationExecutionSourceError::Mismatch),
        }
    }
    let after_directory = fstat(directory).map_err(map_errno)?;
    if !stat_binding_equal(&before_directory, &after_directory) {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    Ok(())
}

fn stat_binding_equal(before: &rustix_process::fs::Stat, after: &rustix_process::fs::Stat) -> bool {
    before.st_dev == after.st_dev
        && before.st_ino == after.st_ino
        && before.st_mode == after.st_mode
        && before.st_size == after.st_size
        && before.st_nlink == after.st_nlink
        && before.st_mtime == after.st_mtime
        && before.st_mtime_nsec == after.st_mtime_nsec
        && before.st_ctime == after.st_ctime
        && before.st_ctime_nsec == after.st_ctime_nsec
}

fn ensure_unchanged(
    parent: &OwnedFd,
    name: &OsStr,
    before: &rustix_process::fs::Stat,
) -> Result<(), VerificationExecutionSourceError> {
    let after = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(map_errno)?;
    if after.st_dev != before.st_dev
        || after.st_ino != before.st_ino
        || after.st_mode != before.st_mode
        || after.st_size != before.st_size
        || after.st_nlink != before.st_nlink
    {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    Ok(())
}

fn verify_directory_mode(
    directory: &OwnedFd,
    expected_mode: u16,
) -> Result<(), VerificationExecutionSourceError> {
    let stat = fstat(directory).map_err(map_errno)?;
    if !FileType::from_raw_mode(stat.st_mode).is_dir()
        || (mode_bits_from_stat(&stat) & 0o7777) as u16 != expected_mode
    {
        return Err(VerificationExecutionSourceError::Mismatch);
    }
    Ok(())
}

fn map_runtime_error(error: RustCiDiscoveryError) -> VerificationExecutionSourceError {
    match error {
        RustCiDiscoveryError::Inspect { source, .. }
        | RustCiDiscoveryError::Materialize { source, .. } => {
            VerificationExecutionSourceError::Io(source)
        }
        _ => VerificationExecutionSourceError::Mismatch,
    }
}

fn map_io(source: io::Error) -> VerificationExecutionSourceError {
    VerificationExecutionSourceError::Io(source)
}

fn map_errno(source: Errno) -> VerificationExecutionSourceError {
    match source {
        Errno::LOOP | Errno::NOENT | Errno::NOTDIR | Errno::EXIST => {
            VerificationExecutionSourceError::Mismatch
        }
        source => VerificationExecutionSourceError::Io(source.into()),
    }
}

fn map_create_error(source: Errno) -> VerificationExecutionSourceError {
    if source == Errno::EXIST {
        VerificationExecutionSourceError::Mismatch
    } else {
        map_errno(source)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions, hard_link};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use forge_domain::{FileByteCount, VerificationInputId, WorkspaceRelativePath};
    use forge_workspace::{ConfinedWorkspace, WorkspaceStateLayout};
    use uuid::Uuid;

    use super::*;

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
        workspace_root: PathBuf,
        runtime: RustCiRuntimePaths,
    }

    impl Fixture {
        fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let root = std::env::temp_dir().join(format!(
                "forge-verification-source-{label}-{}-{timestamp}-{serial}",
                std::process::id()
            ));
            fs::create_dir_all(&root)?;
            let workspace_root = root.join("workspace");
            fs::create_dir_all(&workspace_root)?;
            let runtime_root = root.join("runtime");
            let workspace_namespace = runtime_root.join("workspaces");
            let execution_namespace = runtime_root.join("executions");
            let workspace_runtime = workspace_namespace.join("workspace");
            let execution_root = execution_namespace.join("execution");
            let target = workspace_runtime.join("target");
            let temporary = execution_root.join("tmp");
            let home = execution_root.join("home");
            let cargo_home = execution_root.join("cargo-home");
            let registry_target = runtime_root.join("registry-source");
            for directory in [
                runtime_root.as_path(),
                workspace_namespace.as_path(),
                execution_namespace.as_path(),
                workspace_runtime.as_path(),
                execution_root.as_path(),
                target.as_path(),
                temporary.as_path(),
                home.as_path(),
                cargo_home.as_path(),
                registry_target.as_path(),
            ] {
                fs::create_dir_all(directory)?;
            }
            symlink(&registry_target, cargo_home.join("registry"))?;

            let identity = |path: &Path| -> Result<FilesystemIdentity, Box<dyn std::error::Error>> {
                let fd = open_verified_directory_path(path)?;
                Ok(filesystem_identity_from_fd(&fd)?)
            };
            let runtime = RustCiRuntimePaths {
                root_identity: identity(&runtime_root)?,
                workspace_namespace_identity: identity(&workspace_namespace)?,
                execution_namespace_identity: identity(&execution_namespace)?,
                workspace_identity: identity(&workspace_runtime)?,
                execution_identity: identity(&execution_root)?,
                target_identity: identity(&target)?,
                temporary_identity: identity(&temporary)?,
                home_identity: identity(&home)?,
                cargo_home_identity: identity(&cargo_home)?,
                root: runtime_root,
                workspace_namespace,
                execution_namespace,
                workspace_root: workspace_runtime,
                execution_root,
                target,
                temporary,
                home,
                cargo_home,
                registry_target,
            };
            Ok(Self {
                root,
                workspace_root,
                runtime,
            })
        }

        fn published_input(
            &self,
            content: &[u8],
            mode: u32,
        ) -> Result<PublishedVerificationInput, Box<dyn std::error::Error>> {
            self.published_input_files(&[("src/main.rs", content, mode)])
        }

        fn published_input_files(
            &self,
            files: &[(&str, &[u8], u32)],
        ) -> Result<PublishedVerificationInput, Box<dyn std::error::Error>> {
            for (relative, content, mode) in files {
                let file = self.workspace_root.join(relative);
                if let Some(parent) = file.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&file, content)?;
                fs::set_permissions(&file, Permissions::from_mode(*mode))?;
            }
            let layout = WorkspaceStateLayout::initialize(&self.workspace_root)?;
            let existing = WorkspaceStateLayout::inspect_existing(&self.workspace_root)?
                .ok_or("missing workspace state")?;
            let workspace = ConfinedWorkspace::open(&existing)?;
            let cancellation = AtomicBool::new(false);
            let staged = workspace.stage_verification_input(
                VerificationInputId::from_uuid(Uuid::now_v7()),
                &cancellation,
            )?;
            let published = staged.publish()?;
            drop(staged);
            drop(workspace);
            drop(layout);
            Ok(published)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.runtime.cleanup();
            restore_permissions(&self.root);
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn restore_permissions(path: &Path) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if metadata.file_type().is_symlink() {
            return;
        }
        let mode = if metadata.is_dir() { 0o700 } else { 0o600 };
        let _ = fs::set_permissions(path, Permissions::from_mode(mode));
        if metadata.is_dir()
            && let Ok(entries) = fs::read_dir(path)
        {
            for entry in entries.flatten() {
                restore_permissions(&entry.path());
            }
        }
    }

    #[test]
    fn error_display_does_not_include_runtime_paths() {
        let error = VerificationExecutionSourceError::Mismatch;
        assert_eq!(
            error.to_string(),
            "verification source does not match its execution contract"
        );
    }

    #[test]
    fn prepared_source_copies_large_executable_content_and_rejects_reuse()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("copy")?;
        let content = vec![0x5a; 40 * 1024];
        let input = fixture.published_input(&content, 0o755)?;
        let source = VerificationExecutionSource::prepare(&fixture.runtime, &input)?;
        assert_eq!(
            source.root(),
            fixture
                .runtime
                .execution_root()
                .join(VERIFICATION_SOURCE_DIRECTORY)
        );
        let output = source.root().join("src/main.rs");
        assert_eq!(
            fs::symlink_metadata(source.root())?.permissions().mode() & 0o777,
            u32::from(VERIFICATION_SOURCE_ROOT_MODE)
        );
        assert_eq!(
            fs::symlink_metadata(source.root().join("src"))?
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(fs::read(&output)?, content);
        assert_eq!(
            fs::symlink_metadata(&output)?.permissions().mode() & 0o777,
            0o555
        );
        source.validate(&fixture.runtime, &input)?;
        assert!(matches!(
            VerificationExecutionSource::prepare(&fixture.runtime, &input),
            Err(VerificationExecutionSourceError::Mismatch)
        ));
        let retained_root = source.root().to_path_buf();
        drop(source);
        assert!(retained_root.is_dir());
        Ok(())
    }

    #[test]
    fn prepared_source_preserves_non_utf8_manifested_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("binary")?;
        let content = b"fn main() {\0\xff\n}";
        let input = fixture.published_input(content, 0o600)?;
        let source = VerificationExecutionSource::prepare(&fixture.runtime, &input)?;
        assert_eq!(fs::read(source.root().join("src/main.rs"))?, content);
        source.validate(&fixture.runtime, &input)?;
        Ok(())
    }

    #[test]
    fn partial_copy_failure_leaves_cleanup_to_runtime_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("partial")?;
        let input = fixture
            .published_input_files(&[("a.rs", b"first", 0o644), ("z.rs", b"durable", 0o644)])?;
        let execution = open_runtime_execution_directory(&fixture.runtime)?;
        mkdirat(
            &execution,
            VERIFICATION_SOURCE_DIRECTORY,
            from_sealed_mode(VERIFICATION_SOURCE_DIRECTORY_MODE),
        )?;
        let partial = fixture
            .runtime
            .execution_root()
            .join(VERIFICATION_SOURCE_DIRECTORY);
        fs::write(partial.join("z.rs"), b"preexisting")?;
        fs::set_permissions(partial.join("z.rs"), Permissions::from_mode(0o444))?;
        let source = openat(
            &execution,
            VERIFICATION_SOURCE_DIRECTORY,
            directory_open_flags(),
            Mode::empty(),
        )?;
        assert!(matches!(
            copy_manifest(&source, &input),
            Err(VerificationExecutionSourceError::Mismatch)
        ));
        assert_eq!(fs::read(partial.join("a.rs"))?, b"first");
        assert_eq!(fs::read(partial.join("z.rs"))?, b"preexisting");
        input.validate()?;
        drop(source);
        assert!(partial.exists());
        fixture.runtime.cleanup()?;
        assert!(!partial.exists());
        Ok(())
    }

    #[test]
    fn source_cleanup_rejects_symlinks_and_hardlinks() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("cleanup-entries")?;
        let execution = open_runtime_execution_directory(&fixture.runtime)?;
        mkdirat(
            &execution,
            VERIFICATION_SOURCE_DIRECTORY,
            from_sealed_mode(VERIFICATION_SOURCE_DIRECTORY_MODE),
        )?;
        let partial = fixture
            .runtime
            .execution_root()
            .join(VERIFICATION_SOURCE_DIRECTORY);
        let outside = fixture.root.join("outside");
        fs::write(&outside, b"outside")?;
        symlink(&outside, partial.join("link"))?;
        assert!(matches!(
            prepare_runtime_source_cleanup(&fixture.runtime),
            Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry)
        ));
        assert!(
            fs::symlink_metadata(partial.join("link"))?
                .file_type()
                .is_symlink()
        );
        fs::remove_file(partial.join("link"))?;

        let hardlink_source = fixture.root.join("hardlink-source");
        fs::write(&hardlink_source, b"hardlink")?;
        hard_link(&hardlink_source, partial.join("hardlink"))?;
        assert!(matches!(
            prepare_runtime_source_cleanup(&fixture.runtime),
            Err(RustCiDiscoveryError::ProductRuntimeUnexpectedEntry)
        ));
        fs::remove_file(partial.join("hardlink"))?;
        fs::remove_file(hardlink_source)?;
        fixture.runtime.cleanup()?;
        Ok(())
    }

    #[test]
    fn validation_rejects_tamper_unexpected_entry_and_symlink()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new("validate")?;
        let expected_content = b"fn main() {}\n";
        let input = fixture.published_input(expected_content, 0o644)?;
        let source = VerificationExecutionSource::prepare(&fixture.runtime, &input)?;
        let output = source.root().join("src/main.rs");
        fs::set_permissions(&output, Permissions::from_mode(0o644))?;
        fs::write(&output, b"tampered")?;
        fs::set_permissions(&output, Permissions::from_mode(0o444))?;
        assert!(matches!(
            source.validate(&fixture.runtime, &input),
            Err(VerificationExecutionSourceError::Mismatch)
        ));

        fs::set_permissions(&output, Permissions::from_mode(0o644))?;
        fs::write(&output, expected_content)?;
        fs::set_permissions(&output, Permissions::from_mode(0o444))?;
        source.validate(&fixture.runtime, &input)?;

        let extra = source.root().join("unexpected");
        fs::set_permissions(source.root(), Permissions::from_mode(0o700))?;
        fs::write(&extra, b"extra")?;
        fs::set_permissions(source.root(), Permissions::from_mode(0o555))?;
        assert!(matches!(
            source.validate(&fixture.runtime, &input),
            Err(VerificationExecutionSourceError::Mismatch)
        ));
        fs::set_permissions(source.root(), Permissions::from_mode(0o700))?;
        fs::remove_file(&extra)?;
        fs::set_permissions(source.root(), Permissions::from_mode(0o555))?;
        source.validate(&fixture.runtime, &input)?;

        let source_directory = source.root().join("src");
        fs::set_permissions(&source_directory, Permissions::from_mode(0o700))?;
        fs::remove_file(&output)?;
        symlink(input.source_root().join("src/main.rs"), &output)?;
        fs::set_permissions(&source_directory, Permissions::from_mode(0o555))?;
        assert!(matches!(
            source.validate(&fixture.runtime, &input),
            Err(VerificationExecutionSourceError::Mismatch)
        ));
        input.validate()?;
        Ok(())
    }

    #[test]
    fn tree_validator_rejects_missing_or_unexpected_manifest_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!("forge-verification-tree-{}", Uuid::now_v7()));
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, Permissions::from_mode(0o700))?;
        let expected_file = root.join("expected");
        fs::write(&expected_file, b"ok")?;
        fs::set_permissions(&expected_file, Permissions::from_mode(0o444))?;
        let path = WorkspaceRelativePath::new(PathBuf::from("expected"))?;
        let entry = VerificationInputEntry::file(
            path,
            0o644,
            FileByteCount::new(2),
            FileContentHash::from_bytes(*blake3::hash(b"ok").as_bytes()),
        )?;
        let key = entry
            .path()
            .as_path()
            .as_os_str()
            .as_encoded_bytes()
            .to_vec();
        let expected = BTreeMap::from([(key, &entry)]);
        let fd = open_verified_directory_path(&root)?;
        let mut seen = BTreeSet::new();
        validate_tree(
            &fd,
            Path::new(""),
            &expected,
            &mut seen,
            VERIFICATION_SOURCE_DIRECTORY_MODE,
            0,
        )?;
        assert_eq!(seen.len(), expected.len());
        fs::remove_file(&expected_file)?;
        let mut seen = BTreeSet::new();
        validate_tree(
            &fd,
            Path::new(""),
            &expected,
            &mut seen,
            VERIFICATION_SOURCE_DIRECTORY_MODE,
            0,
        )?;
        assert_ne!(seen.len(), expected.len());
        fs::write(&expected_file, b"ok")?;
        fs::set_permissions(&expected_file, Permissions::from_mode(0o444))?;
        fs::write(root.join("unexpected"), b"bad")?;
        let mut seen = BTreeSet::new();
        assert!(matches!(
            validate_tree(
                &fd,
                Path::new(""),
                &expected,
                &mut seen,
                VERIFICATION_SOURCE_DIRECTORY_MODE,
                0,
            ),
            Err(VerificationExecutionSourceError::Mismatch)
        ));
        restore_permissions(&root);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
