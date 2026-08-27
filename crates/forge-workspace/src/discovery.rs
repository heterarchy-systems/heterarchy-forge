use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use base64::Engine;
use forge_domain::{LocationId, LocationRevision, LocationState, RegisteredLocation};
use thiserror::Error;

const MAX_WORKSPACE_CANDIDATES: usize = 256;
const MAX_SELECTOR_CHARS: usize = 512;
const MAX_LOCATOR_WIRE_BYTES: usize = 4_096;
const MAX_LOCATOR_PATH_BYTES: usize = 1_024;
const MAX_LOCATOR_ENCODED_PATH_BYTES: usize = 1_368;
const LOCATOR_VERSION: &str = "hf1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkspaceCandidateKind {
    LocationRoot,
    DirectChild,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum SignalPresence {
    #[default]
    Absent,
    Present,
}

impl SignalPresence {
    const fn from_bool(value: bool) -> Self {
        if value { Self::Present } else { Self::Absent }
    }

    const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkspaceSignals {
    cargo_workspace: SignalPresence,
    git_repository: SignalPresence,
    agent_instructions: SignalPresence,
    forge_state: SignalPresence,
}

impl WorkspaceSignals {
    pub const fn cargo_workspace(self) -> bool {
        self.cargo_workspace.is_present()
    }

    pub const fn git_repository(self) -> bool {
        self.git_repository.is_present()
    }

    pub const fn agent_instructions(self) -> bool {
        self.agent_instructions.is_present()
    }

    pub const fn forge_state(self) -> bool {
        self.forge_state.is_present()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceCandidate {
    location_id: LocationId,
    kind: WorkspaceCandidateKind,
    relative_root: PathBuf,
    absolute_root: PathBuf,
    display_name: OsString,
    signals: WorkspaceSignals,
}

/// Opaque native-path key for re-resolving a previously discovered candidate.
///
/// The constructor remains private so callers obtain keys only from an actual
/// discovery result. A later scan must still resolve the key again before any
/// effect; possession of this value is not a capability or Workspace authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceCandidateKey {
    location_id: LocationId,
    relative_root: PathBuf,
}

impl WorkspaceCandidateKey {
    pub const fn location_id(&self) -> LocationId {
        self.location_id
    }

    pub fn relative_root(&self) -> &Path {
        &self.relative_root
    }

    /// Bind this opaque candidate key to the exact Location revision observed
    /// by the discovery caller.  The resulting locator is correlation data,
    /// not a capability; service resolution re-scans and revalidates it.
    pub fn locator(
        &self,
        expected_revision: LocationRevision,
    ) -> Result<WorkspaceLocator, WorkspaceLocatorError> {
        WorkspaceLocator::from_candidate_key(self, expected_revision)
    }
}

/// Canonical, bounded correlation token for a discovered Workspace candidate.
///
/// The wire form is `hf1:<location-uuid>:<revision>:<base64url-path>`.  The
/// path component is encoded from its native Unix bytes, not from a lossy
/// UTF-8 display label.  Only the Location root (`.`) and one direct child
/// are valid paths.  A locator never grants authority by itself: callers must
/// pass it through [`crate::LocationService::resolve_locator_current`], which
/// rechecks the Location revision and candidate against the live filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WorkspaceLocator {
    location_id: LocationId,
    expected_revision: LocationRevision,
    encoded_relative_root: String,
    relative_root: PathBuf,
}

impl WorkspaceLocator {
    pub fn new(
        location_id: LocationId,
        expected_revision: LocationRevision,
        relative_root: impl AsRef<Path>,
    ) -> Result<Self, WorkspaceLocatorError> {
        let relative_root = validate_locator_path(relative_root.as_ref())?.to_path_buf();
        let encoded_relative_root = encode_locator_path(&relative_root)?;
        Ok(Self {
            location_id,
            expected_revision,
            encoded_relative_root,
            relative_root,
        })
    }

    pub fn from_candidate_key(
        key: &WorkspaceCandidateKey,
        expected_revision: LocationRevision,
    ) -> Result<Self, WorkspaceLocatorError> {
        Self::new(key.location_id, expected_revision, &key.relative_root)
    }

    pub const fn location_id(&self) -> LocationId {
        self.location_id
    }

    pub const fn expected_revision(&self) -> LocationRevision {
        self.expected_revision
    }

    pub fn relative_root(&self) -> &Path {
        &self.relative_root
    }

    pub fn relative_root_bytes(&self) -> &[u8] {
        self.relative_root.as_os_str().as_bytes()
    }

    pub fn encoded_relative_root(&self) -> &str {
        &self.encoded_relative_root
    }

    pub fn encode(&self) -> String {
        format!(
            "{LOCATOR_VERSION}:{}:{}:{}",
            self.location_id, self.expected_revision, self.encoded_relative_root
        )
    }

    pub fn decode(value: &str) -> Result<Self, WorkspaceLocatorError> {
        if value.is_empty() {
            return Err(WorkspaceLocatorError::Empty);
        }
        if value.len() > MAX_LOCATOR_WIRE_BYTES {
            return Err(WorkspaceLocatorError::WireTooLong {
                actual: value.len(),
                maximum: MAX_LOCATOR_WIRE_BYTES,
            });
        }
        let mut fields = value.split(':');
        let Some(version) = fields.next() else {
            return Err(WorkspaceLocatorError::MalformedWire);
        };
        let Some(location_text) = fields.next() else {
            return Err(WorkspaceLocatorError::MalformedWire);
        };
        let Some(revision_text) = fields.next() else {
            return Err(WorkspaceLocatorError::MalformedWire);
        };
        let Some(encoded_relative_root) = fields.next() else {
            return Err(WorkspaceLocatorError::MalformedWire);
        };
        if fields.next().is_some() || version != LOCATOR_VERSION {
            return Err(WorkspaceLocatorError::MalformedWire);
        }

        let location_id = LocationId::from_str(location_text)
            .map_err(|_| WorkspaceLocatorError::InvalidLocationId)?;
        if location_id.to_string() != location_text {
            return Err(WorkspaceLocatorError::NonCanonicalLocationId);
        }
        let revision_value = revision_text
            .parse::<i64>()
            .map_err(|_| WorkspaceLocatorError::InvalidRevision)?;
        let expected_revision = LocationRevision::new(revision_value)
            .map_err(|_| WorkspaceLocatorError::InvalidRevision)?;
        if expected_revision.to_string() != revision_text {
            return Err(WorkspaceLocatorError::NonCanonicalRevision);
        }
        let relative_root = decode_locator_path(encoded_relative_root)?;
        let locator = Self {
            location_id,
            expected_revision,
            encoded_relative_root: encoded_relative_root.to_owned(),
            relative_root,
        };
        if locator.encode() != value {
            return Err(WorkspaceLocatorError::NonCanonicalWire);
        }
        Ok(locator)
    }

    pub fn candidate_key(&self) -> WorkspaceCandidateKey {
        WorkspaceCandidateKey {
            location_id: self.location_id,
            relative_root: self.relative_root.clone(),
        }
    }
}

impl fmt::Display for WorkspaceLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.encode())
    }
}

impl FromStr for WorkspaceLocator {
    type Err = WorkspaceLocatorError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::decode(value)
    }
}

impl TryFrom<(&WorkspaceCandidateKey, LocationRevision)> for WorkspaceLocator {
    type Error = WorkspaceLocatorError;

    fn try_from(value: (&WorkspaceCandidateKey, LocationRevision)) -> Result<Self, Self::Error> {
        Self::from_candidate_key(value.0, value.1)
    }
}

impl TryFrom<(WorkspaceCandidateKey, LocationRevision)> for WorkspaceLocator {
    type Error = WorkspaceLocatorError;

    fn try_from(value: (WorkspaceCandidateKey, LocationRevision)) -> Result<Self, Self::Error> {
        Self::from_candidate_key(&value.0, value.1)
    }
}

fn encode_locator_path(path: &Path) -> Result<String, WorkspaceLocatorError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.len() > MAX_LOCATOR_PATH_BYTES {
        return Err(WorkspaceLocatorError::PathTooLong {
            actual: bytes.len(),
            maximum: MAX_LOCATOR_PATH_BYTES,
        });
    }
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    if encoded.len() > MAX_LOCATOR_ENCODED_PATH_BYTES {
        return Err(WorkspaceLocatorError::EncodedPathTooLong {
            actual: encoded.len(),
            maximum: MAX_LOCATOR_ENCODED_PATH_BYTES,
        });
    }
    Ok(encoded)
}

fn decode_locator_path(encoded: &str) -> Result<PathBuf, WorkspaceLocatorError> {
    if encoded.is_empty() {
        return Err(WorkspaceLocatorError::EncodedPathEmpty);
    }
    if encoded.len() > MAX_LOCATOR_ENCODED_PATH_BYTES {
        return Err(WorkspaceLocatorError::EncodedPathTooLong {
            actual: encoded.len(),
            maximum: MAX_LOCATOR_ENCODED_PATH_BYTES,
        });
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| WorkspaceLocatorError::MalformedEncodedPath)?;
    if bytes.len() > MAX_LOCATOR_PATH_BYTES {
        return Err(WorkspaceLocatorError::PathTooLong {
            actual: bytes.len(),
            maximum: MAX_LOCATOR_PATH_BYTES,
        });
    }
    let canonical = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes);
    if canonical != encoded {
        return Err(WorkspaceLocatorError::NonCanonicalEncodedPath);
    }
    Ok(validate_locator_path(Path::new(OsStr::from_bytes(&bytes)))?.to_path_buf())
}

fn validate_locator_path(path: &Path) -> Result<&Path, WorkspaceLocatorError> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() {
        return Err(WorkspaceLocatorError::PathEmpty);
    }
    if bytes.len() > MAX_LOCATOR_PATH_BYTES {
        return Err(WorkspaceLocatorError::PathTooLong {
            actual: bytes.len(),
            maximum: MAX_LOCATOR_PATH_BYTES,
        });
    }
    if bytes.contains(&0) {
        return Err(WorkspaceLocatorError::PathContainsNul);
    }
    if bytes == b"." {
        return Ok(path);
    }
    if bytes[0] == b'/' {
        return Err(WorkspaceLocatorError::AbsolutePath);
    }
    if bytes.contains(&b'/') {
        return Err(WorkspaceLocatorError::MultiComponentPath);
    }
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(path),
        (Some(Component::ParentDir), None) => Err(WorkspaceLocatorError::TraversalPath),
        (Some(Component::CurDir), None) => Err(WorkspaceLocatorError::NonCanonicalPath),
        _ => Err(WorkspaceLocatorError::InvalidPath),
    }
}

impl WorkspaceCandidate {
    pub fn key(&self) -> WorkspaceCandidateKey {
        WorkspaceCandidateKey {
            location_id: self.location_id,
            relative_root: self.relative_root.clone(),
        }
    }

    pub const fn location_id(&self) -> LocationId {
        self.location_id
    }

    pub const fn kind(&self) -> WorkspaceCandidateKind {
        self.kind
    }

    pub fn relative_root(&self) -> &Path {
        &self.relative_root
    }

    pub fn absolute_root(&self) -> &Path {
        &self.absolute_root
    }

    pub fn display_name(&self) -> &OsStr {
        &self.display_name
    }

    pub fn display_label(&self) -> Cow<'_, str> {
        self.display_name.to_string_lossy()
    }

    pub const fn signals(&self) -> WorkspaceSignals {
        self.signals
    }

    fn matches_selector(&self, selector: &WorkspaceSelector) -> bool {
        self.display_name
            .to_str()
            .is_some_and(|name| name == selector.as_str())
            || self
                .relative_root
                .to_str()
                .is_some_and(|path| path == selector.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSelector(String);

impl WorkspaceSelector {
    pub fn new(value: impl Into<String>) -> Result<Self, WorkspaceSelectorError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(WorkspaceSelectorError::Empty);
        }
        if trimmed.chars().any(char::is_control) {
            return Err(WorkspaceSelectorError::ControlCharacter);
        }
        let character_count = trimmed.chars().count();
        if character_count > MAX_SELECTOR_CHARS {
            return Err(WorkspaceSelectorError::TooLong {
                actual: character_count,
                maximum: MAX_SELECTOR_CHARS,
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkspaceSelectorError {
    #[error("Workspace selector must not be empty")]
    Empty,
    #[error("Workspace selector must not contain control characters")]
    ControlCharacter,
    #[error("Workspace selector has {actual} characters; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceDiscovery {
    location_id: LocationId,
    location_root: PathBuf,
    candidates: Vec<WorkspaceCandidate>,
}

impl WorkspaceDiscovery {
    pub fn scan(location: &RegisteredLocation) -> Result<Self, WorkspaceDiscoveryError> {
        let location_root = validate_location_root(location)?;
        let root_candidate = build_root_candidate(location, &location_root);
        let children = scan_direct_children(location.id(), &location_root)?;
        let candidates = collect_candidates(root_candidate, children);

        Ok(Self {
            location_id: location.id(),
            location_root,
            candidates,
        })
    }

    pub const fn location_id(&self) -> LocationId {
        self.location_id
    }

    pub fn location_root(&self) -> &Path {
        &self.location_root
    }

    pub fn candidates(&self) -> &[WorkspaceCandidate] {
        &self.candidates
    }

    pub fn resolve(
        &self,
        selector: &WorkspaceSelector,
    ) -> Result<&WorkspaceCandidate, WorkspaceResolveError> {
        let mut matches = self
            .candidates
            .iter()
            .filter(|candidate| candidate.matches_selector(selector));
        let Some(first) = matches.next() else {
            return Err(WorkspaceResolveError::NotFound {
                selector: selector.as_str().to_owned(),
            });
        };
        let Some(second) = matches.next() else {
            return Ok(first);
        };

        let mut candidates = Vec::with_capacity(2 + matches.size_hint().0);
        candidates.push(first.display_label().into_owned());
        candidates.push(second.display_label().into_owned());
        candidates.extend(matches.map(|candidate| candidate.display_label().into_owned()));
        Err(WorkspaceResolveError::Ambiguous {
            selector: selector.as_str().to_owned(),
            candidates,
        })
    }

    pub fn resolve_key(
        &self,
        key: &WorkspaceCandidateKey,
    ) -> Result<&WorkspaceCandidate, WorkspaceKeyResolveError> {
        if key.location_id != self.location_id {
            return Err(WorkspaceKeyResolveError::LocationMismatch {
                expected: self.location_id,
                actual: key.location_id,
            });
        }
        self.candidates
            .iter()
            .find(|candidate| candidate.relative_root == key.relative_root)
            .ok_or_else(|| WorkspaceKeyResolveError::NotFound {
                location_id: key.location_id,
                relative_root: key.relative_root.clone(),
            })
    }

    pub fn resolve_default(&self) -> Result<&WorkspaceCandidate, WorkspaceResolveError> {
        match self.candidates.as_slice() {
            [candidate] => Ok(candidate),
            candidates => Err(WorkspaceResolveError::SelectionRequired {
                candidate_count: candidates.len(),
            }),
        }
    }
}

fn validate_location_root(
    location: &RegisteredLocation,
) -> Result<PathBuf, WorkspaceDiscoveryError> {
    if location.state() != LocationState::Enabled {
        return Err(WorkspaceDiscoveryError::LocationDisabled(location.id()));
    }

    let stored_root = location.root().as_path();
    let metadata = fs::metadata(stored_root).map_err(|source| {
        WorkspaceDiscoveryError::LocationUnavailable {
            path: stored_root.to_path_buf(),
            source,
        }
    })?;
    if !metadata.is_dir() {
        return Err(WorkspaceDiscoveryError::LocationIsNotDirectory(
            stored_root.to_path_buf(),
        ));
    }

    let observed_root = fs::canonicalize(stored_root).map_err(|source| {
        WorkspaceDiscoveryError::CanonicalizeLocation {
            path: stored_root.to_path_buf(),
            source,
        }
    })?;
    if observed_root != stored_root {
        return Err(WorkspaceDiscoveryError::LocationIdentityMoved {
            stored: stored_root.to_path_buf(),
            observed: observed_root,
        });
    }
    Ok(stored_root.to_path_buf())
}

fn build_root_candidate(location: &RegisteredLocation, location_root: &Path) -> WorkspaceCandidate {
    WorkspaceCandidate {
        location_id: location.id(),
        kind: WorkspaceCandidateKind::LocationRoot,
        relative_root: PathBuf::from("."),
        absolute_root: location_root.to_path_buf(),
        display_name: OsString::from(location.name().as_str()),
        signals: inspect_signals(location_root),
    }
}

fn scan_direct_children(
    location_id: LocationId,
    location_root: &Path,
) -> Result<Vec<WorkspaceCandidate>, WorkspaceDiscoveryError> {
    let entries =
        fs::read_dir(location_root).map_err(|source| WorkspaceDiscoveryError::ReadLocation {
            path: location_root.to_path_buf(),
            source,
        })?;
    let mut children = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| WorkspaceDiscoveryError::ReadEntry {
            path: location_root.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        if is_hidden(&name) {
            continue;
        }
        let file_type =
            entry
                .file_type()
                .map_err(|source| WorkspaceDiscoveryError::InspectEntry {
                    path: entry.path(),
                    source,
                })?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        if children.len() >= MAX_WORKSPACE_CANDIDATES - 1 {
            return Err(WorkspaceDiscoveryError::TooManyCandidates {
                maximum: MAX_WORKSPACE_CANDIDATES,
            });
        }
        let child_path = entry.path();
        children.push(build_child_candidate(
            location_id,
            location_root,
            name,
            &child_path,
        )?);
    }

    children.sort_by(|left, right| {
        left.relative_root
            .as_os_str()
            .as_bytes()
            .cmp(right.relative_root.as_os_str().as_bytes())
    });
    Ok(children)
}

fn build_child_candidate(
    location_id: LocationId,
    location_root: &Path,
    name: OsString,
    child_path: &Path,
) -> Result<WorkspaceCandidate, WorkspaceDiscoveryError> {
    let canonical_child = fs::canonicalize(child_path).map_err(|source| {
        WorkspaceDiscoveryError::CanonicalizeChild {
            path: child_path.to_path_buf(),
            source,
        }
    })?;
    if !canonical_child.starts_with(location_root) {
        return Err(WorkspaceDiscoveryError::ChildEscapesLocation {
            child: canonical_child,
            location_root: location_root.to_path_buf(),
        });
    }

    let signals = inspect_signals(&canonical_child);
    Ok(WorkspaceCandidate {
        location_id,
        kind: WorkspaceCandidateKind::DirectChild,
        relative_root: PathBuf::from(&name),
        absolute_root: canonical_child,
        display_name: name,
        signals,
    })
}

fn collect_candidates(
    root_candidate: WorkspaceCandidate,
    children: Vec<WorkspaceCandidate>,
) -> Vec<WorkspaceCandidate> {
    let mut candidates = Vec::with_capacity(children.len() + 1);
    candidates.push(root_candidate);
    candidates.extend(children);
    candidates
}

fn inspect_signals(root: &Path) -> WorkspaceSignals {
    WorkspaceSignals {
        cargo_workspace: SignalPresence::from_bool(root.join("Cargo.toml").is_file()),
        git_repository: SignalPresence::from_bool(root.join(".git").exists()),
        agent_instructions: SignalPresence::from_bool(
            root.join("AGENTS.md").is_file() || root.join(".agents").is_dir(),
        ),
        forge_state: SignalPresence::from_bool(root.join(".heterarchy-forge").is_dir()),
    }
}

fn is_hidden(name: &OsStr) -> bool {
    name.as_bytes().first() == Some(&b'.')
}

#[derive(Debug, Error)]
pub enum WorkspaceDiscoveryError {
    #[error("Location is disabled: {0}")]
    LocationDisabled(LocationId),
    #[error("Location is unavailable: {path}")]
    LocationUnavailable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Location root is not a directory: {0}")]
    LocationIsNotDirectory(PathBuf),
    #[error("failed to canonicalize Location root {path}")]
    CanonicalizeLocation {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("Location root moved: stored={stored}, observed={observed}")]
    LocationIdentityMoved { stored: PathBuf, observed: PathBuf },
    #[error("failed to read Location root {path}")]
    ReadLocation {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read an entry under Location root {path}")]
    ReadEntry {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect candidate {path}")]
    InspectEntry {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to canonicalize direct child candidate {path}")]
    CanonicalizeChild {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("direct child candidate escapes Location: child={child}, root={location_root}")]
    ChildEscapesLocation {
        child: PathBuf,
        location_root: PathBuf,
    },
    #[error("Location exposes more than the supported {maximum} Workspace candidates")]
    TooManyCandidates { maximum: usize },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkspaceResolveError {
    #[error("Workspace selector was not found: {selector}")]
    NotFound { selector: String },
    #[error("Workspace selector {selector} is ambiguous: {candidates:?}")]
    Ambiguous {
        selector: String,
        candidates: Vec<String>,
    },
    #[error("Workspace selection is required across {candidate_count} candidates")]
    SelectionRequired { candidate_count: usize },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkspaceKeyResolveError {
    #[error("Workspace candidate belongs to Location {actual}; expected {expected}")]
    LocationMismatch {
        expected: LocationId,
        actual: LocationId,
    },
    #[error("Workspace candidate was not found for Location {location_id}: {relative_root}")]
    NotFound {
        location_id: LocationId,
        relative_root: PathBuf,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WorkspaceLocatorError {
    #[error("Workspace locator must not be empty")]
    Empty,
    #[error("Workspace locator wire value is malformed")]
    MalformedWire,
    #[error("Workspace locator wire value has {actual} bytes; maximum is {maximum}")]
    WireTooLong { actual: usize, maximum: usize },
    #[error("Workspace locator contains an invalid Location id")]
    InvalidLocationId,
    #[error("Workspace locator Location id is not canonical")]
    NonCanonicalLocationId,
    #[error("Workspace locator contains an invalid Location revision")]
    InvalidRevision,
    #[error("Workspace locator Location revision is not canonical")]
    NonCanonicalRevision,
    #[error("Workspace locator wire value is not canonical")]
    NonCanonicalWire,
    #[error("Workspace locator path encoding must not be empty")]
    EncodedPathEmpty,
    #[error("Workspace locator path encoding is malformed")]
    MalformedEncodedPath,
    #[error("Workspace locator path encoding is not canonical")]
    NonCanonicalEncodedPath,
    #[error("Workspace locator path encoding has {actual} bytes; maximum is {maximum}")]
    EncodedPathTooLong { actual: usize, maximum: usize },
    #[error("Workspace locator path must not be empty")]
    PathEmpty,
    #[error("Workspace locator path has {actual} bytes; maximum is {maximum}")]
    PathTooLong { actual: usize, maximum: usize },
    #[error("Workspace locator path contains a NUL byte")]
    PathContainsNul,
    #[error("Workspace locator path must be relative")]
    AbsolutePath,
    #[error("Workspace locator path must contain only one direct child component")]
    MultiComponentPath,
    #[error("Workspace locator path contains traversal")]
    TraversalPath,
    #[error("Workspace locator path is not canonical")]
    NonCanonicalPath,
    #[error("Workspace locator path is invalid")]
    InvalidPath,
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::str::FromStr;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        WorkspaceCandidateKind, WorkspaceDiscovery, WorkspaceLocator, WorkspaceLocatorError,
        WorkspaceResolveError, WorkspaceSelector, WorkspaceSignals,
    };
    use forge_domain::{
        LocationId, LocationName, LocationRevision, LocationRoot, LocationState,
        RegisteredLocation, TimestampMillis,
    };

    #[test]
    fn scan_discovers_root_and_sorted_direct_children_without_hidden_or_symlink_dirs()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("scan")?;
        fs::create_dir_all(root.join("B"))?;
        fs::create_dir_all(root.join("A"))?;
        fs::create_dir_all(root.join(".hidden"))?;
        fs::write(
            root.join("A/Cargo.toml"),
            "[package]\nname='a'\nversion='0.1.0'\n",
        )?;
        symlink(root.join("A"), root.join("linked-a"))?;

        let location = registered_location(&root, LocationState::Enabled)?;
        let discovery = WorkspaceDiscovery::scan(&location)?;
        let candidates = discovery.candidates();

        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].kind(), WorkspaceCandidateKind::LocationRoot);
        assert_eq!(candidates[0].relative_root(), Path::new("."));
        assert_eq!(candidates[1].display_name(), OsStr::new("A"));
        assert!(candidates[1].signals().cargo_workspace());
        assert_eq!(candidates[2].display_name(), OsStr::new("B"));
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.display_name() != "linked-a")
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn workspace_signals_report_each_signal_without_exposing_storage_bools()
    -> Result<(), Box<dyn std::error::Error>> {
        let empty = WorkspaceSignals::default();
        assert!(!empty.cargo_workspace());
        assert!(!empty.git_repository());
        assert!(!empty.agent_instructions());
        assert!(!empty.forge_state());

        let root = unique_test_root("signals")?;
        fs::create_dir_all(root.join(".git"))?;
        fs::create_dir_all(root.join(".agents"))?;
        fs::create_dir_all(root.join(".heterarchy-forge"))?;
        fs::write(root.join("Cargo.toml"), "[workspace]\n")?;

        let signals = super::inspect_signals(&root);
        assert!(signals.cargo_workspace());
        assert!(signals.git_repository());
        assert!(signals.agent_instructions());
        assert!(signals.forge_state());

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn workspace_signals_map_each_marker_independently() -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            ("Cargo.toml", "cargo", true),
            (".git", "git", false),
            ("AGENTS.md", "agents", true),
            (".heterarchy-forge", "forge", false),
        ];

        for (marker, expected, is_file) in cases {
            let root = unique_test_root(expected)?;
            fs::create_dir_all(&root)?;
            if is_file {
                fs::write(root.join(marker), "marker")?;
            } else {
                fs::create_dir_all(root.join(marker))?;
            }

            let signals = super::inspect_signals(&root);
            assert_eq!(signals.cargo_workspace(), expected == "cargo");
            assert_eq!(signals.git_repository(), expected == "git");
            assert_eq!(signals.agent_instructions(), expected == "agents");
            assert_eq!(signals.forge_state(), expected == "forge");

            fs::remove_dir_all(root)?;
        }
        Ok(())
    }

    #[test]
    fn explicit_resolution_never_falls_back_to_an_active_or_default_workspace()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("resolve")?;
        fs::create_dir_all(root.join("A"))?;
        fs::create_dir_all(root.join("B"))?;
        let location = registered_location(&root, LocationState::Enabled)?;
        let discovery = WorkspaceDiscovery::scan(&location)?;

        let selected = discovery.resolve(&WorkspaceSelector::new("A")?)?;
        assert_eq!(selected.relative_root(), Path::new("A"));

        let root_selected = discovery.resolve(&WorkspaceSelector::new(".")?)?;
        assert_eq!(root_selected.kind(), WorkspaceCandidateKind::LocationRoot);

        assert!(matches!(
            discovery.resolve(&WorkspaceSelector::new("missing")?),
            Err(WorkspaceResolveError::NotFound { .. })
        ));
        assert!(matches!(
            discovery.resolve_default(),
            Err(WorkspaceResolveError::SelectionRequired { candidate_count: 3 })
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn selector_ambiguity_remains_deterministic_without_allocating_for_unique_matches()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("ambiguous")?;
        fs::create_dir_all(root.join("Same"))?;
        let location = RegisteredLocation::from_parts_with_revision(
            LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215e")?,
            forge_domain::LocationName::new("Same")?,
            forge_domain::LocationRoot::from_canonical(fs::canonicalize(&root)?)?,
            LocationState::Enabled,
            forge_domain::TimestampMillis::new(1)?,
            forge_domain::TimestampMillis::new(1)?,
            forge_domain::LocationRevision::INITIAL,
        );
        let discovery = WorkspaceDiscovery::scan(&location)?;

        assert_eq!(
            discovery.resolve(&WorkspaceSelector::new("Same")?),
            Err(WorkspaceResolveError::Ambiguous {
                selector: "Same".to_owned(),
                candidates: vec!["Same".to_owned(), "Same".to_owned()],
            })
        );

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn candidate_key_preserves_native_path_bytes_and_requires_a_fresh_scan()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("native-key")?;
        fs::create_dir_all(&root)?;
        let native_name = OsString::from("워크스페이스");
        fs::create_dir_all(root.join(&native_name))?;
        let location = registered_location(&root, LocationState::Enabled)?;
        let discovery = WorkspaceDiscovery::scan(&location)?;
        let candidate = discovery
            .candidates()
            .iter()
            .find(|candidate| {
                candidate.relative_root().as_os_str().as_bytes() == native_name.as_bytes()
            })
            .ok_or("native candidate missing")?;
        let key = candidate.key();

        assert_eq!(key.location_id(), location.id());
        assert_eq!(
            key.relative_root().as_os_str().as_bytes(),
            native_name.as_bytes()
        );
        assert_eq!(
            discovery.resolve_key(&key)?.absolute_root(),
            candidate.absolute_root()
        );

        fs::remove_dir_all(root.join(&native_name))?;
        let rescanned = WorkspaceDiscovery::scan(&location)?;
        assert!(matches!(
            rescanned.resolve_key(&key),
            Err(super::WorkspaceKeyResolveError::NotFound { .. })
        ));

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn workspace_locator_round_trips_native_relative_path_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("locator-native")?;
        let child_name = OsString::from_vec(b"native-\xC3\xA9".to_vec());
        let child = root.join(&child_name);
        fs::create_dir_all(&child)?;
        let location = registered_location(&root, LocationState::Enabled)?;
        let discovery = WorkspaceDiscovery::scan(&location)?;
        let candidate = discovery
            .candidates()
            .iter()
            .find(|candidate| {
                candidate.relative_root().as_os_str().as_bytes() == child_name.as_bytes()
            })
            .ok_or("native candidate was not discovered")?;

        let locator =
            WorkspaceLocator::from_candidate_key(&candidate.key(), LocationRevision::INITIAL)?;
        let encoded = locator.encode();
        let decoded = WorkspaceLocator::decode(&encoded)?;
        assert_eq!(decoded.location_id(), location.id());
        assert_eq!(decoded.expected_revision(), LocationRevision::INITIAL);
        assert_eq!(decoded.relative_root_bytes(), child_name.as_bytes());
        assert_eq!(
            decoded.candidate_key().relative_root(),
            candidate.relative_root()
        );
        assert_eq!(decoded.encode(), encoded);

        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn workspace_locator_rejects_malformed_noncanonical_oversized_and_unsafe_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc12170")?;
        let revision = LocationRevision::INITIAL;
        assert!(matches!(
            WorkspaceLocator::new(id, revision, Path::new("/absolute")),
            Err(WorkspaceLocatorError::AbsolutePath)
        ));
        assert!(matches!(
            WorkspaceLocator::new(id, revision, Path::new("../escape")),
            Err(WorkspaceLocatorError::MultiComponentPath | WorkspaceLocatorError::TraversalPath)
        ));
        assert!(matches!(
            WorkspaceLocator::new(id, revision, Path::new("one/two")),
            Err(WorkspaceLocatorError::MultiComponentPath)
        ));

        let canonical = WorkspaceLocator::new(id, revision, Path::new("child"))?.encode();
        assert!(matches!(
            WorkspaceLocator::decode(&canonical.replace("Y2hpbGQ", "Y2hpbGQ=")),
            Err(WorkspaceLocatorError::MalformedEncodedPath
                | WorkspaceLocatorError::NonCanonicalEncodedPath
                | WorkspaceLocatorError::NonCanonicalWire)
        ));
        assert!(matches!(
            WorkspaceLocator::decode(&format!("hf1:{id}:1:aR")),
            Err(WorkspaceLocatorError::MalformedEncodedPath
                | WorkspaceLocatorError::NonCanonicalEncodedPath)
        ));
        assert!(matches!(
            WorkspaceLocator::decode(&"x".repeat(4_097)),
            Err(WorkspaceLocatorError::WireTooLong { .. })
        ));
        Ok(())
    }

    #[test]
    fn candidate_key_never_crosses_location_identity() -> Result<(), Box<dyn std::error::Error>> {
        let first_root = unique_test_root("key-location-a")?;
        let second_root = unique_test_root("key-location-b")?;
        fs::create_dir_all(&first_root)?;
        fs::create_dir_all(&second_root)?;
        let first = registered_location(&first_root, LocationState::Enabled)?;
        let second = RegisteredLocation::from_parts_with_revision(
            LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215f")?,
            forge_domain::LocationName::new("Second")?,
            forge_domain::LocationRoot::from_canonical(fs::canonicalize(&second_root)?)?,
            LocationState::Enabled,
            forge_domain::TimestampMillis::new(1)?,
            forge_domain::TimestampMillis::new(1)?,
            forge_domain::LocationRevision::INITIAL,
        );
        let first_discovery = WorkspaceDiscovery::scan(&first)?;
        let second_discovery = WorkspaceDiscovery::scan(&second)?;
        let key = first_discovery.candidates()[0].key();

        assert!(matches!(
            second_discovery.resolve_key(&key),
            Err(super::WorkspaceKeyResolveError::LocationMismatch { .. })
        ));

        fs::remove_dir_all(first_root)?;
        fs::remove_dir_all(second_root)?;
        Ok(())
    }

    #[test]
    fn disabled_location_is_not_scanned() -> Result<(), Box<dyn std::error::Error>> {
        let root = unique_test_root("disabled")?;
        fs::create_dir_all(&root)?;
        let location = registered_location(&root, LocationState::Disabled)?;
        assert!(WorkspaceDiscovery::scan(&location).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn stored_root_identity_failures_are_rejected_without_repair_or_scan()
    -> Result<(), Box<dyn std::error::Error>> {
        let symlink_root = unique_test_root("identity-symlink")?;
        let stored = symlink_root.join("stored");
        let target = symlink_root.join("target");
        fs::create_dir_all(&stored)?;
        fs::create_dir_all(target.join("child"))?;
        let canonical_stored = fs::canonicalize(&stored)?;
        let canonical_target = fs::canonicalize(&target)?;
        let location = registered_location(&stored, LocationState::Enabled)?;
        fs::remove_dir(&stored)?;
        symlink(&target, &stored)?;

        let symlink_result = WorkspaceDiscovery::scan(&location);
        assert!(matches!(
            symlink_result,
            Err(super::WorkspaceDiscoveryError::LocationIdentityMoved {
                stored: observed_stored,
                observed
            }) if observed_stored == canonical_stored && observed == canonical_target
        ));
        fs::remove_dir_all(symlink_root)?;

        let deleted_root = unique_test_root("identity-deleted")?;
        fs::create_dir_all(&deleted_root)?;
        let canonical_deleted_root = fs::canonicalize(&deleted_root)?;
        let deleted_location = registered_location(&deleted_root, LocationState::Enabled)?;
        fs::remove_dir_all(&deleted_root)?;
        assert!(matches!(
            WorkspaceDiscovery::scan(&deleted_location),
            Err(super::WorkspaceDiscoveryError::LocationUnavailable { path, .. })
                if path == canonical_deleted_root
        ));

        let file_root = unique_test_root("identity-file")?;
        fs::create_dir_all(&file_root)?;
        let canonical_file_root = fs::canonicalize(&file_root)?;
        let file_location = registered_location(&file_root, LocationState::Enabled)?;
        fs::remove_dir(&file_root)?;
        fs::write(&file_root, "replacement")?;
        assert!(matches!(
            WorkspaceDiscovery::scan(&file_location),
            Err(super::WorkspaceDiscoveryError::LocationIsNotDirectory(path))
                if path == canonical_file_root
        ));
        fs::remove_file(file_root)?;
        Ok(())
    }

    fn registered_location(
        root: &Path,
        state: LocationState,
    ) -> Result<RegisteredLocation, Box<dyn std::error::Error>> {
        let canonical_root = fs::canonicalize(root)?;
        Ok(RegisteredLocation::from_parts_with_revision(
            LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215e")?,
            LocationName::new("Root Location")?,
            LocationRoot::from_canonical(canonical_root)?,
            state,
            TimestampMillis::new(1)?,
            TimestampMillis::new(1)?,
            LocationRevision::INITIAL,
        ))
    }

    fn unique_test_root(label: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        Ok(std::env::temp_dir().join(format!("heterarchy-forge-{label}-{unique}")))
    }
}
