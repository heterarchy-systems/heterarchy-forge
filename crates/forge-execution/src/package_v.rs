//! Rust-native structural verification for the sealed `PackageV1` command.
//!
//! `PackageV` is deliberately a small, offline validator.  It reads only the
//! published verification snapshot supplied by Forge (or the equivalent
//! read-only process root), checks the manifest and declared artifact bytes,
//! and emits one bounded JSON result.  It never fetches citations, executes a
//! research tool, opens SQLite, or makes a profitability claim.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;

use forge_domain::WorkspaceRelativePath;
use forge_workspace::{PublishedVerificationInput, VerificationInputError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The fixed command exposed by the Forge command catalog.
pub const PACKAGE_V_COMMAND_ID: &str = "forge:research-package-v1";
/// The hidden argv token accepted by `forge-backend` before normal startup.
pub const PACKAGE_V_SUBCOMMAND: &str = "internal-verify-research-package-v1";
/// The only manifest argument accepted by the hidden command.
pub const PACKAGE_V_MANIFEST_NAME: &str = "package-v.json";
/// The structural contract version bound into the server-owned capability.
pub const PACKAGE_V_CONTRACT_VERSION: u32 = 1;
/// Maximum manifest bytes accepted by `PackageV`.
const PACKAGE_V_MAX_MANIFEST_BYTES: usize = 256 * 1024;
/// Maximum declared files, including the root manifest.
const PACKAGE_V_MAX_FILES: usize = 64;
/// Maximum total declared artifact bytes, excluding the root manifest.
const PACKAGE_V_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum report bytes.
const PACKAGE_V_MAX_REPORT_BYTES: u64 = 2 * 1024 * 1024;
/// Maximum claims entries.
const PACKAGE_V_MAX_CLAIMS: usize = 1_024;
/// Maximum citation entries.
const PACKAGE_V_MAX_CITATIONS: usize = 512;
/// Maximum URL bytes.
const PACKAGE_V_MAX_URL_BYTES: usize = 2_048;
/// Maximum number of errors retained in one validator result.
const PACKAGE_V_MAX_ERRORS: usize = 32;
const PACKAGE_V_MAX_ERROR_BYTES: usize = 512;
const PACKAGE_V_MAX_TEXT_BYTES: usize = 8 * 1024 * 1024;
static NO_CANCELLATION: AtomicBool = AtomicBool::new(false);

/// The process-local identity of the current `forge-backend` executable.
///
/// The capability is never serialized into a request or persisted.  Its
/// redacted Debug implementation deliberately omits the path and digest.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct PackageVExecutableCapability {
    path: PathBuf,
    identity: ExecutableIdentity,
    sha256: [u8; 32],
    contract_version: u32,
}

impl fmt::Debug for PackageVExecutableCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageVExecutableCapability")
            .field("contract_version", &self.contract_version)
            .field("regular_file", &true)
            .field("sha256_present", &true)
            .finish_non_exhaustive()
    }
}

impl PackageVExecutableCapability {
    /// Capture the canonical current executable and its immutable identity.
    pub fn prepare_current() -> Result<Self, PackageVExecutableError> {
        let path = std::env::current_exe().map_err(PackageVExecutableError::CurrentExe)?;
        Self::prepare_at(&path)
    }

    /// Capture one exact executable path.  This constructor is testable and
    /// remains private to the execution crate's public API surface.
    pub fn prepare_at(path: &Path) -> Result<Self, PackageVExecutableError> {
        let path = validate_executable_path(path)?;
        let identity = inspect_executable(&path)?;
        let sha256 = hash_file(&path)?;
        Ok(Self {
            path,
            identity,
            sha256,
            contract_version: PACKAGE_V_CONTRACT_VERSION,
        })
    }

    /// Revalidate the exact current file before a `PackageV` process is spawned.
    pub fn revalidate(&self) -> Result<(), PackageVExecutableError> {
        let path = validate_executable_path(&self.path)?;
        if path != self.path {
            return Err(PackageVExecutableError::ExecutableChanged);
        }
        let identity = inspect_executable(&path)?;
        if identity != self.identity {
            return Err(PackageVExecutableError::ExecutableChanged);
        }
        if hash_file(&path)? != self.sha256 {
            return Err(PackageVExecutableError::ExecutableChanged);
        }
        Ok(())
    }

    pub const fn contract_version(&self) -> u32 {
        self.contract_version
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Stable bytes for the command catalog fingerprint.  The bytes include
    /// the contract version and physical executable identity but never a
    /// caller identity or Execution UUID.
    pub fn catalog_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(&self.contract_version.to_le_bytes());
        bytes.extend_from_slice(&self.identity.device.to_le_bytes());
        bytes.extend_from_slice(&self.identity.inode.to_le_bytes());
        bytes.extend_from_slice(&self.identity.length.to_le_bytes());
        bytes.extend_from_slice(&self.identity.mode.to_le_bytes());
        bytes.extend_from_slice(&self.sha256);
        bytes
    }
}

pub(crate) fn is_exact_package_request(
    request: &forge_domain::ExecutionRequest,
    capability: &PackageVExecutableCapability,
) -> bool {
    if request.permissions() != forge_domain::ExecutionPermissions::new(true, false, false)
        || request.cwd().is_some()
    {
        return false;
    }
    let forge_domain::ExecutionKind::Structured { program, arguments } = request.kind() else {
        return false;
    };
    program.as_path() == capability.path()
        && arguments.len() == 2
        && arguments[0].as_os_str() == std::ffi::OsStr::new(PACKAGE_V_SUBCOMMAND)
        && arguments[1].as_os_str() == std::ffi::OsStr::new(PACKAGE_V_MANIFEST_NAME)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExecutableIdentity {
    device: u64,
    inode: u64,
    length: u64,
    mode: u32,
}

fn validate_executable_path(path: &Path) -> Result<PathBuf, PackageVExecutableError> {
    if !path.is_absolute() {
        return Err(PackageVExecutableError::ExecutableNotAbsolute);
    }
    if path.starts_with("/Volumes/256.SSD") {
        return Err(PackageVExecutableError::ExternalStorageRejected);
    }
    let metadata = fs::symlink_metadata(path).map_err(PackageVExecutableError::Inspect)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(PackageVExecutableError::ExecutableUnavailable);
    }
    let canonical = fs::canonicalize(path).map_err(PackageVExecutableError::Inspect)?;
    if canonical != path {
        return Err(PackageVExecutableError::ExecutableChanged);
    }
    Ok(path.to_path_buf())
}

fn inspect_executable(path: &Path) -> Result<ExecutableIdentity, PackageVExecutableError> {
    let metadata = fs::symlink_metadata(path).map_err(PackageVExecutableError::Inspect)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o111 == 0
    {
        return Err(PackageVExecutableError::ExecutableUnavailable);
    }
    Ok(ExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        mode: metadata.mode(),
    })
}

fn hash_file(path: &Path) -> Result<[u8; 32], PackageVExecutableError> {
    let file = File::open(path).map_err(PackageVExecutableError::Inspect)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(PackageVExecutableError::Inspect)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[derive(Debug, Error)]
pub enum PackageVExecutableError {
    #[error("current executable could not be resolved")]
    CurrentExe(#[source] std::io::Error),
    #[error("PackageV executable path must be absolute")]
    ExecutableNotAbsolute,
    #[error("PackageV executable is unavailable")]
    ExecutableUnavailable,
    #[error("PackageV executable identity changed")]
    ExecutableChanged,
    #[error("PackageV cannot use the external SSD root")]
    ExternalStorageRejected,
    #[error("PackageV executable inspection failed")]
    Inspect(#[source] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageVResult {
    #[serde(rename = "packageVersion")]
    package_version: u32,
    valid: bool,
    #[serde(rename = "manifestSha256")]
    manifest_sha256: String,
    #[serde(rename = "checkedFiles")]
    checked_files: usize,
    #[serde(rename = "checkedClaims")]
    checked_claims: usize,
    #[serde(rename = "checkedCitations")]
    checked_citations: usize,
    #[serde(rename = "artifactKind")]
    artifact_kind: String,
    #[serde(rename = "noTrade")]
    no_trade: bool,
    errors: Vec<String>,
}

impl PackageVResult {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            package_version: PACKAGE_V_CONTRACT_VERSION,
            valid: false,
            manifest_sha256: String::new(),
            checked_files: 0,
            checked_claims: 0,
            checked_citations: 0,
            artifact_kind: "unknown".to_owned(),
            no_trade: false,
            errors: vec![message.into()],
        }
    }

    pub const fn valid(&self) -> bool {
        self.valid
    }

    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

#[derive(Debug, Error)]
pub enum PackageVValidationError {
    #[error("PackageV manifest is missing or unreadable")]
    ManifestRead(#[source] std::io::Error),
    #[error("PackageV snapshot file could not be read")]
    SnapshotRead(#[source] VerificationInputError),
    #[error("PackageV manifest is not valid UTF-8")]
    ManifestUtf8(#[source] std::str::Utf8Error),
    #[error("PackageV manifest JSON is invalid")]
    ManifestJson(#[source] serde_json::Error),
    #[error("PackageV manifest exceeds the byte bound")]
    ManifestTooLarge,
    #[error("PackageV package root is invalid")]
    InvalidRoot,
    #[error("PackageV result JSON is too large")]
    ResultTooLarge,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "artifactKind")]
    artifact_kind: ArtifactKind,
    #[serde(rename = "reportPath")]
    report_path: String,
    #[serde(rename = "reportSha256")]
    report_sha256: String,
    #[serde(rename = "claimsPath")]
    claims_path: String,
    #[serde(rename = "claimsSha256")]
    claims_sha256: String,
    #[serde(rename = "citationsPath")]
    citations_path: String,
    #[serde(rename = "citationsSha256")]
    citations_sha256: String,
    #[serde(rename = "noTrade")]
    no_trade: bool,
    #[serde(rename = "simulationState")]
    simulation_state: SimulationState,
    #[serde(rename = "quantProtocolPath")]
    quant_protocol_path: Option<String>,
    #[serde(rename = "quantProtocolSha256")]
    quant_protocol_sha256: Option<String>,
    #[serde(rename = "quantResultPath")]
    quant_result_path: Option<String>,
    #[serde(rename = "quantResultSha256")]
    quant_result_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ArtifactKind {
    OfficialReport,
    QuantProtocol,
    QuantResult,
}

impl ArtifactKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::OfficialReport => "official_report",
            Self::QuantProtocol => "quant_protocol",
            Self::QuantResult => "quant_result",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SimulationState {
    SimulatedOnly,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    id: String,
    #[serde(rename = "claimClass")]
    class: String,
    section: String,
    #[serde(rename = "citationIds")]
    citation_ids: Vec<String>,
    #[serde(rename = "numericRunId")]
    numeric_run_id: Option<String>,
    #[serde(rename = "resultField")]
    result_field: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Citation {
    id: String,
    url: String,
    publisher: String,
    title: String,
    #[serde(rename = "publicationTime")]
    publication_time: Option<String>,
    #[serde(rename = "observationTime")]
    observation_time: Option<String>,
    #[serde(rename = "retrievalTime")]
    retrieval_time: Option<String>,
    #[serde(rename = "sourceClass")]
    source_class: String,
}

/// Validate a `PackageV1` manifest and artifacts from Forge's published input.
pub fn validate_published_input(
    input: &PublishedVerificationInput,
) -> Result<PackageVResult, PackageVValidationError> {
    let manifest_path = WorkspaceRelativePath::new(PathBuf::from(PACKAGE_V_MANIFEST_NAME))
        .map_err(|_| PackageVValidationError::InvalidRoot)?;
    let manifest = input
        .read_execution_file(&manifest_path, &NO_CANCELLATION)
        .map_err(PackageVValidationError::SnapshotRead)?;
    let manifest = bounded_manifest(manifest)?;
    let parsed = parse_manifest(&manifest)?;
    let mut files = BTreeMap::new();
    let names = declared_paths(&parsed).map_err(|()| PackageVValidationError::InvalidRoot)?;
    for path in names {
        if path == PACKAGE_V_MANIFEST_NAME {
            continue;
        }
        let relative = WorkspaceRelativePath::new(PathBuf::from(&path))
            .map_err(|_| PackageVValidationError::InvalidRoot)?;
        let bytes = input
            .read_execution_file(&relative, &NO_CANCELLATION)
            .map_err(PackageVValidationError::SnapshotRead)?;
        let _previous = files.insert(path, bytes);
    }
    validate_package_bytes(&manifest, &files)
}

/// Validate a `PackageV1` package rooted at the process's read-only snapshot.
/// The root and every declared artifact are checked with no-follow metadata.
pub fn validate_package_root(
    root: &Path,
    manifest_path: &Path,
) -> Result<PackageVResult, PackageVValidationError> {
    if manifest_path != Path::new(PACKAGE_V_MANIFEST_NAME) {
        return Err(PackageVValidationError::InvalidRoot);
    }
    let root = fs::canonicalize(root).map_err(PackageVValidationError::ManifestRead)?;
    if !root.is_dir() || root.starts_with("/Volumes/256.SSD") {
        return Err(PackageVValidationError::InvalidRoot);
    }
    let manifest_file = root.join(manifest_path);
    let manifest = read_confined_file(&root, &manifest_file, PACKAGE_V_MAX_MANIFEST_BYTES)?;
    let manifest = bounded_manifest(manifest)?;
    let parsed = parse_manifest(&manifest)?;
    let names = declared_paths(&parsed).map_err(|()| PackageVValidationError::InvalidRoot)?;
    let mut files = BTreeMap::new();
    for path in names {
        if path == PACKAGE_V_MANIFEST_NAME {
            continue;
        }
        let relative = PathBuf::from(&path);
        let file = root.join(&relative);
        let bytes = read_confined_file(&root, &file, max_file_bytes(&relative, &parsed))?;
        let _previous = files.insert(path, bytes);
    }
    validate_package_bytes(&manifest, &files)
}

fn bounded_manifest(bytes: Vec<u8>) -> Result<Vec<u8>, PackageVValidationError> {
    if bytes.len() > PACKAGE_V_MAX_MANIFEST_BYTES {
        Err(PackageVValidationError::ManifestTooLarge)
    } else {
        Ok(bytes)
    }
}

fn parse_manifest(bytes: &[u8]) -> Result<PackageManifest, PackageVValidationError> {
    let text = std::str::from_utf8(bytes).map_err(PackageVValidationError::ManifestUtf8)?;
    let value: Value = serde_json::from_str(text).map_err(PackageVValidationError::ManifestJson)?;
    let object = value
        .as_object()
        .ok_or(PackageVValidationError::InvalidRoot)?;
    let required = [
        "schemaVersion",
        "artifactKind",
        "reportPath",
        "reportSha256",
        "claimsPath",
        "claimsSha256",
        "citationsPath",
        "citationsSha256",
        "noTrade",
        "simulationState",
        "quantProtocolPath",
        "quantProtocolSha256",
        "quantResultPath",
        "quantResultSha256",
    ];
    if required.iter().any(|key| !object.contains_key(*key)) {
        return Err(PackageVValidationError::InvalidRoot);
    }
    serde_json::from_value(value).map_err(PackageVValidationError::ManifestJson)
}

fn declared_paths(manifest: &PackageManifest) -> Result<Vec<String>, ()> {
    let mut paths = BTreeSet::new();
    let mut add = |path: &str| -> Result<(), ()> {
        let normalized = normalize_relative_path(path)?;
        if !paths.insert(normalized) {
            return Err(());
        }
        Ok(())
    };
    add(PACKAGE_V_MANIFEST_NAME)?;
    add(&manifest.report_path)?;
    add(&manifest.claims_path)?;
    add(&manifest.citations_path)?;
    if let Some(path) = manifest.quant_protocol_path.as_deref() {
        add(path)?;
    }
    if let Some(path) = manifest.quant_result_path.as_deref() {
        add(path)?;
    }
    if paths.len() > PACKAGE_V_MAX_FILES {
        return Err(());
    }
    Ok(paths.into_iter().collect())
}

fn normalize_relative_path(value: &str) -> Result<String, ()> {
    if value.is_empty() || value.len() > forge_domain::MAX_VERIFICATION_INPUT_PATH_BYTES {
        return Err(());
    }
    let path = Path::new(value);
    if path.is_absolute() || value.bytes().any(|byte| byte == 0) {
        return Err(());
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or(())?;
                if part.is_empty() || part == "." || part == ".." {
                    return Err(());
                }
                components.push(part);
            }
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => return Err(()),
        }
    }
    if components.is_empty() {
        return Err(());
    }
    Ok(components.join("/"))
}

fn max_file_bytes(path: &Path, manifest: &PackageManifest) -> usize {
    if path == Path::new(&manifest.report_path) {
        usize::try_from(PACKAGE_V_MAX_REPORT_BYTES).unwrap_or(usize::MAX)
    } else {
        usize::try_from(forge_domain::MAX_VERIFICATION_INPUT_FILE_BYTES).unwrap_or(usize::MAX)
    }
}

fn read_confined_file(
    root: &Path,
    path: &Path,
    maximum: usize,
) -> Result<Vec<u8>, PackageVValidationError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| PackageVValidationError::InvalidRoot)?;
    normalize_relative_path(
        relative
            .to_str()
            .ok_or(PackageVValidationError::InvalidRoot)?,
    )
    .map_err(|()| PackageVValidationError::InvalidRoot)?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(PackageVValidationError::InvalidRoot);
        };
        current.push(part);
        let metadata =
            fs::symlink_metadata(&current).map_err(PackageVValidationError::ManifestRead)?;
        if metadata.file_type().is_symlink() {
            return Err(PackageVValidationError::InvalidRoot);
        }
        if current != path && !metadata.is_dir() {
            return Err(PackageVValidationError::InvalidRoot);
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(PackageVValidationError::ManifestRead)?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum as u64 {
        return Err(PackageVValidationError::InvalidRoot);
    }
    let file = File::open(path).map_err(PackageVValidationError::ManifestRead)?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    file.take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(PackageVValidationError::ManifestRead)?;
    if bytes.len() > maximum {
        return Err(PackageVValidationError::InvalidRoot);
    }
    Ok(bytes)
}

#[allow(clippy::too_many_lines)]
fn validate_package_bytes(
    manifest_bytes: &[u8],
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<PackageVResult, PackageVValidationError> {
    let manifest = parse_manifest(manifest_bytes)?;
    let manifest_sha256 = hex(&sha256(manifest_bytes));
    let mut errors = Vec::new();
    let mut push_error = |message: &str| {
        if errors.len() < PACKAGE_V_MAX_ERRORS {
            let mut text = message.to_owned();
            text.truncate(PACKAGE_V_MAX_ERROR_BYTES);
            errors.push(text);
        }
    };
    if manifest.schema_version != PACKAGE_V_CONTRACT_VERSION {
        push_error("schemaVersion must be 1");
    }
    if !manifest.no_trade {
        push_error("noTrade must be true");
    }
    if !matches!(manifest.simulation_state, SimulationState::SimulatedOnly) {
        push_error("simulationState must be simulated_only");
    }
    let expected_paths = declared_paths(&manifest).unwrap_or_default();
    let expected_set: BTreeSet<_> = expected_paths.iter().cloned().collect();
    if files.len() != expected_set.len().saturating_sub(1) {
        push_error("declared artifact files are incomplete");
    }
    let mut total_bytes = 0_u64;
    for (path, bytes) in files {
        if path == PACKAGE_V_MANIFEST_NAME {
            continue;
        }
        total_bytes = total_bytes.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if !expected_set.contains(path) {
            push_error("undeclared artifact file present");
        }
    }
    if total_bytes > PACKAGE_V_MAX_TOTAL_BYTES {
        push_error("declared artifact bytes exceed the PackageV bound");
    }

    let report = checked_file(
        files,
        &manifest.report_path,
        &manifest.report_sha256,
        PACKAGE_V_MAX_REPORT_BYTES,
        &mut push_error,
    );
    if let Some(report) = report.as_deref()
        && (report.is_empty() || std::str::from_utf8(report).is_err())
    {
        push_error("report must be non-empty UTF-8");
    }
    let claims = checked_file(
        files,
        &manifest.claims_path,
        &manifest.claims_sha256,
        forge_domain::MAX_VERIFICATION_INPUT_FILE_BYTES,
        &mut push_error,
    );
    let citations = checked_file(
        files,
        &manifest.citations_path,
        &manifest.citations_sha256,
        forge_domain::MAX_VERIFICATION_INPUT_FILE_BYTES,
        &mut push_error,
    );
    let (checked_claims, _claim_ids, referenced_citations) =
        parse_claims(claims.as_deref(), &mut push_error);
    let (checked_citations, citation_ids) = parse_citations(citations.as_deref(), &mut push_error);
    if referenced_citations
        .iter()
        .any(|id| !citation_ids.contains(id))
    {
        push_error("claim references an unknown citation");
    }
    if citation_ids
        .iter()
        .any(|id| !referenced_citations.contains(id))
    {
        push_error("citation is orphaned");
    }

    match manifest.artifact_kind {
        ArtifactKind::OfficialReport => {
            if manifest.quant_protocol_path.is_some()
                || manifest.quant_protocol_sha256.is_some()
                || manifest.quant_result_path.is_some()
                || manifest.quant_result_sha256.is_some()
            {
                push_error("official_report must not declare quant artifacts");
            }
        }
        ArtifactKind::QuantProtocol => {
            if manifest.quant_protocol_path.is_none() || manifest.quant_protocol_sha256.is_none() {
                push_error("quant_protocol requires a protocol artifact");
            }
            if manifest.quant_result_path.is_some() || manifest.quant_result_sha256.is_some() {
                push_error("quant_protocol must not declare a result artifact");
            }
        }
        ArtifactKind::QuantResult => {
            if manifest.quant_protocol_path.is_none()
                || manifest.quant_protocol_sha256.is_none()
                || manifest.quant_result_path.is_none()
                || manifest.quant_result_sha256.is_none()
            {
                push_error("quant_result requires protocol and result artifacts");
            }
        }
    }
    if let (Some(path), Some(hash)) = (
        manifest.quant_protocol_path.as_deref(),
        manifest.quant_protocol_sha256.as_deref(),
    ) {
        let protocol = checked_file(
            files,
            path,
            hash,
            forge_domain::MAX_VERIFICATION_INPUT_FILE_BYTES,
            &mut push_error,
        );
        validate_quant_artifact(protocol.as_deref(), &mut push_error);
    }
    if let (Some(path), Some(hash)) = (
        manifest.quant_result_path.as_deref(),
        manifest.quant_result_sha256.as_deref(),
    ) {
        let result = checked_file(
            files,
            path,
            hash,
            forge_domain::MAX_VERIFICATION_INPUT_FILE_BYTES,
            &mut push_error,
        );
        validate_quant_artifact(result.as_deref(), &mut push_error);
    }
    let valid = errors.is_empty();
    let result = PackageVResult {
        package_version: PACKAGE_V_CONTRACT_VERSION,
        valid,
        manifest_sha256,
        checked_files: expected_set.len(),
        checked_claims,
        checked_citations,
        artifact_kind: manifest.artifact_kind.as_str().to_owned(),
        no_trade: manifest.no_trade,
        errors,
    };
    if result
        .to_json_bytes()
        .map_or(true, |json| json.len() > 64 * 1024)
    {
        return Err(PackageVValidationError::ResultTooLarge);
    }
    Ok(result)
}

fn checked_file(
    files: &BTreeMap<String, Vec<u8>>,
    path: &str,
    declared_hash: &str,
    maximum: u64,
    push_error: &mut impl FnMut(&str),
) -> Option<Vec<u8>> {
    let Ok(normalized) = normalize_relative_path(path) else {
        push_error("artifact path is invalid");
        return None;
    };
    let Some(bytes) = files.get(&normalized) else {
        push_error("declared artifact is missing");
        return None;
    };
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        push_error("artifact exceeds its byte bound");
    }
    let Ok(expected) = parse_hash(declared_hash) else {
        push_error("artifact hash must be lowercase SHA-256 hex");
        return Some(bytes.clone());
    };
    if sha256(bytes) != expected {
        push_error("artifact hash does not match bytes");
    }
    Some(bytes.clone())
}

fn parse_claims(
    bytes: Option<&[u8]>,
    push_error: &mut impl FnMut(&str),
) -> (usize, BTreeSet<String>, BTreeSet<String>) {
    let Some(bytes) = bytes else {
        return (0, BTreeSet::new(), BTreeSet::new());
    };
    if bytes.len() > PACKAGE_V_MAX_TEXT_BYTES {
        push_error("claims JSON exceeds the bounded parser input");
        return (0, BTreeSet::new(), BTreeSet::new());
    }
    let Ok(claims) = serde_json::from_slice::<Vec<Claim>>(bytes) else {
        push_error("claims JSON has invalid structure");
        return (0, BTreeSet::new(), BTreeSet::new());
    };
    if claims.len() > PACKAGE_V_MAX_CLAIMS {
        push_error("claims exceed the PackageV bound");
    }
    let mut ids = BTreeSet::new();
    for claim in &claims {
        if claim.id.is_empty() || claim.id.len() > 128 || !ids.insert(claim.id.clone()) {
            push_error("claim IDs must be non-empty and unique");
        }
        if claim.class.is_empty() || claim.section.is_empty() {
            push_error("claims require class and section");
        }
        if claim.citation_ids.is_empty() {
            push_error("each claim requires at least one citation");
        }
        if claim.class.to_ascii_lowercase().contains("numeric")
            && (claim.numeric_run_id.as_deref().is_none_or(str::is_empty)
                || claim.result_field.as_deref().is_none_or(str::is_empty))
        {
            push_error("numeric claims require a run identity and result field");
        }
    }
    let referenced_citations = claims
        .iter()
        .flat_map(|claim| claim.citation_ids.iter().cloned())
        .collect();
    (claims.len(), ids, referenced_citations)
}

fn parse_citations(
    bytes: Option<&[u8]>,
    push_error: &mut impl FnMut(&str),
) -> (usize, BTreeSet<String>) {
    let Some(bytes) = bytes else {
        return (0, BTreeSet::new());
    };
    if bytes.len() > PACKAGE_V_MAX_TEXT_BYTES {
        push_error("citations JSON exceeds the bounded parser input");
        return (0, BTreeSet::new());
    }
    let Ok(citations) = serde_json::from_slice::<Vec<Citation>>(bytes) else {
        push_error("citations JSON has invalid structure");
        return (0, BTreeSet::new());
    };
    if citations.len() > PACKAGE_V_MAX_CITATIONS {
        push_error("citations exceed the PackageV bound");
    }
    let mut ids = BTreeSet::new();
    for citation in &citations {
        if citation.id.is_empty() || citation.id.len() > 128 || !ids.insert(citation.id.clone()) {
            push_error("citation IDs must be non-empty and unique");
        }
        if !valid_https_url(&citation.url) || citation.url.len() > PACKAGE_V_MAX_URL_BYTES {
            push_error("citations require bounded canonical HTTPS URLs");
        }
        if citation.publisher.is_empty()
            || citation.title.is_empty()
            || citation.source_class.is_empty()
            || [
                citation.publication_time.as_deref(),
                citation.observation_time.as_deref(),
                citation.retrieval_time.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|value| value.len() > PACKAGE_V_MAX_TEXT_BYTES)
        {
            push_error("citation metadata is empty or exceeds its bound");
        }
    }
    (citations.len(), ids)
}

fn validate_quant_artifact(bytes: Option<&[u8]>, push_error: &mut impl FnMut(&str)) {
    let Some(bytes) = bytes else { return };
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        push_error("quant artifact must be valid JSON");
        return;
    };
    let Some(object) = value.as_object() else {
        push_error("quant artifact must be a JSON object");
        return;
    };
    if object
        .get("noTrade")
        .is_some_and(|value| value != &Value::Bool(true))
    {
        push_error("quant artifact noTrade must be true");
    }
}

fn valid_https_url(value: &str) -> bool {
    value.starts_with("https://")
        && !value[8..].is_empty()
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn parse_hash(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(());
    }
    let mut bytes = [0_u8; 32];
    let (chunks, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(());
    }
    for (index, chunk) in chunks.iter().enumerate() {
        bytes[index] = (hex_value(chunk[0])? << 4) | hex_value(chunk[1])?;
    }
    Ok(bytes)
}

fn hex_value(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    fn fixture_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
        let unique = format!(
            "{}-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
            Uuid::now_v7()
        );
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            PathBuf::from("/tmp")
        };
        let root = base.join(format!("forge-package-v-{unique}"));
        fs::create_dir_all(&root)?;
        Ok(root)
    }

    fn sha_text(value: &str) -> String {
        hex(&sha256(value.as_bytes()))
    }

    fn write_official(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let report = "# Report\nConclusion, uncertainty, and limitations.\n";
        let claims = r#"[{"id":"claim-1","claimClass":"qualitative","section":"Conclusion","citationIds":["citation-1"]}]"#;
        let citations = r#"[{"id":"citation-1","url":"https://example.com/source","publisher":"Example","title":"Source","publicationTime":null,"observationTime":null,"retrievalTime":null,"sourceClass":"primary"}]"#;
        fs::write(root.join("report.md"), report)?;
        fs::write(root.join("claims.json"), claims)?;
        fs::write(root.join("citations.json"), citations)?;
        let manifest = format!(
            "{{\"schemaVersion\":1,\"artifactKind\":\"official_report\",\"reportPath\":\"report.md\",\"reportSha256\":\"{}\",\"claimsPath\":\"claims.json\",\"claimsSha256\":\"{}\",\"citationsPath\":\"citations.json\",\"citationsSha256\":\"{}\",\"noTrade\":true,\"simulationState\":\"simulated_only\",\"quantProtocolPath\":null,\"quantProtocolSha256\":null,\"quantResultPath\":null,\"quantResultSha256\":null}}",
            sha_text(report),
            sha_text(claims),
            sha_text(citations),
        );
        fs::write(root.join(PACKAGE_V_MANIFEST_NAME), manifest)?;
        Ok(())
    }

    #[test]
    fn valid_official_report_is_structurally_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root()?;
        write_official(&root)?;
        let result = validate_package_root(&root, Path::new(PACKAGE_V_MANIFEST_NAME))?;
        assert!(result.valid());
        assert_eq!(result.checked_files, 4);
        assert_eq!(result.checked_claims, 1);
        assert_eq!(result.checked_citations, 1);
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn tampered_artifact_and_path_escape_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root()?;
        write_official(&root)?;
        fs::write(root.join("report.md"), "tampered")?;
        let result = validate_package_root(&root, Path::new(PACKAGE_V_MANIFEST_NAME))?;
        assert!(!result.valid());
        let manifest = fs::read_to_string(root.join(PACKAGE_V_MANIFEST_NAME))?
            .replace("report.md", "../report.md");
        fs::write(root.join(PACKAGE_V_MANIFEST_NAME), manifest)?;
        assert!(validate_package_root(&root, Path::new(PACKAGE_V_MANIFEST_NAME)).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn symlink_and_report_bound_are_rejected_before_hash_acceptance()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let root = fixture_root()?;
        write_official(&root)?;
        let outside = root
            .parent()
            .ok_or("fixture parent missing")?
            .join(format!("package-v-outside-{}", Uuid::now_v7()));
        fs::write(&outside, b"outside")?;
        fs::remove_file(root.join("report.md"))?;
        symlink(&outside, root.join("report.md"))?;
        assert!(validate_package_root(&root, Path::new(PACKAGE_V_MANIFEST_NAME)).is_err());
        fs::remove_file(root.join("report.md"))?;
        fs::write(
            root.join("report.md"),
            vec![b'x'; usize::try_from(PACKAGE_V_MAX_REPORT_BYTES).unwrap_or(usize::MAX) + 1],
        )?;
        assert!(validate_package_root(&root, Path::new(PACKAGE_V_MANIFEST_NAME)).is_err());
        fs::remove_file(&outside)?;
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn executable_capability_rejects_non_executable_and_external_storage()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = fixture_root()?;
        let file = root.join("backend");
        fs::write(&file, b"backend")?;
        let mut permissions = fs::metadata(&file)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&file, permissions)?;
        let capability = PackageVExecutableCapability::prepare_at(&file)?;
        capability.revalidate()?;
        fs::write(&file, b"changed")?;
        assert!(matches!(
            capability.revalidate(),
            Err(PackageVExecutableError::ExecutableChanged)
        ));
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
