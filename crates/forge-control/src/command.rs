use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::AtomicBool;

use forge_domain::{
    ActivityId, ExecutionArgument, ExecutionAttribution, ExecutionId, ExecutionKind,
    ExecutionLimits, ExecutionOutputLimit, ExecutionPermissions, ExecutionProgram,
    ExecutionRequest, ExecutionRequestDigest, ExecutionTimeoutMillis, FileContentHash,
    ProjectCommandCatalogFingerprint, ProjectCommandClass, VerificationInputId,
    WorkspaceRelativePath,
};
use forge_execution::{
    PACKAGE_V_COMMAND_ID, PACKAGE_V_MANIFEST_NAME, PACKAGE_V_SUBCOMMAND,
    PackageVExecutableCapability, PackageVExecutableError,
};
use forge_workspace::{
    MAX_FILE_READ_BYTES, PublishedVerificationInput, VerificationInputError,
    WorkspaceStateGateError,
};
use thiserror::Error;

use crate::error::{ControlError, ControlErrorCode};
use crate::filesystem::{FileActivityScope, FileReadRequest};
use crate::service::{ForgeControl, ResolvedWorkspaceScope};

/// Maximum encoded size of a project command identity.
pub const MAX_PROJECT_COMMAND_ID_BYTES: usize = 128;

pub(crate) const RUST_CI_PROGRAM: &str = "/Library/Developer/CommandLineTools/usr/bin/make";
const PROJECT_COMMAND_TIMEOUT_MILLIS: u64 = 10 * 60 * 1_000;
const PACKAGE_V_TIMEOUT_MILLIS: u64 = 5 * 60 * 1_000;
const PACKAGE_V_OUTPUT_LIMIT: u64 = 64 * 1024;

/// Make targets that are safe to expose as bounded verification commands.
///
/// The list is intentionally server-owned. A caller can select one of these
/// exact identities after discovery, but cannot provide a program, shell
/// string, arguments, timeout, or permissions of its own.
pub(crate) const VERIFY_MAKE_TARGETS: &[&str] = &["ci", "rules", "check", "test", "doctor"];
/// The initial generated-output lane has exactly one sealed target.
pub(crate) const GENERATED_MAKE_TARGETS: &[&str] = &["package"];
const CATALOG_FINGERPRINT_DOMAIN: &[u8] = b"heterarchy-forge.project-command-catalog.v1\0";

/// Validated identity of a discovered project command.
///
/// IDs are compared byte-for-byte.  They are never trimmed or normalized, so
/// a caller cannot turn a different string into an existing command by
/// relying on whitespace handling at another boundary.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProjectCommandId(String);

impl ProjectCommandId {
    pub fn new(value: impl Into<String>) -> Result<Self, ProjectCommandIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ProjectCommandIdError::Empty);
        }
        if value.len() > MAX_PROJECT_COMMAND_ID_BYTES {
            return Err(ProjectCommandIdError::TooLong {
                actual: value.len(),
                maximum: MAX_PROJECT_COMMAND_ID_BYTES,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(ProjectCommandIdError::ControlCharacter);
        }
        if value.chars().any(char::is_whitespace) {
            return Err(ProjectCommandIdError::Whitespace);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b':' | b'-')
        }) {
            return Err(ProjectCommandIdError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProjectCommandId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl AsRef<str> for ProjectCommandId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for ProjectCommandId {
    type Err = ProjectCommandIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ProjectCommandId {
    type Error = ProjectCommandIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for ProjectCommandId {
    type Error = ProjectCommandIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ProjectCommandIdError {
    #[error("project command id must not be empty")]
    Empty,
    #[error("project command id has {actual} bytes; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
    #[error("project command id must not contain control characters")]
    ControlCharacter,
    #[error("project command id must not contain whitespace")]
    Whitespace,
    #[error("project command id contains a character outside [a-z0-9:-]")]
    InvalidCharacter,
}

/// One bounded, structured project command discovered from trusted workspace
/// metadata. The command is represented as argv and never as a shell string.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredProjectCommand {
    id: ProjectCommandId,
    program: String,
    args: Vec<String>,
    class: ProjectCommandClass,
}

impl DiscoveredProjectCommand {
    fn make_verify(target: &str) -> Result<Self, ProjectCommandIdError> {
        Ok(Self {
            id: ProjectCommandId::new(format!("make:{target}"))?,
            program: RUST_CI_PROGRAM.to_owned(),
            args: vec![target.to_owned()],
            class: ProjectCommandClass::Verify,
        })
    }

    fn make_generated_package() -> Result<Self, ProjectCommandIdError> {
        Ok(Self {
            id: ProjectCommandId::new("make:package")?,
            program: RUST_CI_PROGRAM.to_owned(),
            args: vec!["package".to_owned()],
            class: ProjectCommandClass::GeneratedPackage,
        })
    }

    fn research_package(
        capability: &PackageVExecutableCapability,
    ) -> Result<Self, ProjectCommandIdError> {
        Ok(Self {
            id: ProjectCommandId::new(PACKAGE_V_COMMAND_ID)?,
            program: capability.path().to_string_lossy().into_owned(),
            args: vec![
                PACKAGE_V_SUBCOMMAND.to_owned(),
                PACKAGE_V_MANIFEST_NAME.to_owned(),
            ],
            class: ProjectCommandClass::Verify,
        })
    }

    pub fn id(&self) -> &ProjectCommandId {
        &self.id
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub const fn class(&self) -> ProjectCommandClass {
        self.class
    }
}

/// Activity-attributed request for project command discovery.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCommandListRequest {
    pub scope: ResolvedWorkspaceScope,
    pub activity: FileActivityScope,
}

/// Confined command discovery result.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectCommandListResult {
    scope: ResolvedWorkspaceScope,
    activity_id: ActivityId,
    commands: Vec<DiscoveredProjectCommand>,
    fingerprint: ProjectCommandCatalogFingerprint,
}

/// One exact command resolved from a freshly verified catalog snapshot.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProjectCommandExecution {
    request: ExecutionRequest,
    class: ProjectCommandClass,
    fingerprint: ProjectCommandCatalogFingerprint,
}

/// Exact command plus the immutable source tree from which it was resolved.
#[must_use]
#[derive(Debug)]
pub(crate) struct PreparedProjectCommandVerification {
    execution: ResolvedProjectCommandExecution,
    input: PublishedVerificationInput,
}

impl PreparedProjectCommandVerification {
    pub(crate) fn into_parts(
        self,
    ) -> (ResolvedProjectCommandExecution, PublishedVerificationInput) {
        (self.execution, self.input)
    }
}

impl ResolvedProjectCommandExecution {
    pub const fn request(&self) -> &ExecutionRequest {
        &self.request
    }

    pub const fn class(&self) -> ProjectCommandClass {
        self.class
    }

    pub const fn fingerprint(&self) -> ProjectCommandCatalogFingerprint {
        self.fingerprint
    }

    pub fn into_request(self) -> ExecutionRequest {
        self.request
    }
}

impl ProjectCommandListResult {
    /// Parse one already-confined Makefile snapshot with the same command and
    /// fingerprint authority used by live discovery.
    fn from_makefile_bytes_with_capability(
        scope: ResolvedWorkspaceScope,
        activity_id: ActivityId,
        bytes: &[u8],
        capability: &PackageVExecutableCapability,
    ) -> Result<Self, ControlError> {
        let makefile = std::str::from_utf8(bytes)
            .map_err(|error| ControlError::with_source(ControlErrorCode::InvalidInput, error))?;
        let commands = discover_make_commands_with_capability(makefile, capability)?;
        let fingerprint = catalog_fingerprint_with_capability(bytes, &commands, capability);
        Ok(Self {
            scope,
            activity_id,
            commands,
            fingerprint,
        })
    }

    pub const fn scope(&self) -> &ResolvedWorkspaceScope {
        &self.scope
    }

    pub const fn activity_id(&self) -> ActivityId {
        self.activity_id
    }

    pub fn commands(&self) -> &[DiscoveredProjectCommand] {
        &self.commands
    }

    pub const fn fingerprint(&self) -> ProjectCommandCatalogFingerprint {
        self.fingerprint
    }

    /// Calculate the stable descriptor digest before an Execution UUID or
    /// Agent/Goal attribution exists.  The request digest intentionally covers
    /// only the server-owned program, argv, cwd, limits and permissions.
    pub fn request_digest(
        &self,
        command_id: &ProjectCommandId,
    ) -> Result<ExecutionRequestDigest, ControlError> {
        let request =
            self.resolve_execution(command_id, ExecutionId::from_uuid(uuid::Uuid::nil()))?;
        Ok(forge_execution::execution_request_digest(request.request()))
    }

    /// Resolve only an identity returned by this exact discovery snapshot.
    /// Unknown IDs, including otherwise well-formed arbitrary IDs, are
    /// rejected before any process request can be built.
    pub fn resolve(
        &self,
        command_id: &ProjectCommandId,
    ) -> Result<&DiscoveredProjectCommand, ControlError> {
        self.commands
            .iter()
            .find(|command| command.id() == command_id)
            .ok_or_else(|| ControlError::new(ControlErrorCode::InvalidInput))
    }

    /// Convert an exact discovered command to the server-owned structured
    /// execution request.  The caller supplies only the execution identity;
    /// program, argv, cwd, limits, and permissions are fixed here.
    pub fn to_execution_request(
        &self,
        command_id: &ProjectCommandId,
        execution_id: ExecutionId,
    ) -> Result<ExecutionRequest, ControlError> {
        Ok(self
            .resolve_execution(command_id, execution_id)?
            .into_request())
    }

    pub fn resolve_execution(
        &self,
        command_id: &ProjectCommandId,
        execution_id: ExecutionId,
    ) -> Result<ResolvedProjectCommandExecution, ControlError> {
        let command = self.resolve(command_id)?;
        let program = ExecutionProgram::new(PathBuf::from(command.program()))
            .map_err(|source| ControlError::with_source(ControlErrorCode::Internal, source))?;
        let arguments = command
            .args()
            .iter()
            .cloned()
            .map(|argument| {
                ExecutionArgument::new(OsString::from(argument))
                    .map_err(|source| ControlError::with_source(ControlErrorCode::Internal, source))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let timeout_millis = if command.id().as_str() == PACKAGE_V_COMMAND_ID {
            PACKAGE_V_TIMEOUT_MILLIS
        } else {
            PROJECT_COMMAND_TIMEOUT_MILLIS
        };
        let timeout = ExecutionTimeoutMillis::new(timeout_millis)
            .map_err(|source| ControlError::with_source(ControlErrorCode::Internal, source))?;
        let output_limit = if command.id().as_str() == PACKAGE_V_COMMAND_ID {
            ExecutionOutputLimit::new(PACKAGE_V_OUTPUT_LIMIT)
                .map_err(|source| ControlError::with_source(ControlErrorCode::Internal, source))?
        } else {
            ExecutionOutputLimit::DEFAULT
        };
        let limits = ExecutionLimits::new(timeout, output_limit);
        let request = ExecutionRequest::new(
            ExecutionAttribution::new(execution_id, self.scope.workspace_id(), self.activity_id),
            ExecutionKind::Structured { program, arguments },
            None,
            limits,
            ExecutionPermissions::new(true, false, false),
        )
        .map_err(|source| ControlError::with_source(ControlErrorCode::Internal, source))?;
        Ok(ResolvedProjectCommandExecution {
            request,
            class: command.class(),
            fingerprint: self.fingerprint,
        })
    }

    pub fn matches_fingerprint(&self, expected: ProjectCommandCatalogFingerprint) -> bool {
        self.fingerprint == expected
    }
}

impl ForgeControl {
    /// Discover structured verification commands from the root Makefile using
    /// the existing confined file-read authority path.
    pub fn project_command_list(
        &self,
        request: &ProjectCommandListRequest,
    ) -> Result<ProjectCommandListResult, ControlError> {
        let path = WorkspaceRelativePath::new(PathBuf::from("Makefile"))
            .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
        let capability = PackageVExecutableCapability::prepare_current()
            .map_err(map_package_v_executable_error)?;
        let bytes = match self.file_read(&FileReadRequest {
            scope: request.scope.clone(),
            activity: request.activity,
            path,
        }) {
            Ok(read) => read.read().content().to_vec(),
            Err(error) if error.code() == ControlErrorCode::FileNotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        ProjectCommandListResult::from_makefile_bytes_with_capability(
            request.scope.clone(),
            request.activity.activity_id,
            &bytes,
            &capability,
        )
    }

    /// Re-read and resolve one exact command identity before creating its
    /// structured execution request.  This keeps command discovery and
    /// process authority on the server side instead of trusting a stale or
    /// caller-constructed descriptor.
    pub fn project_command_execution_request(
        &self,
        request: &ProjectCommandListRequest,
        command_id: &ProjectCommandId,
        execution_id: ExecutionId,
    ) -> Result<ExecutionRequest, ControlError> {
        self.project_command_list(request)?
            .to_execution_request(command_id, execution_id)
    }

    /// Re-discover a command and require the exact catalog snapshot observed
    /// by the caller. This is the stale fence for server-owned descriptors;
    /// it does not accept caller-supplied argv or an output root.
    pub fn project_command_execution_request_fenced(
        &self,
        request: &ProjectCommandListRequest,
        command_id: &ProjectCommandId,
        expected_fingerprint: ProjectCommandCatalogFingerprint,
        execution_id: ExecutionId,
    ) -> Result<ResolvedProjectCommandExecution, ControlError> {
        let snapshot = self.project_command_list(request)?;
        if !snapshot.matches_fingerprint(expected_fingerprint) {
            return Err(ControlError::new(ControlErrorCode::CommandCatalogChanged));
        }
        snapshot.resolve_execution(command_id, execution_id)
    }

    /// Freeze the current project source, then resolve the command only from
    /// the snapshot's Makefile. Publication happens before durable admission;
    /// a later admission failure preserves the orphan for explicit recovery.
    pub(crate) fn prepare_project_command_verification(
        &self,
        request: &ProjectCommandListRequest,
        command_id: &ProjectCommandId,
        expected_fingerprint: ProjectCommandCatalogFingerprint,
        execution_id: ExecutionId,
        cancellation: &AtomicBool,
    ) -> Result<PreparedProjectCommandVerification, ControlError> {
        let input_id = VerificationInputId::from_uuid(execution_id.into_uuid());
        let published = self.prepare_workspace_verification_input(
            &request.scope,
            request.activity,
            input_id,
            cancellation,
        )?;
        let makefile_path = WorkspaceRelativePath::new(PathBuf::from("Makefile"))
            .map_err(|error| ControlError::with_source(ControlErrorCode::Internal, error))?;
        let capability = PackageVExecutableCapability::prepare_current()
            .map_err(map_package_v_executable_error)?;
        let makefile = match published.read_file(&makefile_path, MAX_FILE_READ_BYTES, cancellation)
        {
            Ok(bytes) => bytes,
            Err(VerificationInputError::FileUnavailable) => Vec::new(),
            Err(error) => return Err(map_verification_input_error(error)),
        };
        let snapshot = ProjectCommandListResult::from_makefile_bytes_with_capability(
            request.scope.clone(),
            request.activity.activity_id,
            &makefile,
            &capability,
        )?;
        if !snapshot.matches_fingerprint(expected_fingerprint) {
            return Err(ControlError::new(ControlErrorCode::CommandCatalogChanged));
        }
        let execution = snapshot.resolve_execution(command_id, execution_id)?;
        Ok(PreparedProjectCommandVerification {
            execution,
            input: published,
        })
    }

    pub(crate) fn prepare_workspace_verification_input(
        &self,
        expected_scope: &crate::ResolvedWorkspaceScope,
        activity: crate::FileActivityScope,
        input_id: VerificationInputId,
        cancellation: &AtomicBool,
    ) -> Result<PublishedVerificationInput, ControlError> {
        let (scope, layout, store) = self.open_effect_workspace(expected_scope)?;
        self.ensure_non_overlapping_effect_scope(&scope, layout.workspace_root())?;
        crate::filesystem::authorize_activity(&store, activity)?;
        let filesystem = forge_workspace::ConfinedWorkspace::open(&layout)
            .map_err(crate::filesystem::map_filesystem_error)?;
        let staged = filesystem
            .stage_verification_input(input_id, cancellation)
            .map_err(map_verification_input_error)?;
        let published = staged.publish().map_err(map_verification_input_error)?;
        crate::filesystem::authorize_activity(&store, activity)?;
        if !self.committed_scope_matches_with_store(&scope, &store) {
            return Err(ControlError::new(ControlErrorCode::WorkspaceRootConflict));
        }
        Ok(published)
    }
}

fn map_verification_input_error(error: VerificationInputError) -> ControlError {
    let code = match error {
        VerificationInputError::Cancelled => ControlErrorCode::RequestCancelled,
        VerificationInputError::Manifest(
            forge_domain::VerificationInputManifestError::EntryCapacity
            | forge_domain::VerificationInputManifestError::FileCapacity
            | forge_domain::VerificationInputManifestError::ByteCapacity
            | forge_domain::VerificationInputManifestError::PathCapacity,
        )
        | VerificationInputError::ManifestTooLarge { .. }
        | VerificationInputError::ScanLimitExceeded { .. } => ControlErrorCode::CapacityExceeded,
        VerificationInputError::Filesystem(error) => {
            return crate::filesystem::map_filesystem_error(error);
        }
        VerificationInputError::SnapshotStale => ControlErrorCode::WorkspaceRevisionConflict,
        VerificationInputError::Collision
        | VerificationInputError::SnapshotInvalid
        | VerificationInputError::NotFound
        | VerificationInputError::FingerprintMismatch
        | VerificationInputError::AtomicPublishUnsupported
        | VerificationInputError::CleanupFailed => ControlErrorCode::ExecutionConflict,
        VerificationInputError::StateGate(source) => {
            let code = match &source {
                WorkspaceStateGateError::Busy => ControlErrorCode::ExecutionConflict,
                WorkspaceStateGateError::OpenRoot { .. }
                | WorkspaceStateGateError::InspectRoot { .. }
                | WorkspaceStateGateError::InspectRootPath { .. }
                | WorkspaceStateGateError::CanonicalizeRoot { .. }
                | WorkspaceStateGateError::RootSymlink(_)
                | WorkspaceStateGateError::RootNotDirectory(_)
                | WorkspaceStateGateError::RootFingerprintChanged
                | WorkspaceStateGateError::RootPathChanged { .. }
                | WorkspaceStateGateError::GuardScopeMismatch => {
                    ControlErrorCode::WorkspaceRootConflict
                }
                WorkspaceStateGateError::Lock { .. } => ControlErrorCode::PersistenceFailure,
            };
            return ControlError::with_source(code, source);
        }
        VerificationInputError::Manifest(_)
        | VerificationInputError::ManifestMalformed
        | VerificationInputError::FileUnavailable
        | VerificationInputError::ReadTooLarge { .. }
        | VerificationInputError::InvalidPath => ControlErrorCode::Internal,
    };
    ControlError::with_source(code, error)
}

fn map_package_v_executable_error(error: PackageVExecutableError) -> ControlError {
    ControlError::with_source(ControlErrorCode::ExecutionConflict, error)
}

#[cfg(test)]
fn discover_make_commands(makefile: &str) -> Result<Vec<DiscoveredProjectCommand>, ControlError> {
    let capability =
        PackageVExecutableCapability::prepare_current().map_err(map_package_v_executable_error)?;
    discover_make_commands_with_capability(makefile, &capability)
}

fn discover_make_commands_with_capability(
    makefile: &str,
    capability: &PackageVExecutableCapability,
) -> Result<Vec<DiscoveredProjectCommand>, ControlError> {
    let mut commands = VERIFY_MAKE_TARGETS
        .iter()
        .copied()
        .filter(|target| has_make_target(makefile, target))
        .map(DiscoveredProjectCommand::make_verify)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ControlError::with_source(ControlErrorCode::Internal, source))?;
    if GENERATED_MAKE_TARGETS
        .iter()
        .copied()
        .any(|target| has_make_target(makefile, target))
    {
        commands.push(
            DiscoveredProjectCommand::make_generated_package()
                .map_err(|source| ControlError::with_source(ControlErrorCode::Internal, source))?,
        );
    }
    commands.push(
        DiscoveredProjectCommand::research_package(capability)
            .map_err(|source| ControlError::with_source(ControlErrorCode::Internal, source))?,
    );
    Ok(commands)
}

#[cfg(test)]
fn catalog_fingerprint(
    makefile: &[u8],
    commands: &[DiscoveredProjectCommand],
) -> ProjectCommandCatalogFingerprint {
    catalog_fingerprint_inner(makefile, commands, None)
}

fn catalog_fingerprint_with_capability(
    makefile: &[u8],
    commands: &[DiscoveredProjectCommand],
    capability: &PackageVExecutableCapability,
) -> ProjectCommandCatalogFingerprint {
    catalog_fingerprint_inner(makefile, commands, Some(capability))
}

fn catalog_fingerprint_inner(
    makefile: &[u8],
    commands: &[DiscoveredProjectCommand],
    capability: Option<&PackageVExecutableCapability>,
) -> ProjectCommandCatalogFingerprint {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, b"domain", CATALOG_FINGERPRINT_DOMAIN);
    hash_field(&mut hasher, b"makefile", makefile);
    if let Some(capability) = capability {
        hash_field(
            &mut hasher,
            b"package-v-capability",
            &capability.catalog_bytes(),
        );
    }
    hash_field(
        &mut hasher,
        b"command-count",
        &u64::try_from(commands.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for command in commands {
        hash_field(&mut hasher, b"id", command.id().as_str().as_bytes());
        hash_field(&mut hasher, b"program", command.program().as_bytes());
        hash_field(
            &mut hasher,
            b"class",
            match command.class() {
                ProjectCommandClass::Verify => b"verify",
                ProjectCommandClass::GeneratedPackage => b"generated-package",
            },
        );
        hash_field(
            &mut hasher,
            b"argument-count",
            &u64::try_from(command.args().len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        for argument in command.args() {
            hash_field(&mut hasher, b"argument", argument.as_bytes());
        }
    }
    ProjectCommandCatalogFingerprint::from_hash(FileContentHash::from_bytes(
        *hasher.finalize().as_bytes(),
    ))
}

fn hash_field(hasher: &mut blake3::Hasher, label: &[u8], value: &[u8]) {
    hasher.update(&u64::try_from(label.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(label);
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}

pub(crate) fn is_exact_rust_verify_request(command_id: &str, request: &ExecutionRequest) -> bool {
    let Some(target) = command_id.strip_prefix("make:") else {
        return false;
    };
    if !VERIFY_MAKE_TARGETS.contains(&target)
        || request.permissions() != ExecutionPermissions::new(true, false, false)
        || request.cwd().is_some()
    {
        return false;
    }
    let ExecutionKind::Structured { program, arguments } = request.kind() else {
        return false;
    };
    program.as_path() == Path::new(RUST_CI_PROGRAM)
        && arguments.len() == 1
        && arguments[0].as_os_str() == OsStr::new(target)
}

pub(crate) fn is_exact_research_package_request(
    command_id: &str,
    request: &ExecutionRequest,
) -> bool {
    if command_id != PACKAGE_V_COMMAND_ID
        || request.permissions() != ExecutionPermissions::new(true, false, false)
        || request.cwd().is_some()
    {
        return false;
    }
    let ExecutionKind::Structured { program, arguments } = request.kind() else {
        return false;
    };
    let Ok(capability) = PackageVExecutableCapability::prepare_current() else {
        return false;
    };
    program.as_path() == capability.path()
        && arguments.len() == 2
        && arguments[0].as_os_str() == OsStr::new(PACKAGE_V_SUBCOMMAND)
        && arguments[1].as_os_str() == OsStr::new(PACKAGE_V_MANIFEST_NAME)
}

pub(crate) fn is_exact_project_verify_request(
    command_id: &str,
    request: &ExecutionRequest,
) -> bool {
    is_exact_rust_verify_request(command_id, request)
        || is_exact_research_package_request(command_id, request)
}

pub(crate) fn is_exact_rust_generated_package_request(
    command_id: &str,
    request: &ExecutionRequest,
) -> bool {
    command_id == "make:package"
        && request.permissions() == ExecutionPermissions::new(true, false, false)
        && request.cwd().is_none()
        && matches!(
            request.kind(),
            ExecutionKind::Structured { program, arguments }
                if program.as_path() == Path::new(RUST_CI_PROGRAM)
                    && arguments.len() == 1
                    && arguments[0].as_os_str() == OsStr::new("package")
        )
}

/// Return whether a Makefile contains an exact, unindented root rule for the
/// requested target.  Assignments, comments, recipes, prefixes, and target
/// names containing the requested text are not treated as rules.
fn has_make_target(makefile: &str, target: &str) -> bool {
    makefile.lines().any(|line| {
        let line = strip_make_comment(line);
        if line.is_empty() || line.chars().next().is_some_and(char::is_whitespace) {
            return false;
        }
        let Some(colon) = line.find(':') else {
            return false;
        };
        line[..colon]
            .split_whitespace()
            .any(|candidate| candidate == target)
    })
}

fn strip_make_comment(line: &str) -> &str {
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if character == '#' && !escaped {
            return &line[..index];
        }
        if character == '\\' {
            escaped = !escaped;
        } else {
            escaped = false;
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use forge_domain::{
        ActivityId, ExecutionId, ExecutionKind, LocationId, LocationRevision, ProjectCommandClass,
        WorkspaceId, WorkspaceRevision,
    };
    use forge_workspace::{VerificationInputError, WorkspaceLocator, WorkspaceStateGateError};
    use uuid::Uuid;

    use super::{
        DiscoveredProjectCommand, MAX_PROJECT_COMMAND_ID_BYTES, PACKAGE_V_COMMAND_ID,
        ProjectCommandId, ProjectCommandIdError, ProjectCommandListResult, RUST_CI_PROGRAM,
        catalog_fingerprint, discover_make_commands, has_make_target,
        is_exact_research_package_request, is_exact_rust_generated_package_request,
        is_exact_rust_verify_request, map_verification_input_error,
    };
    use crate::error::{ControlError, ControlErrorCode};
    use crate::service::ResolvedWorkspaceScope;
    use forge_execution::PackageVExecutableCapability;

    fn id(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn command_snapshot() -> Result<ProjectCommandListResult, Box<dyn std::error::Error>> {
        let locator = WorkspaceLocator::new(
            LocationId::from_uuid(id(1)),
            LocationRevision::INITIAL,
            Path::new("workspace"),
        )?;
        let scope = ResolvedWorkspaceScope::from_observation(
            WorkspaceId::from_uuid(id(2)),
            WorkspaceRevision::INITIAL,
            locator,
        );
        let commands = vec![DiscoveredProjectCommand::make_verify("ci")?];
        Ok(ProjectCommandListResult {
            scope,
            activity_id: ActivityId::from_uuid(id(3)),
            fingerprint: catalog_fingerprint(b"ci:\n", &commands),
            commands,
        })
    }

    #[test]
    fn verification_state_gate_errors_preserve_control_family() {
        let cases = [
            (
                WorkspaceStateGateError::Busy,
                ControlErrorCode::ExecutionConflict,
            ),
            (
                WorkspaceStateGateError::RootFingerprintChanged,
                ControlErrorCode::WorkspaceRootConflict,
            ),
            (
                WorkspaceStateGateError::GuardScopeMismatch,
                ControlErrorCode::WorkspaceRootConflict,
            ),
        ];
        for (source, expected) in cases {
            let error = map_verification_input_error(VerificationInputError::StateGate(source));
            assert_eq!(error.code(), expected);
        }
    }

    #[test]
    fn project_command_id_rejects_ambiguous_text_and_bounds_bytes() {
        assert_eq!(
            ProjectCommandId::new("").err(),
            Some(ProjectCommandIdError::Empty)
        );
        assert_eq!(
            ProjectCommandId::new("make: ci").err(),
            Some(ProjectCommandIdError::Whitespace)
        );
        assert_eq!(
            ProjectCommandId::new("make:ci\n").err(),
            Some(ProjectCommandIdError::ControlCharacter)
        );
        assert_eq!(
            ProjectCommandId::new("make:CI").err(),
            Some(ProjectCommandIdError::InvalidCharacter)
        );
        assert_eq!(
            ProjectCommandId::new("x".repeat(MAX_PROJECT_COMMAND_ID_BYTES + 1)).err(),
            Some(ProjectCommandIdError::TooLong {
                actual: MAX_PROJECT_COMMAND_ID_BYTES + 1,
                maximum: MAX_PROJECT_COMMAND_ID_BYTES,
            })
        );
    }

    #[test]
    fn make_target_discovery_requires_exact_root_rule_prefix() {
        let makefile = "ci:\n\t@echo ok\nclean:\n\trm -rf target\n  test:\nci-extra:\n\t@echo no\nci := not-a-rule\n# ci: comment\n";
        assert!(has_make_target(makefile, "ci"));
        assert!(has_make_target(makefile, "clean"));
        assert!(!has_make_target(makefile, "test"));
        assert!(has_make_target(makefile, "ci-extra"));
        assert!(!has_make_target(makefile, "ci-ex"));
        assert!(!has_make_target(makefile, "c"));
    }

    #[test]
    fn command_discovery_partitions_verification_and_generated_package_targets()
    -> Result<(), Box<dyn std::error::Error>> {
        let makefile = "ci:\n\t@echo ci\nrules:\n\t@echo rules\ncheck:\n\t@echo check\ntest:\n\t@echo test\ndoctor:\n\t@echo doctor\npackage:\n\tcargo xtask package\nfmt:\n\tcargo fmt\nclean:\n\tcargo clean\n";
        let commands = discover_make_commands(makefile)?;
        let ids: Vec<_> = commands
            .iter()
            .map(|command| command.id().as_str())
            .collect();
        assert_eq!(
            ids,
            vec![
                "make:ci",
                "make:rules",
                "make:check",
                "make:test",
                "make:doctor",
                "make:package",
                PACKAGE_V_COMMAND_ID,
            ]
        );
        assert!(!ids.contains(&"make:fmt"));
        assert!(!ids.contains(&"make:clean"));
        assert!(matches!(
            commands
                .iter()
                .find(|command| command.id().as_str() == "make:package")
                .map(DiscoveredProjectCommand::class),
            Some(ProjectCommandClass::GeneratedPackage)
        ));
        assert!(matches!(
            commands.last().map(DiscoveredProjectCommand::class),
            Some(ProjectCommandClass::Verify)
        ));
        Ok(())
    }

    #[test]
    fn package_request_is_exact_and_catalog_fingerprint_fences_staleness()
    -> Result<(), Box<dyn std::error::Error>> {
        let commands = discover_make_commands("package:\n\tcargo xtask package\n")?;
        let fingerprint = catalog_fingerprint(b"package:\n\tcargo xtask package\n", &commands);
        let changed = catalog_fingerprint(b"package:\n\t@false\n", &commands);
        assert_ne!(fingerprint, changed);

        let mut snapshot = command_snapshot()?;
        snapshot.commands = commands;
        snapshot.fingerprint = fingerprint;
        let request = snapshot.to_execution_request(
            &ProjectCommandId::new("make:package")?,
            ExecutionId::from_uuid(id(6)),
        )?;
        assert!(is_exact_rust_generated_package_request(
            "make:package",
            &request
        ));
        assert!(!is_exact_rust_generated_package_request(
            "make:ci", &request
        ));
        assert!(snapshot.matches_fingerprint(fingerprint));
        assert!(!snapshot.matches_fingerprint(changed));
        Ok(())
    }

    #[test]
    fn research_package_descriptor_digest_excludes_execution_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let capability = PackageVExecutableCapability::prepare_current()?;
        let snapshot = ProjectCommandListResult::from_makefile_bytes_with_capability(
            command_snapshot()?.scope,
            ActivityId::from_uuid(id(7)),
            b"",
            &capability,
        )?;
        let command_id = ProjectCommandId::new(PACKAGE_V_COMMAND_ID)?;
        let first = snapshot.to_execution_request(&command_id, ExecutionId::from_uuid(id(8)))?;
        let second = snapshot.to_execution_request(&command_id, ExecutionId::from_uuid(id(9)))?;
        assert!(is_exact_research_package_request(
            PACKAGE_V_COMMAND_ID,
            &first
        ));
        assert_eq!(
            forge_execution::execution_request_digest(&first),
            forge_execution::execution_request_digest(&second)
        );
        assert_eq!(
            snapshot.request_digest(&command_id)?,
            forge_execution::execution_request_digest(&first)
        );
        assert_eq!(first.timeout().get(), 5 * 60 * 1_000);
        assert_eq!(first.output_limit().get(), 64 * 1024);
        Ok(())
    }

    #[test]
    fn make_ci_resolves_and_converts_to_server_owned_execution()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = command_snapshot()?;
        let command_id = ProjectCommandId::new("make:ci")?;
        let execution_id = ExecutionId::from_uuid(id(4));
        let request = snapshot.to_execution_request(&command_id, execution_id)?;
        assert_eq!(request.id(), execution_id);
        assert_eq!(request.cwd(), None);
        assert_eq!(request.timeout().get(), 10 * 60 * 1_000);
        assert_eq!(
            request.output_limit(),
            forge_domain::ExecutionOutputLimit::DEFAULT
        );
        assert_eq!(
            request.permissions(),
            forge_domain::ExecutionPermissions::new(true, false, false)
        );
        let ExecutionKind::Structured { program, arguments } = request.kind() else {
            return Err("discovered commands must remain structured".into());
        };
        assert_eq!(program.as_path(), Path::new(RUST_CI_PROGRAM));
        assert_eq!(arguments.len(), 1);
        assert_eq!(arguments[0].as_os_str(), "ci");
        assert!(is_exact_rust_verify_request("make:ci", &request));
        assert!(!is_exact_rust_verify_request("make:check", &request));
        Ok(())
    }

    #[test]
    fn unknown_command_id_is_rejected_before_execution_conversion()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = command_snapshot()?;
        let unknown = ProjectCommandId::new("make:unknown")?;
        let result = snapshot.to_execution_request(&unknown, ExecutionId::from_uuid(id(5)));
        assert_eq!(
            result.err().as_ref().map(ControlError::code),
            Some(ControlErrorCode::InvalidInput)
        );
        Ok(())
    }
}
