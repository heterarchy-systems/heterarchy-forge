//! Deterministic Harness Library and Workspace-applied Harness models.
//!
//! Local bundle discovery, manifest parsing, filesystem inspection, and hash
//! computation belong to adapters. This module owns only bounded identities,
//! bundle metadata, applied-state transitions, verification outcomes, and CAS
//! revisions.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{TimestampMillis, WorkspaceId};

pub const MAX_HARNESS_NAME_BYTES: usize = 128;
pub const MAX_HARNESS_VERSION_BYTES: usize = 64;
pub const MAX_HARNESS_MANAGED_FILES: u16 = 256;
pub const MAX_HARNESS_SKILLS: u16 = 64;
pub const MAX_HARNESS_VERIFIERS: u16 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessBundleId(Uuid);

impl HarnessBundleId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for HarnessBundleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for HarnessBundleId {
    type Err = HarnessBundleIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(HarnessBundleIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum HarnessBundleIdParseError {
    #[error("Harness Bundle id is not a UUID")]
    InvalidUuid(#[source] uuid::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessName(String);

impl HarnessName {
    pub fn new(value: String) -> Result<Self, HarnessNameError> {
        let bytes = value.as_bytes();
        if value.trim().is_empty() {
            return Err(HarnessNameError::Empty);
        }
        if bytes.len() > MAX_HARNESS_NAME_BYTES {
            return Err(HarnessNameError::TooLong {
                actual: bytes.len(),
                maximum: MAX_HARNESS_NAME_BYTES,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(HarnessNameError::ControlCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HarnessNameError {
    #[error("Harness name must not be empty")]
    Empty,
    #[error("Harness name has {actual} bytes; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
    #[error("Harness name contains a control character")]
    ControlCharacter,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessVersion(String);

impl HarnessVersion {
    pub fn new(value: String) -> Result<Self, HarnessVersionError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() {
            return Err(HarnessVersionError::Empty);
        }
        if bytes.len() > MAX_HARNESS_VERSION_BYTES {
            return Err(HarnessVersionError::TooLong {
                actual: bytes.len(),
                maximum: MAX_HARNESS_VERSION_BYTES,
            });
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'-' | b'+'))
        {
            return Err(HarnessVersionError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HarnessVersionError {
    #[error("Harness version must not be empty")]
    Empty,
    #[error("Harness version has {actual} bytes; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
    #[error("Harness version contains a non-canonical character")]
    InvalidCharacter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessContentHash([u8; 32]);

impl HarnessContentHash {
    pub const BYTE_LEN: usize = 32;
    pub const HEX_LEN: usize = Self::BYTE_LEN * 2;
    pub const ALGORITHM: &str = "sha256";
    pub const ENCODED_LEN: usize = Self::ALGORITHM.len() + 1 + Self::HEX_LEN;

    pub const fn from_bytes(value: [u8; Self::BYTE_LEN]) -> Self {
        Self(value)
    }

    pub const fn into_bytes(self) -> [u8; Self::BYTE_LEN] {
        self.0
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.0
    }
}

impl fmt::Display for HarnessContentHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(Self::ALGORITHM)?;
        formatter.write_str(":")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for HarnessContentHash {
    type Err = HarnessContentHashParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != Self::ENCODED_LEN {
            return Err(HarnessContentHashParseError::InvalidLength {
                actual: value.len(),
            });
        }
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err(HarnessContentHashParseError::InvalidAlgorithm);
        };
        let mut decoded = [0_u8; Self::BYTE_LEN];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let high = decode_lower_hex(pair[0])?;
            let low = decode_lower_hex(pair[1])?;
            decoded[index] = (high << 4) | low;
        }
        Ok(Self(decoded))
    }
}

const fn decode_lower_hex(value: u8) -> Result<u8, HarnessContentHashParseError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(HarnessContentHashParseError::InvalidEncoding),
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HarnessContentHashParseError {
    #[error("Harness content hash has {actual} encoded bytes")]
    InvalidLength { actual: usize },
    #[error("Harness content hash algorithm must be sha256")]
    InvalidAlgorithm,
    #[error("Harness content hash must use canonical lower hexadecimal")]
    InvalidEncoding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessRevision(i64);

impl HarnessRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, HarnessRevisionError> {
        if value < 1 {
            Err(HarnessRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, HarnessRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(HarnessRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HarnessRevisionError {
    #[error("Harness revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Harness revision overflowed at {current}")]
    Overflow { current: i64 },
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessBundleDescriptor {
    id: HarnessBundleId,
    name: HarnessName,
    version: HarnessVersion,
    content_hash: HarnessContentHash,
    managed_file_count: u16,
    skill_count: u16,
    verifier_count: u16,
}

impl HarnessBundleDescriptor {
    pub fn new(
        id: HarnessBundleId,
        name: HarnessName,
        version: HarnessVersion,
        content_hash: HarnessContentHash,
        managed_file_count: u16,
        skill_count: u16,
        verifier_count: u16,
    ) -> Result<Self, HarnessBundleError> {
        if managed_file_count == 0 || managed_file_count > MAX_HARNESS_MANAGED_FILES {
            return Err(HarnessBundleError::ManagedFileCount {
                actual: managed_file_count,
                maximum: MAX_HARNESS_MANAGED_FILES,
            });
        }
        if skill_count > MAX_HARNESS_SKILLS {
            return Err(HarnessBundleError::SkillCount {
                actual: skill_count,
                maximum: MAX_HARNESS_SKILLS,
            });
        }
        if verifier_count > MAX_HARNESS_VERIFIERS {
            return Err(HarnessBundleError::VerifierCount {
                actual: verifier_count,
                maximum: MAX_HARNESS_VERIFIERS,
            });
        }
        Ok(Self {
            id,
            name,
            version,
            content_hash,
            managed_file_count,
            skill_count,
            verifier_count,
        })
    }

    pub const fn id(&self) -> HarnessBundleId {
        self.id
    }
    pub const fn name(&self) -> &HarnessName {
        &self.name
    }
    pub const fn version(&self) -> &HarnessVersion {
        &self.version
    }
    pub const fn content_hash(&self) -> HarnessContentHash {
        self.content_hash
    }
    pub const fn managed_file_count(&self) -> u16 {
        self.managed_file_count
    }
    pub const fn skill_count(&self) -> u16 {
        self.skill_count
    }
    pub const fn verifier_count(&self) -> u16 {
        self.verifier_count
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HarnessBundleError {
    #[error("Harness managed-file count {actual} is outside 1..={maximum}")]
    ManagedFileCount { actual: u16, maximum: u16 },
    #[error("Harness skill count {actual} exceeds {maximum}")]
    SkillCount { actual: u16, maximum: u16 },
    #[error("Harness verifier count {actual} exceeds {maximum}")]
    VerifierCount { actual: u16, maximum: u16 },
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredHarnessBundle {
    descriptor: HarnessBundleDescriptor,
    registered_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: HarnessRevision,
}

impl RegisteredHarnessBundle {
    pub const fn create(
        descriptor: HarnessBundleDescriptor,
        registered_at: TimestampMillis,
    ) -> Self {
        Self {
            descriptor,
            registered_at,
            updated_at: registered_at,
            revision: HarnessRevision::INITIAL,
        }
    }

    pub fn from_parts(
        descriptor: HarnessBundleDescriptor,
        registered_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: HarnessRevision,
    ) -> Result<Self, RegisteredHarnessBundleError> {
        if updated_at.get() < registered_at.get() {
            return Err(RegisteredHarnessBundleError::TimestampOrder);
        }
        Ok(Self {
            descriptor,
            registered_at,
            updated_at,
            revision,
        })
    }

    pub fn refresh(
        &self,
        descriptor: HarnessBundleDescriptor,
        expected_revision: HarnessRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, RegisteredHarnessBundleError> {
        if self.revision != expected_revision {
            return Err(RegisteredHarnessBundleError::RevisionConflict);
        }
        if descriptor.id() != self.descriptor.id() {
            return Err(RegisteredHarnessBundleError::IdentityMismatch);
        }
        if observed_at.get() < self.updated_at.get() {
            return Err(RegisteredHarnessBundleError::TimestampOrder);
        }
        Ok(Self {
            descriptor,
            updated_at: observed_at,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| RegisteredHarnessBundleError::RevisionOverflow)?,
            ..self.clone()
        })
    }

    pub const fn descriptor(&self) -> &HarnessBundleDescriptor {
        &self.descriptor
    }
    pub const fn registered_at(&self) -> TimestampMillis {
        self.registered_at
    }
    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }
    pub const fn revision(&self) -> HarnessRevision {
        self.revision
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredHarnessBundleError {
    #[error("Harness Bundle refresh identity does not match the registered Bundle")]
    IdentityMismatch,
    #[error("Harness Bundle revision does not match the expected revision")]
    RevisionConflict,
    #[error("Harness Bundle timestamp moved backwards")]
    TimestampOrder,
    #[error("Harness Bundle revision overflowed")]
    RevisionOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarnessVerificationState {
    Applied,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HarnessVerificationOutcome {
    Ready,
    Failed,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedHarness {
    workspace_id: WorkspaceId,
    bundle: HarnessBundleDescriptor,
    state: HarnessVerificationState,
    applied_at: TimestampMillis,
    verified_at: Option<TimestampMillis>,
    revision: HarnessRevision,
}

impl AppliedHarness {
    pub const fn applied(
        workspace_id: WorkspaceId,
        bundle: HarnessBundleDescriptor,
        applied_at: TimestampMillis,
    ) -> Self {
        Self {
            workspace_id,
            bundle,
            state: HarnessVerificationState::Applied,
            applied_at,
            verified_at: None,
            revision: HarnessRevision::INITIAL,
        }
    }

    pub fn from_parts(
        workspace_id: WorkspaceId,
        bundle: HarnessBundleDescriptor,
        state: HarnessVerificationState,
        applied_at: TimestampMillis,
        verified_at: Option<TimestampMillis>,
        revision: HarnessRevision,
    ) -> Result<Self, AppliedHarnessError> {
        validate_verification_timestamp(state, applied_at, verified_at)?;
        Ok(Self {
            workspace_id,
            bundle,
            state,
            applied_at,
            verified_at,
            revision,
        })
    }

    pub fn record_verification(
        &self,
        outcome: HarnessVerificationOutcome,
        expected_revision: HarnessRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, AppliedHarnessError> {
        if self.revision != expected_revision {
            return Err(AppliedHarnessError::RevisionConflict);
        }
        if observed_at.get() < self.applied_at.get()
            || self
                .verified_at
                .is_some_and(|previous| observed_at.get() < previous.get())
        {
            return Err(AppliedHarnessError::TimestampOrder);
        }
        let state = match outcome {
            HarnessVerificationOutcome::Ready => HarnessVerificationState::Ready,
            HarnessVerificationOutcome::Failed => HarnessVerificationState::Failed,
        };
        Ok(Self {
            state,
            verified_at: Some(observed_at),
            revision: self
                .revision
                .checked_next()
                .map_err(|_| AppliedHarnessError::RevisionOverflow)?,
            ..self.clone()
        })
    }

    pub fn replace_bundle(
        &self,
        bundle: HarnessBundleDescriptor,
        expected_revision: HarnessRevision,
        applied_at: TimestampMillis,
    ) -> Result<Self, AppliedHarnessError> {
        if self.revision != expected_revision {
            return Err(AppliedHarnessError::RevisionConflict);
        }
        if applied_at.get() < self.applied_at.get() {
            return Err(AppliedHarnessError::TimestampOrder);
        }
        Ok(Self {
            bundle,
            state: HarnessVerificationState::Applied,
            applied_at,
            verified_at: None,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| AppliedHarnessError::RevisionOverflow)?,
            ..self.clone()
        })
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn bundle(&self) -> &HarnessBundleDescriptor {
        &self.bundle
    }
    pub const fn state(&self) -> HarnessVerificationState {
        self.state
    }
    pub const fn applied_at(&self) -> TimestampMillis {
        self.applied_at
    }
    pub const fn verified_at(&self) -> Option<TimestampMillis> {
        self.verified_at
    }
    pub const fn revision(&self) -> HarnessRevision {
        self.revision
    }
}

fn validate_verification_timestamp(
    state: HarnessVerificationState,
    applied_at: TimestampMillis,
    verified_at: Option<TimestampMillis>,
) -> Result<(), AppliedHarnessError> {
    let shape_is_valid = match state {
        HarnessVerificationState::Applied => verified_at.is_none(),
        HarnessVerificationState::Ready | HarnessVerificationState::Failed => verified_at.is_some(),
    };
    if !shape_is_valid {
        return Err(AppliedHarnessError::InvalidVerificationEvidence);
    }
    if verified_at.is_some_and(|value| value.get() < applied_at.get()) {
        return Err(AppliedHarnessError::TimestampOrder);
    }
    Ok(())
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum AppliedHarnessError {
    #[error("Harness applied-state revision does not match the expected revision")]
    RevisionConflict,
    #[error("Harness applied-state timestamp moved backwards")]
    TimestampOrder,
    #[error("Harness verification state and timestamp evidence disagree")]
    InvalidVerificationEvidence,
    #[error("Harness applied-state revision overflowed")]
    RevisionOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(fill: u8) -> Result<HarnessBundleDescriptor, Box<dyn std::error::Error>> {
        Ok(HarnessBundleDescriptor::new(
            HarnessBundleId::from_uuid(Uuid::from_u128(u128::from(fill) + 1)),
            HarnessName::new("Rust Dev Harness".to_owned())?,
            HarnessVersion::new("3.0.0".to_owned())?,
            HarnessContentHash::from_bytes([fill; HarnessContentHash::BYTE_LEN]),
            40,
            1,
            3,
        )?)
    }

    #[test]
    fn applied_harness_verification_and_switch_are_cas_guarded()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = AppliedHarness::applied(
            WorkspaceId::from_uuid(Uuid::from_u128(1)),
            descriptor(0xA1)?,
            TimestampMillis::new(10)?,
        );
        assert_eq!(first.state(), HarnessVerificationState::Applied);
        assert!(first.verified_at().is_none());
        let ready = first.record_verification(
            HarnessVerificationOutcome::Ready,
            first.revision(),
            TimestampMillis::new(11)?,
        )?;
        assert_eq!(ready.state(), HarnessVerificationState::Ready);
        assert_eq!(ready.revision().get(), 2);
        assert!(
            ready
                .record_verification(
                    HarnessVerificationOutcome::Failed,
                    HarnessRevision::INITIAL,
                    TimestampMillis::new(12)?,
                )
                .is_err()
        );
        let switched = ready.replace_bundle(
            descriptor(0xB2)?,
            ready.revision(),
            TimestampMillis::new(12)?,
        )?;
        assert_eq!(switched.state(), HarnessVerificationState::Applied);
        assert!(switched.verified_at().is_none());
        assert_eq!(switched.revision().get(), 3);
        Ok(())
    }

    #[test]
    fn harness_hash_wire_form_is_canonical() -> Result<(), Box<dyn std::error::Error>> {
        let hash = HarnessContentHash::from_bytes([0xAB; HarnessContentHash::BYTE_LEN]);
        let encoded = hash.to_string();
        assert!(encoded.starts_with("sha256:"));
        assert_eq!(encoded.parse::<HarnessContentHash>()?, hash);
        assert!("sha256:ABC".parse::<HarnessContentHash>().is_err());
        Ok(())
    }
}
