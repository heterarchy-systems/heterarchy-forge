//! Deterministic identities and durable registration state for optional Harness Skills.
//!
//! Skill source inspection, directory traversal, and content hashing belong to
//! adapters. This module owns only bounded identities, descriptors, and catalog
//! revision transitions.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

use crate::{HarnessContentHash, TimestampMillis};

pub const MAX_HARNESS_SKILL_NAME_BYTES: usize = 128;
pub const MAX_HARNESS_SKILL_FILES: u16 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessSkillId(Uuid);

impl HarnessSkillId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for HarnessSkillId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for HarnessSkillId {
    type Err = HarnessSkillIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(HarnessSkillIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum HarnessSkillIdParseError {
    #[error("Harness Skill id is not a UUID")]
    InvalidUuid(#[source] uuid::Error),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessSkillName(String);

impl HarnessSkillName {
    pub fn new(value: String) -> Result<Self, HarnessSkillNameError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() {
            return Err(HarnessSkillNameError::Empty);
        }
        if bytes.len() > MAX_HARNESS_SKILL_NAME_BYTES {
            return Err(HarnessSkillNameError::TooLong {
                actual: bytes.len(),
                maximum: MAX_HARNESS_SKILL_NAME_BYTES,
            });
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.'))
        {
            return Err(HarnessSkillNameError::InvalidCharacter);
        }
        if matches!(value.as_str(), "." | "..") {
            return Err(HarnessSkillNameError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HarnessSkillNameError {
    #[error("Harness Skill name must not be empty")]
    Empty,
    #[error("Harness Skill name has {actual} bytes; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
    #[error("Harness Skill name contains a non-canonical path character")]
    InvalidCharacter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HarnessSkillRevision(i64);

impl HarnessSkillRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, HarnessSkillRevisionError> {
        if value < 1 {
            Err(HarnessSkillRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, HarnessSkillRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(HarnessSkillRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HarnessSkillRevisionError {
    #[error("Harness Skill revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Harness Skill revision overflowed at {current}")]
    Overflow { current: i64 },
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessSkillDescriptor {
    id: HarnessSkillId,
    name: HarnessSkillName,
    content_hash: HarnessContentHash,
    file_count: u16,
}

impl HarnessSkillDescriptor {
    pub fn new(
        id: HarnessSkillId,
        name: HarnessSkillName,
        content_hash: HarnessContentHash,
        file_count: u16,
    ) -> Result<Self, HarnessSkillDescriptorError> {
        if file_count == 0 || file_count > MAX_HARNESS_SKILL_FILES {
            return Err(HarnessSkillDescriptorError::FileCount {
                actual: file_count,
                maximum: MAX_HARNESS_SKILL_FILES,
            });
        }
        Ok(Self {
            id,
            name,
            content_hash,
            file_count,
        })
    }

    pub const fn id(&self) -> HarnessSkillId {
        self.id
    }

    pub const fn name(&self) -> &HarnessSkillName {
        &self.name
    }

    pub const fn content_hash(&self) -> HarnessContentHash {
        self.content_hash
    }

    pub const fn file_count(&self) -> u16 {
        self.file_count
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum HarnessSkillDescriptorError {
    #[error("Harness Skill file count {actual} is outside 1..={maximum}")]
    FileCount { actual: u16, maximum: u16 },
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredHarnessSkill {
    descriptor: HarnessSkillDescriptor,
    registered_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: HarnessSkillRevision,
}

impl RegisteredHarnessSkill {
    pub const fn create(
        descriptor: HarnessSkillDescriptor,
        registered_at: TimestampMillis,
    ) -> Self {
        Self {
            descriptor,
            registered_at,
            updated_at: registered_at,
            revision: HarnessSkillRevision::INITIAL,
        }
    }

    pub fn from_parts(
        descriptor: HarnessSkillDescriptor,
        registered_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: HarnessSkillRevision,
    ) -> Result<Self, RegisteredHarnessSkillError> {
        if updated_at.get() < registered_at.get() {
            return Err(RegisteredHarnessSkillError::TimestampOrder);
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
        descriptor: HarnessSkillDescriptor,
        expected_revision: HarnessSkillRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, RegisteredHarnessSkillError> {
        if self.revision != expected_revision {
            return Err(RegisteredHarnessSkillError::RevisionConflict);
        }
        if descriptor.id() != self.descriptor.id() {
            return Err(RegisteredHarnessSkillError::IdentityMismatch);
        }
        if observed_at.get() < self.updated_at.get() {
            return Err(RegisteredHarnessSkillError::TimestampOrder);
        }
        Ok(Self {
            descriptor,
            updated_at: observed_at,
            revision: self
                .revision
                .checked_next()
                .map_err(|_| RegisteredHarnessSkillError::RevisionOverflow)?,
            ..self.clone()
        })
    }

    pub const fn descriptor(&self) -> &HarnessSkillDescriptor {
        &self.descriptor
    }

    pub const fn registered_at(&self) -> TimestampMillis {
        self.registered_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(&self) -> HarnessSkillRevision {
        self.revision
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredHarnessSkillError {
    #[error("Harness Skill refresh identity does not match the registered Skill")]
    IdentityMismatch,
    #[error("Harness Skill revision does not match the expected revision")]
    RevisionConflict,
    #[error("Harness Skill timestamp moved backwards")]
    TimestampOrder,
    #[error("Harness Skill revision overflowed")]
    RevisionOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skill_name_and_registration_revision_are_bounded() -> Result<(), Box<dyn std::error::Error>>
    {
        let id = HarnessSkillId::from_uuid(Uuid::from_u128(0x4601));
        let descriptor = HarnessSkillDescriptor::new(
            id,
            HarnessSkillName::new("fastapi-skill".to_owned())?,
            HarnessContentHash::from_bytes([7; 32]),
            4,
        )?;
        let first = RegisteredHarnessSkill::create(descriptor.clone(), TimestampMillis::new(10)?);
        let refreshed = first.refresh(descriptor, first.revision(), TimestampMillis::new(11)?)?;
        assert_eq!(refreshed.revision().get(), 2);
        assert!(HarnessSkillName::new("../escape".to_owned()).is_err());
        Ok(())
    }
}
