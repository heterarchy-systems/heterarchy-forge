use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use thiserror::Error;
use uuid::Uuid;

const MAX_LOCATION_NAME_CHARS: usize = 128;
const MAX_LOCATION_LIST_LIMIT: u32 = 1_000;

/// Stable opaque identity for an owner-approved Location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocationId(Uuid);

impl LocationId {
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for LocationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for LocationId {
    type Err = LocationIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value)
            .map(Self)
            .map_err(LocationIdParseError::InvalidUuid)
    }
}

#[derive(Debug, Error)]
pub enum LocationIdParseError {
    #[error("invalid Location UUID")]
    InvalidUuid(#[source] uuid::Error),
}

/// Human-facing Location name with bounded, non-control text.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocationName(String);

impl LocationName {
    pub fn new(value: impl Into<String>) -> Result<Self, LocationNameError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(LocationNameError::Empty);
        }
        if trimmed.chars().any(char::is_control) {
            return Err(LocationNameError::ControlCharacter);
        }
        let character_count = trimmed.chars().count();
        if character_count > MAX_LOCATION_NAME_CHARS {
            return Err(LocationNameError::TooLong {
                actual: character_count,
                maximum: MAX_LOCATION_NAME_CHARS,
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LocationName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LocationNameError {
    #[error("Location name must not be empty")]
    Empty,
    #[error("Location name must not contain control characters")]
    ControlCharacter,
    #[error("Location name has {actual} characters; maximum is {maximum}")]
    TooLong { actual: usize, maximum: usize },
}

/// Absolute persisted filesystem identity observed as canonical at effect ingress.
///
/// This records the owner-approved path observed during registration. It does
/// not prove that the live filesystem object still exists or still resolves to
/// this identity; discovery revalidates that boundary before scanning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocationRoot(PathBuf);

impl LocationRoot {
    /// Wraps a path already canonicalized by the filesystem effect boundary.
    /// No filesystem I/O is performed, and ongoing identity is not inferred.
    pub fn from_canonical(path: PathBuf) -> Result<Self, LocationRootError> {
        if !path.is_absolute() {
            return Err(LocationRootError::NotAbsolute(path));
        }
        Ok(Self(path))
    }

    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LocationRootError {
    #[error("Location root must be an absolute canonical path: {0}")]
    NotAbsolute(PathBuf),
}

/// Milliseconds since the Unix epoch observed by the effect layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimestampMillis(i64);

impl TimestampMillis {
    pub const fn new(value: i64) -> Result<Self, TimestampMillisError> {
        if value < 0 {
            Err(TimestampMillisError::Negative(value))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TimestampMillisError {
    #[error("timestamp milliseconds must be non-negative, got {0}")]
    Negative(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocationState {
    Enabled,
    Disabled,
}

/// Monotonic revision for a durable Location state projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocationRevision(i64);

impl LocationRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, LocationRevisionError> {
        if value < 1 {
            Err(LocationRevisionError::Invalid { actual: value })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, LocationRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(LocationRevisionError::Overflow { current: self.0 }),
        }
    }
}

impl fmt::Display for LocationRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum LocationRevisionError {
    #[error("Location revision must be at least 1, got {actual}")]
    Invalid { actual: i64 },
    #[error("Location revision overflowed at {current}")]
    Overflow { current: i64 },
}

/// Validated command for registering an owner-approved Location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterLocation {
    id: LocationId,
    name: LocationName,
    root: LocationRoot,
    observed_at: TimestampMillis,
}

/// Durable compare-and-set command for a Location state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetLocationState {
    id: LocationId,
    expected_revision: LocationRevision,
    state: LocationState,
    observed_at: TimestampMillis,
}

impl SetLocationState {
    pub const fn new(
        id: LocationId,
        expected_revision: LocationRevision,
        state: LocationState,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            expected_revision,
            state,
            observed_at,
        }
    }

    pub const fn id(&self) -> LocationId {
        self.id
    }

    pub const fn expected_revision(&self) -> LocationRevision {
        self.expected_revision
    }

    pub const fn state(&self) -> LocationState {
        self.state
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

impl RegisterLocation {
    pub const fn new(
        id: LocationId,
        name: LocationName,
        root: LocationRoot,
        observed_at: TimestampMillis,
    ) -> Self {
        Self {
            id,
            name,
            root,
            observed_at,
        }
    }

    pub const fn id(&self) -> LocationId {
        self.id
    }

    pub fn name(&self) -> &LocationName {
        &self.name
    }

    pub fn root(&self) -> &LocationRoot {
        &self.root
    }

    pub const fn observed_at(&self) -> TimestampMillis {
        self.observed_at
    }
}

/// Durable Location projection returned by the registry boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredLocation {
    id: LocationId,
    name: LocationName,
    root: LocationRoot,
    state: LocationState,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: LocationRevision,
}

impl RegisteredLocation {
    pub const fn from_parts_with_revision(
        id: LocationId,
        name: LocationName,
        root: LocationRoot,
        state: LocationState,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: LocationRevision,
    ) -> Self {
        Self {
            id,
            name,
            root,
            state,
            created_at,
            updated_at,
            revision,
        }
    }

    pub const fn id(&self) -> LocationId {
        self.id
    }

    pub fn name(&self) -> &LocationName {
        &self.name
    }

    pub fn root(&self) -> &LocationRoot {
        &self.root
    }

    pub const fn state(&self) -> LocationState {
        self.state
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(&self) -> LocationRevision {
        self.revision
    }
}

/// Bounded query limit for Location lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocationListLimit(u32);

impl LocationListLimit {
    pub const DEFAULT: Self = Self(100);

    pub const fn new(value: u32) -> Result<Self, LocationListLimitError> {
        if value == 0 || value > MAX_LOCATION_LIST_LIMIT {
            Err(LocationListLimitError::OutOfRange {
                actual: value,
                maximum: MAX_LOCATION_LIST_LIMIT,
            })
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum LocationListLimitError {
    #[error("Location list limit {actual} is outside 1..={maximum}")]
    OutOfRange { actual: u32, maximum: u32 },
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::str::FromStr;

    use uuid::Uuid;

    use super::{
        LocationId, LocationListLimit, LocationName, LocationRevision, LocationRoot, LocationState,
        RegisteredLocation, SetLocationState, TimestampMillis,
    };

    #[test]
    fn location_values_validate_and_preserve_meaning() -> Result<(), Box<dyn std::error::Error>> {
        let id = LocationId::from_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215e")?;
        assert_eq!(
            id.into_uuid(),
            Uuid::parse_str("018f47a2-4d8b-7ca0-a9bd-0e2f2bc1215e")?
        );

        let name = LocationName::new("  Forge Workspace  ")?;
        assert_eq!(name.as_str(), "Forge Workspace");

        let root = LocationRoot::from_canonical(PathBuf::from("/tmp/forge-workspace"))?;
        assert_eq!(root.as_path(), std::path::Path::new("/tmp/forge-workspace"));

        assert_eq!(TimestampMillis::new(42)?.get(), 42);
        assert_eq!(LocationListLimit::new(25)?.get(), 25);
        Ok(())
    }

    #[test]
    fn invalid_location_values_fail_closed() {
        assert!(LocationName::new("   ").is_err());
        assert!(LocationName::new("bad\nname").is_err());
        assert!(LocationRoot::from_canonical(PathBuf::from("relative/path")).is_err());
        assert!(TimestampMillis::new(-1).is_err());
        assert!(LocationListLimit::new(0).is_err());
        assert!(LocationListLimit::new(1_001).is_err());
    }

    #[test]
    fn location_revision_boundaries_are_typed_and_checked() -> Result<(), Box<dyn std::error::Error>>
    {
        assert_eq!(LocationRevision::INITIAL.get(), 1);
        assert!(LocationRevision::new(0).is_err());
        assert_eq!(LocationRevision::new(7)?.get(), 7);
        assert_eq!(LocationRevision::INITIAL.checked_next()?.get(), 2);
        let maximum = LocationRevision::new(i64::MAX)?;
        assert!(maximum.checked_next().is_err());
        Ok(())
    }

    #[test]
    fn set_location_state_command_keeps_revision_and_observation_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let id = LocationId::from_uuid(Uuid::from_u128(9));
        let command = SetLocationState::new(
            id,
            LocationRevision::INITIAL,
            LocationState::Disabled,
            TimestampMillis::new(42)?,
        );
        assert_eq!(command.id(), id);
        assert_eq!(command.expected_revision(), LocationRevision::INITIAL);
        assert_eq!(command.state(), LocationState::Disabled);
        assert_eq!(command.observed_at().get(), 42);
        Ok(())
    }

    #[test]
    fn registered_location_exposes_its_revision() -> Result<(), Box<dyn std::error::Error>> {
        let location = RegisteredLocation::from_parts_with_revision(
            LocationId::from_uuid(Uuid::from_u128(10)),
            LocationName::new("Revisioned")?,
            LocationRoot::from_canonical(PathBuf::from("/tmp/revisioned"))?,
            LocationState::Enabled,
            TimestampMillis::new(1)?,
            TimestampMillis::new(1)?,
            LocationRevision::INITIAL,
        );
        assert_eq!(location.revision(), LocationRevision::INITIAL);
        Ok(())
    }
}
