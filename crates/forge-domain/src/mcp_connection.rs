//! Typed durable settings for the public MCP connection boundary.
//!
//! The public value accepted here is deliberately narrower than a general
//! URL.  A connection setting is an optional HTTPS host (optionally supplied
//! with the `https://` scheme and the `/mcp` path), plus a non-zero local
//! listener port.  A blank host selects Cloudflare Quick Tunnel mode.  When a
//! host is present, the canonical origin and MCP endpoint are derived once at
//! this validation boundary and are never reconstructed by persistence or UI
//! callers.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::TimestampMillis;

/// Default local listener port for the Forge MCP bridge.
pub const DEFAULT_MCP_LOCAL_PORT: u16 = 7_979;

/// Maximum accepted DNS host length in bytes.
pub const MAX_MCP_PUBLIC_HOST_BYTES: usize = 253;

/// Maximum canonical origin length in bytes.
pub const MAX_MCP_PUBLIC_ORIGIN_BYTES: usize = 261;

/// Maximum canonical MCP endpoint length in bytes.
pub const MAX_MCP_ENDPOINT_BYTES: usize = MAX_MCP_PUBLIC_ORIGIN_BYTES + 4;

const HTTPS_PREFIX: &str = "https://";
const MCP_PATH: &str = "/mcp";

/// Validated public HTTPS host and its canonical MCP endpoint.
///
/// The value stores the canonical origin (`https://host`) and derives the
/// endpoint (`https://host/mcp`) without retaining caller-provided path
/// spelling.  Bare hosts and `https://` inputs are both accepted at the
/// parse boundary; any other scheme, path, query, fragment, credential, port,
/// or malformed DNS label is rejected.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct McpPublicBase {
    origin: String,
    endpoint: String,
}

impl McpPublicBase {
    /// Parse a bare host or an HTTPS host with an optional `/mcp` suffix.
    pub fn parse(value: impl AsRef<str>) -> Result<Self, McpPublicBaseError> {
        let input = value.as_ref().trim();
        if input.is_empty() {
            return Err(McpPublicBaseError::Empty);
        }

        let without_scheme = if input
            .get(..HTTPS_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(HTTPS_PREFIX))
        {
            &input[HTTPS_PREFIX.len()..]
        } else if input.contains("://") {
            return Err(McpPublicBaseError::HttpsRequired);
        } else {
            input
        };

        let host = strip_optional_mcp_path(without_scheme)?;
        let host = validate_public_host(host)?;
        let origin = format!("{HTTPS_PREFIX}{host}");
        let endpoint = format!("{origin}{MCP_PATH}");
        debug_assert!(origin.len() <= MAX_MCP_PUBLIC_ORIGIN_BYTES);
        debug_assert!(endpoint.len() <= MAX_MCP_ENDPOINT_BYTES);
        Ok(Self { origin, endpoint })
    }

    /// Canonical `https://host` origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Canonical `https://host/mcp` endpoint.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The host component without scheme or path.
    pub fn host(&self) -> &str {
        self.origin.strip_prefix(HTTPS_PREFIX).unwrap_or_default()
    }
}

impl fmt::Display for McpPublicBase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.origin())
    }
}

impl FromStr for McpPublicBase {
    type Err = McpPublicBaseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Alias emphasizing that [`McpPublicBase`] exposes a canonical origin.
pub type McpPublicOrigin = McpPublicBase;

fn strip_optional_mcp_path(value: &str) -> Result<&str, McpPublicBaseError> {
    if value.contains('?') || value.contains('#') {
        return Err(McpPublicBaseError::InvalidSuffix);
    }
    if let Some(host) = value.strip_suffix("/mcp/") {
        return Ok(host);
    }
    if let Some(host) = value.strip_suffix(MCP_PATH) {
        return Ok(host);
    }
    if let Some(host) = value.strip_suffix('/') {
        if host.ends_with('/') {
            return Err(McpPublicBaseError::InvalidPath);
        }
        return Ok(host);
    }
    if value.contains('/') {
        return Err(McpPublicBaseError::InvalidPath);
    }
    Ok(value)
}

fn validate_public_host(value: &str) -> Result<String, McpPublicBaseError> {
    if value.is_empty() {
        return Err(McpPublicBaseError::InvalidHost);
    }
    if value.len() > MAX_MCP_PUBLIC_HOST_BYTES {
        return Err(McpPublicBaseError::HostTooLong {
            actual: value.len(),
            maximum: MAX_MCP_PUBLIC_HOST_BYTES,
        });
    }
    if value.contains('@') || value.contains(':') || value.contains('[') || value.contains(']') {
        return Err(McpPublicBaseError::PortOrCredentialsNotAllowed);
    }
    if !value.is_ascii() {
        return Err(McpPublicBaseError::InvalidHost);
    }

    let normalized = value.to_ascii_lowercase();
    if normalized == "localhost" || normalized.ends_with('.') {
        return Err(McpPublicBaseError::InvalidHost);
    }
    if normalized.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err(McpPublicBaseError::IpAddressNotAllowed);
    }
    if !normalized.contains('.') {
        return Err(McpPublicBaseError::DomainRequired);
    }

    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(McpPublicBaseError::InvalidHostLabel);
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(McpPublicBaseError::InvalidHostLabel);
        }
    }
    Ok(normalized)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum McpPublicBaseError {
    #[error("MCP public base is empty")]
    Empty,
    #[error("MCP public base must use HTTPS")]
    HttpsRequired,
    #[error("MCP public base path must be /mcp or empty")]
    InvalidPath,
    #[error("MCP public base query or fragment is not allowed")]
    InvalidSuffix,
    #[error("MCP public base host is invalid")]
    InvalidHost,
    #[error("MCP public base host has {actual} bytes; maximum is {maximum}")]
    HostTooLong { actual: usize, maximum: usize },
    #[error("MCP public base host must be a DNS name, not an IP address")]
    IpAddressNotAllowed,
    #[error("MCP public base host must contain a domain separator")]
    DomainRequired,
    #[error("MCP public base host label is invalid")]
    InvalidHostLabel,
    #[error("MCP public base credentials and explicit ports are not allowed")]
    PortOrCredentialsNotAllowed,
}

/// Validated non-zero local TCP port.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct McpLocalPort(u16);

impl McpLocalPort {
    pub const DEFAULT: Self = Self(DEFAULT_MCP_LOCAL_PORT);

    pub const fn new(value: u16) -> Result<Self, McpLocalPortError> {
        if value == 0 {
            Err(McpLocalPortError::Zero)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl Default for McpLocalPort {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for McpLocalPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for McpLocalPort {
    type Err = McpLocalPortError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .trim()
            .parse::<u16>()
            .map_err(|_| McpLocalPortError::Invalid(value.to_owned()))
            .and_then(Self::new)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum McpLocalPortError {
    #[error("MCP local port must not be zero")]
    Zero,
    #[error("MCP local port is invalid: {0}")]
    Invalid(String),
}

/// Revision for the singleton durable MCP connection settings record.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct McpConnectionRevision(i64);

impl McpConnectionRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn new(value: i64) -> Result<Self, McpConnectionRevisionError> {
        if value > 0 {
            Ok(Self(value))
        } else {
            Err(McpConnectionRevisionError::Invalid { actual: value })
        }
    }

    pub const fn get(self) -> i64 {
        self.0
    }

    pub const fn checked_next(self) -> Result<Self, McpConnectionRevisionError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(McpConnectionRevisionError::Overflow { current: self.0 }),
        }
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum McpConnectionRevisionError {
    #[error("MCP connection settings revision must be positive, got {actual}")]
    Invalid { actual: i64 },
    #[error("MCP connection settings revision overflowed from {current}")]
    Overflow { current: i64 },
}

/// Validated mutable fields for the durable MCP connection settings record.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpConnectionSettings {
    public_base: Option<McpPublicBase>,
    local_port: McpLocalPort,
}

impl McpConnectionSettings {
    pub const fn new(public_base: Option<McpPublicBase>, local_port: McpLocalPort) -> Self {
        Self {
            public_base,
            local_port,
        }
    }

    /// Parse UI/configuration input while applying the default port.
    pub fn from_input(
        public_base: impl AsRef<str>,
        local_port: Option<u16>,
    ) -> Result<Self, McpConnectionSettingsError> {
        let local_port = local_port.unwrap_or(DEFAULT_MCP_LOCAL_PORT);
        let public_base = public_base.as_ref().trim();
        let public_base = if public_base.is_empty() {
            None
        } else {
            Some(McpPublicBase::parse(public_base)?)
        };
        Ok(Self::new(public_base, McpLocalPort::new(local_port)?))
    }

    pub const fn public_base(&self) -> Option<&McpPublicBase> {
        self.public_base.as_ref()
    }

    pub fn public_origin(&self) -> Option<&str> {
        self.public_base.as_ref().map(McpPublicBase::origin)
    }

    pub fn mcp_endpoint(&self) -> Option<&str> {
        self.public_base.as_ref().map(McpPublicBase::endpoint)
    }

    pub const fn local_port(&self) -> McpLocalPort {
        self.local_port
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum McpConnectionSettingsError {
    #[error(transparent)]
    PublicBase(#[from] McpPublicBaseError),
    #[error(transparent)]
    LocalPort(#[from] McpLocalPortError),
}

/// Durable singleton record for MCP connection settings.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredMcpConnectionSettings {
    settings: McpConnectionSettings,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
    revision: McpConnectionRevision,
}

impl RegisteredMcpConnectionSettings {
    pub const fn initial(settings: McpConnectionSettings, observed_at: TimestampMillis) -> Self {
        Self {
            settings,
            created_at: observed_at,
            updated_at: observed_at,
            revision: McpConnectionRevision::INITIAL,
        }
    }

    pub fn from_parts(
        settings: McpConnectionSettings,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
        revision: McpConnectionRevision,
    ) -> Result<Self, McpConnectionSettingsTransitionError> {
        if updated_at.get() < created_at.get() {
            return Err(McpConnectionSettingsTransitionError::TimestampOrder);
        }
        Ok(Self {
            settings,
            created_at,
            updated_at,
            revision,
        })
    }

    pub fn update(
        &self,
        settings: McpConnectionSettings,
        expected_revision: McpConnectionRevision,
        observed_at: TimestampMillis,
    ) -> Result<Self, McpConnectionSettingsTransitionError> {
        if self.revision != expected_revision {
            return Err(McpConnectionSettingsTransitionError::RevisionConflict);
        }
        if observed_at.get() < self.updated_at.get() {
            return Err(McpConnectionSettingsTransitionError::TimestampOrder);
        }
        Ok(Self {
            settings,
            updated_at: observed_at,
            revision: self
                .revision
                .checked_next()
                .map_err(McpConnectionSettingsTransitionError::RevisionOverflow)?,
            ..self.clone()
        })
    }

    pub const fn settings(&self) -> &McpConnectionSettings {
        &self.settings
    }

    pub const fn public_base(&self) -> Option<&McpPublicBase> {
        self.settings.public_base()
    }

    pub fn public_origin(&self) -> Option<&str> {
        self.settings.public_origin()
    }

    pub fn mcp_endpoint(&self) -> Option<&str> {
        self.settings.mcp_endpoint()
    }

    pub const fn local_port(&self) -> McpLocalPort {
        self.settings.local_port()
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub const fn revision(&self) -> McpConnectionRevision {
        self.revision
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum McpConnectionSettingsTransitionError {
    #[error("MCP connection settings timestamps are out of order")]
    TimestampOrder,
    #[error("MCP connection settings revision does not match")]
    RevisionConflict,
    #[error("MCP connection settings revision overflowed")]
    RevisionOverflow(McpConnectionRevisionError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_base_normalizes_supported_inputs() -> Result<(), Box<dyn std::error::Error>> {
        for input in [
            "skygptcodex.store",
            "HTTPS://SKYGPTCODEX.STORE",
            "https://skygptcodex.store/",
            "https://skygptcodex.store/mcp",
            "https://skygptcodex.store/mcp/",
        ] {
            let base = McpPublicBase::parse(input)?;
            assert_eq!(base.origin(), "https://skygptcodex.store");
            assert_eq!(base.endpoint(), "https://skygptcodex.store/mcp");
        }
        Ok(())
    }

    #[test]
    fn public_base_rejects_ambiguous_or_insecure_inputs() {
        for input in [
            "",
            "http://skygptcodex.store",
            "skygptcodex.store/other",
            "https://skygptcodex.store/mcp/extra",
            "https://user@skygptcodex.store",
            "https://skygptcodex.store:443",
            "https://127.0.0.1",
            "localhost",
            "https://skygptcodex.store?token=secret",
        ] {
            assert!(McpPublicBase::parse(input).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn local_port_defaults_and_rejects_zero() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(McpLocalPort::default().get(), DEFAULT_MCP_LOCAL_PORT);
        assert_eq!(McpLocalPort::from_str("7979")?.get(), 7_979);
        assert!(matches!(McpLocalPort::new(0), Err(McpLocalPortError::Zero)));
        Ok(())
    }

    #[test]
    fn settings_update_is_revision_and_timestamp_bound() -> Result<(), Box<dyn std::error::Error>> {
        let first = McpConnectionSettings::from_input("skygptcodex.store", None)?;
        let second = McpConnectionSettings::from_input("mcp.skygptcodex.store", Some(8_000))?;
        let initial = RegisteredMcpConnectionSettings::initial(first, TimestampMillis::new(10)?);
        let updated = initial.update(second, initial.revision(), TimestampMillis::new(11)?)?;
        assert_eq!(updated.revision().get(), 2);
        assert_eq!(
            updated.mcp_endpoint(),
            Some("https://mcp.skygptcodex.store/mcp")
        );
        assert!(matches!(
            initial.update(
                updated.settings().clone(),
                updated.revision(),
                TimestampMillis::new(11)?
            ),
            Err(McpConnectionSettingsTransitionError::RevisionConflict)
        ));
        assert!(matches!(
            updated.update(
                updated.settings().clone(),
                updated.revision(),
                TimestampMillis::new(10)?
            ),
            Err(McpConnectionSettingsTransitionError::TimestampOrder)
        ));
        Ok(())
    }

    #[test]
    fn blank_public_base_selects_quick_tunnel_mode() -> Result<(), Box<dyn std::error::Error>> {
        let settings = McpConnectionSettings::from_input("   ", None)?;
        assert_eq!(settings.public_base(), None);
        assert_eq!(settings.public_origin(), None);
        assert_eq!(settings.mcp_endpoint(), None);
        assert_eq!(settings.local_port().get(), DEFAULT_MCP_LOCAL_PORT);
        Ok(())
    }
}
