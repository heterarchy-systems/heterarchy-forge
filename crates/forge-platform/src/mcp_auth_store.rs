//! macOS Keychain adapter for the local MCP bearer-token hash pepper.
//!
//! The adapter stores one fixed-width secret and never generates, formats, or
//! logs it. Token lifecycle policy remains outside this platform boundary.

use std::fmt;

use thiserror::Error;

const PEPPER_BYTES: usize = 32;

#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "com.heterarchy.forge.mcp-token";
#[cfg(target_os = "macos")]
const KEYCHAIN_ACCOUNT: &str = "local-bearer-hash-pepper-v1";
#[cfg(target_os = "macos")]
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;

/// Fixed-width secret used only as the BLAKE3 keyed-hash key.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct McpTokenPepper([u8; PEPPER_BYTES]);

impl McpTokenPepper {
    pub const fn new(bytes: [u8; PEPPER_BYTES]) -> Self {
        Self(bytes)
    }

    /// Transfer ownership into the application token service.
    pub const fn into_bytes(self) -> [u8; PEPPER_BYTES] {
        self.0
    }
}

impl TryFrom<Vec<u8>> for McpTokenPepper {
    type Error = McpTokenPepperError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let actual = value.len();
        let bytes = value
            .try_into()
            .map_err(|_| McpTokenPepperError::CorruptLength {
                actual,
                expected: PEPPER_BYTES,
            })?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for McpTokenPepper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpTokenPepper(<redacted>)")
    }
}

/// Narrow owner for the one Heterarchy Forge Keychain item.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacOsMcpTokenPepperStore;

impl MacOsMcpTokenPepperStore {
    #[cfg(target_os = "macos")]
    pub fn load(self) -> Result<Option<McpTokenPepper>, McpTokenPepperError> {
        use security_framework::passwords::{PasswordOptions, generic_password};

        match generic_password(PasswordOptions::new_generic_password(
            KEYCHAIN_SERVICE,
            KEYCHAIN_ACCOUNT,
        )) {
            Ok(bytes) => McpTokenPepper::try_from(bytes).map(Some),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(McpTokenPepperError::Keychain(error)),
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn load(self) -> Result<Option<McpTokenPepper>, McpTokenPepperError> {
        Err(McpTokenPepperError::UnsupportedPlatform)
    }

    /// Store a caller-generated pepper only when the managed item is absent.
    ///
    /// Callers must serialize this explicit first-issue operation. The value
    /// is re-read after the write so a competing process cannot be reported as
    /// successful with a different effective pepper.
    #[cfg(target_os = "macos")]
    pub fn store_if_absent(self, pepper: &McpTokenPepper) -> Result<(), McpTokenPepperError> {
        use security_framework::passwords::set_generic_password;

        if self.load()?.is_some() {
            return Err(McpTokenPepperError::AlreadyExists);
        }
        set_generic_password(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, &pepper.0)
            .map_err(McpTokenPepperError::Keychain)?;
        match self.load()? {
            Some(stored) if stored == *pepper => Ok(()),
            Some(_) => Err(McpTokenPepperError::ConcurrentReplacement),
            None => Err(McpTokenPepperError::WriteUnconfirmed),
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn store_if_absent(self, _pepper: &McpTokenPepper) -> Result<(), McpTokenPepperError> {
        Err(McpTokenPepperError::UnsupportedPlatform)
    }
}

#[derive(Debug, Error)]
pub enum McpTokenPepperError {
    #[error("stored MCP token pepper has invalid length {actual}; expected {expected}")]
    CorruptLength { actual: usize, expected: usize },
    #[error("MCP token pepper already exists")]
    AlreadyExists,
    #[error("MCP token pepper changed during explicit creation")]
    ConcurrentReplacement,
    #[error("MCP token pepper write could not be confirmed")]
    WriteUnconfirmed,
    #[cfg(target_os = "macos")]
    #[error("macOS Keychain operation failed")]
    Keychain(#[source] security_framework::base::Error),
    #[cfg(not(target_os = "macos"))]
    #[error("MCP token pepper storage is supported only on macOS")]
    UnsupportedPlatform,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pepper_is_fixed_width_redacted_and_explicitly_transferable() {
        let bytes = [0x5a; PEPPER_BYTES];
        let pepper = McpTokenPepper::new(bytes);
        assert_eq!(format!("{pepper:?}"), "McpTokenPepper(<redacted>)");
        assert_eq!(pepper.into_bytes(), bytes);
    }

    #[test]
    fn persisted_pepper_decoder_rejects_noncanonical_lengths() {
        assert!(McpTokenPepper::try_from(vec![0_u8; PEPPER_BYTES - 1]).is_err());
        assert!(McpTokenPepper::try_from(vec![0_u8; PEPPER_BYTES + 1]).is_err());
        assert!(McpTokenPepper::try_from(vec![0_u8; PEPPER_BYTES]).is_ok());
    }
}
