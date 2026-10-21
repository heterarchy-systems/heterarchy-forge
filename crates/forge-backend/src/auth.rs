//! Issuer bearer authentication for the backend transport adapter.
//!
//! The raw bearer secret is accepted only at configuration time. The adapter
//! stores its SHA-256 digest, compares equal-length digests in constant time,
//! and never exposes the secret or digest through diagnostics.

use sha2::{Digest, Sha256};

/// Constant-time equality over equal-length digests.
fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

fn digest(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

/// Issuer bearer authenticator storing only the secret digest.
#[must_use]
#[derive(Clone)]
pub struct IssuerAuth {
    secret_digest: [u8; 32],
}

impl std::fmt::Debug for IssuerAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("IssuerAuth").finish_non_exhaustive()
    }
}

impl IssuerAuth {
    pub fn new(secret: &str) -> Self {
        Self {
            secret_digest: digest(secret),
        }
    }

    /// Verify one `Authorization: Bearer <secret>` header value.
    pub fn verify_bearer(&self, header_value: Option<&str>) -> bool {
        let Some(value) = header_value.and_then(|value| value.strip_prefix("Bearer ")) else {
            return false;
        };
        constant_time_eq(&digest(value), &self.secret_digest)
    }
}

#[cfg(test)]
mod tests {
    use super::{IssuerAuth, digest};

    #[test]
    fn diagnostics_do_not_expose_credentials_or_digests() -> Result<(), crate::config::ConfigError>
    {
        let secret = "diagnostic-credential-sentinel";
        let config = crate::config::BackendConfig::new(
            std::net::IpAddr::from([127, 0, 0, 1]),
            8810,
            secret,
            forge_domain::ForgeBackendId::from_uuid(uuid::Uuid::from_u128(1)),
            forge_domain::OrchestrationIssuerId::from_uuid(uuid::Uuid::from_u128(2)),
        )?;
        let diagnostic = format!("{config:?} {:?}", IssuerAuth::new(secret));
        assert!(!diagnostic.contains(secret));
        assert!(!diagnostic.contains(&format!("{:?}", digest(secret))));
        Ok(())
    }
}
