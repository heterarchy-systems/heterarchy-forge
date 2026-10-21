//! Versioned wire envelope for requests, replies, and SSE event payloads.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::FORGE_API_VERSION;
use crate::error::ForgeError;

/// Inbound request envelope. The URL `{op}` segment must equal the body `op`;
/// mismatches are rejected as `InvalidInput` before admission.
#[must_use]
#[derive(Debug, Clone, Deserialize)]
pub struct RequestEnvelope {
    pub forge_api: u32,
    pub request_id: Uuid,
    pub op: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

impl RequestEnvelope {
    /// Envelope version check: this slice speaks exactly version 1.
    pub const fn version_ok(&self) -> bool {
        self.forge_api == FORGE_API_VERSION
    }
}

/// Success reply envelope. Version and request identity are always echoed.
#[must_use]
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SuccessEnvelope {
    pub forge_api: u32,
    pub request_id: Uuid,
    pub ok: bool,
    pub result: serde_json::Value,
}

/// Failure reply envelope. Version and request identity are always echoed.
#[must_use]
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FailureEnvelope {
    pub forge_api: u32,
    pub request_id: Uuid,
    pub ok: bool,
    pub error: ForgeError,
}

/// One reply union used by handlers before serialization.
#[must_use]
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum Reply {
    Success(SuccessEnvelope),
    Failure(FailureEnvelope),
}

impl Reply {
    pub fn success(request_id: Uuid, result: serde_json::Value) -> Self {
        Self::Success(SuccessEnvelope {
            forge_api: FORGE_API_VERSION,
            request_id,
            ok: true,
            result,
        })
    }

    pub fn failure(request_id: Uuid, error: &ForgeError) -> Self {
        Self::Failure(FailureEnvelope {
            forge_api: FORGE_API_VERSION,
            request_id,
            ok: false,
            error: error.clone(),
        })
    }
}

/// Serialized semantic event payload delivered on the page endpoint and over
/// SSE. The SSE event id is the durable sequence.
#[must_use]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SemanticEventDto {
    pub sequence: u64,
    pub kind: String,
    pub revision: i64,
    pub observed_at_ms: i64,
    pub digest: String,
    pub subjects: serde_json::Value,
}

/// Terminal in-stream hint emitted before a slow-consumer disconnect or a
/// stream-level failure. Cursor-neutral: it carries no event id.
#[must_use]
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StreamResyncHint {
    pub resync_required: bool,
    pub reason: String,
    pub high_water: Option<u64>,
}
