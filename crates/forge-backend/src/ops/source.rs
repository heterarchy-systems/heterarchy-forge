//! Typed source-read HTTP adapter inputs and projections.
//!
//! This module owns only wire conversion and the synchronous typed
//! `forge-control` calls. Workspace confinement, Activity authorization, and
//! filesystem bounds remain in Forge control and the confined workspace
//! adapter.

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use forge_control::{
    FileActivityScope, FileListRequest, FileListResult, FileReadSliceRequest, FileReadSliceResult,
    ForgeControlClient, ResolvedWorkspaceScope, TextSearchRequest, TextSearchResult,
};
use forge_domain::{
    FileEntryKind, FileListOptions, MAX_WORKSPACE_RELATIVE_PATH_BYTES, SourceEol, SourceLineRange,
    TextSearchOptions, TextSearchQuery, WorkspaceRelativePath,
};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{ActivityDto, ScopeDto, decode_approval_activity, decode_scope};
use crate::error::ForgeError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileListBody {
    scope: ScopeDto,
    activity: ActivityDto,
    directory_base64: Option<String>,
    max_results: Option<u32>,
    max_output_bytes: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TextSearchBody {
    scope: ScopeDto,
    activity: ActivityDto,
    root_base64: Option<String>,
    query: String,
    max_results: Option<u32>,
    max_output_bytes: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileReadSliceBody {
    scope: ScopeDto,
    activity: ActivityDto,
    path_base64: String,
    start_line: u64,
    end_line: u64,
}

/// Parse one bounded directory-list request from the HTTP payload.
pub(super) fn parse_file_list(value: &Value) -> Result<FileListRequest, ForgeError> {
    let body: FileListBody = super::parse_body(value, "file.list payload is invalid")?;
    let options = file_list_options(body.max_results, body.max_output_bytes)?;
    Ok(FileListRequest {
        scope: decode_scope(&body.scope)?,
        activity: decode_file_activity(&body.activity)?,
        directory: body
            .directory_base64
            .as_deref()
            .map(decode_relative_path)
            .transpose()?,
        options,
    })
}

/// Parse one bounded literal text-search request from the HTTP payload.
pub(super) fn parse_text_search(value: &Value) -> Result<TextSearchRequest, ForgeError> {
    let body: TextSearchBody = super::parse_body(value, "text.search payload is invalid")?;
    let options = text_search_options(body.max_results, body.max_output_bytes)?;
    Ok(TextSearchRequest {
        scope: decode_scope(&body.scope)?,
        activity: decode_file_activity(&body.activity)?,
        root: body
            .root_base64
            .as_deref()
            .map(decode_relative_path)
            .transpose()?,
        query: TextSearchQuery::new(body.query)
            .map_err(|_| ForgeError::invalid_input("text.search query is invalid"))?,
        options,
    })
}

/// Parse one bounded exact line-range source read from the HTTP payload.
pub(super) fn parse_file_read_slice(value: &Value) -> Result<FileReadSliceRequest, ForgeError> {
    let body: FileReadSliceBody = super::parse_body(value, "file.read_slice payload is invalid")?;
    Ok(FileReadSliceRequest {
        scope: decode_scope(&body.scope)?,
        activity: decode_file_activity(&body.activity)?,
        path: decode_relative_path(&body.path_base64)?,
        line_range: SourceLineRange::new(body.start_line, body.end_line)
            .map_err(|_| ForgeError::invalid_input("file.read_slice line range is invalid"))?,
    })
}

/// Execute a typed confined directory listing and project its bounded result.
pub(super) fn execute_file_list(
    client: &ForgeControlClient,
    request: &FileListRequest,
) -> Result<Value, ForgeError> {
    let result = client
        .file_list(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    file_list_json(&result)
}

/// Execute a typed confined literal text search and project its bounded result.
pub(super) fn execute_text_search(
    client: &ForgeControlClient,
    request: &TextSearchRequest,
) -> Result<Value, ForgeError> {
    let result = client
        .text_search(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    text_search_json(&result)
}

/// Execute a typed confined source slice and preserve exact UTF-8/hash/EOL
/// metadata in the JSON projection.
pub(super) fn execute_file_read_slice(
    client: &ForgeControlClient,
    request: &FileReadSliceRequest,
) -> Result<Value, ForgeError> {
    let result = client
        .file_read_slice(request.clone())
        .map_err(|error| super::forge_error_of_client(&error))?;
    file_read_slice_json(&result)
}

fn decode_file_activity(activity: &ActivityDto) -> Result<FileActivityScope, ForgeError> {
    let activity = decode_approval_activity(activity)?;
    Ok(FileActivityScope {
        activity_id: activity.activity_id,
        runtime_instance_id: activity.runtime_instance_id,
        observed_at: activity.observed_at,
    })
}

fn file_list_options(
    max_results: Option<u32>,
    max_output_bytes: Option<u32>,
) -> Result<FileListOptions, ForgeError> {
    let defaults = FileListOptions::default();
    FileListOptions::new(
        max_results
            .map(usize::try_from)
            .transpose()
            .map_err(|_| ForgeError::invalid_input("file.list max_results is invalid"))?
            .unwrap_or(defaults.max_results()),
        max_output_bytes
            .map(usize::try_from)
            .transpose()
            .map_err(|_| ForgeError::invalid_input("file.list max_output_bytes is invalid"))?
            .unwrap_or(defaults.max_output_bytes()),
    )
    .map_err(|_| ForgeError::invalid_input("file.list bounds are invalid"))
}

fn text_search_options(
    max_results: Option<u32>,
    max_output_bytes: Option<u32>,
) -> Result<TextSearchOptions, ForgeError> {
    let defaults = TextSearchOptions::default();
    TextSearchOptions::new(
        max_results
            .map(usize::try_from)
            .transpose()
            .map_err(|_| ForgeError::invalid_input("text.search max_results is invalid"))?
            .unwrap_or(defaults.max_results()),
        max_output_bytes
            .map(usize::try_from)
            .transpose()
            .map_err(|_| ForgeError::invalid_input("text.search max_output_bytes is invalid"))?
            .unwrap_or(defaults.max_output_bytes()),
    )
    .map_err(|_| ForgeError::invalid_input("text.search bounds are invalid"))
}

pub(super) fn decode_relative_path(value: &str) -> Result<WorkspaceRelativePath, ForgeError> {
    if value.is_empty() || value.len() > base64_url_no_pad_len(MAX_WORKSPACE_RELATIVE_PATH_BYTES) {
        return Err(ForgeError::invalid_input("source path token is invalid"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ForgeError::invalid_input("source path token is invalid"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(ForgeError::invalid_input(
            "source path token is not canonical",
        ));
    }
    WorkspaceRelativePath::new(PathBuf::from(OsString::from_vec(bytes)))
        .map_err(|_| ForgeError::invalid_input("source path is not confined"))
}

pub(super) fn encode_relative_path(path: &WorkspaceRelativePath) -> String {
    URL_SAFE_NO_PAD.encode(path.as_path().as_os_str().as_bytes())
}

const fn base64_url_no_pad_len(byte_count: usize) -> usize {
    let full_triplets = (byte_count / 3) * 4;
    let remainder = byte_count % 3;
    full_triplets + if remainder == 0 { 0 } else { remainder + 1 }
}

pub(crate) fn scope_json(scope: &ResolvedWorkspaceScope) -> Result<Value, ForgeError> {
    let relative_root = scope
        .locator()
        .relative_root()
        .to_str()
        .ok_or_else(ForgeError::internal)?;
    Ok(json!({
        "workspace_id": scope.workspace_id().into_uuid(),
        "workspace_revision": scope.workspace_revision().get(),
        "locator": {
            "location_id": scope.locator().location_id().into_uuid(),
            "expected_revision": scope.locator().expected_revision().get(),
            "relative_root": relative_root,
        },
    }))
}

fn activity_json(activity_id: forge_domain::ActivityId) -> Value {
    json!(activity_id.into_uuid())
}

fn file_list_json(result: &FileListResult) -> Result<Value, ForgeError> {
    Ok(json!({
        "scope": scope_json(result.scope())?,
        "activity_id": activity_json(result.activity_id()),
        "directory_base64": result.directory().map(encode_relative_path),
        "entries": result.entries().iter().map(file_list_entry_json).collect::<Vec<_>>(),
        "scanned_entries": result.scanned_entries(),
        "truncated": result.truncated(),
    }))
}

fn file_list_entry_json(entry: &forge_domain::FileListEntry) -> Value {
    json!({
        "path_base64": encode_relative_path(entry.path()),
        "kind": file_entry_kind_json(entry.kind()),
        "size_bytes": entry.size().map(forge_domain::FileByteCount::get),
    })
}

fn file_entry_kind_json(kind: FileEntryKind) -> &'static str {
    match kind {
        FileEntryKind::Directory => "directory",
        FileEntryKind::RegularFile => "regular_file",
        FileEntryKind::SymbolicLink => "symbolic_link",
        FileEntryKind::Other => "other",
    }
}

fn text_search_json(result: &TextSearchResult) -> Result<Value, ForgeError> {
    Ok(json!({
        "scope": scope_json(result.scope())?,
        "activity_id": activity_json(result.activity_id()),
        "root_base64": result.root().map(encode_relative_path),
        "matches": result.matches().iter().map(|entry| json!({
            "path_base64": encode_relative_path(entry.path()),
            "line": entry.line(),
            "preview": entry.preview(),
        })).collect::<Vec<_>>(),
        "scanned_entries": result.scanned_entries(),
        "scanned_files": result.scanned_files(),
        "truncated": result.truncated(),
    }))
}

fn file_read_slice_json(result: &FileReadSliceResult) -> Result<Value, ForgeError> {
    let content = std::str::from_utf8(result.content()).map_err(|_| ForgeError::internal())?;
    Ok(json!({
        "scope": scope_json(result.scope())?,
        "activity_id": activity_json(result.activity_id()),
        "path_base64": encode_relative_path(result.path()),
        "content": content,
        "whole_file_hash": result.whole_file_hash().to_string(),
        "range_hash": result.range_hash().to_string(),
        "line_hashes": result.line_hashes().iter().map(ToString::to_string).collect::<Vec<_>>(),
        "start_line": result.line_range().start_line(),
        "end_line": result.line_range().end_line(),
        "total_lines": result.total_lines(),
        "eol": source_eol_json(result.eol()),
        "has_final_newline": result.has_final_newline(),
    }))
}

fn source_eol_json(value: SourceEol) -> &'static str {
    match value {
        SourceEol::Lf => "lf",
        SourceEol::CrLf => "crlf",
        SourceEol::Cr => "cr",
        SourceEol::Mixed => "mixed",
        SourceEol::None => "none",
    }
}
