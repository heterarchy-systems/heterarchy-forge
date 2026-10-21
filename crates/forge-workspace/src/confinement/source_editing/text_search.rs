//! Literal source search with per-invocation byte and cooperative time bounds.

use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use forge_domain::{
    FileEntryKind, MAX_TEXT_SEARCH_PREVIEW_BYTES, MAX_TEXT_SEARCH_SCAN_ENTRIES, TextSearchMatch,
    TextSearchOptions, TextSearchQuery, TextSearchResult, source_line_spans,
};
use rustix::fs::fstat;

use super::{
    ConfinedFilesystemError, ConfinedWorkspace, MAX_TEXT_SEARCH_FILE_BYTES, join_components,
    open_regular_leaf, read_directory_entries, validate_source_path, walk_directories,
};

const MAX_TEXT_SEARCH_READ_BYTES: usize = 64 * 1024 * 1024;
const TEXT_SEARCH_DEADLINE: Duration = Duration::from_secs(5);
const SEARCH_READ_CHUNK_BYTES: usize = 16 * 1024;
const TEXT_SEARCH_PREVIEW_CONTEXT_BYTES: usize = MAX_TEXT_SEARCH_PREVIEW_BYTES / 3;

struct SearchBudget {
    remaining_bytes: usize,
    deadline: Instant,
}

impl SearchBudget {
    fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }
}

impl ConfinedWorkspace {
    /// Recursively search text files for a literal UTF-8 query. Symlinked and
    /// generated paths are never traversed; binary/non-UTF-8 files are skipped
    /// as non-source data. Traversal and response memory are bounded.
    pub fn text_search(
        &self,
        root: Option<&forge_domain::WorkspaceRelativePath>,
        query: &TextSearchQuery,
        options: TextSearchOptions,
    ) -> Result<TextSearchResult, ConfinedFilesystemError> {
        let mut budget = SearchBudget {
            remaining_bytes: MAX_TEXT_SEARCH_READ_BYTES,
            deadline: Instant::now() + TEXT_SEARCH_DEADLINE,
        };
        self.text_search_with_budget(root, query, options, &mut budget)
    }

    fn text_search_with_budget(
        &self,
        root: Option<&forge_domain::WorkspaceRelativePath>,
        query: &TextSearchQuery,
        options: TextSearchOptions,
        budget: &mut SearchBudget,
    ) -> Result<TextSearchResult, ConfinedFilesystemError> {
        self.ensure_root_for_source(false)?;
        let initial_components = if let Some(root) = root {
            validate_source_path(root)?;
            super::super::collect_components(root)?
        } else {
            Vec::new()
        };
        let mut pending = vec![initial_components];
        let mut matches = Vec::with_capacity(options.max_results());
        let mut scanned_entries = 0_usize;
        let mut scanned_files = 0_usize;
        let mut output_bytes = 0_usize;
        let mut truncated = false;

        'search: while let Some(components) = pending.pop() {
            if budget.expired() {
                truncated = true;
                break;
            }
            let directory = walk_directories(&self.root, &components, false)?;
            let (observations, directory_truncated, directory_scanned_entries) =
                read_directory_entries(&directory, MAX_TEXT_SEARCH_SCAN_ENTRIES, || {
                    budget.expired()
                })?;
            if directory_truncated {
                truncated = true;
            }
            scanned_entries = scanned_entries.saturating_add(directory_scanned_entries);
            if scanned_entries > MAX_TEXT_SEARCH_SCAN_ENTRIES {
                truncated = true;
                break;
            }
            let mut child_directories = Vec::new();
            for observation in observations {
                if scanned_entries > MAX_TEXT_SEARCH_SCAN_ENTRIES || budget.expired() {
                    truncated = true;
                    break 'search;
                }
                match observation.kind {
                    FileEntryKind::Directory => {
                        let mut child = components.clone();
                        child.push(observation.name);
                        child_directories.push(child);
                    }
                    FileEntryKind::RegularFile => {
                        let remaining_results = options.max_results().saturating_sub(matches.len());
                        if remaining_results == 0 {
                            truncated = true;
                            break;
                        }
                        let path = join_components(&components, &observation.name)?;
                        let Some(leaf) = open_regular_leaf(&directory, &observation.name)? else {
                            continue;
                        };
                        scanned_files = scanned_files.saturating_add(1);
                        let file_result = search_file(
                            leaf,
                            &path,
                            query,
                            remaining_results,
                            options.max_output_bytes(),
                            &mut output_bytes,
                            budget,
                        )?;
                        matches.extend(file_result.matches);
                        if file_result.truncated {
                            truncated = true;
                            break 'search;
                        }
                    }
                    FileEntryKind::SymbolicLink | FileEntryKind::Other => {}
                }
            }
            for child in child_directories.into_iter().rev() {
                pending.push(child);
            }
            if scanned_entries > MAX_TEXT_SEARCH_SCAN_ENTRIES
                || matches.len() >= options.max_results()
            {
                truncated = true;
                break;
            }
        }
        self.ensure_root_for_source(false)?;
        TextSearchResult::new(
            root.cloned(),
            matches,
            scanned_entries.min(MAX_TEXT_SEARCH_SCAN_ENTRIES),
            scanned_files,
            truncated,
        )
        .map_err(ConfinedFilesystemError::TextSearchResult)
    }
}

#[derive(Debug)]
struct SearchFileResult {
    matches: Vec<TextSearchMatch>,
    truncated: bool,
}

fn search_file(
    fd: OwnedFd,
    path: &forge_domain::WorkspaceRelativePath,
    query: &TextSearchQuery,
    max_results: usize,
    max_output_bytes: usize,
    output_bytes: &mut usize,
    budget: &mut SearchBudget,
) -> Result<SearchFileResult, ConfinedFilesystemError> {
    let Some(bytes) = read_search_file(fd, budget)? else {
        return Ok(SearchFileResult {
            matches: Vec::new(),
            truncated: true,
        });
    };
    if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
        return Ok(SearchFileResult {
            matches: Vec::new(),
            truncated: false,
        });
    }
    let mut matches = Vec::new();
    let mut truncated = false;
    let mut retained_output = *output_bytes;
    for (line_number, span) in source_line_spans(&bytes).enumerate() {
        if line_number % 256 == 0 && budget.expired() {
            return Ok(SearchFileResult {
                matches: Vec::new(),
                truncated: true,
            });
        }
        let line = &bytes[span.start()..span.end()];
        let line_without_eol = line.strip_suffix(b"\n").unwrap_or(line);
        let line_without_eol = line_without_eol
            .strip_suffix(b"\r")
            .unwrap_or(line_without_eol);
        let line_text = std::str::from_utf8(line_without_eol)
            .map_err(|_| ConfinedFilesystemError::SourceSearchNonUtf8)?;
        if !line_text.contains(query.as_str()) {
            continue;
        }
        let preview = bounded_preview(line_text, query.as_str());
        let cost = path.as_path().as_os_str().as_encoded_bytes().len()
            + line_number.to_string().len()
            + preview.len();
        let next_output =
            retained_output
                .checked_add(cost)
                .ok_or(ConfinedFilesystemError::OutputTooLarge {
                    actual: usize::MAX,
                    maximum: max_output_bytes,
                })?;
        if next_output > max_output_bytes {
            truncated = true;
            break;
        }
        retained_output = next_output;
        let line_number = u64::try_from(line_number + 1)
            .map_err(|_| ConfinedFilesystemError::SourceSearchLineOverflow)?;
        let item = TextSearchMatch::new(path.clone(), line_number, preview)
            .map_err(ConfinedFilesystemError::TextSearchMatch)?;
        matches.push(item);
        if matches.len() >= max_results {
            truncated = true;
            break;
        }
    }
    if budget.expired() {
        return Ok(SearchFileResult {
            matches: Vec::new(),
            truncated: true,
        });
    }
    *output_bytes = retained_output;
    Ok(SearchFileResult { matches, truncated })
}

/// Read a complete supported candidate, charging all bytes even for non-text.
/// `None` means the current file was incomplete; no partial match is publishable.
fn read_search_file(
    fd: OwnedFd,
    budget: &mut SearchBudget,
) -> Result<Option<Vec<u8>>, ConfinedFilesystemError> {
    if budget.expired() {
        return Ok(None);
    }
    let before = fstat(&fd).map_err(super::super::pre_syscall)?;
    let size =
        usize::try_from(before.st_size).map_err(|_| ConfinedFilesystemError::FileTooLarge {
            actual: usize::MAX,
            maximum: MAX_TEXT_SEARCH_FILE_BYTES,
        })?;
    if size > MAX_TEXT_SEARCH_FILE_BYTES {
        return Ok(Some(Vec::new()));
    }
    if size > budget.remaining_bytes {
        return Ok(None);
    }
    let mut file = File::from(fd);
    let mut bytes = Vec::with_capacity(size);
    let mut chunk = [0_u8; SEARCH_READ_CHUNK_BYTES];
    while bytes.len() < size {
        if budget.expired() {
            return Ok(None);
        }
        let limit = chunk.len().min(size - bytes.len());
        let read = match file.read(&mut chunk[..limit]) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(ConfinedFilesystemError::StdIo {
                    operation: super::super::FilesystemOperation::ReadSearchFile,
                    committed: false,
                    source,
                });
            }
        };
        if read == 0 {
            return Ok(None);
        }
        budget.remaining_bytes -= read;
        bytes.extend_from_slice(&chunk[..read]);
    }
    let after = fstat(&file).map_err(super::super::pre_syscall)?;
    if budget.expired() || before.st_size != after.st_size {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn bounded_preview(line: &str, query: &str) -> String {
    if line.len() <= MAX_TEXT_SEARCH_PREVIEW_BYTES {
        return line.to_owned();
    }
    let match_start = line.find(query).unwrap_or(0);
    let mut start = match_start.saturating_sub(TEXT_SEARCH_PREVIEW_CONTEXT_BYTES);
    let mut end = (match_start + query.len() + TEXT_SEARCH_PREVIEW_CONTEXT_BYTES).min(line.len());
    while start > 0 && !line.is_char_boundary(start) {
        start -= 1;
    }
    while end < line.len() && !line.is_char_boundary(end) {
        end += 1;
    }
    if end.saturating_sub(start) > MAX_TEXT_SEARCH_PREVIEW_BYTES {
        end = (start + MAX_TEXT_SEARCH_PREVIEW_BYTES).min(line.len());
        while end > start && !line.is_char_boundary(end) {
            end -= 1;
        }
    }
    line[start..end].to_owned()
}

#[cfg(test)]
mod tests;
