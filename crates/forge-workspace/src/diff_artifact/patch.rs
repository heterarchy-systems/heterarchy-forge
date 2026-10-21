//! Version 2 rendering of validated, bounded patch windows.

use std::io::{self, Write};

use forge_domain::{
    DiffChangeKind, DiffLineCount, DiffRenderKind, WorkspaceRelativePath, source_line_spans,
};
use similar::{Algorithm, ChangeTag, TextDiff, udiff::UnifiedDiffHunk};

use super::{
    BoundedWriter, DiffRenderError, MAX_DIFF_RENDERED_BYTES, MAX_DIFF_SOURCE_LINES,
    RenderedDiffEvidence, RenderedTextDiff, diff_headers, redact_line,
};
use crate::patch_review::{
    PatchReview, PatchReviewSide, advance_private_key_state, begins_private_key,
};

/// Render only windows retained from the exact validated source patch.
///
/// Coordinates refer to the complete source/result snapshots. Redaction keeps
/// every logical line, including key blocks that began outside a window.
pub fn render_patch_diff_evidence(
    path: &WorkspaceRelativePath,
    review: &PatchReview,
) -> Result<RenderedDiffEvidence, DiffRenderError> {
    if review.disposition().is_oversized() {
        return Ok(oversized());
    }
    let headers = diff_headers(path, DiffChangeKind::Modified)?;
    let mut output = BoundedWriter::new(MAX_DIFF_RENDERED_BYTES, 4_096);
    let mut additions = 0_u32;
    let mut deletions = 0_u32;
    let mut header_written = false;
    for window in review.windows() {
        let Some(old) = redact_side(window.source())? else {
            return Ok(oversized());
        };
        let Some(new) = redact_side(window.result())? else {
            return Ok(oversized());
        };
        let old_lines = line_slices(&old);
        let new_lines = line_slices(&new);
        let diff = TextDiff::configure()
            .algorithm(Algorithm::Patience)
            .diff_slices(&old_lines, &new_lines);
        let old_base = line_base(window.source())?;
        let new_base = line_base(window.result())?;
        for hunk in diff.unified_diff().iter_hunks() {
            let result = (|| {
                if !header_written {
                    writeln!(output, "--- {}\n+++ {}", headers.0, headers.1)?;
                    header_written = true;
                }
                write_hunk(&mut output, &hunk, old_base, new_base)
            })();
            if output.overflowed() {
                return Ok(oversized());
            }
            let (added, removed) = result.map_err(DiffRenderError::Render)?;
            additions = additions.saturating_add(added);
            deletions = deletions.saturating_add(removed);
        }
    }
    if !header_written && review.source_hash() != review.result_hash() {
        // Equal redacted lines must not imply that the source bytes were equal.
        writeln!(
            output,
            "--- {}\n+++ {}\n# Source bytes changed; differences are hidden by redaction.",
            headers.0, headers.1
        )
        .map_err(DiffRenderError::Render)?;
    }
    Ok(RenderedDiffEvidence::Text(RenderedTextDiff {
        bytes: output.into_inner(),
        additions: DiffLineCount::new(additions),
        deletions: DiffLineCount::new(deletions),
    }))
}

const fn oversized() -> RenderedDiffEvidence {
    RenderedDiffEvidence::SummaryOnly {
        render_kind: DiffRenderKind::Oversized,
    }
}

fn line_base(side: &PatchReviewSide) -> Result<usize, DiffRenderError> {
    usize::try_from(side.start_line().unwrap_or(1).saturating_sub(1))
        .map_err(|_| DiffRenderError::InvalidSourcePair)
}

fn line_slices(text: &str) -> Vec<&str> {
    source_line_spans(text.as_bytes())
        .map(|span| &text[span.start()..span.end()])
        .collect()
}

fn redact_side(side: &PatchReviewSide) -> Result<Option<String>, DiffRenderError> {
    if usize::try_from(side.line_count()).map_err(|_| DiffRenderError::InvalidSourcePair)?
        > MAX_DIFF_SOURCE_LINES
    {
        return Ok(None);
    }
    let text = std::str::from_utf8(side.bytes()).map_err(|_| DiffRenderError::InvalidSourcePair)?;
    let mut output = BoundedWriter::new(
        MAX_DIFF_RENDERED_BYTES,
        text.len().min(MAX_DIFF_RENDERED_BYTES),
    );
    let mut inside = side.private_key_in_progress();
    for span in source_line_spans(text.as_bytes()) {
        let line = &text[span.start()..span.end()];
        let (body, ending) = line_ending(line);
        let masked = inside || begins_private_key(line.as_bytes());
        inside = advance_private_key_state(inside, line.as_bytes());
        let result = if masked {
            write!(output, "[REDACTED PRIVATE KEY]{ending}")
        } else {
            // Strip and re-attach every supported delimiter so V1's line
            // redactor cannot accidentally swallow a lone-CR boundary.
            write!(output, "{}{ending}", redact_line(body))
        };
        if output.overflowed() {
            return Ok(None);
        }
        result.map_err(DiffRenderError::Render)?;
    }
    String::from_utf8(output.into_inner())
        .map(Some)
        .map_err(|_| DiffRenderError::InvalidSourcePair)
}

fn line_ending(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = line.strip_suffix('\n') {
        (body, "\n")
    } else if let Some(body) = line.strip_suffix('\r') {
        (body, "\r")
    } else {
        (line, "")
    }
}

fn write_hunk(
    output: &mut BoundedWriter,
    hunk: &UnifiedDiffHunk<'_, '_, '_, str>,
    old_base: usize,
    new_base: usize,
) -> io::Result<(u32, u32)> {
    let first = hunk
        .ops()
        .first()
        .ok_or_else(|| io::Error::other("empty patch hunk"))?;
    let last = hunk
        .ops()
        .last()
        .ok_or_else(|| io::Error::other("empty patch hunk"))?;
    let old_count = last.old_range().end - first.old_range().start;
    let new_count = last.new_range().end - first.new_range().start;
    let old_start = old_base + first.old_range().start + usize::from(old_count != 0);
    let new_start = new_base + first.new_range().start + usize::from(new_count != 0);
    writeln!(
        output,
        "@@ -{old_start},{old_count} +{new_start},{new_count} @@"
    )?;
    let mut added = 0_u32;
    let mut removed = 0_u32;
    for change in hunk.iter_changes() {
        match change.tag() {
            ChangeTag::Insert => added += 1,
            ChangeTag::Delete => removed += 1,
            ChangeTag::Equal => {}
        }
        write!(output, "{}{}", change.tag(), change.value())?;
        if !change.value().ends_with('\n') {
            writeln!(output)?;
            if change.value().ends_with('\r') {
                // Review artifacts preserve the CR byte and name its logical
                // delimiter explicitly; LF separates artifact display rows.
                writeln!(output, "\\ CR line ending")?;
            } else {
                writeln!(output, "\\ No newline at end of file")?;
            }
        }
    }
    Ok((added, removed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patch_review::build_patch_review;
    use forge_domain::{
        FileContentHash, FilePatch, FilePatchHunk, SourceLineRange, SourceRangeHash,
    };

    fn patch(
        source: &[u8],
        line: u64,
        replacement: &[u8],
    ) -> Result<PatchReview, Box<dyn std::error::Error>> {
        let span = source_line_spans(source)
            .nth(usize::try_from(line - 1)?)
            .ok_or("test line missing")?;
        let patch = FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(source).as_bytes()),
            vec![FilePatchHunk::new(
                SourceLineRange::new(line, line)?,
                SourceRangeHash::from_bytes(
                    *blake3::hash(&source[span.start()..span.end()]).as_bytes(),
                ),
                replacement.to_vec(),
            )?],
        )?;
        Ok(build_patch_review(source, &patch.compile(source)?))
    }

    fn render(review: &PatchReview) -> Result<RenderedDiffEvidence, Box<dyn std::error::Error>> {
        Ok(render_patch_diff_evidence(
            &WorkspaceRelativePath::new("source.rs".into())?,
            review,
        )?)
    }

    #[test]
    fn large_file_patch_keeps_absolute_hunk_coordinates_and_bounded_text()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::fmt::Write as _;
        let mut source = String::new();
        for line in 1..=12_000 {
            writeln!(source, "original source line {line}")?;
        }
        let review = patch(source.as_bytes(), 10_000, b"changed source line\n")?;
        let RenderedDiffEvidence::Text(text) = render(&review)? else {
            return Err("small patch lost text review".into());
        };
        let display = std::str::from_utf8(text.bytes())?;
        assert!(display.contains("@@ -9997,7 +9997,7 @@"));
        assert!(display.contains("-original source line 10000\n+changed source line\n"));
        assert!(!display.contains("original source line 1\n"));
        assert!(text.bytes().len() < 1_024);
        assert_eq!(text.additions(), DiffLineCount::new(1));
        assert_eq!(text.deletions(), DiffLineCount::new(1));
        Ok(())
    }

    #[test]
    fn private_key_start_outside_window_stays_redacted_without_shifting_public_lines()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut source = String::from("-----BEGIN PRIVATE KEY-----\n");
        for _ in 2..20 {
            source.push_str("private-secret-material\n");
        }
        source.push_str("-----END PRIVATE KEY-----\npublic old\nlast\n");
        let review = patch(source.as_bytes(), 21, b"public new\n")?;
        assert!(review.windows()[0].source().private_key_in_progress());
        let RenderedDiffEvidence::Text(text) = render(&review)? else {
            return Err("expected redacted text".into());
        };
        let display = std::str::from_utf8(text.bytes())?;
        assert!(display.contains("@@ -18,5 +18,5 @@"));
        assert!(display.contains("[REDACTED PRIVATE KEY]"));
        assert!(display.contains("-public old\n+public new\n"));
        assert!(!display.contains("private-secret-material"));
        Ok(())
    }

    #[test]
    fn cr_and_missing_terminal_newline_have_truthful_review_markers()
    -> Result<(), Box<dyn std::error::Error>> {
        let review = patch(b"one\rtwo\r", 2, b"TWO")?;
        let RenderedDiffEvidence::Text(text) = render(&review)? else {
            return Err("expected CR text".into());
        };
        let display = std::str::from_utf8(text.bytes())?;
        assert!(display.contains("@@ -1,2 +1,2 @@"));
        assert!(display.contains("\\ CR line ending"));
        assert!(display.contains("\\ No newline at end of file"));
        Ok(())
    }

    #[test]
    fn secret_only_edit_is_visible_without_disclosing_the_changed_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let review = patch(b"token = before-secret\n", 1, b"token = after-secret\n")?;
        let RenderedDiffEvidence::Text(text) = render(&review)? else {
            return Err("expected redaction notice".into());
        };
        let display = std::str::from_utf8(text.bytes())?;
        assert!(display.contains("differences are hidden by redaction"));
        assert!(!display.contains("before-secret"));
        assert!(!display.contains("after-secret"));
        Ok(())
    }

    #[test]
    fn deleting_all_output_has_a_zero_length_result_range() -> Result<(), Box<dyn std::error::Error>>
    {
        let review = patch(b"last line\n", 1, b"")?;
        let RenderedDiffEvidence::Text(text) = render(&review)? else {
            return Err("expected deletion text".into());
        };
        assert!(std::str::from_utf8(text.bytes())?.contains("@@ -1,1 +0,0 @@"));
        assert_eq!(text.additions(), DiffLineCount::new(0));
        assert_eq!(text.deletions(), DiffLineCount::new(1));
        Ok(())
    }

    #[test]
    fn rendered_byte_overflow_is_summary_without_truncated_text()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = vec![b'a'; 65_525];
        let replacement = vec![b'b'; 65_525];
        let review = patch(&source, 1, &replacement)?;
        assert!(review.disposition().is_ready());
        assert_eq!(render(&review)?, oversized());
        Ok(())
    }
}
