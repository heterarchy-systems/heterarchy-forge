//! Bounded, transient source-patch review windows.
//!
//! The source patch compiler owns validation and exact byte geometry.  This
//! module consumes that validated geometry to make small, line-oriented
//! windows suitable for a later redaction/rendering step.  It deliberately
//! does not persist or redact the bytes.  The builder is crate-private so a
//! review can only be made from a patch that has already crossed the workspace
//! validation boundary.

use std::fmt;

use forge_domain::{CompiledFilePatch, FileContentHash, SourceByteSpan, source_line_spans};

/// Number of unchanged lines retained on either side of each affected anchor.
pub const PATCH_REVIEW_CONTEXT_LINES: usize = 3;

/// Aggregate bound for raw source and result bytes retained by one review.
pub const MAX_PATCH_REVIEW_BYTES: usize = 128 * 1024;

/// Whether transient review windows were retained or exceeded their bound.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchReviewDisposition {
    /// Every selected window fits within [`MAX_PATCH_REVIEW_BYTES`].
    Ready,
    /// The validated patch remains valid, but its review windows do not fit.
    Oversized,
}

impl PatchReviewDisposition {
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    pub const fn is_oversized(self) -> bool {
        matches!(self, Self::Oversized)
    }
}

/// A bounded line-oriented view of one review side.
///
/// `start_line` is absent when the side has no addressable retained line,
/// such as an all-output-deleted result.  In particular, an empty replacement
/// never manufactures a one-based [`forge_domain::SourceLineRange`].
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct PatchReviewSide {
    start_line: Option<u64>,
    line_count: u64,
    bytes: Vec<u8>,
    private_key_in_progress: bool,
}

impl PatchReviewSide {
    pub const fn start_line(&self) -> Option<u64> {
        self.start_line
    }

    pub const fn line_count(&self) -> u64 {
        self.line_count
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn private_key_in_progress(&self) -> bool {
        self.private_key_in_progress
    }

    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for PatchReviewSide {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PatchReviewSide")
            .field("start_line", &self.start_line)
            .field("line_count", &self.line_count)
            .field("byte_len", &self.bytes.len())
            .field("private_key_in_progress", &self.private_key_in_progress)
            .finish()
    }
}

/// One merged review group containing source and compiled-result windows.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct PatchReviewWindow {
    group_ordinal: usize,
    hunk_ordinals: Vec<usize>,
    source: PatchReviewSide,
    result: PatchReviewSide,
}

impl PatchReviewWindow {
    pub const fn group_ordinal(&self) -> usize {
        self.group_ordinal
    }

    pub fn hunk_ordinals(&self) -> &[usize] {
        &self.hunk_ordinals
    }

    pub const fn source(&self) -> &PatchReviewSide {
        &self.source
    }

    pub const fn result(&self) -> &PatchReviewSide {
        &self.result
    }
}

impl fmt::Debug for PatchReviewWindow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PatchReviewWindow")
            .field("group_ordinal", &self.group_ordinal)
            .field("hunk_ordinals", &self.hunk_ordinals)
            .field("source", &self.source)
            .field("result", &self.result)
            .finish()
    }
}

/// Bounded, non-durable review projection for one validated source patch.
#[must_use]
#[derive(Clone, PartialEq, Eq)]
pub struct PatchReview {
    disposition: PatchReviewDisposition,
    source_hash: FileContentHash,
    result_hash: FileContentHash,
    windows: Vec<PatchReviewWindow>,
}

impl PatchReview {
    pub const fn disposition(&self) -> PatchReviewDisposition {
        self.disposition
    }

    pub const fn source_hash(&self) -> FileContentHash {
        self.source_hash
    }

    pub const fn result_hash(&self) -> FileContentHash {
        self.result_hash
    }

    pub fn windows(&self) -> &[PatchReviewWindow] {
        &self.windows
    }
}

impl fmt::Debug for PatchReview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PatchReview")
            .field("disposition", &self.disposition)
            .field("source_hash", &self.source_hash)
            .field("result_hash", &self.result_hash)
            .field("windows", &self.windows)
            .finish()
    }
}

/// Build transient review windows from a validated compiled patch.
///
/// The caller must pass the exact source snapshot used to compile `compiled`.
/// The compiler's geometry is the authority for hunk locations; this function
/// never searches for replacement text or applies a line-count delta.  A
/// valid patch may produce [`PatchReviewDisposition::Oversized`], which is a
/// review projection outcome rather than a patch rejection.
pub(crate) fn build_patch_review(source: &[u8], compiled: &CompiledFilePatch) -> PatchReview {
    let geometry = compiled.hunk_geometry();
    let source_spans: Vec<_> = geometry.iter().map(|hunk| hunk.source_span()).collect();
    let result_spans: Vec<_> = geometry.iter().map(|hunk| hunk.result_span()).collect();
    let source_plans = collect_side_plans(source, &source_spans);
    let result_plans = collect_side_plans(compiled.content(), &result_spans);
    let hunk_ordinals: Vec<_> = geometry.iter().map(|hunk| hunk.ordinal()).collect();
    let groups = merge_groups(&source_plans, &result_plans, &hunk_ordinals);

    let mut retained_bytes = 0_usize;
    let Some(source_sides) =
        retain_side_windows(source, &groups, Side::Source, &mut retained_bytes)
    else {
        return oversized_review(compiled);
    };
    let Some(result_sides) = retain_side_windows(
        compiled.content(),
        &groups,
        Side::Result,
        &mut retained_bytes,
    ) else {
        return oversized_review(compiled);
    };

    let windows = groups
        .into_iter()
        .zip(source_sides)
        .zip(result_sides)
        .enumerate()
        .map(
            |(group_ordinal, ((group, source), result))| PatchReviewWindow {
                group_ordinal,
                hunk_ordinals: group.hunk_ordinals,
                source,
                result,
            },
        )
        .collect();

    PatchReview {
        disposition: PatchReviewDisposition::Ready,
        source_hash: compiled.source_hash(),
        result_hash: compiled.result_hash(),
        windows,
    }
}

fn oversized_review(compiled: &CompiledFilePatch) -> PatchReview {
    PatchReview {
        disposition: PatchReviewDisposition::Oversized,
        source_hash: compiled.source_hash(),
        result_hash: compiled.result_hash(),
        windows: Vec::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LineInterval {
    start: usize,
    end: usize,
}

impl LineInterval {
    const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    fn touches(self, other: Self) -> bool {
        self.start <= other.end.saturating_add(1) && other.start <= self.end.saturating_add(1)
    }

    fn union(self, other: Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineAnchor {
    Lines { start: usize, end: usize },
    Boundary { insertion: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SidePlan {
    anchor: LineAnchor,
    context: Option<LineInterval>,
}

#[derive(Debug)]
struct SidePlans {
    plans: Vec<SidePlan>,
}

#[derive(Debug)]
struct ReviewGroupPlan {
    hunk_ordinals: Vec<usize>,
    source: Option<LineInterval>,
    result: Option<LineInterval>,
}

#[derive(Debug, Clone, Copy)]
enum Side {
    Source,
    Result,
}

impl Side {
    const fn interval(self, group: &ReviewGroupPlan) -> Option<LineInterval> {
        match self {
            Self::Source => group.source,
            Self::Result => group.result,
        }
    }
}

fn collect_side_plans(bytes: &[u8], spans: &[SourceByteSpan]) -> SidePlans {
    let mut plans = vec![
        SidePlan {
            anchor: LineAnchor::Boundary { insertion: 0 },
            context: None,
        };
        spans.len()
    ];
    let mut lines = source_line_spans(bytes);
    let mut current = lines.next();
    let mut line_index = 0_usize;

    for (hunk_index, span) in spans.iter().copied().enumerate() {
        if span.is_empty() {
            while current.is_some_and(|line| line.end() <= span.start()) {
                current = lines.next();
                line_index = line_index.saturating_add(1);
            }
            let anchor = match current {
                Some(line) if span.start() >= line.start() && span.start() < line.end() => {
                    LineAnchor::Lines {
                        start: line_index,
                        end: line_index,
                    }
                }
                _ => LineAnchor::Boundary {
                    insertion: line_index,
                },
            };
            plans[hunk_index].anchor = anchor;
        } else {
            while current.is_some_and(|line| line.end() <= span.start()) {
                current = lines.next();
                line_index = line_index.saturating_add(1);
            }

            let mut first = None;
            let mut last = None;
            while let Some(line) = current {
                if line.start() >= span.end() {
                    break;
                }
                if line.end() > span.start() {
                    first.get_or_insert(line_index);
                    last = Some(line_index);
                }
                current = lines.next();
                line_index = line_index.saturating_add(1);
            }
            plans[hunk_index].anchor = match (first, last) {
                (Some(start), Some(end)) => LineAnchor::Lines { start, end },
                _ => LineAnchor::Boundary {
                    insertion: line_index,
                },
            };
        }
    }

    let total_lines = line_index.saturating_add(usize::from(current.is_some())) + lines.count();
    for plan in &mut plans {
        plan.context = context_interval(plan.anchor, total_lines);
    }
    SidePlans { plans }
}

fn context_interval(anchor: LineAnchor, total_lines: usize) -> Option<LineInterval> {
    if total_lines == 0 {
        return None;
    }
    match anchor {
        LineAnchor::Lines { start, end } => Some(LineInterval::new(
            start.saturating_sub(PATCH_REVIEW_CONTEXT_LINES),
            end.saturating_add(PATCH_REVIEW_CONTEXT_LINES)
                .min(total_lines.saturating_sub(1)),
        )),
        LineAnchor::Boundary { insertion } => Some(LineInterval::new(
            insertion.saturating_sub(PATCH_REVIEW_CONTEXT_LINES),
            insertion
                .saturating_add(PATCH_REVIEW_CONTEXT_LINES)
                .min(total_lines.saturating_sub(1)),
        )),
    }
}

fn merge_groups(
    source: &SidePlans,
    result: &SidePlans,
    hunk_ordinals: &[usize],
) -> Vec<ReviewGroupPlan> {
    let mut groups = Vec::with_capacity(hunk_ordinals.len());
    for (hunk_index, ordinal) in hunk_ordinals.iter().copied().enumerate() {
        let mut candidate = ReviewGroupPlan {
            hunk_ordinals: vec![ordinal],
            source: source.plans[hunk_index].context,
            result: result.plans[hunk_index].context,
        };
        let mut group_index = 0_usize;
        while group_index < groups.len() {
            if groups_touch(&candidate, &groups[group_index]) {
                let existing = groups.remove(group_index);
                merge_group(&mut candidate, existing);
            } else {
                group_index += 1;
            }
        }
        groups.push(candidate);
    }
    groups.sort_by_key(|group| group.hunk_ordinals.first().copied().unwrap_or(usize::MAX));
    groups
}

fn groups_touch(left: &ReviewGroupPlan, right: &ReviewGroupPlan) -> bool {
    left.source
        .is_some_and(|left| right.source.is_some_and(|right| left.touches(right)))
        || left
            .result
            .is_some_and(|left| right.result.is_some_and(|right| left.touches(right)))
}

fn merge_group(target: &mut ReviewGroupPlan, other: ReviewGroupPlan) {
    target.source = union_optional(target.source, other.source);
    target.result = union_optional(target.result, other.result);
    target.hunk_ordinals.extend(other.hunk_ordinals);
    target.hunk_ordinals.sort_unstable();
}

fn union_optional(left: Option<LineInterval>, right: Option<LineInterval>) -> Option<LineInterval> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.union(right)),
        (left @ Some(_), None) | (None, left @ Some(_)) => left,
        (None, None) => None,
    }
}

fn retain_side_windows(
    bytes: &[u8],
    groups: &[ReviewGroupPlan],
    side: Side,
    retained_bytes: &mut usize,
) -> Option<Vec<PatchReviewSide>> {
    let mut windows: Vec<_> = groups
        .iter()
        .map(|_| PatchReviewSide {
            start_line: None,
            line_count: 0,
            bytes: Vec::new(),
            private_key_in_progress: false,
        })
        .collect();
    let mut targets: Vec<_> = groups
        .iter()
        .enumerate()
        .filter_map(|(group_index, group)| {
            Side::interval(side, group).map(|interval| (group_index, interval))
        })
        .collect();
    targets.sort_by_key(|(_, interval)| (interval.start, interval.end));

    let mut target_index = 0_usize;
    let mut private_key_in_progress = false;
    for (line_index, line) in source_line_spans(bytes).enumerate() {
        while targets
            .get(target_index)
            .is_some_and(|(_, interval)| line_index > interval.end)
        {
            target_index += 1;
        }

        if let Some((group_index, interval)) = targets.get(target_index).copied()
            && line_index >= interval.start
            && line_index <= interval.end
        {
            if line_index == interval.start {
                windows[group_index].start_line = Some(line_index as u64 + 1);
                windows[group_index].private_key_in_progress = private_key_in_progress;
            }
            let line_bytes = &bytes[line.start()..line.end()];
            let next = (*retained_bytes).checked_add(line_bytes.len())?;
            if next > MAX_PATCH_REVIEW_BYTES {
                return None;
            }
            windows[group_index].bytes.extend_from_slice(line_bytes);
            windows[group_index].line_count = windows[group_index].line_count.saturating_add(1);
            *retained_bytes = next;
        }

        private_key_in_progress =
            advance_private_key_state(private_key_in_progress, &bytes[line.start()..line.end()]);
    }
    Some(windows)
}

pub(crate) fn advance_private_key_state(inside: bool, line: &[u8]) -> bool {
    if inside {
        if ends_private_key(line) {
            return false;
        }
        return true;
    }
    begins_private_key(line) && !ends_private_key(line)
}

pub(crate) fn begins_private_key(line: &[u8]) -> bool {
    contains_ascii_case_insensitive(line, b"-----BEGIN ")
        && contains_ascii_case_insensitive(line, b"PRIVATE KEY-----")
}

fn ends_private_key(line: &[u8]) -> bool {
    contains_ascii_case_insensitive(line, b"-----END ")
        && contains_ascii_case_insensitive(line, b"PRIVATE KEY-----")
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forge_domain::{FilePatch, FilePatchHunk, SourceLineRange, SourceRangeHash};

    fn compiled_patch(
        source: &[u8],
        hunks: &[(u64, u64, &[u8])],
    ) -> Result<CompiledFilePatch, Box<dyn std::error::Error>> {
        let lines: Vec<_> = source_line_spans(source).collect();
        let patch_hunks = hunks
            .iter()
            .map(|(start_line, end_line, replacement)| {
                let start = usize::try_from(start_line.saturating_sub(1))?;
                let end = usize::try_from(*end_line)?;
                let source_start = lines[start].start();
                let source_end = lines[end - 1].end();
                Ok(FilePatchHunk::new(
                    SourceLineRange::new(*start_line, *end_line)?,
                    SourceRangeHash::from_bytes(
                        *blake3::hash(&source[source_start..source_end]).as_bytes(),
                    ),
                    replacement.to_vec(),
                )?)
            })
            .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
        Ok(FilePatch::new(
            FileContentHash::from_bytes(*blake3::hash(source).as_bytes()),
            patch_hunks,
        )?
        .compile(source)?)
    }

    fn line_source(line: usize) -> Vec<u8> {
        format!("line-{line}\n").into_bytes()
    }

    #[test]
    fn sparse_hunks_retain_small_source_and_result_windows()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut source = Vec::new();
        for line in 1..=256 {
            source.extend_from_slice(&line_source(line));
        }
        let compiled = compiled_patch(
            &source,
            &[
                (10, 10, b"changed-10\n"),
                (120, 120, b"changed-120\n"),
                (240, 240, b"changed-240\n"),
            ],
        )?;
        let review = build_patch_review(&source, &compiled);
        assert_eq!(review.disposition(), PatchReviewDisposition::Ready);
        assert_eq!(review.windows().len(), 3);
        assert_eq!(review.windows()[0].hunk_ordinals(), &[0]);
        assert_eq!(review.windows()[1].hunk_ordinals(), &[1]);
        assert_eq!(review.windows()[2].hunk_ordinals(), &[2]);
        assert_eq!(review.windows()[0].source().start_line(), Some(7));
        assert_eq!(review.windows()[0].source().line_count(), 7);
        assert!(review.windows().iter().all(|window| {
            window.source().bytes().len() < source.len()
                && window.result().bytes().len() < compiled.content().len()
        }));
        Ok(())
    }

    #[test]
    fn newline_dense_source_keeps_raw_review_memory_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"x\n".repeat(200_000);
        let compiled = compiled_patch(
            &source,
            &[
                (2, 2, b"two\n"),
                (100_000, 100_000, b"middle\n"),
                (199_999, 199_999, b"last\n"),
            ],
        )?;
        let review = build_patch_review(&source, &compiled);
        assert_eq!(review.disposition(), PatchReviewDisposition::Ready);
        let retained: usize = review
            .windows()
            .iter()
            .map(|window| window.source().bytes().len() + window.result().bytes().len())
            .sum();
        assert!(retained <= MAX_PATCH_REVIEW_BYTES);
        assert!(retained < source.len() / 100);
        Ok(())
    }

    #[test]
    fn groups_merge_when_either_side_context_touches() {
        let source = SidePlans {
            plans: vec![
                SidePlan {
                    anchor: LineAnchor::Boundary { insertion: 0 },
                    context: Some(LineInterval::new(0, 1)),
                },
                SidePlan {
                    anchor: LineAnchor::Boundary { insertion: 10 },
                    context: Some(LineInterval::new(10, 11)),
                },
            ],
        };
        let result = SidePlans {
            plans: vec![
                SidePlan {
                    anchor: LineAnchor::Boundary { insertion: 0 },
                    context: Some(LineInterval::new(0, 1)),
                },
                SidePlan {
                    anchor: LineAnchor::Boundary { insertion: 2 },
                    context: Some(LineInterval::new(2, 3)),
                },
            ],
        };
        let groups = merge_groups(&source, &result, &[0, 1]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].hunk_ordinals, vec![0, 1]);

        let source = SidePlans {
            plans: vec![
                SidePlan {
                    anchor: LineAnchor::Boundary { insertion: 0 },
                    context: Some(LineInterval::new(0, 1)),
                },
                SidePlan {
                    anchor: LineAnchor::Boundary { insertion: 2 },
                    context: Some(LineInterval::new(2, 3)),
                },
            ],
        };
        let result = SidePlans {
            plans: vec![
                SidePlan {
                    anchor: LineAnchor::Boundary { insertion: 0 },
                    context: Some(LineInterval::new(0, 1)),
                },
                SidePlan {
                    anchor: LineAnchor::Boundary { insertion: 10 },
                    context: Some(LineInterval::new(10, 11)),
                },
            ],
        };
        let groups = merge_groups(&source, &result, &[0, 1]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].hunk_ordinals, vec![0, 1]);
    }

    #[test]
    fn adjacent_hunks_keep_joined_result_bytes_in_one_group()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"one\ntwo\nthree\n";
        let compiled = compiled_patch(source, &[(1, 1, b"A"), (2, 2, b"B")])?;
        assert_eq!(compiled.content(), b"ABthree\n");
        let review = build_patch_review(source, &compiled);
        assert_eq!(review.disposition(), PatchReviewDisposition::Ready);
        assert_eq!(review.windows().len(), 1);
        assert_eq!(review.windows()[0].hunk_ordinals(), &[0, 1]);
        assert_eq!(review.windows()[0].result().bytes(), b"ABthree\n");
        Ok(())
    }

    #[test]
    fn mixed_endings_suffix_join_and_eof_deletion_keep_exact_line_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"one\r\ntwo\rthree\nlast";
        let compiled = compiled_patch(source, &[(2, 2, b"TWO")])?;
        let review = build_patch_review(source, &compiled);
        assert_eq!(review.disposition(), PatchReviewDisposition::Ready);
        assert_eq!(review.windows().len(), 1);
        assert_eq!(review.windows()[0].source().start_line(), Some(1));
        assert_eq!(review.windows()[0].source().line_count(), 4);
        assert_eq!(
            review.windows()[0].result().bytes(),
            b"one\r\nTWOthree\nlast"
        );

        let eof_source = b"one\ntwo\n";
        let eof_compiled = compiled_patch(eof_source, &[(2, 2, b"")])?;
        let eof_review = build_patch_review(eof_source, &eof_compiled);
        assert_eq!(eof_review.windows().len(), 1);
        assert_eq!(eof_review.windows()[0].result().start_line(), Some(1));
        assert_eq!(eof_review.windows()[0].result().line_count(), 1);
        Ok(())
    }

    #[test]
    fn all_output_deleted_has_no_fabricated_result_line() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = b"only line\n";
        let compiled = compiled_patch(source, &[(1, 1, b"")])?;
        assert!(compiled.content().is_empty());
        let review = build_patch_review(source, &compiled);
        assert_eq!(review.disposition(), PatchReviewDisposition::Ready);
        let result = review.windows()[0].result();
        assert_eq!(result.start_line(), None);
        assert_eq!(result.line_count(), 0);
        assert!(result.bytes().is_empty());
        assert!(!result.private_key_in_progress());
        Ok(())
    }

    #[test]
    fn pem_state_entering_window_is_recorded_without_allocating_marker_text()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = b"-----BEGIN PRIVATE KEY-----\nsecret-1\nsecret-2\nsecret-3\n-----END PRIVATE KEY-----\nsafe\nchanged\ntrailer\n";
        let compiled = compiled_patch(source, &[(7, 7, b"changed-again\n")])?;
        let review = build_patch_review(source, &compiled);
        let window = &review.windows()[0];
        assert_eq!(window.source().start_line(), Some(4));
        assert!(window.source().private_key_in_progress());
        assert!(window.result().private_key_in_progress());
        assert!(format!("{review:?}").contains("byte_len"));
        assert!(!format!("{review:?}").contains("secret-1"));
        Ok(())
    }

    #[test]
    fn oversized_review_is_explicit_and_does_not_reject_valid_patch()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = vec![b'x'; MAX_PATCH_REVIEW_BYTES + 1];
        let compiled = compiled_patch(&source, &[(1, 1, &source)])?;
        let review = build_patch_review(&source, &compiled);
        assert_eq!(review.disposition(), PatchReviewDisposition::Oversized);
        assert!(review.windows().is_empty());
        assert_eq!(review.source_hash(), compiled.source_hash());
        assert_eq!(review.result_hash(), compiled.result_hash());
        Ok(())
    }
}
