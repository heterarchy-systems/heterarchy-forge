use std::fs;
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::WorkspaceStateLayout;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn workspace(label: &str) -> Result<(PathBuf, ConfinedWorkspace), Box<dyn std::error::Error>> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!("forge-search-{label}-{unique}"));
    fs::create_dir_all(&root)?;
    WorkspaceStateLayout::initialize(&root)?;
    let layout = WorkspaceStateLayout::inspect_existing(&root)?.ok_or("missing layout")?;
    let confined = ConfinedWorkspace::open(&layout)?;
    Ok((root, confined))
}

fn budget(bytes: usize) -> SearchBudget {
    SearchBudget {
        remaining_bytes: bytes,
        deadline: Instant::now() + Duration::from_secs(300),
    }
}

#[test]
fn text_search_bounds_total_bytes_even_for_rejected_binary_candidates() -> TestResult {
    let (root, confined) = workspace("aggregate-budget")?;
    for index in 0..5 {
        let file = fs::File::create(root.join(format!("binary-{index}.dat")))?;
        file.set_len(u64::try_from(MAX_TEXT_SEARCH_FILE_BYTES)?)?;
    }
    let query = TextSearchQuery::new("not-present".to_owned())?;
    let mut budget = budget(MAX_TEXT_SEARCH_READ_BYTES);
    let result = confined.text_search_with_budget(
        None,
        &query,
        TextSearchOptions::default(),
        &mut budget,
    )?;
    fs::remove_dir_all(root)?;
    assert!(result.matches().is_empty());
    assert!(
        result.truncated(),
        "aggregate byte exhaustion must be observable"
    );
    assert_eq!(budget.remaining_bytes, 0);
    Ok(())
}

#[test]
fn text_search_exact_fit_preserves_all_line_endings_and_final_line() -> TestResult {
    let (root, confined) = workspace("exact-fit")?;
    let content = b"hit\rhit\r\nhit\nhit";
    fs::write(root.join("lines.rs"), content)?;
    let query = TextSearchQuery::new("hit".to_owned())?;
    let mut budget = budget(content.len());
    let result = confined.text_search_with_budget(
        None,
        &query,
        TextSearchOptions::default(),
        &mut budget,
    )?;
    fs::remove_dir_all(root)?;
    assert!(!result.truncated());
    assert_eq!(budget.remaining_bytes, 0);
    assert_eq!(
        result
            .matches()
            .iter()
            .map(TextSearchMatch::line)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    assert!(result.matches().iter().all(|item| item.preview() == "hit"));
    Ok(())
}

#[test]
fn text_search_insufficient_next_file_budget_retains_previous_hits() -> TestResult {
    let (root, confined) = workspace("previous-hit")?;
    fs::write(root.join("first.rs"), b"hit\n")?;
    fs::create_dir(root.join("nested"))?;
    fs::write(root.join("nested/next.rs"), b"hit-second\n")?;
    let query = TextSearchQuery::new("hit".to_owned())?;
    let mut budget = budget(5);
    let result = confined.text_search_with_budget(
        None,
        &query,
        TextSearchOptions::default(),
        &mut budget,
    )?;
    fs::remove_dir_all(root)?;
    assert!(result.truncated());
    assert_eq!(budget.remaining_bytes, 1);
    assert_eq!(result.matches().len(), 1);
    assert_eq!(result.matches()[0].path().as_path(), Path::new("first.rs"));
    Ok(())
}

#[test]
fn text_search_charges_binary_and_invalid_utf8_before_skipping() -> TestResult {
    for content in [b"\0xx".as_slice(), b"\xffxx".as_slice()] {
        let (root, confined) = workspace("rejected-text")?;
        fs::write(root.join("invalid.rs"), content)?;
        fs::create_dir(root.join("nested"))?;
        fs::write(root.join("nested/match.rs"), b"needle")?;
        let query = TextSearchQuery::new("needle".to_owned())?;
        let mut budget = budget(8);
        let result = confined.text_search_with_budget(
            None,
            &query,
            TextSearchOptions::default(),
            &mut budget,
        )?;
        fs::remove_dir_all(root)?;
        assert!(result.truncated());
        assert!(result.matches().is_empty());
        assert_eq!(budget.remaining_bytes, 5);
    }
    Ok(())
}

#[test]
fn text_search_expired_deadline_does_not_read_and_oversized_files_still_skip() -> TestResult {
    let (root, confined) = workspace("deadline")?;
    fs::write(root.join("source.rs"), b"hit")?;
    let query = TextSearchQuery::new("hit".to_owned())?;
    let mut expired = SearchBudget {
        remaining_bytes: 3,
        deadline: Instant::now(),
    };
    let result = confined.text_search_with_budget(
        None,
        &query,
        TextSearchOptions::default(),
        &mut expired,
    )?;
    fs::remove_file(root.join("source.rs"))?;
    fs::File::create(root.join("oversized.rs"))?
        .set_len(u64::try_from(MAX_TEXT_SEARCH_FILE_BYTES)? + 1)?;
    let mut available = budget(1);
    let skipped = confined.text_search_with_budget(
        None,
        &query,
        TextSearchOptions::default(),
        &mut available,
    )?;
    fs::remove_dir_all(root)?;
    assert!(result.truncated());
    assert_eq!(result.scanned_files(), 0);
    assert_eq!(expired.remaining_bytes, 3);
    assert!(!skipped.truncated());
    assert!(skipped.matches().is_empty());
    assert_eq!(available.remaining_bytes, 1);
    Ok(())
}

#[test]
fn text_search_unexpected_eof_does_not_publish_partial_file_matches() -> TestResult {
    let (root, _confined) = workspace("partial-file")?;
    fs::write(root.join("partial.rs"), b"prefixneedle")?;
    let mut file = fs::File::open(root.join("partial.rs"))?;
    // A short descriptor stream reproduces the same read/EOF outcome as shrinkage,
    // without a timing-dependent truncate race or a production-only test hook.
    file.seek(SeekFrom::Start(6))?;
    let path = forge_domain::WorkspaceRelativePath::new(PathBuf::from("partial.rs"))?;
    let query = TextSearchQuery::new("needle".to_owned())?;
    let mut budget = budget(12);
    let mut output_bytes = 7;
    let result = search_file(
        file.into(),
        &path,
        &query,
        10,
        1024,
        &mut output_bytes,
        &mut budget,
    )?;
    fs::remove_dir_all(root)?;
    assert!(result.truncated);
    assert!(result.matches.is_empty());
    assert_eq!(output_bytes, 7);
    assert_eq!(budget.remaining_bytes, 6);
    Ok(())
}
