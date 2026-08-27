use std::path::PathBuf;

use thiserror::Error;

/// Result of an owner-initiated native folder selection.
#[must_use = "folder selection must be handled explicitly"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderSelection {
    Selected(PathBuf),
    Cancelled,
}

/// Failures at the native folder-picker boundary.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FolderPickerError {
    #[error("native folder picker requires the macOS main thread")]
    MainThreadRequired,
    #[error("native folder dialog was aborted")]
    NativeDialogAborted,
    #[error("native folder dialog was accepted without a URL")]
    AcceptedWithoutUrl,
    #[error("native folder dialog was accepted without a file path")]
    AcceptedWithoutFilePath,
    #[error("native folder dialog returned unexpected modal response {response}")]
    UnexpectedModalResponse { response: isize },
    #[error("folder picker is unsupported on this platform")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ModalSelection {
    MissingUrl,
    MissingFilePath,
    Selected(PathBuf),
}

const MODAL_RESPONSE_OK: isize = 1;
const MODAL_RESPONSE_CANCEL: isize = 0;
const MODAL_RESPONSE_ABORT: isize = -1_001;

fn classify_modal_response(
    response: isize,
    selection: ModalSelection,
) -> Result<FolderSelection, FolderPickerError> {
    match response {
        MODAL_RESPONSE_CANCEL => Ok(FolderSelection::Cancelled),
        MODAL_RESPONSE_ABORT => Err(FolderPickerError::NativeDialogAborted),
        MODAL_RESPONSE_OK => match selection {
            ModalSelection::MissingUrl => Err(FolderPickerError::AcceptedWithoutUrl),
            ModalSelection::MissingFilePath => Err(FolderPickerError::AcceptedWithoutFilePath),
            ModalSelection::Selected(path) => Ok(FolderSelection::Selected(path)),
        },
        response => Err(FolderPickerError::UnexpectedModalResponse { response }),
    }
}

/// Opens the native macOS folder picker.
#[must_use = "folder picker result must be handled explicitly"]
pub fn pick_folder() -> Result<FolderSelection, FolderPickerError> {
    #[cfg(target_os = "macos")]
    {
        pick_folder_macos()
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(FolderPickerError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "macos")]
fn pick_folder_macos() -> Result<FolderSelection, FolderPickerError> {
    use objc2::MainThreadMarker;
    use objc2_app_kit::NSOpenPanel;

    let Some(mtm) = MainThreadMarker::new() else {
        return Err(FolderPickerError::MainThreadRequired);
    };
    let panel = NSOpenPanel::openPanel(mtm);
    panel.setCanChooseDirectories(true);
    panel.setCanChooseFiles(false);
    panel.setAllowsMultipleSelection(false);
    let response = panel.runModal();
    let selection = selection_from_panel(&panel);
    classify_modal_response(response, selection)
}

#[cfg(target_os = "macos")]
fn selection_from_panel(panel: &objc2_app_kit::NSOpenPanel) -> ModalSelection {
    let urls = panel.URLs();
    let Some(url) = urls.firstObject() else {
        return ModalSelection::MissingUrl;
    };
    if !url.isFileURL() {
        return ModalSelection::MissingFilePath;
    }
    let Some(path) = url.path() else {
        return ModalSelection::MissingFilePath;
    };
    let path = path.to_string();
    if path.is_empty() {
        ModalSelection::MissingFilePath
    } else {
        ModalSelection::Selected(PathBuf::from(path))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FolderPickerError, FolderSelection, ModalSelection, classify_modal_response, pick_folder,
    };
    use std::path::PathBuf;

    #[test]
    fn classifies_ok_cancel_abort_unexpected_and_missing_payloads() {
        assert_eq!(
            classify_modal_response(1, ModalSelection::Selected(PathBuf::from("/tmp/selected")),),
            Ok(FolderSelection::Selected(PathBuf::from("/tmp/selected")))
        );
        assert_eq!(
            classify_modal_response(0, ModalSelection::MissingUrl),
            Ok(FolderSelection::Cancelled)
        );
        assert_eq!(
            classify_modal_response(-1_001, ModalSelection::MissingUrl),
            Err(FolderPickerError::NativeDialogAborted)
        );
        assert_eq!(
            classify_modal_response(7, ModalSelection::MissingUrl),
            Err(FolderPickerError::UnexpectedModalResponse { response: 7 })
        );
        assert_eq!(
            classify_modal_response(1, ModalSelection::MissingUrl),
            Err(FolderPickerError::AcceptedWithoutUrl)
        );
        assert_eq!(
            classify_modal_response(1, ModalSelection::MissingFilePath),
            Err(FolderPickerError::AcceptedWithoutFilePath)
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn non_macos_picker_is_typed_unsupported() {
        assert_eq!(pick_folder(), Err(FolderPickerError::UnsupportedPlatform));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn spawned_thread_is_rejected_before_appkit_access() -> Result<(), Box<dyn std::error::Error>> {
        let result = std::thread::spawn(pick_folder)
            .join()
            .map_err(|_| "picker thread panicked")?;
        assert_eq!(result, Err(FolderPickerError::MainThreadRequired));
        Ok(())
    }
}
