//! macOS and host-platform adapters for Heterarchy Forge.

mod app_paths;
mod logging;
mod macos_folder_picker;
#[path = "mcp_auth_store.rs"]
mod mcp_token_pepper;

pub use app_paths::{AppPathError, AppPaths};
pub use logging::{LoggingError, LoggingGuard, init_logging};
pub use macos_folder_picker::{FolderPickerError, FolderSelection, pick_folder};
pub use mcp_token_pepper::{MacOsMcpTokenPepperStore, McpTokenPepper, McpTokenPepperError};
