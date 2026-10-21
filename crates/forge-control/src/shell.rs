//! Server-side analysis for Agent-originated shell executions.
//!
//! Shell text remains the ergonomic input surface, but the caller does not
//! declare its permissions.  FORGE derives a bounded execution intent before
//! the existing sandbox/durable execution runtime is allowed to launch it.
//! The analyzer deliberately accepts common composition (`|`, `&&`, `||`, `;`)
//! while escalating syntax or commands whose effects cannot be established
//! statically.  The sandbox remains the enforcement boundary.

use forge_domain::{ExecutionCommandId, ExecutionPermissions, ExecutionScript};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_SHELL_TOKENS: usize = 512;
const SHELL_INTENT_DIGEST_BYTES: usize = 16;

#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShellExecutionClass {
    ReadOnly,
    Verify,
    SourceWrite,
    Network,
    Opaque,
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzedShellExecution {
    script: ExecutionScript,
    intent_id: ExecutionCommandId,
    class: ShellExecutionClass,
    permissions: ExecutionPermissions,
    rust_tooling: bool,
}

impl AnalyzedShellExecution {
    pub fn script(&self) -> &ExecutionScript {
        &self.script
    }

    pub fn intent_id(&self) -> &ExecutionCommandId {
        &self.intent_id
    }

    pub const fn class(&self) -> ShellExecutionClass {
        self.class
    }

    pub const fn permissions(&self) -> ExecutionPermissions {
        self.permissions
    }

    pub const fn requires_rust_tooling(&self) -> bool {
        self.rust_tooling
    }

    pub const fn is_opaque(&self) -> bool {
        matches!(self.class, ShellExecutionClass::Opaque)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ShellAnalysisError {
    #[error("shell script is invalid: {0}")]
    InvalidScript(String),
    #[error("shell script contains an unterminated quote or escape")]
    UnterminatedSyntax,
    #[error("shell script contains too many tokens; maximum is {maximum}")]
    TooManyTokens { maximum: usize },
    #[error("shell command is denied by FORGE policy: {command}")]
    DeniedCommand { command: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ShellToken {
    Word(String),
    Separator,
    RedirectRead,
    RedirectWrite,
    OpaqueSyntax,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolingProfile {
    Baseline,
    Rust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandEffect {
    class: ShellExecutionClass,
    permissions: ExecutionPermissions,
    tooling: ToolingProfile,
}

impl CommandEffect {
    const READ: Self = Self::new(
        ShellExecutionClass::ReadOnly,
        ExecutionPermissions::new(true, false, false),
        ToolingProfile::Baseline,
    );
    const VERIFY: Self = Self::new(
        ShellExecutionClass::Verify,
        ExecutionPermissions::new(true, false, false),
        ToolingProfile::Baseline,
    );
    const RUST_VERIFY: Self = Self::new(
        ShellExecutionClass::Verify,
        ExecutionPermissions::new(true, false, false),
        ToolingProfile::Rust,
    );
    const WRITE: Self = Self::new(
        ShellExecutionClass::SourceWrite,
        ExecutionPermissions::new(true, true, false),
        ToolingProfile::Baseline,
    );
    const RUST_WRITE: Self = Self::new(
        ShellExecutionClass::SourceWrite,
        ExecutionPermissions::new(true, true, false),
        ToolingProfile::Rust,
    );
    const NETWORK: Self = Self::new(
        ShellExecutionClass::Network,
        ExecutionPermissions::new(true, false, true),
        ToolingProfile::Baseline,
    );
    const OPAQUE: Self = Self::new(
        ShellExecutionClass::Opaque,
        ExecutionPermissions::new(true, true, true),
        ToolingProfile::Baseline,
    );

    const fn new(
        class: ShellExecutionClass,
        permissions: ExecutionPermissions,
        tooling: ToolingProfile,
    ) -> Self {
        Self {
            class,
            permissions,
            tooling,
        }
    }

    fn merge(self, other: Self) -> Self {
        let tooling = if matches!(self.tooling, ToolingProfile::Rust)
            || matches!(other.tooling, ToolingProfile::Rust)
        {
            ToolingProfile::Rust
        } else {
            ToolingProfile::Baseline
        };
        Self {
            class: max_class(self.class, other.class),
            permissions: ExecutionPermissions::new(
                self.permissions.workspace_read() || other.permissions.workspace_read(),
                self.permissions.workspace_write() || other.permissions.workspace_write(),
                self.permissions.network() || other.permissions.network(),
            ),
            tooling,
        }
    }
}

/// Analyze one bounded shell script into a server-owned execution intent.
///
/// Unknown commands are not treated as safe. They become `Opaque`, which lets
/// the caller retain a productive shell escape hatch while forcing the stronger
/// approval path. Explicitly destructive/privileged commands fail closed.
pub fn analyze_shell_script(script: String) -> Result<AnalyzedShellExecution, ShellAnalysisError> {
    let script = ExecutionScript::new(script)
        .map_err(|error| ShellAnalysisError::InvalidScript(error.to_string()))?;
    let tokens = tokenize(script.as_str())?;
    let effect = analyze_tokens(&tokens)?;
    let intent_id = shell_intent_id(script.as_str())?;
    Ok(AnalyzedShellExecution {
        script,
        intent_id,
        class: effect.class,
        permissions: effect.permissions,
        rust_tooling: matches!(effect.tooling, ToolingProfile::Rust),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteMode {
    None,
    Single,
    Double,
}

struct ShellTokenizer<'a> {
    bytes: &'a [u8],
    tokens: Vec<ShellToken>,
    word: String,
    index: usize,
    quote: QuoteMode,
    escaped: bool,
}

impl<'a> ShellTokenizer<'a> {
    fn new(script: &'a str) -> Self {
        Self {
            bytes: script.as_bytes(),
            tokens: Vec::new(),
            word: String::new(),
            index: 0,
            quote: QuoteMode::None,
            escaped: false,
        }
    }

    fn run(mut self) -> Result<Vec<ShellToken>, ShellAnalysisError> {
        while self.index < self.bytes.len() {
            self.consume_current()?;
            self.index += 1;
        }
        if self.escaped || !matches!(self.quote, QuoteMode::None) {
            return Err(ShellAnalysisError::UnterminatedSyntax);
        }
        flush_word(&mut self.tokens, &mut self.word)?;
        Ok(self.tokens)
    }

    fn consume_current(&mut self) -> Result<(), ShellAnalysisError> {
        let byte = self.bytes[self.index];
        if self.escaped {
            self.word.push(char::from(byte));
            self.escaped = false;
            return Ok(());
        }
        match self.quote {
            QuoteMode::Single => {
                self.word.push(char::from(byte));
                if byte == b'\'' {
                    self.quote = QuoteMode::None;
                }
                Ok(())
            }
            QuoteMode::Double => self.consume_double_quoted(byte),
            QuoteMode::None => self.consume_unquoted(byte),
        }
    }

    fn consume_double_quoted(&mut self, byte: u8) -> Result<(), ShellAnalysisError> {
        self.word.push(char::from(byte));
        match byte {
            b'"' => self.quote = QuoteMode::None,
            b'\\' => self.escaped = true,
            b'`' => push_token(&mut self.tokens, ShellToken::OpaqueSyntax)?,
            b'$' if self.peek() == Some(b'(') => {
                push_token(&mut self.tokens, ShellToken::OpaqueSyntax)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn consume_unquoted(&mut self, byte: u8) -> Result<(), ShellAnalysisError> {
        match byte {
            b'\\' => self.escaped = true,
            b'\'' => {
                self.quote = QuoteMode::Single;
                self.word.push('\'');
            }
            b'"' => {
                self.quote = QuoteMode::Double;
                self.word.push('"');
            }
            b' ' | b'\t' => flush_word(&mut self.tokens, &mut self.word)?,
            b'\n' | b';' => self.push_separator()?,
            b'|' => {
                self.push_separator()?;
                if self.peek() == Some(b'|') {
                    self.index += 1;
                }
            }
            b'&' if self.peek() == Some(b'&') => {
                self.push_separator()?;
                self.index += 1;
            }
            b'&' | b'`' | b'(' | b')' | b'{' | b'}' => self.push_opaque()?,
            b'>' => {
                flush_word(&mut self.tokens, &mut self.word)?;
                if self.peek() == Some(b'>') {
                    self.index += 1;
                }
                push_token(&mut self.tokens, ShellToken::RedirectWrite)?;
            }
            b'<' => {
                flush_word(&mut self.tokens, &mut self.word)?;
                if self.peek() == Some(b'<') {
                    self.index += 1;
                    push_token(&mut self.tokens, ShellToken::OpaqueSyntax)?;
                } else {
                    push_token(&mut self.tokens, ShellToken::RedirectRead)?;
                }
            }
            b'$' if self.peek() == Some(b'(') => self.push_opaque()?,
            _ => self.word.push(char::from(byte)),
        }
        Ok(())
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index + 1).copied()
    }

    fn push_separator(&mut self) -> Result<(), ShellAnalysisError> {
        flush_word(&mut self.tokens, &mut self.word)?;
        push_token(&mut self.tokens, ShellToken::Separator)
    }

    fn push_opaque(&mut self) -> Result<(), ShellAnalysisError> {
        flush_word(&mut self.tokens, &mut self.word)?;
        push_token(&mut self.tokens, ShellToken::OpaqueSyntax)
    }
}

fn tokenize(script: &str) -> Result<Vec<ShellToken>, ShellAnalysisError> {
    ShellTokenizer::new(script).run()
}

fn flush_word(tokens: &mut Vec<ShellToken>, word: &mut String) -> Result<(), ShellAnalysisError> {
    if !word.is_empty() {
        push_token(tokens, ShellToken::Word(std::mem::take(word)))?;
    }
    Ok(())
}

fn push_token(tokens: &mut Vec<ShellToken>, token: ShellToken) -> Result<(), ShellAnalysisError> {
    if tokens.len() >= MAX_SHELL_TOKENS {
        return Err(ShellAnalysisError::TooManyTokens {
            maximum: MAX_SHELL_TOKENS,
        });
    }
    tokens.push(token);
    Ok(())
}

fn analyze_tokens(tokens: &[ShellToken]) -> Result<CommandEffect, ShellAnalysisError> {
    let mut effect = CommandEffect::new(
        ShellExecutionClass::ReadOnly,
        ExecutionPermissions::new(false, false, false),
        ToolingProfile::Baseline,
    );
    let mut command_words = Vec::new();
    let mut pending_write_redirect = false;
    let mut pending_read_redirect = false;

    for token in tokens {
        match token {
            ShellToken::Word(word) => {
                if pending_write_redirect {
                    effect = effect.merge(CommandEffect::WRITE);
                    pending_write_redirect = false;
                } else if pending_read_redirect {
                    effect = effect.merge(CommandEffect::READ);
                    pending_read_redirect = false;
                } else {
                    command_words.push(word.as_str());
                }
            }
            ShellToken::Separator => {
                effect = effect.merge(classify_command(&command_words)?);
                command_words.clear();
            }
            ShellToken::RedirectWrite => pending_write_redirect = true,
            ShellToken::RedirectRead => pending_read_redirect = true,
            ShellToken::OpaqueSyntax => effect = effect.merge(CommandEffect::OPAQUE),
        }
    }
    effect = effect.merge(classify_command(&command_words)?);
    if pending_write_redirect || pending_read_redirect {
        return Err(ShellAnalysisError::UnterminatedSyntax);
    }
    Ok(effect)
}

fn classify_command(words: &[&str]) -> Result<CommandEffect, ShellAnalysisError> {
    let Some(command) = words.first().copied() else {
        return Ok(CommandEffect::new(
            ShellExecutionClass::ReadOnly,
            ExecutionPermissions::new(false, false, false),
            ToolingProfile::Baseline,
        ));
    };
    let command = command.rsplit('/').next().unwrap_or(command);
    if is_denied_command(command, words) {
        return Err(ShellAnalysisError::DeniedCommand {
            command: command.to_owned(),
        });
    }

    let effect = match command {
        "pwd" | "ls" | "rg" | "grep" | "head" | "tail" | "cat" | "wc" | "sort" | "uniq" | "cut"
        | "dirname" | "basename" | "stat" | "du" | "df" | "readlink" | "realpath" | "printf"
        | "echo" | "true" | "false" => CommandEffect::READ,
        "git" => classify_git(words),
        "cargo" => classify_cargo(words),
        "sed" => {
            if words
                .iter()
                .skip(1)
                .any(|arg| *arg == "-i" || arg.starts_with("-i"))
            {
                CommandEffect::WRITE
            } else {
                CommandEffect::READ
            }
        }
        "find" => {
            if words
                .iter()
                .any(|arg| matches!(*arg, "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir"))
            {
                CommandEffect::OPAQUE
            } else {
                CommandEffect::READ
            }
        }
        "pyrefly" | "ruff" | "pytest" => classify_python_diagnostic(command, words),
        "uv" => classify_uv_run(words),
        "make"
            if words.len() == 2
                && matches!(words[1], "rules" | "check" | "test" | "ci" | "doctor") =>
        {
            CommandEffect::RUST_VERIFY
        }
        "codegraph"
            if words.len() == 2 && matches!(words[1], "status" | "--version" | "--help") =>
        {
            CommandEffect::READ
        }
        "rustc" | "rustdoc" => CommandEffect::RUST_VERIFY,
        "rustfmt" if words.iter().skip(1).any(|arg| *arg == "--check") => {
            CommandEffect::RUST_VERIFY
        }
        "rustfmt" => CommandEffect::RUST_WRITE,
        "curl" | "wget" => CommandEffect::NETWORK,
        "mkdir" | "touch" | "cp" | "mv" => CommandEffect::WRITE,
        _ => CommandEffect::OPAQUE,
    };
    Ok(effect)
}

fn classify_python_diagnostic(command: &str, words: &[&str]) -> CommandEffect {
    match command {
        "pyrefly" => classify_pyrefly(words),
        "ruff" => classify_ruff(words),
        "pytest" => CommandEffect::VERIFY,
        _ => CommandEffect::OPAQUE,
    }
}

fn classify_pyrefly(words: &[&str]) -> CommandEffect {
    match words.get(1).copied() {
        Some("init" | "suppress") => CommandEffect::WRITE,
        Some("check") if words.iter().skip(2).any(is_pyrefly_source_write_flag) => {
            CommandEffect::WRITE
        }
        Some("check") => CommandEffect::VERIFY,
        _ => CommandEffect::OPAQUE,
    }
}

fn is_pyrefly_source_write_flag(argument: &&str) -> bool {
    matches!(
        *argument,
        "--update-baseline" | "--prune-baseline" | "--suppress-errors" | "--remove-unused-ignores"
    ) || argument.starts_with("--update-baseline=")
        || argument.starts_with("--prune-baseline=")
        || argument.starts_with("--suppress-errors=")
        || argument.starts_with("--remove-unused-ignores=")
}

fn classify_ruff(words: &[&str]) -> CommandEffect {
    if words.get(1).copied() != Some("check") {
        return CommandEffect::OPAQUE;
    }
    if words.iter().skip(2).any(is_ruff_source_write_flag) {
        CommandEffect::WRITE
    } else {
        CommandEffect::VERIFY
    }
}

fn is_ruff_source_write_flag(argument: &&str) -> bool {
    matches!(*argument, "--fix" | "--fix-only" | "--unsafe-fixes" | "-o")
        || *argument == "--output-file"
        || argument.starts_with("--output-file=")
}

fn classify_uv_run(words: &[&str]) -> CommandEffect {
    if words.get(1).copied() != Some("run") {
        return CommandEffect::OPAQUE;
    }
    let mut index = 2;
    let mut no_editable = false;
    while let Some(argument) = words.get(index).copied() {
        match argument {
            "--no-editable" if !no_editable => no_editable = true,
            "--frozen" | "--no-sync" | "--offline" => {}
            _ if argument.starts_with('-') => return CommandEffect::OPAQUE,
            _ => break,
        }
        index += 1;
    }
    if !no_editable {
        return CommandEffect::OPAQUE;
    }
    let Some(wrapped) = words.get(index..) else {
        return CommandEffect::OPAQUE;
    };
    let Some(wrapped_command) = wrapped.first().copied() else {
        return CommandEffect::OPAQUE;
    };
    let wrapped_command = wrapped_command
        .rsplit('/')
        .next()
        .unwrap_or(wrapped_command);
    classify_python_diagnostic(wrapped_command, wrapped)
}

fn classify_git(words: &[&str]) -> CommandEffect {
    let subcommand = words
        .iter()
        .skip(1)
        .find(|word| !word.starts_with('-'))
        .copied();
    match subcommand {
        Some(
            "status" | "diff" | "log" | "show" | "rev-parse" | "ls-files" | "grep" | "cat-file",
        ) => CommandEffect::READ,
        Some("fetch" | "pull" | "push" | "clone") => CommandEffect::new(
            ShellExecutionClass::Network,
            ExecutionPermissions::new(true, true, true),
            ToolingProfile::Baseline,
        ),
        Some("add" | "commit" | "tag" | "branch" | "switch" | "checkout" | "restore") => {
            CommandEffect::WRITE
        }
        _ => CommandEffect::OPAQUE,
    }
}

fn classify_cargo(words: &[&str]) -> CommandEffect {
    let subcommand = words
        .iter()
        .skip(1)
        .find(|word| !word.starts_with('-'))
        .copied();
    match subcommand {
        Some(
            "check" | "test" | "clippy" | "build" | "doc" | "metadata" | "run" | "bench"
            | "package" | "clean" | "tree",
        ) => CommandEffect::RUST_VERIFY,
        Some("fmt") if words.iter().skip(2).any(|arg| *arg == "--check") => {
            CommandEffect::RUST_VERIFY
        }
        Some("fmt" | "fix") => CommandEffect::RUST_WRITE,
        Some("fetch" | "install" | "update" | "publish" | "search") => CommandEffect::new(
            ShellExecutionClass::Network,
            ExecutionPermissions::new(true, true, true),
            ToolingProfile::Rust,
        ),
        _ => CommandEffect::OPAQUE,
    }
}

fn is_denied_command(command: &str, words: &[&str]) -> bool {
    if matches!(
        command,
        "sudo" | "doas" | "su" | "shutdown" | "reboot" | "halt" | "killall"
    ) {
        return true;
    }
    if command == "rm" {
        return true;
    }
    command == "git" && words.iter().any(|word| matches!(*word, "reset" | "clean"))
}

fn max_class(left: ShellExecutionClass, right: ShellExecutionClass) -> ShellExecutionClass {
    use ShellExecutionClass::{Network, Opaque, ReadOnly, SourceWrite, Verify};
    match (left, right) {
        (Opaque, _) | (_, Opaque) => Opaque,
        (Network, _) | (_, Network) => Network,
        (SourceWrite, _) | (_, SourceWrite) => SourceWrite,
        (Verify, _) | (_, Verify) => Verify,
        (ReadOnly, ReadOnly) => ReadOnly,
    }
}

fn shell_intent_id(script: &str) -> Result<ExecutionCommandId, ShellAnalysisError> {
    let digest = Sha256::digest(script.as_bytes());
    let mut value = String::from("shell:");
    for byte in &digest[..SHELL_INTENT_DIGEST_BYTES] {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    ExecutionCommandId::new(value)
        .map_err(|error| ShellAnalysisError::InvalidScript(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze(script: &str) -> Result<AnalyzedShellExecution, ShellAnalysisError> {
        analyze_shell_script(script.to_owned())
    }

    #[test]
    fn pipelines_and_conditionals_preserve_read_only_productivity() -> Result<(), ShellAnalysisError>
    {
        let analyzed = analyze("rg 'WriterLease' crates | head -n 20 && git status --short")?;
        assert_eq!(analyzed.class(), ShellExecutionClass::ReadOnly);
        assert_eq!(
            analyzed.permissions(),
            ExecutionPermissions::new(true, false, false)
        );
        assert!(!analyzed.is_opaque());
        Ok(())
    }

    #[test]
    fn rust_verification_is_distinguished_from_source_write() -> Result<(), ShellAnalysisError> {
        let verify = analyze(
            "cargo check -p forge-control && cargo test -p forge-control && cargo run -p forge-control --bin smoke && cargo package -p forge-control && cargo clean -p forge-control",
        )?;
        assert_eq!(verify.class(), ShellExecutionClass::Verify);
        assert_eq!(
            verify.permissions(),
            ExecutionPermissions::new(true, false, false)
        );
        assert!(verify.requires_rust_tooling());

        let format = analyze("cargo fmt --all")?;
        assert_eq!(format.class(), ShellExecutionClass::SourceWrite);
        assert_eq!(
            format.permissions(),
            ExecutionPermissions::new(true, true, false)
        );
        assert!(format.requires_rust_tooling());

        let fix = analyze("cargo fix -p forge-control")?;
        assert_eq!(fix.class(), ShellExecutionClass::SourceWrite);
        assert!(fix.permissions().workspace_write());
        assert!(fix.requires_rust_tooling());

        for checked_format in [
            "cargo fmt --all --check",
            "cargo fmt --all -- --check",
            "rustfmt --check",
        ] {
            let analyzed = analyze(checked_format)?;
            assert_eq!(analyzed.class(), ShellExecutionClass::Verify);
            assert_eq!(
                analyzed.permissions(),
                ExecutionPermissions::new(true, false, false)
            );
            assert!(analyzed.requires_rust_tooling());
        }
        Ok(())
    }

    #[test]
    fn canonical_development_commands_do_not_claim_source_write() -> Result<(), ShellAnalysisError>
    {
        for command in [
            "make rules",
            "make check",
            "make test",
            "make ci",
            "make doctor",
        ] {
            let analyzed = analyze(command)?;
            assert_eq!(analyzed.class(), ShellExecutionClass::Verify);
            assert_eq!(
                analyzed.permissions(),
                ExecutionPermissions::new(true, false, false)
            );
            assert!(analyzed.requires_rust_tooling());
        }
        for command in [
            "codegraph status",
            "codegraph --help",
            "codegraph --version",
        ] {
            let analyzed = analyze(command)?;
            assert_eq!(analyzed.class(), ShellExecutionClass::ReadOnly);
            assert_eq!(
                analyzed.permissions(),
                ExecutionPermissions::new(true, false, false)
            );
            assert!(!analyzed.requires_rust_tooling());
        }
        for command in [
            "make fmt",
            "make -f custom.mk check",
            "codegraph build",
            "codegraph status --output result.json",
            "codegraph status > result.json",
        ] {
            assert!(analyze(command)?.permissions().workspace_write());
        }
        Ok(())
    }

    #[test]
    fn python_diagnostics_are_baseline_verify_without_wrapper_fallbacks()
    -> Result<(), ShellAnalysisError> {
        for script in [
            "pyrefly check",
            "ruff check",
            "ruff check --diff",
            "pytest -q tests",
            "uv run --no-editable pyrefly check",
            "uv run --no-editable --frozen --no-sync --offline ruff check",
            "uv run --no-editable pytest -q",
        ] {
            let analyzed = analyze(script)?;
            assert_eq!(analyzed.class(), ShellExecutionClass::Verify, "{script}");
            assert_eq!(
                analyzed.permissions(),
                ExecutionPermissions::new(true, false, false),
                "{script}"
            );
            assert!(!analyzed.requires_rust_tooling(), "{script}");
            assert!(!analyzed.is_opaque(), "{script}");
        }

        for script in [
            "pyrefly check --update-baseline",
            "pyrefly check --prune-baseline",
            "pyrefly suppress",
            "ruff check --fix",
            "ruff check --fix-only",
            "ruff check --unsafe-fixes",
            "ruff check --output-file diagnostics.json",
            "uv run --no-editable pyrefly check --suppress-errors",
            "uv run --no-editable ruff check --fix",
            "pyrefly check > diagnostics.txt",
        ] {
            let analyzed = analyze(script)?;
            assert_eq!(
                analyzed.class(),
                ShellExecutionClass::SourceWrite,
                "{script}"
            );
            assert!(analyzed.permissions().workspace_write(), "{script}");
            assert!(!analyzed.requires_rust_tooling(), "{script}");
        }

        for script in [
            "uv run pyrefly check",
            "uv run --no-editable python -m pytest",
            "uv run --no-editable arbitrary-check",
            "uv run --no-editable --locked pytest",
            "uv run --no-editable pyrefly check $(printf unsafe)",
        ] {
            let analyzed = analyze(script)?;
            assert!(analyzed.is_opaque(), "{script}");
            assert_eq!(
                analyzed.permissions(),
                ExecutionPermissions::new(true, true, true),
                "{script}"
            );
        }
        Ok(())
    }

    #[test]
    fn redirection_is_treated_as_write_without_rejecting_shell_composition()
    -> Result<(), ShellAnalysisError> {
        let analyzed = analyze("rg TODO crates > todo.txt")?;
        assert_eq!(analyzed.class(), ShellExecutionClass::SourceWrite);
        assert!(analyzed.permissions().workspace_write());
        Ok(())
    }

    #[test]
    fn unknown_or_dynamic_execution_escalates_to_opaque() -> Result<(), ShellAnalysisError> {
        let unknown = analyze("python3 scripts/check.py | tee result.txt")?;
        assert!(unknown.is_opaque());
        assert_eq!(
            unknown.permissions(),
            ExecutionPermissions::new(true, true, true)
        );

        let substitution = analyze("echo $(git status --short)")?;
        assert!(substitution.is_opaque());
        Ok(())
    }

    #[test]
    fn destructive_commands_fail_closed() {
        assert_eq!(
            analyze_shell_script("rm -rf target".to_owned()),
            Err(ShellAnalysisError::DeniedCommand {
                command: "rm".to_owned()
            })
        );
        assert!(analyze_shell_script("git reset --hard HEAD".to_owned()).is_err());
    }

    #[test]
    fn shell_intent_is_stable_and_content_bound() -> Result<(), ShellAnalysisError> {
        let first = analyze("ls -la")?;
        let retry = analyze("ls -la")?;
        let changed = analyze("ls -l")?;
        assert_eq!(first.intent_id(), retry.intent_id());
        assert_ne!(first.intent_id(), changed.intent_id());
        Ok(())
    }
}
