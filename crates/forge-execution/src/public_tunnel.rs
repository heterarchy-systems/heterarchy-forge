//! Owned Cloudflare tunnel process for the public MCP transport.
//!
//! A configured custom MCP host has precedence. When no custom host is
//! configured, Forge starts a Cloudflare Quick Tunnel and discovers the
//! generated `*.trycloudflare.com` origin from `cloudflared` output. The child
//! process and output-reader threads are always owned and joined here.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use forge_domain::{McpLocalPort, McpPublicBase, McpPublicBaseError};
use thiserror::Error;

const CLOUDFLARED_PROGRAM: &str = "cloudflared";
const QUICK_TUNNEL_SUFFIX: &str = ".trycloudflare.com";
const QUICK_TUNNEL_ATTEMPTS: usize = 4;
const QUICK_TUNNEL_STARTUP_TIMEOUT: Duration = Duration::from_secs(45);
const CUSTOM_TUNNEL_STABILITY_WINDOW: Duration = Duration::from_secs(3);
const QUICK_TUNNEL_POLL_INTERVAL: Duration = Duration::from_millis(50);
const OUTPUT_QUEUE_CAPACITY: usize = 128;

#[derive(Debug, Clone, Copy)]
struct TunnelStartPolicy {
    attempts: usize,
    startup_timeout: Duration,
    custom_stability_window: Duration,
    poll_interval: Duration,
}

impl Default for TunnelStartPolicy {
    fn default() -> Self {
        Self {
            attempts: QUICK_TUNNEL_ATTEMPTS,
            startup_timeout: QUICK_TUNNEL_STARTUP_TIMEOUT,
            custom_stability_window: CUSTOM_TUNNEL_STABILITY_WINDOW,
            poll_interval: QUICK_TUNNEL_POLL_INTERVAL,
        }
    }
}

/// Owned `cloudflared` process backing the public MCP endpoint.
#[must_use]
#[derive(Debug)]
pub struct CloudflarePublicTunnel {
    public_base: McpPublicBase,
    process: Option<OwnedCloudflaredProcess>,
}

impl CloudflarePublicTunnel {
    /// Start a custom-host tunnel when `custom_base` is configured; otherwise
    /// start a Quick Tunnel and discover its generated public hostname.
    pub fn start(
        custom_base: Option<&McpPublicBase>,
        local_port: McpLocalPort,
    ) -> Result<Self, CloudflarePublicTunnelError> {
        let program = preferred_cloudflared_program();
        Self::start_with_program(
            &program,
            custom_base,
            local_port,
            TunnelStartPolicy::default(),
        )
    }

    fn start_with_program(
        program: &OsStr,
        custom_base: Option<&McpPublicBase>,
        local_port: McpLocalPort,
        policy: TunnelStartPolicy,
    ) -> Result<Self, CloudflarePublicTunnelError> {
        match custom_base {
            Some(public_base) => {
                let mut process =
                    OwnedCloudflaredProcess::spawn_custom(program, public_base.host(), local_port)?;
                if let Err(error) = wait_for_custom_tunnel_stability(&mut process, policy) {
                    let _ignored = process.stop();
                    return Err(error);
                }
                Ok(Self {
                    public_base: public_base.clone(),
                    process: Some(process),
                })
            }
            None => start_quick_tunnel(program, local_port, policy),
        }
    }

    pub fn public_base(&self) -> &McpPublicBase {
        &self.public_base
    }

    pub fn public_origin(&self) -> &str {
        self.public_base.origin()
    }

    pub fn public_endpoint(&self) -> &str {
        self.public_base.endpoint()
    }

    pub fn stop(mut self) -> Result<(), CloudflarePublicTunnelError> {
        if let Some(mut process) = self.process.take() {
            process.stop()?;
        }
        Ok(())
    }
}

impl Drop for CloudflarePublicTunnel {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ignored = process.stop();
        }
    }
}

#[derive(Debug)]
struct OwnedCloudflaredProcess {
    child: Child,
    readers: Vec<JoinHandle<()>>,
    output: Receiver<String>,
}

impl OwnedCloudflaredProcess {
    fn spawn_custom(
        program: &OsStr,
        host: &str,
        local_port: McpLocalPort,
    ) -> Result<Self, CloudflarePublicTunnelError> {
        let origin = loopback_origin(local_port);
        let arguments = [
            OsString::from("tunnel"),
            OsString::from("--hostname"),
            OsString::from(host),
            OsString::from("--url"),
            OsString::from(origin),
            OsString::from("--no-autoupdate"),
        ];
        Self::spawn(program, &arguments)
    }

    fn spawn_quick(
        program: &OsStr,
        local_port: McpLocalPort,
    ) -> Result<Self, CloudflarePublicTunnelError> {
        let origin = loopback_origin(local_port);
        let arguments = [
            OsString::from("tunnel"),
            OsString::from("--no-autoupdate"),
            OsString::from("--url"),
            OsString::from(origin),
        ];
        Self::spawn(program, &arguments)
    }

    fn spawn(program: &OsStr, arguments: &[OsString]) -> Result<Self, CloudflarePublicTunnelError> {
        let mut child = Command::new(program)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(CloudflarePublicTunnelError::Spawn)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(CloudflarePublicTunnelError::MissingOutputPipe)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(CloudflarePublicTunnelError::MissingOutputPipe)?;
        let (sender, output) = mpsc::sync_channel(OUTPUT_QUEUE_CAPACITY);
        let stdout_reader = spawn_output_reader("cloudflared-stdout", stdout, sender.clone())?;
        let stderr_reader = spawn_output_reader("cloudflared-stderr", stderr, sender)?;
        Ok(Self {
            child,
            readers: vec![stdout_reader, stderr_reader],
            output,
        })
    }

    fn next_output(&self) -> Option<String> {
        self.output.try_recv().ok()
    }

    fn exited(&mut self) -> Result<bool, CloudflarePublicTunnelError> {
        self.child
            .try_wait()
            .map(|status| status.is_some())
            .map_err(CloudflarePublicTunnelError::Inspect)
    }

    fn stop(&mut self) -> Result<(), CloudflarePublicTunnelError> {
        let running = self
            .child
            .try_wait()
            .map_err(CloudflarePublicTunnelError::Inspect)?
            .is_none();
        if running {
            self.child
                .kill()
                .map_err(CloudflarePublicTunnelError::Terminate)?;
        }
        self.child
            .wait()
            .map_err(CloudflarePublicTunnelError::Reap)?;
        for reader in self.readers.drain(..) {
            reader
                .join()
                .map_err(|_| CloudflarePublicTunnelError::OutputReaderPanicked)?;
        }
        Ok(())
    }
}

fn start_quick_tunnel(
    program: &OsStr,
    local_port: McpLocalPort,
    policy: TunnelStartPolicy,
) -> Result<CloudflarePublicTunnel, CloudflarePublicTunnelError> {
    let attempts = policy.attempts.max(1);
    for attempt in 1..=attempts {
        let mut process = OwnedCloudflaredProcess::spawn_quick(program, local_port)?;
        match wait_for_quick_tunnel_base(&mut process, policy) {
            Ok(public_base) => {
                return Ok(CloudflarePublicTunnel {
                    public_base,
                    process: Some(process),
                });
            }
            Err(error) => {
                let _ignored = process.stop();
                if attempt == attempts {
                    return Err(error);
                }
            }
        }
    }
    Err(CloudflarePublicTunnelError::QuickTunnelUnavailable)
}

fn wait_for_custom_tunnel_stability(
    process: &mut OwnedCloudflaredProcess,
    policy: TunnelStartPolicy,
) -> Result<(), CloudflarePublicTunnelError> {
    let deadline = Instant::now() + policy.custom_stability_window;
    loop {
        if process.exited()? {
            return Err(CloudflarePublicTunnelError::CustomTunnelExitedEarly);
        }
        if Instant::now() >= deadline {
            return Ok(());
        }
        thread::sleep(policy.poll_interval);
    }
}

fn wait_for_quick_tunnel_base(
    process: &mut OwnedCloudflaredProcess,
    policy: TunnelStartPolicy,
) -> Result<McpPublicBase, CloudflarePublicTunnelError> {
    let deadline = Instant::now() + policy.startup_timeout;
    loop {
        while let Some(line) = process.next_output() {
            if let Some(public_base) = parse_quick_tunnel_base(&line)? {
                return Ok(public_base);
            }
        }
        if process.exited()? {
            return Err(CloudflarePublicTunnelError::ExitedBeforeReady);
        }
        if Instant::now() >= deadline {
            return Err(CloudflarePublicTunnelError::StartupTimeout);
        }
        thread::sleep(policy.poll_interval);
    }
}

fn spawn_output_reader<R>(
    name: &str,
    reader: R,
    sender: SyncSender<String>,
) -> Result<JoinHandle<()>, CloudflarePublicTunnelError>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            for line in BufReader::new(reader).lines() {
                let Ok(line) = line else {
                    break;
                };
                let _ignored = sender.try_send(line);
            }
        })
        .map_err(CloudflarePublicTunnelError::OutputReaderSpawn)
}

fn parse_quick_tunnel_base(
    line: &str,
) -> Result<Option<McpPublicBase>, CloudflarePublicTunnelError> {
    for token in line.split_whitespace() {
        let candidate = token.trim_matches(|character: char| {
            matches!(
                character,
                '|' | '[' | ']' | '(' | ')' | '<' | '>' | ',' | ';' | '\'' | '"'
            )
        });
        let Some(host) = candidate.strip_prefix("https://") else {
            continue;
        };
        let host = host.trim_end_matches('/');
        if !host.ends_with(QUICK_TUNNEL_SUFFIX) {
            continue;
        }
        return McpPublicBase::parse(host)
            .map(Some)
            .map_err(CloudflarePublicTunnelError::InvalidQuickTunnelUrl);
    }
    Ok(None)
}

fn loopback_origin(local_port: McpLocalPort) -> String {
    format!("http://127.0.0.1:{}", local_port.get())
}

fn preferred_cloudflared_program() -> OsString {
    std::env::current_exe()
        .ok()
        .as_deref()
        .and_then(bundled_cloudflared_for_executable)
        .unwrap_or_else(|| OsString::from(CLOUDFLARED_PROGRAM))
}

fn bundled_cloudflared_for_executable(executable: &Path) -> Option<OsString> {
    let bundled = executable.parent()?.join(CLOUDFLARED_PROGRAM);
    let metadata = fs::symlink_metadata(&bundled).ok()?;
    if metadata.file_type().is_file() {
        return Some(bundled.into_os_string());
    }
    None
}

#[derive(Debug, Error)]
pub enum CloudflarePublicTunnelError {
    #[error("failed to spawn cloudflared")]
    Spawn(#[source] io::Error),
    #[error("cloudflared output pipe is unavailable")]
    MissingOutputPipe,
    #[error("failed to spawn cloudflared output reader")]
    OutputReaderSpawn(#[source] io::Error),
    #[error("cloudflared output reader panicked")]
    OutputReaderPanicked,
    #[error("failed to inspect cloudflared process")]
    Inspect(#[source] io::Error),
    #[error("failed to terminate cloudflared process")]
    Terminate(#[source] io::Error),
    #[error("failed to reap cloudflared process")]
    Reap(#[source] io::Error),
    #[error("cloudflared exited before publishing a Quick Tunnel URL")]
    ExitedBeforeReady,
    #[error("cloudflared custom tunnel exited during the startup stability window")]
    CustomTunnelExitedEarly,
    #[error("timed out waiting for a Cloudflare Quick Tunnel URL")]
    StartupTimeout,
    #[error("Cloudflare Quick Tunnel did not become available")]
    QuickTunnelUnavailable,
    #[error("cloudflared emitted an invalid Quick Tunnel URL")]
    InvalidQuickTunnelUrl(#[source] McpPublicBaseError),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use uuid::Uuid;

    use super::*;

    #[test]
    fn quick_tunnel_parser_accepts_only_trycloudflare_https_origin()
    -> Result<(), Box<dyn std::error::Error>> {
        let parsed = parse_quick_tunnel_base(
            "INF Your quick Tunnel has been created! Visit it at https://blue-bird-7.trycloudflare.com",
        )?
        .ok_or("missing quick tunnel")?;
        assert_eq!(parsed.origin(), "https://blue-bird-7.trycloudflare.com");
        assert_eq!(
            parsed.endpoint(),
            "https://blue-bird-7.trycloudflare.com/mcp"
        );
        assert!(parse_quick_tunnel_base("https://example.com")?.is_none());
        assert!(parse_quick_tunnel_base("http://blue-bird-7.trycloudflare.com")?.is_none());
        Ok(())
    }

    #[test]
    fn bundled_cloudflared_is_preferred_only_for_regular_sibling_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let root =
            std::env::temp_dir().join(format!("forge-cloudflared-path-{}", std::process::id()));
        let _ignored = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let executable = root.join("forge-desktop");
        fs::write(&executable, b"desktop")?;
        assert_eq!(bundled_cloudflared_for_executable(&executable), None);

        let bundled = root.join(CLOUDFLARED_PROGRAM);
        fs::write(&bundled, b"cloudflared")?;
        assert_eq!(
            bundled_cloudflared_for_executable(&executable),
            Some(bundled.into_os_string())
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn custom_tunnel_rejects_cloudflared_that_exits_during_stability_window()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "forge-custom-tunnel-exit-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ));
        fs::create_dir_all(&root)?;
        let program = root.join("cloudflared-test");
        fs::write(&program, b"#!/bin/sh\nexit 7\n")?;
        let mut permissions = fs::metadata(&program)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&program, permissions)?;

        let public_base = McpPublicBase::parse("mcp.example.com")?;
        let result = CloudflarePublicTunnel::start_with_program(
            program.as_os_str(),
            Some(&public_base),
            McpLocalPort::new(7_979)?,
            TunnelStartPolicy {
                attempts: 1,
                startup_timeout: Duration::from_millis(50),
                // Use the production stability budget here. Under the full
                // parallel workspace suite macOS may delay scheduling the
                // freshly spawned shell beyond a sub-second test window,
                // which made this integration check flaky even though the
                // child exits immediately once scheduled.
                custom_stability_window: CUSTOM_TUNNEL_STABILITY_WINDOW,
                poll_interval: Duration::from_millis(5),
            },
        );
        assert!(
            matches!(
                result,
                Err(CloudflarePublicTunnelError::CustomTunnelExitedEarly)
            ),
            "unexpected custom tunnel result: {result:?}"
        );
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
