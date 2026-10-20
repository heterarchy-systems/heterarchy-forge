//! Standalone lifecycle proof using isolated state and only owned child PIDs.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use forge_persistence::GlobalRegistry;
use serde_json::json;
use uuid::Uuid;

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn spawn(config: &Path, log: &Path) -> Result<OwnedChild, Box<dyn std::error::Error>> {
    Ok(OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_forge-backend"))
            .args(["serve".as_ref(), config.as_os_str()])
            .stdin(Stdio::null())
            .stdout(File::create(log.with_extension("stdout"))?)
            .stderr(File::create(log.with_extension("stderr"))?)
            .spawn()?,
    ))
}

async fn wait_for_start(
    child: &mut OwnedChild,
    log: &Path,
) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let output = fs::read_to_string(log.with_extension("stdout"))?;
        if let Some(address) = output.lines().find_map(|line| line.parse().ok()) {
            return Ok(address);
        }
        if let Some(status) = child.0.try_wait()? {
            return Err(format!(
                "host exited during startup: {status}: {}",
                fs::read_to_string(log.with_extension("stderr"))?
            )
            .into());
        }
        if Instant::now() >= deadline {
            return Err("host startup did not finish within its budget".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_exit(child: &mut OwnedChild) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err("host shutdown required forced termination".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn read_capability(
    address: SocketAddr,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    stream
        .write_all(
            b"GET /api/v1/capability HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        stream.take(64 * 1024).read_to_end(&mut response),
    )
    .await??;
    let offset = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .ok_or("capability HTTP header missing")?;
    Ok(serde_json::from_slice(&response[offset + 4..])?)
}

#[tokio::test]
#[ignore = "requires explicitly configured real native Rust host home"]
async fn standalone_prepares_real_rust_ci_and_fences_the_selected_cache()
-> Result<(), Box<dyn std::error::Error>> {
    let host_home = PathBuf::from(
        std::env::var_os("FORGE_NATIVE_RUST_CI_HOME")
            .ok_or("FORGE_NATIVE_RUST_CI_HOME required")?,
    );
    // The real local candidate is required to share the host-home device.
    let root = host_home
        .join("Library")
        .join("Caches")
        .join(format!("forge-host-rust-ci-{}", Uuid::now_v7()));
    fs::create_dir_all(&root)?;
    let fixture = Fixture(fs::canonicalize(root)?);
    let registry = fixture.0.join("registry.sqlite3");
    drop(GlobalRegistry::open(&registry)?);
    fs::write(fixture.0.join("api.secret"), "host-api-credential")?;
    fs::write(fixture.0.join("session.secret"), "session-credential")?;
    let cache = fixture.0.join(format!(
        "rust-ci-{}-local",
        forge_execution::RUST_CI_PINNED_VERSION
    ));
    let mut config = json!({
        "listen":"127.0.0.1:0","registry_path":registry,"product_cache_root":cache,
        "backend_id":Uuid::now_v7(),"issuer_id":Uuid::now_v7(),"destination_id":Uuid::now_v7(),
        "api_bearer_file":fixture.0.join("api.secret"),"session_authority":"127.0.0.1:1","session_bearer_file":fixture.0.join("session.secret"),
        "rust_ci":{"host_home":host_home,"local_cache_root":fixture.0.join("rust-ci")},
    });
    let config_path = fixture.0.join("backend.json");
    fs::write(&config_path, serde_json::to_vec(&config)?)?;
    let log = fixture.0.join("enabled");
    let mut enabled = spawn(&config_path, &log)?;
    let address = match wait_for_start(&mut enabled, &log).await {
        Ok(address) => address,
        Err(error) => {
            let architecture = forge_execution::RustCiHostArchitecture::current()
                .ok_or("unsupported native Rust CI architecture")?;
            let input = forge_execution::RustCiDiscoveryInput::from_roots(
                cache.clone(),
                host_home.clone(),
                architecture,
                forge_domain::RuntimeInstanceId::from_uuid(Uuid::now_v7()),
            )?;
            let observed = forge_execution::RustCiToolchainCapability::discover(&input);
            return Err(format!("{error}; native local capability diagnosis: {observed:?}").into());
        }
    };
    let capability = read_capability(address).await?;
    assert_eq!(capability["execution"]["rust_ci_available"], true);
    assert!(
        capability["runtime_instance"]
            .as_str()
            .and_then(|value| Uuid::parse_str(value).ok())
            .is_some_and(|id| !id.is_nil())
    );
    assert!(
        fs::read_to_string(log.with_extension("stderr"))?.contains("LocalAfterFourSsdFailures")
    );
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &enabled.0.id().to_string()])
            .status()?
            .success()
    );
    assert!(wait_for_exit(&mut enabled).await?.success());
    assert!(cache.is_dir());
    let wrong = fixture.0.join("wrong-cache");
    fs::create_dir(&wrong)?;
    config["product_cache_root"] = json!(wrong);
    fs::write(&config_path, serde_json::to_vec(&config)?)?;
    let mismatch_log = fixture.0.join("mismatch");
    let mut mismatch = spawn(&config_path, &mismatch_log)?;
    assert!(!wait_for_exit(&mut mismatch).await?.success());
    assert!(
        fs::read_to_string(mismatch_log.with_extension("stderr"))?
            .contains("does not match the declared cache root")
    );
    assert_eq!(fs::read_dir(&wrong)?.count(), 0);
    Ok(())
}

#[tokio::test]
async fn standalone_sigterm_drains_all_owners_and_releases_the_restart_fence()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture(std::env::temp_dir().join(format!("forge-host-{}", Uuid::now_v7())));
    fs::create_dir_all(fixture.0.join("product-cache"))?;
    let registry_path = fixture.0.join("registry.sqlite3");
    drop(GlobalRegistry::open(&registry_path)?);
    for (name, secret) in [
        ("api.secret", "host-api-credential"),
        ("session.secret", "session-credential"),
    ] {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(fixture.0.join(name))?
            .write_all(secret.as_bytes())?;
    }
    let config = fixture.0.join("backend.json");
    fs::write(
        &config,
        serde_json::to_vec(&json!({
            "listen": "127.0.0.1:0",
            "registry_path": registry_path,
            "product_cache_root": fixture.0.join("product-cache"),
            "backend_id": Uuid::now_v7(),
            "issuer_id": Uuid::now_v7(),
            "destination_id": Uuid::now_v7(),
            "api_bearer_file": fixture.0.join("api.secret"),
            "session_authority": "127.0.0.1:1",
            "session_bearer_file": fixture.0.join("session.secret"),
        }))?,
    )?;

    let first_log = fixture.0.join("first");
    let mut first = spawn(&config, &first_log)?;
    let _address = wait_for_start(&mut first, &first_log).await?;
    let duplicate_log = fixture.0.join("duplicate");
    let mut duplicate = spawn(&config, &duplicate_log)?;
    assert!(!wait_for_exit(&mut duplicate).await?.success());
    assert!(
        fs::read_to_string(duplicate_log.with_extension("stderr"))?
            .contains("already owns this Registry")
    );

    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &first.0.id().to_string()])
            .status()?
            .success()
    );
    assert!(wait_for_exit(&mut first).await?.success());
    let first_errors = fs::read_to_string(first_log.with_extension("stderr"))?;

    let second_log = fixture.0.join("second");
    let mut second = spawn(&config, &second_log)?;
    let _address = wait_for_start(&mut second, &second_log).await?;
    assert!(
        Command::new("/bin/kill")
            .args(["-TERM", &second.0.id().to_string()])
            .status()?
            .success()
    );
    assert!(wait_for_exit(&mut second).await?.success());
    let second_errors = fs::read_to_string(second_log.with_extension("stderr"))?;
    assert!(
        !first_errors.contains("shutdown incomplete"),
        "{first_errors}"
    );
    assert!(
        !second_errors.contains("shutdown incomplete"),
        "{second_errors}"
    );
    Ok(())
}
