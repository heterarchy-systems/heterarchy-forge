use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use forge_domain::RuntimeInstanceId;
use serde_json::json;
use uuid::Uuid;

use super::*;

struct Fixture {
    root: PathBuf,
    host_home: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let raw_root =
            std::env::temp_dir().join(format!("forge-backend-host-toolchain-{}", Uuid::now_v7()));
        fs::create_dir_all(&raw_root)?;
        let root = fs::canonicalize(raw_root)?;
        let host_home = root.join("host-home");
        fs::create_dir_all(&host_home)?;
        Ok(Self { root, host_home })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn config_rejects_unknown_fields() {
    let parsed = serde_json::from_value::<HostRustCiConfig>(json!({
        "host_home": "/tmp/host",
        "local_cache_root": "/tmp/cache",
        "unexpected": true,
    }));
    assert!(parsed.is_err());
}

#[test]
fn host_and_local_roots_require_canonical_existing_directories() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let missing_parent = fixture.root.join("missing").join("cache");
    assert!(matches!(
        validate_local_cache_root(&missing_parent),
        Err(HostToolchainError::InvalidLocalCacheRoot)
    ));
    assert!(!missing_parent.parent().ok_or("missing parent")?.exists());

    let host_alias = fixture.root.join("host-alias");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&fixture.host_home, &host_alias)?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&fixture.host_home, &host_alias)?;
    assert!(matches!(
        validate_host_home(&host_alias),
        Err(HostToolchainError::InvalidHostHome)
    ));
    Ok(())
}

#[test]
fn local_cache_leaf_may_be_absent_without_creating_it() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let parent = fixture.root.join("cache-parent");
    fs::create_dir(&parent)?;
    let leaf = parent.join("rust-ci");
    let validated = validate_local_cache_root(&leaf)?;
    assert_eq!(validated, leaf);
    assert!(!leaf.exists());
    Ok(())
}

#[test]
fn declared_cache_root_must_be_absolute_and_canonical() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let root = fixture.root.join("declared");
    fs::create_dir(&root)?;
    let file = fixture.root.join("declared-file");
    fs::write(&file, b"not a cache directory")?;
    assert!(matches!(
        validate_declared_cache_root(Path::new("relative-cache")),
        Err(HostToolchainError::CacheRootMismatch)
    ));
    assert!(matches!(
        validate_declared_cache_root(&file),
        Err(HostToolchainError::CacheRootMismatch)
    ));

    #[cfg(unix)]
    {
        let alias = fixture.root.join("declared-alias");
        std::os::unix::fs::symlink(&root, &alias)?;
        assert!(matches!(
            validate_declared_cache_root(&alias),
            Err(HostToolchainError::CacheRootMismatch)
        ));
    }
    Ok(())
}

#[test]
fn invalid_configuration_is_typed_and_does_not_expose_configured_paths()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let config = HostRustCiConfig {
        host_home: fixture.host_home.clone(),
        local_cache_root: fixture.root.join("cache").join("rust-ci"),
    };
    let declared = fixture.root.join("declared-cache");
    let Err(error) = prepare(
        &config,
        &declared,
        RuntimeInstanceId::from_uuid(Uuid::from_u128(7)),
    ) else {
        return Err("an absent local cache parent was accepted".into());
    };
    assert!(matches!(error, HostToolchainError::InvalidLocalCacheRoot));
    let configured_root = fixture.root.to_string_lossy().into_owned();
    assert!(!error.to_string().contains(&configured_root));
    Ok(())
}
