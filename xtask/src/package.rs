//! Local macOS `.app` and Installer `.pkg` packaging.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const APP_NAME: &str = "Heterarchy Forge";
const APP_EXECUTABLE: &str = "forge-desktop";
const CLOUDFLARED_EXECUTABLE: &str = "cloudflared";
const APP_IDENTIFIER: &str = "systems.heterarchy.forge";
const CLOUDFLARED_IDENTIFIER: &str = "systems.heterarchy.forge.cloudflared";
const INSTALLER_IDENTIFIER: &str = "systems.heterarchy.forge.installer";
const VERSION_TOKEN: &str = "@@VERSION@@";
const MAX_METADATA_BYTES: u64 = 64 * 1024;
const MAX_WALK_ENTRIES: usize = 4_096;
const MAX_WALK_DEPTH: usize = 16;

const ICON_SPECS: &[(u32, &str)] = &[
    (16, "icon_16x16.png"),
    (32, "icon_16x16@2x.png"),
    (32, "icon_32x32.png"),
    (64, "icon_32x32@2x.png"),
    (128, "icon_128x128.png"),
    (256, "icon_128x128@2x.png"),
    (256, "icon_256x256.png"),
    (512, "icon_256x256@2x.png"),
    (512, "icon_512x512.png"),
    (1_024, "icon_512x512@2x.png"),
];

#[derive(Debug)]
struct PackageSpec {
    version: String,
    architecture: &'static str,
    app_signing_identity: Option<OsString>,
    installer_signing_identity: Option<OsString>,
}

impl PackageSpec {
    fn load(root: &Path) -> Result<Self, String> {
        let manifest = read_bounded_text(&root.join("Cargo.toml"), MAX_METADATA_BYTES)?;
        let parsed = toml::from_str::<toml::Value>(&manifest)
            .map_err(|error| format!("workspace Cargo.toml is invalid: {error}"))?;
        let version = parsed
            .get("workspace")
            .and_then(|value| value.get("package"))
            .and_then(|value| value.get("version"))
            .and_then(toml::Value::as_str)
            .ok_or_else(|| "workspace package version is missing".to_owned())?;
        validate_package_version(version)?;
        Ok(Self {
            version: version.to_owned(),
            architecture: architecture_label()?,
            app_signing_identity: signing_identity("FORGE_APP_SIGNING_IDENTITY")?,
            installer_signing_identity: signing_identity("FORGE_INSTALLER_SIGNING_IDENTITY")?,
        })
    }

    fn versioned_package_name(&self) -> String {
        format!(
            "Heterarchy-Forge-{}-{}.pkg",
            self.version, self.architecture
        )
    }
}

#[derive(Debug)]
struct PackageLayout {
    build_root: PathBuf,
    staging_root: PathBuf,
    app: PathBuf,
    contents: PathBuf,
    macos: PathBuf,
    resources: PathBuf,
    executable: PathBuf,
    cloudflared: PathBuf,
    iconset: PathBuf,
    icon: PathBuf,
    expanded: PathBuf,
    doctor_home: PathBuf,
    dist: PathBuf,
    component_package: PathBuf,
    package: PathBuf,
    latest_package: PathBuf,
}

impl PackageLayout {
    fn new(root: &Path, spec: &PackageSpec) -> Self {
        let build_root = root.join("target/package/macos-local");
        let staging_root = build_root.join("root");
        let app = staging_root.join(format!("{APP_NAME}.app"));
        let contents = app.join("Contents");
        let macos = contents.join("MacOS");
        let resources = contents.join("Resources");
        let dist = root.join("target/dist");
        Self {
            executable: macos.join(APP_EXECUTABLE),
            cloudflared: macos.join(CLOUDFLARED_EXECUTABLE),
            iconset: build_root.join("HeterarchyForge.iconset"),
            icon: resources.join("HeterarchyForge.icns"),
            expanded: build_root.join("expanded"),
            doctor_home: build_root.join("doctor-home"),
            package: dist.join(spec.versioned_package_name()),
            latest_package: dist.join("Heterarchy-Forge.pkg"),
            component_package: build_root.join("systems.heterarchy.forge.pkg"),
            build_root,
            staging_root,
            app,
            contents,
            macos,
            resources,
            dist,
        }
    }

    fn prepare(&self) -> Result<(), String> {
        remove_path_if_present(&self.build_root)?;
        remove_path_if_present(&self.package)?;
        remove_path_if_present(&self.latest_package)?;
        fs::create_dir_all(&self.macos).map_err(path_error("create app MacOS directory"))?;
        fs::create_dir_all(&self.resources)
            .map_err(path_error("create app Resources directory"))?;
        fs::create_dir_all(&self.dist).map_err(path_error("create distribution directory"))?;
        Ok(())
    }
}

pub(super) fn run(root: &Path) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("cargo xtask package is supported only on macOS".to_owned());
    }
    let spec = PackageSpec::load(root)?;
    let layout = PackageLayout::new(root, &spec);
    super::cargo(&["build", "--locked", "--release", "-p", "forge-desktop"])?;
    layout.prepare()?;
    assemble_app(root, &spec, &layout)?;
    sign_app(&spec, &layout)?;
    verify_app(&layout)?;
    run_bundled_doctor(&layout)?;
    build_product_archive(root, &spec, &layout)?;
    verify_product_archive(&layout)?;
    fs::copy(&layout.package, &layout.latest_package)
        .map_err(path_error("copy stable package artifact"))?;
    println!("Heterarchy Forge local package created:");
    println!("  app: {}", layout.app.display());
    println!("  pkg: {}", layout.package.display());
    println!("  stable pkg: {}", layout.latest_package.display());
    if spec.installer_signing_identity.is_none() {
        println!("  installer signature: unsigned local-development package");
    }
    Ok(())
}

fn assemble_app(root: &Path, spec: &PackageSpec, layout: &PackageLayout) -> Result<(), String> {
    let release_binary = root.join("target/release").join(APP_EXECUTABLE);
    require_regular_nonempty_file(&release_binary, "release desktop binary")?;
    fs::copy(&release_binary, &layout.executable)
        .map_err(path_error("copy release desktop binary into app bundle"))?;
    make_executable(&layout.executable, "bundled desktop executable")?;

    let cloudflared = find_path_executable(CLOUDFLARED_EXECUTABLE).ok_or_else(|| {
        "cloudflared is required to build the standalone macOS app bundle".to_owned()
    })?;
    require_regular_nonempty_file(&cloudflared, "cloudflared source executable")?;
    fs::copy(&cloudflared, &layout.cloudflared)
        .map_err(path_error("copy cloudflared into app bundle"))?;
    make_executable(&layout.cloudflared, "bundled cloudflared executable")?;

    let template_path = root.join("packaging/macos/Info.plist.in");
    let template = read_bounded_text(&template_path, MAX_METADATA_BYTES)?;
    let rendered = render_info_plist(&template, &spec.version)?;
    fs::write(layout.contents.join("Info.plist"), rendered)
        .map_err(path_error("write app Info.plist"))?;
    fs::write(layout.contents.join("PkgInfo"), b"APPL????\n")
        .map_err(path_error("write app PkgInfo"))?;
    generate_icon(root, layout)
}

fn make_executable(path: &Path, label: &'static str) -> Result<(), String> {
    let mut permissions = fs::metadata(path)
        .map_err(path_error("read bundled executable metadata"))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).map_err(path_error(label))
}

fn find_path_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| {
            fs::symlink_metadata(candidate).is_ok_and(|metadata| metadata.file_type().is_file())
        })
}

fn generate_icon(root: &Path, layout: &PackageLayout) -> Result<(), String> {
    let source = root.join("docs/assets/hf-image.png");
    require_regular_nonempty_file(&source, "app icon source")?;
    fs::create_dir_all(&layout.iconset).map_err(path_error("create iconset directory"))?;
    let master = layout.build_root.join("icon-master.png");
    run_command(
        "/usr/bin/sips",
        &[
            "--cropToHeightWidth".into(),
            "1024".into(),
            "1024".into(),
            source.into_os_string(),
            "--out".into(),
            master.clone().into_os_string(),
        ],
        root,
    )?;
    for (size, name) in ICON_SPECS {
        let destination = layout.iconset.join(name);
        let dimension = size.to_string();
        run_command(
            "/usr/bin/sips",
            &[
                "--resampleHeightWidth".into(),
                dimension.clone().into(),
                dimension.into(),
                master.clone().into_os_string(),
                "--out".into(),
                destination.into_os_string(),
            ],
            root,
        )?;
    }
    run_command(
        "/usr/bin/iconutil",
        &[
            "--convert".into(),
            "icns".into(),
            "--output".into(),
            layout.icon.clone().into_os_string(),
            layout.iconset.clone().into_os_string(),
        ],
        root,
    )?;
    require_regular_nonempty_file(&layout.icon, "generated app icon")
}

fn sign_app(spec: &PackageSpec, layout: &PackageLayout) -> Result<(), String> {
    sign_macho(
        spec,
        &layout.cloudflared,
        CLOUDFLARED_IDENTIFIER,
        &layout.build_root,
    )?;
    sign_macho(spec, &layout.app, APP_IDENTIFIER, &layout.build_root)
}

fn sign_macho(
    spec: &PackageSpec,
    path: &Path,
    identifier: &str,
    current_dir: &Path,
) -> Result<(), String> {
    let identity = spec
        .app_signing_identity
        .clone()
        .unwrap_or_else(|| OsString::from("-"));
    let mut arguments = vec![
        OsString::from("--force"),
        OsString::from("--sign"),
        identity,
        OsString::from("--identifier"),
        OsString::from(identifier),
    ];
    if spec.app_signing_identity.is_some() {
        arguments.extend([
            OsString::from("--options"),
            OsString::from("runtime"),
            OsString::from("--timestamp"),
        ]);
    } else {
        arguments.push(OsString::from("--timestamp=none"));
    }
    arguments.push(path.as_os_str().to_owned());
    run_command("/usr/bin/codesign", &arguments, current_dir)
}

fn verify_app(layout: &PackageLayout) -> Result<(), String> {
    run_command(
        "/usr/bin/plutil",
        &[
            "-lint".into(),
            layout.contents.join("Info.plist").into_os_string(),
        ],
        &layout.build_root,
    )?;
    run_command(
        "/usr/bin/codesign",
        &[
            "--verify".into(),
            "--strict".into(),
            "--verbose=2".into(),
            layout.app.clone().into_os_string(),
        ],
        &layout.build_root,
    )?;
    require_regular_nonempty_file(&layout.cloudflared, "bundled cloudflared executable")?;
    run_command(
        "/usr/bin/codesign",
        &[
            "--verify".into(),
            "--strict".into(),
            "--verbose=2".into(),
            layout.cloudflared.clone().into_os_string(),
        ],
        &layout.build_root,
    )?;
    run_command(
        "/usr/bin/file",
        &[layout.executable.clone().into_os_string()],
        &layout.build_root,
    )?;
    run_command(
        "/usr/bin/lipo",
        &["-archs".into(), layout.executable.clone().into_os_string()],
        &layout.build_root,
    )?;
    run_command(
        "/usr/bin/file",
        &[layout.cloudflared.clone().into_os_string()],
        &layout.build_root,
    )?;
    run_command(
        "/usr/bin/lipo",
        &["-archs".into(), layout.cloudflared.clone().into_os_string()],
        &layout.build_root,
    )?;
    run_command(
        "/usr/bin/otool",
        &["-L".into(), layout.executable.clone().into_os_string()],
        &layout.build_root,
    )
}

fn run_bundled_doctor(layout: &PackageLayout) -> Result<(), String> {
    fs::create_dir_all(&layout.doctor_home).map_err(path_error("create package doctor home"))?;
    let registry = layout.doctor_home.join("registry.sqlite3");
    let status = Command::new(&layout.executable)
        .arg("--doctor")
        .current_dir(&layout.build_root)
        .env("HOME", &layout.doctor_home)
        .env("HETERARCHY_FORGE_REGISTRY_PATH", &registry)
        .status()
        .map_err(|error| format!("failed to start bundled desktop doctor: {error}"))?;
    if !status.success() {
        return Err(format!(
            "bundled desktop doctor exited with status {status}"
        ));
    }
    if registry.exists() {
        return Err("bundled desktop doctor unexpectedly created its registry".to_owned());
    }
    Ok(())
}

fn build_product_archive(
    root: &Path,
    spec: &PackageSpec,
    layout: &PackageLayout,
) -> Result<(), String> {
    let component_plist = root.join("packaging/macos/component.plist");
    run_command(
        "/usr/bin/plutil",
        &["-lint".into(), component_plist.clone().into_os_string()],
        &layout.build_root,
    )?;
    run_command(
        "/usr/bin/pkgbuild",
        &[
            "--root".into(),
            layout.staging_root.clone().into_os_string(),
            "--component-plist".into(),
            component_plist.into_os_string(),
            "--identifier".into(),
            APP_IDENTIFIER.into(),
            "--version".into(),
            spec.version.clone().into(),
            "--install-location".into(),
            "/Applications".into(),
            "--ownership".into(),
            "recommended".into(),
            layout.component_package.clone().into_os_string(),
        ],
        &layout.build_root,
    )?;
    require_regular_nonempty_file(&layout.component_package, "Installer component package")?;
    let mut arguments = vec![
        OsString::from("--package"),
        layout.component_package.clone().into_os_string(),
        OsString::from("--identifier"),
        OsString::from(INSTALLER_IDENTIFIER),
        OsString::from("--version"),
        OsString::from(&spec.version),
    ];
    if let Some(identity) = &spec.installer_signing_identity {
        arguments.extend([
            OsString::from("--sign"),
            identity.clone(),
            OsString::from("--timestamp"),
        ]);
    }
    arguments.push(layout.package.clone().into_os_string());
    run_command("/usr/bin/productbuild", &arguments, &layout.build_root)?;
    require_regular_nonempty_file(&layout.package, "Installer product archive")
}

fn verify_product_archive(layout: &PackageLayout) -> Result<(), String> {
    remove_path_if_present(&layout.expanded)?;
    run_command(
        "/usr/sbin/pkgutil",
        &[
            "--expand-full".into(),
            layout.package.clone().into_os_string(),
            layout.expanded.clone().into_os_string(),
        ],
        &layout.build_root,
    )?;
    require_regular_nonempty_file(
        &layout.expanded.join("Distribution"),
        "expanded Distribution",
    )?;
    let mut entries = 0_usize;
    let mut apps = Vec::new();
    collect_named_directories(
        &layout.expanded,
        &format!("{APP_NAME}.app"),
        0,
        &mut entries,
        &mut apps,
    )?;
    if apps.len() != 1 {
        return Err(format!(
            "expanded package contained {} Heterarchy Forge app payloads",
            apps.len()
        ));
    }
    let expanded_executable = apps[0].join("Contents/MacOS").join(APP_EXECUTABLE);
    let expanded_cloudflared = apps[0].join("Contents/MacOS").join(CLOUDFLARED_EXECUTABLE);
    require_regular_nonempty_file(&expanded_executable, "expanded package executable")?;
    require_regular_nonempty_file(&expanded_cloudflared, "expanded cloudflared executable")?;
    run_command(
        "/usr/bin/codesign",
        &[
            "--verify".into(),
            "--strict".into(),
            "--verbose=2".into(),
            apps[0].clone().into_os_string(),
        ],
        &layout.build_root,
    )?;
    let bundled_hash = sha256_file(&layout.executable)?;
    let expanded_hash = sha256_file(&expanded_executable)?;
    if bundled_hash != expanded_hash {
        return Err("expanded package executable differs from signed app bundle".to_owned());
    }
    let bundled_cloudflared_hash = sha256_file(&layout.cloudflared)?;
    let expanded_cloudflared_hash = sha256_file(&expanded_cloudflared)?;
    if bundled_cloudflared_hash != expanded_cloudflared_hash {
        return Err("expanded cloudflared differs from signed app bundle".to_owned());
    }
    run_command(
        "/usr/sbin/installer",
        &[
            "-showChoicesXML".into(),
            "-pkg".into(),
            layout.package.clone().into_os_string(),
            "-target".into(),
            OsString::from("/"),
        ],
        &layout.build_root,
    )?;
    Ok(())
}

fn collect_named_directories(
    root: &Path,
    name: &str,
    depth: usize,
    entries: &mut usize,
    matches: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if depth > MAX_WALK_DEPTH {
        return Err(format!(
            "expanded package exceeded walk depth {MAX_WALK_DEPTH}"
        ));
    }
    for entry in fs::read_dir(root).map_err(path_error("read expanded package directory"))? {
        let entry = entry.map_err(path_error("read expanded package entry"))?;
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| "expanded package entry count overflowed".to_owned())?;
        if *entries > MAX_WALK_ENTRIES {
            return Err(format!(
                "expanded package exceeded {MAX_WALK_ENTRIES} entries"
            ));
        }
        let file_type = entry
            .file_type()
            .map_err(path_error("read expanded package entry type"))?;
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        if entry.file_name() == name {
            matches.push(entry.path());
        } else {
            collect_named_directories(&entry.path(), name, depth + 1, entries, matches)?;
        }
    }
    Ok(())
}

fn render_info_plist(template: &str, version: &str) -> Result<String, String> {
    validate_package_version(version)?;
    let occurrences = template.match_indices(VERSION_TOKEN).count();
    if occurrences != 2 {
        return Err(format!(
            "Info.plist template must contain exactly two version tokens, found {occurrences}"
        ));
    }
    let rendered = template.replace(VERSION_TOKEN, version);
    if rendered.contains("@@") {
        return Err("Info.plist template contains an unresolved token".to_owned());
    }
    Ok(rendered)
}

fn validate_package_version(version: &str) -> Result<(), String> {
    if version.is_empty()
        || version.len() > 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err(format!("package version {version:?} is not canonical"));
    }
    Ok(())
}

fn architecture_label() -> Result<&'static str, String> {
    match env::consts::ARCH {
        "aarch64" => Ok("arm64"),
        "x86_64" => Ok("x86_64"),
        other => Err(format!("unsupported macOS package architecture {other:?}")),
    }
}

fn signing_identity(name: &str) -> Result<Option<OsString>, String> {
    let Some(value) = env::var_os(name) else {
        return Ok(None);
    };
    if value.is_empty() || value.as_encoded_bytes().len() > 256 {
        return Err(format!("{name} is empty or oversized"));
    }
    if value.as_encoded_bytes().iter().any(u8::is_ascii_control) {
        return Err(format!("{name} contains a control character"));
    }
    Ok(Some(value))
}

fn read_bounded_text(path: &Path, maximum: u64) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(path_error("read metadata"))?;
    if !metadata.is_file() || metadata.len() > maximum {
        return Err(format!(
            "{} is not a regular file within {maximum} bytes",
            path.display()
        ));
    }
    fs::read_to_string(path).map_err(path_error("read UTF-8 text"))
}

fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
    let file = File::open(path).map_err(path_error("open file for hashing"))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(path_error("read file for hashing"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn require_regular_nonempty_file(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(path_error("read artifact metadata"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(format!("{label} {} is missing or invalid", path.display()));
    }
    Ok(())
}

fn remove_path_if_present(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path).map_err(path_error("remove previous package directory"))
        }
        Ok(_) => fs::remove_file(path).map_err(path_error("remove previous package artifact")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "inspect {} before removal: {error}",
            path.display()
        )),
    }
}

fn run_command(program: &str, arguments: &[OsString], cwd: &Path) -> Result<(), String> {
    let status = Command::new(program)
        .args(arguments)
        .current_dir(cwd)
        .status()
        .map_err(|error| format!("failed to start {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        let display = arguments
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        Err(format!("{program} {display} exited with status {status}"))
    }
}

fn path_error(action: &'static str) -> impl FnOnce(io::Error) -> String {
    move |error| format!("{action}: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_plist_template_is_versioned_without_unresolved_tokens() -> Result<(), String> {
        let root = super::super::workspace_root();
        let template = read_bounded_text(
            &root.join("packaging/macos/Info.plist.in"),
            MAX_METADATA_BYTES,
        )?;
        let rendered = render_info_plist(&template, "1.2.3")?;
        assert!(rendered.contains("<string>1.2.3</string>"));
        assert!(!rendered.contains(VERSION_TOKEN));
        assert!(rendered.contains(APP_IDENTIFIER));
        Ok(())
    }

    #[test]
    fn component_policy_disables_installer_bundle_relocation() -> Result<(), String> {
        let root = super::super::workspace_root();
        let policy = read_bounded_text(
            &root.join("packaging/macos/component.plist"),
            MAX_METADATA_BYTES,
        )?;
        assert!(policy.contains("<key>BundleIsRelocatable</key>\n        <false/>"));
        assert!(policy.contains("<string>Heterarchy Forge.app</string>"));
        assert!(policy.contains("<string>upgrade</string>"));
        Ok(())
    }

    #[test]
    fn version_and_artifact_name_are_bounded_and_arch_specific() -> Result<(), String> {
        validate_package_version("0.1.0")?;
        assert!(validate_package_version("").is_err());
        assert!(validate_package_version("1.0</string>").is_err());
        let spec = PackageSpec {
            version: "0.1.0".to_owned(),
            architecture: "arm64",
            app_signing_identity: None,
            installer_signing_identity: None,
        };
        assert_eq!(
            spec.versioned_package_name(),
            "Heterarchy-Forge-0.1.0-arm64.pkg"
        );
        Ok(())
    }

    #[test]
    fn iconset_contract_has_every_required_resolution_once() {
        assert_eq!(ICON_SPECS.len(), 10);
        let names = ICON_SPECS
            .iter()
            .map(|(_, name)| *name)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), ICON_SPECS.len());
        assert!(ICON_SPECS.contains(&(1_024, "icon_512x512@2x.png")));
    }
}
