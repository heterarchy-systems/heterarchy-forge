# xtask/Cargo.toml

```toml
[package]
name = "xtask"
version = "0.1.0"
edition.workspace = true
rust-version.workspace = true
publish = false

[dependencies]
serde_json = "1"
toml = "0.9"

[lints]
workspace = true
```

## Rationale

- `serde_json`: `cargo metadata --format-version 1`을 구조적으로 검증한다.
- `toml`: root/member `Cargo.toml`을 semantic하게 검증하고 brittle substring search를 피한다.
- `xtask`는 repository tooling crate이며 publish하지 않는다.
- application/runtime dependency를 xtask에 끌어오지 않는다. mechanical verification에 필요한 최소 dependency만 둔다.