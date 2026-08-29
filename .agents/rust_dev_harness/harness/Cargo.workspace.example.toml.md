# Cargo.workspace.example.toml

순수 Rust workspace의 **minimal 2026 baseline** 예시다. 프로젝트 crate 이름/구성은 실제 authority boundary에 맞게 바꾸며, adapter/PyO3/benchmark dependency를 공용 baseline에 강제하지 않는다.

```toml
[workspace]
members = [
    "xtask",
    "crates/<TARGET_CRATE>",
]
resolver = "3"

[workspace.package]
edition = "2024"
# Public library/MSRV contract가 있으면 실제 최소 버전을 명시한다.
# Current-stable-only policy라면 repository profile에 그 정책을 기록하고
# 허위 MSRV 값을 만들지 않는다.
rust-version = "<TARGET_RUST_VERSION>"

[workspace.dependencies]
# 실제 여러 crate가 공유하는 dependency만 올린다.
# <TARGET_DEPENDENCY> = { version = "<VERSION>", default-features = false }

[workspace.lints.rust]
unsafe_code = "forbid"
unused_must_use = "deny"

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "warn", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
dbg_macro = "deny"
```

각 workspace member는 다음을 opt-in한다.

```toml
[lints]
workspace = true
```

## Rules

- `resolver = "3"`와 Edition 2024를 current baseline으로 둔다.
- `rust-version`은 실제 지원 계약이다. 단지 최신 버전을 적어두는 장식 필드로 사용하지 않는다.
- workspace dependency inheritance는 실제로 공유되는 dependency에만 사용한다.
- Criterion, Tokio, Rayon, PyO3, serde 같은 dependency를 공용 workspace baseline에 강제하지 않는다. 프로젝트가 필요할 때만 추가한다.
- feature는 최소 집합을 활성화하고, mutually-exclusive feature는 `PROJECT_PROFILE.md`의 matrix로 관리한다.
- `unsafe_code = "forbid"`가 기본이며, unsafe가 필요한 crate는 repository-local architecture decision과 stronger verification 없이 조용히 완화하지 않는다.