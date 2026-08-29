# deny.toml.example

`cargo xtask deps`에서 사용하는 repository-owned `cargo-deny` policy의 2026 baseline 예시다.

이 파일은 dependency security/license/source policy를 **프로젝트가 직접 소유**하게 하기 위한 template이다. License allow-list, target set, exception은 프로젝트 의존성/배포정책을 검토한 뒤 확정한다.

```toml
[advisories]
unmaintained = "workspace"
unsound = "all"
# ignore = [
#     { id = "RUSTSEC-YYYY-NNNN", reason = "reviewed project-specific exception" },
# ]

[bans]
multiple-versions = "warn"
wildcards = "deny"
# deny = []
# skip / skip-tree는 실제 duplicate 원인을 검토한 뒤 이유와 함께 추가한다.

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []

[licenses]
confidence-threshold = 0.9
# 프로젝트가 승인한 SPDX license만 명시한다.
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
]
# exceptions는 dependency별 license를 검토하고 근거를 남긴 뒤 추가한다.
```

## Policy

- `advisories`: 알려진 vulnerability/unsound/unmaintained 상태를 검토한다. Ignore는 advisory ID와 구체적 reachability/업데이트 제약 근거가 있어야 한다.
- `licenses`: allow-list 밖의 license는 우연히 통과시키지 않는다. 실제 project distribution/license policy에 맞게 좁히거나 필요한 항목만 추가한다.
- `bans`: wildcard dependency를 기본 deny한다. Multiple versions는 template에서는 `warn`이지만 project가 통제 가능한 graph라면 `deny`로 강화할 수 있다.
- `sources`: 알 수 없는 registry/git source는 기본 deny한다. Private registry/git은 명시적 allow policy로 추가한다.
- `graph.all-features`를 공용 template에서 강제하지 않는다. Feature 조합은 `PROJECT_PROFILE.md`의 supported matrix를 따른다.
- advisory/license/source exception은 영구 면제가 아니라 reviewed debt다. 이유와 제거 조건을 기록한다.

## Verification

```text
cargo xtask deps
```

`cargo-deny` binary 또는 실제 `deny.toml`이 없으면 dependency gate는 PASS가 아니라 unverified/failure다.