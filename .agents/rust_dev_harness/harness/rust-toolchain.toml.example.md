# rust-toolchain.toml.example

Repository-owned Rust toolchain policy 예시다.

```toml
[toolchain]
channel = "<PINNED_STABLE_OR_REVIEWED_CHANNEL>"
profile = "minimal"
components = ["rustfmt", "clippy"]
```

## Policy

- production/CI 재현성이 중요하면 reviewed stable version을 pin한다.
- rolling stable을 선택하더라도 그 정책을 `PROJECT_PROFILE.md`에 명시하고 CI/toolchain update가 우연한 workstation 상태에 의해 결정되지 않게 한다.
- nightly는 Miri, fuzz, compiler feature 등 명확한 이유가 있는 별도 extended lane에서 사용한다. ordinary production build authority를 이유 없이 nightly로 바꾸지 않는다.
- `rust-version`/MSRV와 toolchain pin은 다른 계약이다. MSRV는 지원 가능한 최소 compiler이고, toolchain pin은 해당 repository가 현재 검증하는 compiler다.