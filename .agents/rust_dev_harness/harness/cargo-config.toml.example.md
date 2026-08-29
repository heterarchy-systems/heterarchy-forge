# cargo-config.toml.example

Repository root의 `.cargo/config.toml`에 적용하는 최소 `xtask` alias 예시다.

```toml
[alias]
xtask = "run --package xtask --"
```

## Rule

- canonical mechanical entrypoint는 `cargo xtask <command>`다.
- shell script나 Makefile이 이 alias를 재구현하지 않는다.
- polyglot 상위 task runner가 필요하면 이 명령을 호출하는 얇은 adapter만 둔다.