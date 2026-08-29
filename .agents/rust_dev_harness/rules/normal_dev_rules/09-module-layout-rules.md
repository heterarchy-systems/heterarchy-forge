# 09 — Module Layout, Visibility, and Test Organization Rules

2026 Rust/Edition 2024 기준의 **module tree, file layout, visibility, unit/integration test organization** 규칙이다. 이 규칙은 파일을 보기 좋게 나누는 스타일 가이드가 아니라, Rust의 module/privacy/test compilation model을 보존하면서 책임과 권한을 명확히 만드는 규칙이다.

## 1. Module file layout

새 코드와 의도적인 구조 리팩터링에서는 현재 Rust Book의 관용 경로를 우선한다.

```text
src/
├── workspace_checkpoints.rs
└── workspace_checkpoints/
    ├── codec.rs
    ├── repository.rs
    ├── schema.rs
    └── validation.rs
```

부모 module은 `foo.rs`, 자식 module은 `foo/bar.rs` 형태를 기본으로 한다.

`foo/mod.rs`는 compiler가 계속 지원하지만 현재 Rust Book이 **older style, still supported**로 분류한다. 기존 repository가 `mod.rs` convention을 일관되게 사용하고 있다면 단순 스타일 변경만을 위해 전체를 흔들지 않는다. 그러나 새 module tree 또는 의미 있는 리팩터링에서 별도 이유 없이 `mod.rs` 스타일을 새로 확산하지 않는다.

같은 project 안에서 두 스타일을 무계획하게 섞지 않는다.

## 2. Split by responsibility, not line count

Rust에는 일반적인 source-file line-count 제한이 없다. 다음 규칙을 금지한다.

```text
1000 lines → 반드시 split
2000 lines → 반드시 split
unit tests가 길다 → tests/로 이동
```

대신 다음 신호가 동시에 나타나면 production module 분해를 검토한다.

- 서로 다른 변경 이유/change reason이 한 파일에 존재한다.
- schema/migration, repository/transaction, codec, cross-record validation, runtime/effect 같은 독립 책임이 한 module에 혼재한다.
- 서로 독립적으로 테스트·교체·리뷰할 수 있는 하위 권한이 이미 형성됐다.
- visibility를 넓혀야만 내부 구조를 공유할 수 있는 상황이 반복된다.
- 파일 내부 결합 때문에 unrelated change의 merge conflict와 review surface가 지속적으로 커진다.
- compile/dependency/effect authority를 분리하면 실제 이득이 있다.

분해 목표는 작은 파일 개수가 아니라 **응집된 module과 좁은 권한 경계**다.

함수 길이는 파일 길이와 별개다. `clippy::too_many_lines` 같은 함수-level lint는 project risk/profile에 따라 사용할 수 있지만, 이를 source-file hard limit로 오해하지 않는다.

## 3. Visibility is a capability boundary

필요한 가장 좁은 visibility를 사용한다.

```text
private
→ pub(super)
→ pub(crate)
→ pub
```

- 같은 module에서만 필요하면 private 유지.
- 직접 parent module만 조립해야 하면 `pub(super)` 우선.
- crate 내부 여러 module의 안정된 internal API일 때만 `pub(crate)`.
- 실제 crate consumer가 사용해야 하는 API만 `pub`.
- 테스트에서 접근하기 위해 production item을 `pub`/`pub(crate)`로 승격하지 않는다.
- re-export도 실제 facade/authority가 필요할 때만 사용한다.

Module split은 visibility 확장의 명분이 아니다. 구조를 나눈 뒤 오히려 capability surface가 최소화되어야 한다.

## 4. Unit tests stay inside the module tree

작고 응집된 module의 unit test는 구현과 함께 둔다.

```rust
fn validate_restore() -> Result<(), RestoreError> {
    // ...
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_restore() {
        // ...
    }
}
```

이 방식은 unit test가 module privacy를 그대로 사용하고 test build가 아닐 때 test module을 제외하는 Rust의 기본 모델이다.

테스트가 커지면 **unit test semantics를 버리지 않고 물리적으로만 분리**할 수 있다.

```text
src/
├── workspace_checkpoints.rs
└── workspace_checkpoints/
    ├── codec.rs
    ├── repository.rs
    ├── validation.rs
    └── tests.rs
```

부모:

```rust
#[cfg(test)]
mod tests;
```

`workspace_checkpoints/tests.rs`는 여전히 parent module의 child module이므로 private implementation을 테스트할 수 있다.

테스트가 더 커지면 `tests.rs` 아래에 다시 child modules를 둘 수 있다.

```text
workspace_checkpoints/
├── tests.rs
└── tests/
    ├── codec.rs
    ├── corruption.rs
    ├── lifecycle.rs
    └── schema.rs
```

단, **production code를 분해해야 할 문제를 test file 이동만으로 숨기지 않는다.** 큰 module은 먼저 production responsibility를 검토하고, 각 child module의 unit test는 가능한 한 그 책임 가까이에 둔다.

## 5. Root `tests/` is integration-test territory

Cargo package root의 `tests/`는 일반 unit-test 저장소가 아니다. 각 integration-test target은 crate 외부 consumer 관점으로 컴파일된다.

```text
crate/
├── src/
│   └── ...
└── tests/
    ├── public_contract.rs
    ├── migration.rs
    └── crash_recovery.rs
```

Root `tests/`에는 다음을 우선한다.

- public crate/API contract;
- application boundary integration;
- migration compatibility/E2E;
- persistence durability and reopen/restart behavior;
- process/runtime boundary;
- real adapter/infrastructure contract.

Private helper 또는 internal invariant를 테스트하기 위해 production visibility를 넓히고 root `tests/`에서 호출하는 패턴을 금지한다.

Integration-test 공용 helper가 필요하면 helper 자체를 독립 integration test target으로 만들지 않도록 Cargo test target semantics를 고려한 하위 module 구조를 사용한다.

## 6. Recommended large-module shape

예를 들어 persistence checkpoint 책임이 커졌다면 다음 정도의 분해는 자연스럽다.

```text
src/
├── workspace_checkpoints.rs
└── workspace_checkpoints/
    ├── codec.rs
    ├── repository.rs
    ├── schema.rs
    ├── validation.rs
    └── tests.rs
```

`workspace_checkpoints.rs`는 module facade/orchestration 역할을 유지하고, child module은 독립 change reason에 맞춰 분리한다.

반대로 다음과 같은 package explosion은 피한다.

```text
codec.rs
codec_helpers.rs
codec_error.rs
decoder.rs
decoder_helpers.rs
query.rs
query_helpers.rs
```

명확한 독립 책임/권한/변경 이유가 없는 미세 분리는 module navigation과 visibility만 악화시킨다.

## 7. Clippy policy

- `clippy::items_after_test_module`은 test module 뒤의 production item 배치를 잡는 현재 style lint이며 일반 Clippy gate에서 활용한다.
- `clippy::tests_outside_test_module`은 2026 현재 존재하는 **restriction lint**다. unit-test module discipline에는 유용하지만 공용 workspace에서 무조건 deny하지 않는다. Root integration-test crate 등 legitimate test target까지 일괄 정책화하면 불필요한 wrapping을 강제할 수 있으므로 project scope를 검토한 뒤 선택적으로 활성화한다.
- `clippy::inline_modules` 역시 restriction lint이므로 모든 inline module을 금지하는 공용 baseline으로 사용하지 않는다. 작은 module과 `#[cfg(test)]` inline test module은 정당하다.
- 전체 `restriction` group을 기계적으로 enable하지 않는다.

## 8. Harness verification

Generic shared harness가 기계적으로 검증해야 하는 범위:

```text
cargo xtask rules
→ 이 규칙 파일이 materialized bundle에 존재함을 검증

cargo xtask fmt
→ formatting

cargo xtask check
→ cargo check + reviewed Clippy, all targets

cargo xtask test
→ unit + integration + supported test targets

cargo xtask ci
→ rules → fmt → check → test
```

Generic xtask는 다음을 brittle source scanning으로 강제하지 않는다.

- source file line count;
- `mod.rs` 문자열 금지;
- 무조건적인 child-module 개수;
- 특정 directory depth;
- semantic responsibility split을 정규식으로 추론;
- 모든 test가 반드시 별도/inline 파일이어야 한다는 단일 형태.

이 항목들은 compiler/module privacy, Clippy, tests, repository-local architecture/profile 및 code review evidence가 함께 판단한다.

## 9. Review checklist

대형 Rust module을 검토할 때 순서:

1. crate authority가 맞는가?
2. 한 module이 하나의 응집된 책임 집합을 갖는가?
3. 독립 change reason이 이미 child module 후보로 형성됐는가?
4. visibility가 private → `pub(super)` → `pub(crate)` → `pub` 순으로 최소화됐는가?
5. unit test는 private invariant 가까이에 있는가?
6. root `tests/`는 실제 external/integration contract만 검증하는가?
7. test 분리만으로 production god-module을 가리고 있지 않은가?
8. split이 compile/dependency/ownership/review surface를 실제로 개선하는가?
9. line count만을 근거로 한 기계적 split은 아닌가?

## 10. 2026 verification basis

- Rust stable Book — Separating Modules into Different Files: `foo.rs` + `foo/bar.rs`를 관용 경로로 설명하고 `foo/mod.rs`를 older style, still supported로 명시.
  - https://doc.rust-lang.org/stable/book/ch07-05-separating-modules-into-different-files.html
- Rust Book — Test Organization: unit tests와 integration tests의 compilation/privacy 역할 분리.
  - https://doc.rust-lang.org/book/ch11-03-test-organization.html
- Rust Reference — Visibility and Privacy: private/public visibility와 module privacy semantics.
  - https://doc.rust-lang.org/stable/reference/visibility-and-privacy.html
- Clippy current documentation: `items_after_test_module`, `tests_outside_test_module`, `inline_modules`의 현재 역할과 restriction/style 성격.
  - https://rust-lang.github.io/rust-clippy/master/

Research baseline: Rust 1.98.0 / Edition 2024, verified 2026-08-26. Repository-local toolchain/MSRV and established module convention remain concrete authority.
