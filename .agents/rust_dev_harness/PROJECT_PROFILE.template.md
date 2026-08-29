# Rust PROJECT_PROFILE Template

Repository-local profile that connects the shared Rust harness to one concrete project. It records applicability and authority; it is not a silent escape hatch from shared rules.

Adapt this template to `.agents/rust_dev_harness/PROJECT_PROFILE.md` or the repository's equivalent location.

```markdown
# <TARGET_PROJECT> Rust Project Profile

## Project shape

- kind: <library | application | service | cli | runtime | embedded | mixed>
- primary binaries/libraries: <TARGETS>
- normal rules: required
- type rules: required
- async/concurrency rules: <enabled | not-applicable>

## Toolchain and compatibility

- edition: 2024
- workspace resolver: 3
- toolchain policy: <pinned stable | rolling stable | explicit channel>
- rust-toolchain file: <path or none with rationale>
- MSRV policy: <explicit version | current stable only | none/not-public>
- Cargo.lock policy: <committed | library policy>

## Crate and authority map

| Crate / binary | Responsibility | Effects owned | Must not own |
| --- | --- | --- | --- |
| `<TARGET_CRATE>` | <domain/application/runtime/adapter/etc> | <effects> | <forbidden authority> |

Dependency direction:

```text
<interface/runtime/adapters>
          ↓
<application>
          ↓
<domain/core>
```

Record deliberate deviations explicitly.

## Type and API contract

- public API stability: <internal-only | repository-stable | published SemVer>
- domain identity/newtype invariants: <where authoritative constructors/parsers live>
- enum/state evolution: <closed | non-exhaustive/publicly extensible where applicable>
- public trait policy: <downstream-implementable | sealed where applicable>
- conversion/parsing authority: <TARGET>
- ownership model for key resources: <single owner / borrowed / shared / other>
- intended thread-safety: <Send+Sync | Send-only | local/thread-affine | mixed by type>
- public dependency/re-export policy: <TARGET>
- API/SemVer verification: <consumer fixtures / semver tooling / review / not-applicable>

Do not add `Send`, `Sync`, `'static`, `Clone`, shared pointers or broad trait bounds merely to satisfy one runtime implementation. Record intentionally local/thread-affine types here when they are architecturally important.

## Effects and external state

- persistence authority: <TARGET or none>
- network/transport authority: <TARGET or none>
- filesystem/process authority: <TARGET or none>
- clocks/randomness/IDs: <where observations are produced>
- configuration/environment ownership: <TARGET>

Deterministic domain decisions receive relevant observations explicitly rather than reading hidden process-global state.

## Async / concurrency — when enabled

- runtime/executor: <Tokio/other>
- runtime model: <multi-thread/current-thread/local/etc>
- task ownership/supervision: <strategy>
- cancellation propagation: <strategy>
- queue/channel capacities: <documented bounds>
- connection/in-flight limits: <bounds>
- blocking bridge: <strategy and bound>
- CPU parallel executor: <Rayon/dedicated/none and bound>
- graceful shutdown budget: <TARGET>
- concurrency verification: <virtual time/Loom/Shuttle/stress/etc as applicable>

## Feature policy

Choose one:

- composable features → supported all-feature verification
- constrained/mutually-exclusive features → explicit matrix below

Supported feature matrix:

- `<feature set 1>`
- `<feature set 2>`

Unsupported combinations are documented rather than accidentally treated as valid.

## Unsafe / FFI / native boundary

- default unsafe policy: `forbid`
- approved unsafe modules: <none or paths>
- invariant/proof owner for each unsafe boundary: <TARGET>
- approved unsafe trait impls (`Send`/`Sync`/other): <none or type + proof reference>
- FFI/native ABI: <none | C | cxx | uniffi | PyO3 | other>
- thread-affinity/reentrancy requirements: <if any>
- required soundness verification: <Miri/Loom/real ABI/fuzz/etc>

## Dependency / supply-chain policy

- direct dependency review required: <yes/no>
- cargo-deny: <required/optional/not-applicable>
- allowed registries/git sources: <policy>
- build-script/proc-macro/native-sys review: <policy>

## Verification gates

### Mandatory CI

- `cargo xtask rules`
- `cargo xtask fmt`
- `cargo xtask check`
- `cargo xtask test`
- <project-specific mandatory gates>

### Extended / scheduled / high-risk

- `cargo xtask deps` when supply-chain gate is required
- `cargo xtask extended`
- <feature matrix / Miri / fuzz / Loom / Shuttle / API compatibility / integration / fault tests>

### Performance

- `cargo xtask perf` is measurement evidence, not an automatic PASS claim unless reviewed project budgets exist.
- critical workloads/budgets: <TARGETS>

## Operational lifecycle — when applicable

- readiness/liveness authority: <TARGET>
- shutdown sequence: <signal → stop admission → drain/cancel → close → join → report>
- required task/resource leak evidence: <TARGET>

## Explicit exceptions

Every exception records:

- shared rule being deviated from
- concrete reason
- affected scope
- compensating verification
- owner
- review/expiry condition if temporary
```

## Usage rule

1. `rules/normal_dev_rules/` and `rules/type_dev_rules/` are always baseline.
2. Async/concurrent projects additionally apply `rules/async_dev_rules/`.
3. `PROJECT_PROFILE` declares concrete project authority, API stability and applicability; it does not silently weaken shared policy.
4. Live repository architecture, Cargo configuration, types/source and executable verification are final authority for the concrete project.
