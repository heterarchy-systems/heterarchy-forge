# 09 — Public API and Type Evolution Rules

## Public types are compatibility contracts

For libraries, SDKs and stable inter-crate APIs, type shape is part of SemVer/support compatibility. Review not only function names, but fields, variants, trait bounds, implementations, auto traits, lifetimes, feature gates, layouts and re-exported dependency types.

## Representation hiding

Prefer private fields with constructors/accessors when callers do not need to own representation. Public struct fields allow direct construction/destructuring and make later invariant/representation evolution harder.

Use a newtype/private wrapper when an upstream dependency type should not become the permanent public identity of your API.

## Enum/struct evolution

Use `#[non_exhaustive]` when downstream exhaustive construction/matching should be prevented so compatible extension remains possible. Do not use it automatically when a deliberately closed set is itself the contract.

## Trait evolution

A public trait that downstream crates can implement is hard to evolve. Use sealed traits when implementation should remain crate-owned; otherwise design extension traits/method defaults/associated types with downstream implementors in mind.

Adding or tightening supertraits/generic bounds can be breaking even when signatures appear similar.

## Public dependencies

If a public signature exposes a dependency's type/trait, that dependency's version and compatibility become part of your effective public API. Expose external types deliberately and keep versions consistent across related public dependencies where type identity/interoperability matters.

Re-export dependencies only when callers are intentionally expected to use those exact public types.

## Auto traits and layout

Downstream code can depend on whether a public type is `Send`, `Sync`, `Unpin`, `Clone`, `Copy`, etc. Changes can be compatibility-relevant.

`repr(C)` / `repr(transparent)` or any documented layout/ABI promise is a stronger compatibility contract than ordinary Rust layout and is changed only deliberately.

## Features

Feature-gated public types/impls are part of the supported feature matrix. Avoid feature combinations that change one public type's identity incompatibly without a clear contract.

## MSRV

If a public library declares an MSRV, raising it is a support-contract change and follows repository release policy rather than silently following the latest compiler.

## Verification

Public libraries should use repository-owned API/SemVer review evidence appropriate to their release process. Tools such as `cargo-semver-checks` may be useful, but the shared harness does not globally mandate one external tool or treat it as complete proof.

Compile downstream examples/consumer fixtures when type identity, re-exports, features or dependency versions matter.
